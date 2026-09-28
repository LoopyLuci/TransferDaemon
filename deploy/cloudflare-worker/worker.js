// TransferDaemon relay as a Cloudflare Worker (free tier, zero servers).
//
// A Durable Object brokers WebSocket connections keyed by opaque relay token,
// forwarding the EXACT `relayd`/`relayd-ws` binary frames between sessions —
// the same Rust client logic speaks to this relay as to a self-hosted one.
//
// The relay never inspects plaintext: it forwards opaque blobs. Bodies are
// Rust `bincode` (little-endian), matching relayd::protocol:
//   RegisterMsg  { session_token:[u8;32], pow_nonce:u64, seq:u32 }
//   ForwardMsg   { session_token:[u8;32], pow_nonce:u64, sender_seq:u16,
//                  ciphertext:Vec<u8> }               // varint len + bytes
//   KeepaliveMsg { session_token:[u8;32], pow_nonce:u64, seq:u32 }
//   DeliveredMsg { sender_seq:u16, ciphertext:Vec<u8> }  // == ForwardMsg[40..]
//   AckMsg       { sender_seq:u16 }                       // == ForwardMsg[40..42]
//   ChallengeMsg { challenge:[u8;16], expires_at:u64, difficulty:u32 }
//
// Only the token (first 32 bytes) and sender_seq (bytes 40..42) are parsed;
// the rest is forwarded verbatim. PoW is NOT enforced here (Cloudflare's edge
// rate-limits + the per-IP bucket below are the abuse barrier on the free
// tier); full BLAKE3 PoW lives on self-hosted relayd/relayd-ws.
//
// NOTE (SQLite-backed Durable Objects enable WebSocket HIBERNATION): the DO
// must NOT call `ws.accept()` manually — `state.acceptWebSocket()` is enough,
// and messages/closes arrive via the `webSocketMessage`/`webSocketClose`
// handler methods (which survive hibernation). Calling `accept()` throws.
//
// Deploy:  npm i -D wrangler && npx wrangler deploy (see wrangler.toml)

// Byte values MUST match relayd::protocol::Tag (crates/relayd/src/protocol.rs):
// Register 0x01, Forward 0x02, Keepalive 0x03, Challenge 0x04, Error 0x05, Ack 0x06.
const TAG = { Register: 0x01, Forward: 0x02, Keepalive: 0x03, Challenge: 0x04, Error: 0x05, Ack: 0x06 };

export default {
  async fetch(request, env) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('relay requires a WebSocket connection', { status: 400 });
    }
    const id = env.TRANSFERD_RELAY.idFromName('relay');
    return env.TRANSFERD_RELAY.get(id).fetch(request);
  },
};

export class TRANSFERD_RELAY {
  constructor(state, env) {
    this.state = state;
    this.clients = new Map(); // token(hex) → { ws, ip, expires }
    this.rate = new Map();    // ip → { hits, windowStart }
    this.bandwidth = new Map(); // token(hex) → [dayEpoch, dayBytes, weekEpoch, weekBytes, monthEpoch, monthBytes]
    // Node limits from wrangler.toml [vars] (0 = unlimited):
    //   MAX_BLOB_BYTES, MAX_MB_PER_DAY, MAX_MB_PER_WEEK, MAX_MB_PER_MONTH
    this.limits = {
      maxBlobBytes: Number(env.MAX_BLOB_BYTES) || 0,
      dayBytes: (Number(env.MAX_MB_PER_DAY) || 0) << 20,
      weekBytes: (Number(env.MAX_MB_PER_WEEK) || 0) << 20,
      monthBytes: (Number(env.MAX_MB_PER_MONTH) || 0) << 20,
    };
  }

  // Charge `bytes` to `token`'s rolling windows; false if a budget would break.
  chargeBandwidth(token, bytes) {
    const now = Math.floor(Date.now() / 1000);
    const dayE = Math.floor(now / 86400), weekE = Math.floor(now / 604800), monthE = Math.floor(now / 2592000);
    let w = this.bandwidth.get(token);
    if (!w) { w = [dayE, 0, weekE, 0, monthE, 0]; this.bandwidth.set(token, w); }
    const buckets = [
      [dayE, w[0], w[1], this.limits.dayBytes],
      [weekE, w[2], w[3], this.limits.weekBytes],
      [monthE, w[4], w[5], this.limits.monthBytes],
    ];
    for (let i = 0; i < 3; i++) {
      const cur = buckets[i][1] === buckets[i][0] ? buckets[i][2] : 0;
      if (buckets[i][3] && cur + bytes > buckets[i][3]) return false;
    }
    for (let i = 0; i < 3; i++) {
      if (w[i * 2] !== buckets[i][0]) { w[i * 2] = buckets[i][0]; w[i * 2 + 1] = 0; }
      w[i * 2 + 1] += bytes;
    }
    return true;
  }

  async fetch(request) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('relay requires a WebSocket connection', { status: 400 });
    }
    const pair = new WebSocketPair();
    const [server, client] = Object.values(pair);
    // Hibernation is on (SQLite DO): acceptWebSocket() is the accept; do NOT
    // call server.accept() — that throws.
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  limited(ip) {
    const now = Date.now();
    let r = this.rate.get(ip) || { hits: 0, windowStart: now };
    if (now - r.windowStart > 10_000) { r = { hits: 0, windowStart: now }; }
    r.hits += 1;
    this.rate.set(ip, r);
    return r.hits > 30;
  }

  // Rebuild the in-memory token→socket map after a hibernation wake. SQLite
  // Durable Objects hibernate after seconds idle; the `clients` Map is NOT
  // persisted, but the accepted WebSockets (with their `_meta.token`) survive.
  rebuildClients() {
    for (const ws of this.state.getWebSockets()) {
      const t = ws._meta && ws._meta.token;
      if (t && !this.clients.has(t)) {
        this.clients.set(t, {
          ws,
          ip: (ws._meta && ws._meta.ip) || 'unknown',
          expires: Date.now() + 90_000,
        });
      }
    }
  }

  // Hibernation message handler: `message` is the raw payload.
  async webSocketMessage(ws, message) {
    // Any message may follow a hibernation wake — rebuild the routing map.
    this.rebuildClients();
    // The message may arrive as an ArrayBuffer or a wrapper object; normalize.
    let data = message;
    if (data && typeof data === 'object' && data.data !== undefined) {
      data = data.data;
    }
    if (!(data instanceof ArrayBuffer)) return;
    const frame = new Uint8Array(data);
    const tag = frame[0];
    const body = frame.subarray(1);
    // Register/Forward/Keepalive carry a 32-byte token; a Challenge ask is a
    // bare 1-byte frame (matching relayd's wire format) and needs no token.
    if (body.length < 32 && tag !== TAG.Challenge) return;

    const ip = (ws && ws._meta && ws._meta.ip) || 'unknown';
    if (this.limited(ip)) { ws.send(frame); return; }

    const token = toHex(body.subarray(0, 32));
    switch (tag) {
      case TAG.Register:
        // Persist the token on the socket's metadata so rebuildClients() can
        // restore the mapping across hibernation.
        ws._meta = ws._meta || {};
        ws._meta.token = token;
        ws._meta.ip = ip;
        this.clients.set(token, { ws, ip, expires: Date.now() + 90_000 });
        console.log('HARBOR Register ' + token.slice(0, 8) + ' clients=' + this.clients.size);
        ws.send(challengeFrame()); // register accepted (ChallengeMsg reply)
        break;
      case TAG.Forward: {
        // sender_seq = bytes 40..42 (after 32-byte token + 8-byte pow_nonce).
        // DeliveredMsg body == ForwardMsg body[40..] (u16 seq + varint ciphertext).
        const blobBytes = body.length - 40;
        console.log('HARBOR Forward ' + token.slice(0, 8) + ' blob=' + blobBytes + ' dst=' + (this.clients.has(token) ? 'yes' : 'NO') + ' clients=' + this.clients.size);
        if (this.limits.maxBlobBytes && blobBytes > this.limits.maxBlobBytes) {
          ws.send(errorFrame(ErrorCode.PAYLOAD_TOO_LARGE, 0, 'blob exceeds node limit'));
          break;
        }
        if (!this.chargeBandwidth(token, blobBytes)) {
          ws.send(errorFrame(ErrorCode.BANDWIDTH_EXCEEDED, 0, 'token bandwidth budget exceeded'));
          break;
        }
        const dst = this.clients.get(token);
        if (dst && dst.ws.readyState === 1) {
          dst.ws.send(prefix(TAG.Ack, body.subarray(40)));
        }
        ws.send(prefix(TAG.Ack, body.subarray(40, 42)));
        break;
      }
      case TAG.Keepalive: {
        const c = this.clients.get(token);
        if (c) c.expires = Date.now() + 90_000;
        break;
      }
      case TAG.Challenge:
        ws.send(challengeFrame());
        break;
      default:
        break;
    }
  }

  async webSocketClose(ws, code, reason) {
    for (const [token, c] of this.clients) {
      if (c.ws === ws) this.clients.delete(token);
    }
  }

  async webSocketError(ws, error) {
    for (const [token, c] of this.clients) {
      if (c.ws === ws) this.clients.delete(token);
    }
  }
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

const ErrorCode = { InvalidPoW: 1, TokenNotFound: 2, PayloadTooLarge: 4, RateLimited: 5, BandwidthExceeded: 7 };

// ErrorMsg bincode: [code:u16 LE][seq:u32 LE][len:u64 LE][detail bytes].
function errorFrame(code, seq, detail) {
  const d = new TextEncoder().encode(detail);
  const body = new Uint8Array(2 + 4 + 8 + d.length);
  new DataView(body.buffer).setUint16(0, code, true);
  new DataView(body.buffer).setUint32(2, seq, true);
  new DataView(body.buffer).setBigUint64(6, BigInt(d.length), true);
  body.set(d, 14);
  return prefix(TAG.Error, body);
}

function prefix(tag, bytes) {
  const out = new Uint8Array(1 + bytes.length);
  out[0] = tag;
  out.set(bytes, 1);
  return out.buffer;
}

// ChallengeMsg bincode: [challenge:16][expires_at:u64 LE][difficulty:u32 LE].
function challengeFrame() {
  const challenge = crypto.getRandomValues(new Uint8Array(16));
  const expires = Date.now() / 1000 + 60;
  const difficulty = 0;
  const body = new Uint8Array(16 + 8 + 4);
  body.set(challenge, 0);
  new DataView(body.buffer).setBigUint64(16, BigInt(Math.floor(expires)), true);
  new DataView(body.buffer).setUint32(24, difficulty, true);
  const out = new Uint8Array(1 + body.length);
  out[0] = TAG.Challenge;
  out.set(body, 1);
  return out.buffer;
}