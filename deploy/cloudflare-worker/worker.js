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
// Deploy:  npm i -D wrangler && npx wrangler deploy (see wrangler.toml)

const TAG = { Register: 0x01, Forward: 0x02, Challenge: 0x03, Keepalive: 0x04, Ack: 0x05, Error: 0x06 };
const TOKEN = { Register: 0, Forward: 0, Keepalive: 0 }; // token offset in each body

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
  constructor(state) {
    this.state = state;
    this.clients = new Map(); // token(hex) → { ws, ip, expires }
    this.rate = new Map();    // ip → { hits, windowStart }
  }

  async fetch(request) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('relay requires a WebSocket connection', { status: 400 });
    }
    const pair = new WebSocketPair();
    const [server, client] = Object.values(pair);
    this.state.acceptWebSocket(server);
    server.accept();
    server.addEventListener('message', (ev) => this.onMessage(server, ev));
    server.addEventListener('close', () => this.onClose(server));
    server.addEventListener('error', () => this.onClose(server));
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

  onMessage(ws, ev) {
    const data = ev.data;
    if (!(data instanceof ArrayBuffer)) return;
    const frame = new Uint8Array(data);
    const tag = frame[0];
    const body = frame.subarray(1);
    if (body.length < 32) return;

    const ip = (ws && ws._meta && ws._meta.ip) || 'unknown';
    if (this.limited(ip)) { ws.send(frame); return; }

    const token = toHex(body.subarray(0, 32));
    switch (tag) {
      case TAG.Register:
        this.clients.set(token, { ws, ip, expires: Date.now() + 90_000 });
        ws.send(challengeFrame()); // register accepted (ChallengeMsg reply)
        break;
      case TAG.Forward: {
        // sender_seq = bytes 40..42 (after 32-byte token + 8-byte pow_nonce).
        // DeliveredMsg body == ForwardMsg body[40..] (u16 seq + varint ciphertext).
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

  onClose(ws) {
    for (const [token, c] of this.clients) {
      if (c.ws === ws) this.clients.delete(token);
    }
  }
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
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