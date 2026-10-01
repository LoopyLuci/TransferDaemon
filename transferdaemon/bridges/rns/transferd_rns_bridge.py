"""TransferD's Reticulum bridge: what Crosstalk (Reticulum MeshChat) does, for TransferD.

Runs the reference Reticulum stack (RNS) and LXMF in a process of its own, with a configuration of its own (it never
attaches to another local Reticulum instance), and answers TransferD over a local, token-protected JSON-lines socket:

    {"token": ..., "op": "status"}                 identity, LXMF address, interfaces (online, traffic), counts
    {"op": "announce"}                             announce this LXMF address on every interface
    {"op": "peers"}                                LXMF addresses heard (name, hops, interface, last heard): the network map
    {"op": "interfaces"}                           every interface with its state and traffic
    {"op": "send", "to": hex, "content": str, "title": str, "propagated": bool}
                                                   an LXMF message; "id" to follow it
    {"op": "message", "id": hex}                   a sent message's state (outbound, sending, sent, delivered, failed)
    {"op": "inbox", "since": float}                messages received
    {"op": "propagation", "node": hex | null}      the propagation node for store-and-forward (and fetch from it)
    {"op": "stop"}

Interfaces come from the command line: --listen host:port (TCPServerInterface), --connect host:port
(TCPClientInterface), --auto (AutoInterface: other Reticulum nodes on the LAN), --rnode PORT with --freq --bw --sf --cr
--txpower (an RNode LoRa radio). Everything lives in --data: the identity, LXMF's store, control.json (port + token).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socketserver
import sys
import threading
import time
from pathlib import Path

import LXMF
import RNS

STATE_NAMES = {}
for _n in ("GENERATING", "OUTBOUND", "SENDING", "SENT", "DELIVERED", "REJECTED", "CANCELLED", "FAILED"):
    if hasattr(LXMF.LXMessage, _n):
        STATE_NAMES[getattr(LXMF.LXMessage, _n)] = _n.lower()


def write_config(cfg_dir: Path, a) -> None:
    lines = ["[reticulum]", "  enable_transport = No", "  share_instance = No", "  panic_on_interface_error = No", "",
             "[logging]", f"  loglevel = {a.loglevel}", "", "[interfaces]"]
    for i, ep in enumerate(a.listen):
        host, port = ep.rsplit(":", 1)
        lines += [f"  [[TCP Server {i}]]", "    type = TCPServerInterface", "    enabled = yes", f"    listen_ip = {host}",
                  f"    listen_port = {port}"]
    for i, ep in enumerate(a.connect):
        host, port = ep.rsplit(":", 1)
        lines += [f"  [[TCP Client {i}]]", "    type = TCPClientInterface", "    enabled = yes", f"    target_host = {host}",
                  f"    target_port = {port}"]
    if a.auto:
        lines += ["  [[LAN]]", "    type = AutoInterface", "    enabled = yes"]
    if a.rnode:
        lines += ["  [[RNode LoRa]]", "    type = RNodeInterface", "    enabled = yes", f"    port = {a.rnode}",
                  f"    frequency = {a.freq}", f"    bandwidth = {a.bw}", f"    txpower = {a.txpower}",
                  f"    spreadingfactor = {a.sf}", f"    codingrate = {a.cr}"]
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config").write_text("\n".join(lines) + "\n", encoding="utf-8")


class Bridge:
    def __init__(self, a):
        self.data = Path(a.data)
        self.data.mkdir(parents=True, exist_ok=True)
        write_config(self.data / "reticulum", a)
        self.rns = RNS.Reticulum(configdir=str(self.data / "reticulum"))
        id_file = self.data / "identity"
        if id_file.exists():
            self.identity = RNS.Identity.from_file(str(id_file))
        else:
            self.identity = RNS.Identity()
            self.identity.to_file(str(id_file))
        self.router = LXMF.LXMRouter(identity=self.identity, storagepath=str(self.data / "lxmf"))
        self.dest = self.router.register_delivery_identity(self.identity, display_name=a.name)
        self.router.register_delivery_callback(self._delivered)
        self.lock = threading.Lock()
        self.inbox: list[dict] = []
        self.sent: dict[str, LXMF.LXMessage] = {}
        self.peers: dict[str, dict] = {}
        # RNS registers a handler only if it already has aspect_filter; path responses count as hearing a peer too
        self.aspect_filter = "lxmf.delivery"
        self.receive_path_responses = True
        RNS.Transport.register_announce_handler(self)
        self.started = time.time()

    # RNS announce handler interface
    def received_announce(self, destination_hash, announced_identity, app_data):
        name = ""
        try:
            name = LXMF.display_name_from_app_data(app_data) or ""
        except Exception:  # noqa: BLE001 - a peer's app data is theirs to get wrong
            pass
        h = destination_hash.hex()
        with self.lock:
            self.peers[h] = {"address": h, "name": name, "heard": time.time(), "hops": RNS.Transport.hops_to(destination_hash)}

    def _delivered(self, msg):
        with self.lock:
            self.inbox.append({"id": msg.hash.hex() if msg.hash else "", "from": msg.source_hash.hex(), "title": msg.title_as_string(),
                               "content": msg.content_as_string(), "time": msg.timestamp or time.time(),
                               "method": {getattr(LXMF.LXMessage, "DIRECT", -1): "direct",
                                          getattr(LXMF.LXMessage, "PROPAGATED", -2): "propagated",
                                          getattr(LXMF.LXMessage, "OPPORTUNISTIC", -3): "opportunistic"}.get(msg.method, str(msg.method))})

    def interfaces(self):
        out = []
        for i in RNS.Transport.interfaces:
            out.append({"name": str(i), "online": bool(getattr(i, "online", False)), "rx_bytes": getattr(i, "rxb", 0),
                        "tx_bytes": getattr(i, "txb", 0), "kind": type(i).__name__})
        return out

    def status(self):
        return {"identity": self.identity.hash.hex(), "lxmf_address": self.dest.hash.hex(), "interfaces": self.interfaces(),
                "peers": len(self.peers), "inbox": len(self.inbox), "uptime_s": round(time.time() - self.started, 1),
                "rns": getattr(RNS, "__version__", ""), "lxmf": getattr(LXMF, "__version__", "")}

    def announce(self):
        self.router.announce(self.dest.hash)
        return {"announced": self.dest.hash.hex()}

    def send(self, to: str, content: str, title: str = "", propagated: bool = False, wait_s: float = 20):
        h = bytes.fromhex(to)
        ident = RNS.Identity.recall(h)
        if ident is None:
            RNS.Transport.request_path(h)
            end = time.time() + wait_s
            while ident is None and time.time() < end:
                time.sleep(0.2)
                ident = RNS.Identity.recall(h)
        if ident is None:
            raise ValueError(f"no path to {to} yet (has it announced? try again once it has)")
        out = RNS.Destination(ident, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
        method = LXMF.LXMessage.PROPAGATED if propagated else LXMF.LXMessage.DIRECT
        msg = LXMF.LXMessage(out, self.dest, content, title, desired_method=method)
        self.router.handle_outbound(msg)
        mid = msg.hash.hex() if msg.hash else secrets.token_hex(16)
        with self.lock:
            self.sent[mid] = msg
        return {"id": mid, "state": STATE_NAMES.get(msg.state, str(msg.state))}

    def message(self, mid: str):
        msg = self.sent.get(mid)
        if msg is None:
            raise ValueError(f"no sent message {mid}")
        return {"id": mid, "state": STATE_NAMES.get(msg.state, str(msg.state)), "progress": getattr(msg, "progress", None)}

    def propagation(self, node):
        if node:
            self.router.set_outbound_propagation_node(bytes.fromhex(node))
            self.router.request_messages_from_propagation_node(self.identity)
        return {"propagation_node": node}

    def handle(self, req: dict):
        op = req.get("op")
        if op == "status":
            return self.status()
        if op == "announce":
            return self.announce()
        if op == "peers":
            with self.lock:
                peers = sorted(self.peers.values(), key=lambda p: -p["heard"])
            for p in peers:
                p["hops"] = RNS.Transport.hops_to(bytes.fromhex(p["address"]))
            return {"peers": peers}
        if op == "interfaces":
            return {"interfaces": self.interfaces()}
        if op == "send":
            return self.send(req["to"], req.get("content", ""), req.get("title", ""), bool(req.get("propagated")),
                             float(req.get("wait_s", 20)))
        if op == "message":
            return self.message(req["id"])
        if op == "inbox":
            since = float(req.get("since", 0))
            with self.lock:
                return {"messages": [m for m in self.inbox if m["time"] >= since]}
        if op == "propagation":
            return self.propagation(req.get("node"))
        if op == "stop":
            threading.Thread(target=lambda: (time.sleep(0.2), os._exit(0)), daemon=True).start()
            return {"stopping": True}
        raise ValueError(f"unknown op {op!r}")


def serve(bridge: Bridge, data: Path) -> None:
    token = secrets.token_hex(24)

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            for line in self.rfile:
                try:
                    req = json.loads(line)
                    if not secrets.compare_digest(str(req.get("token", "")), token):
                        out = {"error": "bad token"}
                    else:
                        out = {"result": bridge.handle(req)}
                except Exception as e:  # noqa: BLE001 - every failure goes back to the caller as text
                    out = {"error": f"{type(e).__name__}: {e}"}
                self.wfile.write((json.dumps(out) + "\n").encode())
                self.wfile.flush()

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    ctl = data / "control.json"
    tmp = ctl.with_suffix(".tmp")
    tmp.write_text(json.dumps({"port": srv.server_address[1], "token": token, "pid": os.getpid(),
                               "lxmf_address": bridge.dest.hash.hex()}), encoding="utf-8")
    os.replace(tmp, ctl)
    print(f"transferd-rns-bridge: LXMF address {bridge.dest.hash.hex()}, control on 127.0.0.1:{srv.server_address[1]}", flush=True)
    srv.serve_forever()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--data", required=True)
    p.add_argument("--name", default="TransferD")
    p.add_argument("--listen", action="append", default=[])
    p.add_argument("--connect", action="append", default=[])
    p.add_argument("--auto", action="store_true")
    p.add_argument("--rnode", default="")
    p.add_argument("--freq", type=int, default=867200000)
    p.add_argument("--bw", type=int, default=125000)
    p.add_argument("--sf", type=int, default=8)
    p.add_argument("--cr", type=int, default=5)
    p.add_argument("--txpower", type=int, default=7)
    p.add_argument("--loglevel", type=int, default=2)
    a = p.parse_args(argv)
    serve(Bridge(a), Path(a.data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
