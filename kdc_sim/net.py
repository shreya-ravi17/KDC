"""TCP layer so the KDC, Alice and Bob can run as separate programs
(on one computer or on different computers).

Wire format: 4-byte big-endian length + JSON. All secrets inside are already
AES-GCM encrypted by the protocol code, so the sockets carry only what an
eavesdropper is allowed to see.
"""
import json, os, socket, struct, threading
from .crypto_utils import b64, unb64
from .kdc import KDCError
from .client import ProtocolError

MAX_FRAME = 1 << 20


def send_frame(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock):
    (n,) = struct.unpack(">I", _recvn(sock, 4))
    if n > MAX_FRAME:
        raise ConnectionError("frame too large")
    return json.loads(_recvn(sock, n))


def load_key(path):
    with open(path) as f:
        return bytes.fromhex(f.read().strip())


def parse_addr(text):
    host, port = text.rsplit(":", 1)
    return host, int(port)


def _listen(host, port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen()
    return srv


# ---------------------------------------------------------------- KDC side
def serve_kdc(kdc, host, port, ready=None):
    srv = _listen(host, port)
    if ready:
        ready(srv.getsockname()[1])
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_kdc_conn, args=(kdc, conn, addr), daemon=True).start()


def _kdc_conn(kdc, conn, addr):
    with conn:
        try:
            req = recv_frame(conn)
            print(f"[KDC] {addr[0]}: {req['id_a']} asks for a key to talk to {req['id_b']}")
            blob = kdc.handle_request({"id_a": req["id_a"], "id_b": req["id_b"], "n1": req["n1"]})
            send_frame(conn, {"type": "reply", "blob": b64(blob)})
            print("[KDC] session key issued (encrypted for Alice, ticket for Bob)")
        except KDCError as e:
            print(f"[KDC] refused: {e}")
            send_frame(conn, {"type": "error", "msg": str(e)})
        except Exception as e:
            print(f"[KDC] bad request: {e}")


class RemoteKDC:
    """Looks like KDC.handle_request(), but talks to a KDC over TCP."""
    def __init__(self, host, port):
        self.host, self.port = host, port

    def handle_request(self, req):
        with socket.create_connection((self.host, self.port), timeout=10) as s:
            send_frame(s, {"type": "request", **req})
            r = recv_frame(s)
        if r["type"] == "error":
            raise KDCError(r["msg"])
        return unb64(r["blob"])


# ---------------------------------------------------------------- Bob side
def handshake_as_responder(client, conn):
    f = recv_frame(conn)
    sender = f["from"]
    try:
        challenge = client.receive_ticket(sender, unb64(f["ticket"]))
    except ProtocolError as e:
        send_frame(conn, {"type": "error", "msg": str(e)})
        raise
    send_frame(conn, {"type": "challenge", "blob": b64(challenge)})
    f = recv_frame(conn)
    try:
        client.receive_challenge_response(sender, unb64(f["blob"]))
    except ProtocolError as e:
        send_frame(conn, {"type": "error", "msg": str(e)})
        raise
    send_frame(conn, {"type": "ok"})
    return sender


def serve_peer(client, host, port, on_session, ready=None):
    """Accept connections one at a time; after a successful handshake call
    on_session(sender_name, connection)."""
    srv = _listen(host, port)
    if ready:
        ready(srv.getsockname()[1])
    while True:
        conn, addr = srv.accept()
        with conn:
            print(f"\n[Bob] connection from {addr[0]}")
            try:
                sender = handshake_as_responder(client, conn)
                on_session(sender, conn)
            except (ProtocolError, ConnectionError, OSError, KeyError, ValueError) as e:
                print(f"[Bob] connection dropped: {e}")


# -------------------------------------------------------------- Alice side
class RemotePeer:
    """Looks like a Client on the receiving end of steps 3-5, but over TCP."""
    def __init__(self, name, host, port):
        self.name = name
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(None)

    def _check(self, r):
        if r["type"] == "error":
            raise ProtocolError("peer rejected: " + r["msg"])

    def receive_ticket(self, sender, ticket):
        send_frame(self.sock, {"type": "ticket", "from": sender, "ticket": b64(ticket)})
        r = recv_frame(self.sock); self._check(r)
        return unb64(r["blob"])

    def receive_challenge_response(self, sender, blob):
        send_frame(self.sock, {"type": "response", "blob": b64(blob)})
        self._check(recv_frame(self.sock))


# -------------------------------------------------------------------- chat
def chat(client, peer, sock):
    def rx():
        try:
            while True:
                f = recv_frame(sock)
                if f.get("type") != "chat":
                    continue
                blob = unb64(f["blob"])
                print(f"\n  [wire] {f['blob'][:48]}...")
                try:
                    msg = client.receive_secure(peer, blob)
                    print(f"{peer}: {msg}")
                except ProtocolError as e:
                    print(f"[!] {e}")
                print(f"{client.name}> ", end="", flush=True)
        except (ConnectionError, OSError):
            print("\n[connection closed]")
            os._exit(0)

    threading.Thread(target=rx, daemon=True).start()
    print("\nSecure chat ready. Type a message and press Enter. /quit to exit.\n")
    while True:
        try:
            line = input(f"{client.name}> ")
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip() == "/quit":
            break
        if not line.strip():
            continue
        try:
            blob = client.send_secure(peer, line)
        except ProtocolError as e:
            print(f"[!] {e}")
            break
        send_frame(sock, {"type": "chat", "blob": b64(blob)})
    sock.close()
