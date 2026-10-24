"""Bob: waits for Alice, completes the handshake, then chats.
  python bob.py --key keys/Bob.key --port 5001
"""
import argparse, hashlib, socket
from kdc_sim import Client, Network
from kdc_sim.net import serve_peer, load_key, chat


def my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", default="Bob"); p.add_argument("--key"); p.add_argument("--port", type=int, default=5001)
    a = p.parse_args()
    bob = Client(a.name, load_key(a.key or f"keys/{a.name}.key"), Network(verbose=True))

    def on_session(sender, conn):
        fp = hashlib.sha256(bob.sessions[sender]["ks"]).hexdigest()[:16]
        print(f"\n[Bob] handshake OK with {sender}. Session key fingerprint: {fp}")
        print("      (Alice's screen must show the same fingerprint)")
        chat(bob, sender, conn)

    print(f"{a.name} listening on port {a.port}.  Tell Alice to use:  --peer-addr {my_ip()}:{a.port}")
    serve_peer(bob, "0.0.0.0", a.port, on_session)


if __name__ == "__main__":
    main()
