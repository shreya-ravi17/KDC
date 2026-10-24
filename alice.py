"""Alice: asks the KDC for a session key, contacts Bob, then chats.
  python alice.py --kdc 127.0.0.1:5000 --peer-addr BOB_IP:5001
"""
import argparse, hashlib
from kdc_sim import Client, Network
from kdc_sim.kdc import KDCError
from kdc_sim.client import ProtocolError
from kdc_sim.net import RemoteKDC, RemotePeer, load_key, parse_addr, chat


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", default="Alice"); p.add_argument("--peer", default="Bob"); p.add_argument("--key")
    p.add_argument("--kdc", default="127.0.0.1:5000"); p.add_argument("--peer-addr", default="127.0.0.1:5001")
    a = p.parse_args()
    alice = Client(a.name, load_key(a.key or f"keys/{a.name}.key"), Network(verbose=True), kdc=RemoteKDC(*parse_addr(a.kdc)))
    try:
        print(f"Connecting to {a.peer} at {a.peer_addr} ...")
        peer = RemotePeer(a.peer, *parse_addr(a.peer_addr))
        print("\n--- running key distribution protocol ---")
        alice.establish_session(peer)
    except (KDCError, ProtocolError) as e:
        print("\nProtocol failed:", e); return
    except (ConnectionError, OSError) as e:
        print("\nCould not connect:", e, "\nCheck the KDC/Bob are running, the IP:port is right, and the firewall allows it."); return
    fp = hashlib.sha256(alice.sessions[a.peer]["ks"]).hexdigest()[:16]
    print(f"\n[Alice] handshake OK. Session key fingerprint: {fp}")
    chat(alice, a.peer, peer.sock)


if __name__ == "__main__":
    main()
