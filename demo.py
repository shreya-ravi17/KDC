"""Run:  python demo.py
Walks through the full protocol plus several attack scenarios."""
from kdc_sim import KDC, Client, Network
from kdc_sim.client import ProtocolError
from kdc_sim.crypto_utils import generate_key, b64


def banner(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


def setup(clock=None):
    net = Network()
    kdc = KDC(session_lifetime=60, **({"clock": clock} if clock else {}))
    ka, kb = kdc.register("Alice"), kdc.register("Bob")
    kw = {"clock": clock} if clock else {}
    alice = Client("Alice", ka, net, kdc, **kw)
    bob = Client("Bob", kb, net, kdc, **kw)
    return net, kdc, alice, bob


def main():
    banner("SCENARIO 1: Normal session-key distribution (Needham-Schroeder)")
    net, kdc, alice, bob = setup()
    alice.establish_session(bob)
    assert alice.sessions["Bob"]["ks"] == bob.sessions["Alice"]["ks"]
    print(f"\n  Alice and Bob now share Ks = {b64(alice.sessions['Bob']['ks'])[:20]}...")
    blob = alice.send_secure("Bob", "Hello Bob, this is Alice!")
    print("  Bob decrypts:", repr(bob.receive_secure("Alice", blob)))
    blob = bob.send_secure("Alice", "Hi Alice, loud and clear.")
    print("  Alice decrypts:", repr(alice.receive_secure("Bob", blob)))

    banner("SCENARIO 2: Eve (eavesdropper) tries to read the traffic")
    eve_key = generate_key()
    from kdc_sim.crypto_utils import decrypt, CryptoError
    for src, dst, label, payload in net.log:
        if isinstance(payload, bytes):
            try:
                decrypt(eve_key, payload); print("  Eve read", label)
            except CryptoError:
                print(f"  Eve cannot decrypt: {label}")

    banner("SCENARIO 3: Unregistered user (Mallory) asks KDC for a key")
    net2, kdc2, a2, b2 = setup()
    mallory = Client("Mallory", generate_key(), net2, kdc2)
    try:
        mallory.request_session_key("Bob")
    except Exception as e:
        print("  KDC refused:", e)

    banner("SCENARIO 4: Replay of an old ticket to Bob")
    net3, kdc3, a3, b3 = setup()
    ticket = a3.request_session_key("Bob")
    a3.contact_peer(b3, ticket)
    try:
        b3.receive_ticket("Alice", ticket)
    except ProtocolError as e:
        print("  Bob rejected:", e)

    banner("SCENARIO 5: Tampered ticket")
    net4, kdc4, a4, b4 = setup()
    ticket = a4.request_session_key("Bob")
    bad = bytearray(ticket); bad[-1] ^= 1
    try:
        b4.receive_ticket("Alice", bytes(bad))
    except ProtocolError as e:
        print("  Bob rejected:", e)

    banner("SCENARIO 6: Session key expiry")
    t = [1000.0]
    net5, kdc5, a5, b5 = setup(clock=lambda: t[0])
    a5.establish_session(b5)
    t[0] += 61
    try:
        a5.send_secure("Bob", "too late")
    except ProtocolError as e:
        print("  Alice refused to send:", e)

    banner("SCENARIO 7: Fresh key for every session")
    net6, kdc6, a6, b6 = setup()
    a6.establish_session(b6); k1 = a6.sessions["Bob"]["ks"]
    a6.establish_session(b6); k2 = a6.sessions["Bob"]["ks"]
    print("  Keys differ between sessions:", k1 != k2)


if __name__ == "__main__":
    main()
