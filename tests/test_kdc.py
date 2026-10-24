import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kdc_sim import KDC, Client, Network
from kdc_sim.kdc import KDCError
from kdc_sim.client import ProtocolError
from kdc_sim.crypto_utils import generate_key, encrypt, decrypt, CryptoError


def make(clock=None, lifetime=60):
    net = Network(verbose=False)
    kw = {"clock": clock} if clock else {}
    kdc = KDC(session_lifetime=lifetime, **kw)
    a = Client("Alice", kdc.register("Alice"), net, kdc, **kw)
    b = Client("Bob", kdc.register("Bob"), net, kdc, **kw)
    return net, kdc, a, b


class Tests(unittest.TestCase):
    def test_keys_match(self):
        _, _, a, b = make(); a.establish_session(b)
        self.assertEqual(a.sessions["Bob"]["ks"], b.sessions["Alice"]["ks"])

    def test_secure_message(self):
        _, _, a, b = make(); a.establish_session(b)
        self.assertEqual(b.receive_secure("Alice", a.send_secure("Bob", "hi")), "hi")

    def test_unknown_requester_and_peer(self):
        net, kdc, a, b = make()
        m = Client("Mallory", generate_key(), net, kdc)
        with self.assertRaises(KDCError): m.request_session_key("Bob")
        with self.assertRaises(KDCError): a.request_session_key("Nobody")

    def test_replay_ticket(self):
        _, _, a, b = make(); t = a.request_session_key("Bob"); a.contact_peer(b, t)
        with self.assertRaises(ProtocolError): b.receive_ticket("Alice", t)

    def test_tamper_ticket(self):
        _, _, a, b = make(); t = bytearray(a.request_session_key("Bob")); t[-1] ^= 1
        with self.assertRaises(ProtocolError): b.receive_ticket("Alice", bytes(t))

    def test_ticket_wrong_identity(self):
        net, kdc, a, b = make(); c = Client("Carol", kdc.register("Carol"), net, kdc)
        t = a.request_session_key("Bob")
        with self.assertRaises(ProtocolError): b.receive_ticket("Carol", t)

    def test_expired_ticket(self):
        t = [0.0]; _, _, a, b = make(clock=lambda: t[0])
        tk = a.request_session_key("Bob"); t[0] = 100
        with self.assertRaises(ProtocolError): b.receive_ticket("Alice", tk)

    def test_session_expiry(self):
        t = [0.0]; _, _, a, b = make(clock=lambda: t[0]); a.establish_session(b)
        t[0] = 100
        with self.assertRaises(ProtocolError): a.send_secure("Bob", "x")

    def test_replayed_kdc_reply_rejected(self):
        net, kdc, a, b = make()
        a.request_session_key("Bob")
        old_reply = net.log[1][3]
        net.tamper = lambda s, d, l, p: old_reply if l.startswith("2.") else p
        with self.assertRaises(ProtocolError): a.request_session_key("Bob")

    def test_tampered_message(self):
        _, _, a, b = make(); a.establish_session(b)
        m = bytearray(a.send_secure("Bob", "pay 10")); m[-1] ^= 1
        with self.assertRaises(ProtocolError): b.receive_secure("Alice", bytes(m))

    def test_fresh_session_keys(self):
        _, _, a, b = make()
        a.establish_session(b); k1 = a.sessions["Bob"]["ks"]
        a.establish_session(b); self.assertNotEqual(k1, a.sessions["Bob"]["ks"])

    def test_wrong_key_decrypt(self):
        with self.assertRaises(CryptoError):
            decrypt(generate_key(), encrypt(generate_key(), {"a": 1}))

    def test_duplicate_registration(self):
        _, kdc, _, _ = make()
        with self.assertRaises(KDCError): kdc.register("Alice")

    def test_chat_replay_rejected(self):
        _, _, a, b = make(); a.establish_session(b)
        m = a.send_secure("Bob", "pay 10")
        self.assertEqual(b.receive_secure("Alice", m), "pay 10")
        with self.assertRaises(ProtocolError): b.receive_secure("Alice", m)


class NetworkTest(unittest.TestCase):
    def test_end_to_end_over_tcp(self):
        import threading
        from kdc_sim.net import serve_kdc, serve_peer, RemoteKDC, RemotePeer, send_frame, recv_frame
        from kdc_sim.crypto_utils import b64, unb64
        kdc = KDC(); ka = kdc.register("Alice"); kb = kdc.register("Bob")
        kp, bp, e1, e2, e3, got = {}, {}, threading.Event(), threading.Event(), threading.Event(), []
        threading.Thread(target=serve_kdc, args=(kdc, "127.0.0.1", 0, lambda p: (kp.update(p=p), e1.set())), daemon=True).start()
        bob = Client("Bob", kb, Network(verbose=False))
        def on_session(sender, conn):
            f = recv_frame(conn); got.append(bob.receive_secure(sender, unb64(f["blob"]))); e3.set()
        threading.Thread(target=serve_peer, args=(bob, "127.0.0.1", 0, on_session, lambda p: (bp.update(p=p), e2.set())), daemon=True).start()
        self.assertTrue(e1.wait(5) and e2.wait(5))
        alice = Client("Alice", ka, Network(verbose=False), kdc=RemoteKDC("127.0.0.1", kp["p"]))
        peer = RemotePeer("Bob", "127.0.0.1", bp["p"])
        alice.establish_session(peer)
        send_frame(peer.sock, {"type": "chat", "blob": b64(alice.send_secure("Bob", "hello over tcp"))})
        self.assertTrue(e3.wait(5)); self.assertEqual(got, ["hello over tcp"])
        self.assertEqual(alice.sessions["Bob"]["ks"], bob.sessions["Alice"]["ks"])


if __name__ == "__main__":
    unittest.main()
