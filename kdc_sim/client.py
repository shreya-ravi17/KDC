"""A client principal (Alice, Bob, ...). Plays both the initiator and
responder roles of the protocol."""
import time
from .crypto_utils import (encrypt, decrypt, generate_nonce, b64, unb64,
                           CryptoError)


class ProtocolError(Exception):
    pass


class Client:
    def __init__(self, name, master_key, network, kdc=None, clock=time.time):
        self.name = name
        self._master_key = master_key      # shared with the KDC only
        self.net = network
        self.kdc = kdc                     # only needed by initiators
        self.clock = clock
        self.sessions = {}                 # peer -> {"ks": bytes, "expires": float}
        self._pending_nonce = {}           # peer -> n2 awaiting answer
        self._seen_tickets = set()         # replay protection (responder side)

    # =========== Initiator (Alice) ===========
    def request_session_key(self, peer):
        """Steps 1-2: ask the KDC for a session key for talking to `peer`."""
        n1 = generate_nonce()
        req = {"id_a": self.name, "id_b": peer, "n1": n1}
        req = self.net.send(self.name, "KDC", "1. Key request (A, B, N1)", req)
        reply = self.kdc.handle_request(req)
        reply = self.net.send("KDC", self.name, "2. E(Ka,[Ks,B,N1,exp,ticket])", reply)

        try:
            msg = decrypt(self._master_key, reply)
        except CryptoError as e:
            raise ProtocolError("KDC reply could not be decrypted") from e
        if msg["n1"] != n1:
            raise ProtocolError("nonce mismatch: stale or replayed KDC reply")
        if msg["id_b"] != peer:
            raise ProtocolError("KDC reply is for a different peer")
        self.sessions[peer] = {"ks": unb64(msg["ks"]), "expires": msg["expires"], "tx": 0, "rx": 0}
        return unb64(msg["ticket"])

    def contact_peer(self, bob, ticket):
        """Steps 3-5: forward ticket to Bob and run the handshake."""
        ticket = self.net.send(self.name, bob.name, "3. Ticket E(Kb,[Ks,A,ts,exp])", ticket)
        challenge = bob.receive_ticket(self.name, ticket)
        challenge = self.net.send(bob.name, self.name, "4. E(Ks,N2)", challenge)

        ks = self.sessions[bob.name]["ks"]
        n2 = decrypt(ks, challenge)["n2"]
        answer = encrypt(ks, {"n2_minus_1": n2 - 1})
        answer = self.net.send(self.name, bob.name, "5. E(Ks,N2-1)", answer)
        bob.receive_challenge_response(self.name, answer)

    def establish_session(self, bob):
        ticket = self.request_session_key(bob.name)
        self.contact_peer(bob, ticket)

    # =========== Responder (Bob) ===========
    def receive_ticket(self, sender, ticket):
        try:
            t = decrypt(self._master_key, ticket)
        except CryptoError as e:
            raise ProtocolError("ticket rejected: not issued by KDC for me") from e
        if t["id_a"] != sender:
            raise ProtocolError("ticket rejected: identity mismatch")
        if self.clock() > t["expires"]:
            raise ProtocolError("ticket rejected: expired")
        if ticket in self._seen_tickets:
            raise ProtocolError("ticket rejected: replay detected")
        self._seen_tickets.add(ticket)

        ks = unb64(t["ks"])
        self.sessions[sender] = {"ks": ks, "expires": t["expires"], "tx": 0, "rx": 0}
        n2 = generate_nonce()
        self._pending_nonce[sender] = n2
        return encrypt(ks, {"n2": n2})

    def receive_challenge_response(self, sender, blob):
        ks = self.sessions[sender]["ks"]
        try:
            resp = decrypt(ks, blob)
        except CryptoError as e:
            raise ProtocolError("handshake failed: bad response") from e
        if resp["n2_minus_1"] != self._pending_nonce.pop(sender) - 1:
            raise ProtocolError("handshake failed: wrong N2-1 (sender lacks Ks)")

    # =========== Secure messaging ===========
    def send_secure(self, peer, text):
        s = self._live_session(peer)
        s["tx"] += 1
        blob = encrypt(s["ks"], {"from": self.name, "seq": s["tx"], "msg": text})
        return self.net.send(self.name, peer, "SECURE MSG E(Ks,msg)", blob)

    def receive_secure(self, peer, blob):
        s = self._live_session(peer)
        try:
            m = decrypt(s["ks"], blob)
        except CryptoError as e:
            raise ProtocolError("message rejected: bad key or tampered") from e
        if m["from"] != peer:
            raise ProtocolError("message rejected: sender mismatch")
        if m.get("seq", 0) <= s["rx"]:
            raise ProtocolError("message rejected: replayed or out of order")
        s["rx"] = m["seq"]
        return m["msg"]

    def _live_session(self, peer):
        s = self.sessions.get(peer)
        if not s:
            raise ProtocolError(f"no session with {peer}")
        if self.clock() > s["expires"]:
            del self.sessions[peer]
            raise ProtocolError("session key expired")
        return s
