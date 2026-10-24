"""Key Distribution Center.

The KDC shares a long-term *master key* with every registered principal
(established out-of-band at registration). It never sends master keys over
the network. On request it creates a fresh *session key* and distributes it
using the Needham-Schroeder symmetric protocol (with a timestamp/lifetime
added to defeat replay of old tickets - the Denning fix).
"""
import time
from .crypto_utils import generate_key, encrypt, b64


class KDCError(Exception):
    pass


class KDC:
    def __init__(self, session_lifetime=300, clock=time.time):
        self._master_keys = {}        # principal id -> long-term key
        self.session_lifetime = session_lifetime
        self.clock = clock
        self.issued = []              # audit log of (A, B, time)

    # ---- registration (out-of-band, assumed secure) ----
    def register(self, principal_id: str) -> bytes:
        """Register a principal and return its master key (given to the
        principal over a secure channel, e.g. in person / pre-installed)."""
        if principal_id in self._master_keys:
            raise KDCError(f"{principal_id} already registered")
        key = generate_key()
        self._master_keys[principal_id] = key
        return key

    def load_key(self, principal_id: str, key: bytes):
        """Register a principal with a key that was created earlier (key files)."""
        self._master_keys[principal_id] = key

    # ---- Step 1/2 of the protocol ----
    def handle_request(self, request: dict) -> bytes:
        """request = {"id_a", "id_b", "n1"}   (sent in the clear)

        Returns E(Ka, {Ks, id_b, n1, lifetime, ticket}) where
        ticket = E(Kb, {Ks, id_a, timestamp, expires}).
        """
        a, b, n1 = request["id_a"], request["id_b"], request["n1"]
        if a not in self._master_keys:
            raise KDCError(f"unknown requester: {a}")
        if b not in self._master_keys:
            raise KDCError(f"unknown peer: {b}")
        if a == b:
            raise KDCError("cannot create a session key between a principal and itself")

        ks = generate_key()
        now = self.clock()
        expires = now + self.session_lifetime
        ticket = encrypt(self._master_keys[b],
                         {"ks": b64(ks), "id_a": a, "ts": now, "expires": expires})
        reply = encrypt(self._master_keys[a],
                        {"ks": b64(ks), "id_b": b, "n1": n1,
                         "expires": expires, "ticket": b64(ticket)})
        self.issued.append((a, b, now))
        return reply
