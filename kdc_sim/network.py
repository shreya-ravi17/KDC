"""A tiny simulated network. Every message passes through here, so we can
log it (what an eavesdropper such as Eve would see) and let tests tamper
with or replay messages."""
from .crypto_utils import b64


class Network:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.log = []          # list of (src, dst, label, payload)
        self.tamper = None     # optional hook: fn(src,dst,label,payload)->payload

    def send(self, src, dst, label, payload):
        if self.tamper:
            payload = self.tamper(src, dst, label, payload)
        self.log.append((src, dst, label, payload))
        if self.verbose:
            print(f"  [NET] {src:>5} -> {dst:<5} | {label}")
            print(f"        {self._show(payload)}")
        return payload

    @staticmethod
    def _show(p):
        if isinstance(p, bytes):
            s = b64(p)
            return "ciphertext: " + (s if len(s) <= 64 else s[:61] + "...")
        if isinstance(p, dict):
            return "{" + ", ".join(f"{k}: {Network._show(v)}" for k, v in p.items()) + "}"
        return repr(p)
