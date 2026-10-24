"""Symmetric crypto helpers: AES-256-GCM authenticated encryption.

GCM gives confidentiality AND integrity, so a tampered ticket or a message
encrypted under the wrong key is rejected (InvalidTag) instead of decrypting
to garbage.
"""
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY_SIZE = 32    # 256-bit keys
NONCE_SIZE = 12  # 96-bit GCM IV


class CryptoError(Exception):
    """Raised when decryption/authentication fails."""


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def generate_nonce() -> int:
    """Random 64-bit challenge number used for freshness."""
    return int.from_bytes(os.urandom(8), "big")


def encrypt(key: bytes, obj: dict) -> bytes:
    """Encrypt a JSON-serialisable dict. Output = iv || ciphertext||tag."""
    iv = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(obj, sort_keys=True).encode()
    return iv + AESGCM(key).encrypt(iv, plaintext, None)


def decrypt(key: bytes, blob: bytes) -> dict:
    try:
        iv, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
        return json.loads(AESGCM(key).decrypt(iv, ct, None))
    except (InvalidTag, ValueError) as e:
        raise CryptoError("decryption failed (wrong key or tampered data)") from e


def b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode()


def unb64(s: str) -> bytes:
    import base64
    return base64.b64decode(s)
