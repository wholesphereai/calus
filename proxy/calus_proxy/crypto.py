"""Tiny zero-dependency authenticated encryption for the API-key vault.

Provider keys are NEVER stored in plaintext. We derive a 256-bit key from a
server secret (CALUS_SECRET, falling back to CALUS_ADMIN_TOKEN) with PBKDF2, then
encrypt with an HMAC-SHA256 keystream (counter mode) and authenticate with a
separate HMAC tag (encrypt-then-MAC). Stdlib only — works the same on every OS.

This protects keys at rest in the SQLite file. For stronger guarantees put the
DB on an encrypted volume and set a high-entropy CALUS_SECRET.
"""
import os
import hmac
import base64
import hashlib

_MAGIC = b"clk1"          # calus key vault, format v1
_ROUNDS = 200_000


def _server_secret() -> bytes:
    s = os.getenv("CALUS_SECRET") or os.getenv("CALUS_ADMIN_TOKEN") or "calus-insecure-default"
    return s.encode("utf-8")


def _derive(salt: bytes) -> tuple[bytes, bytes]:
    """Derive (enc_key, mac_key) from the server secret and a per-record salt."""
    master = hashlib.pbkdf2_hmac("sha256", _server_secret(), salt, _ROUNDS, dklen=64)
    return master[:32], master[32:]


def _keystream(enc_key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:n])


def encrypt(plaintext: str) -> str:
    """Return a urlsafe-base64 token: magic | salt(16) | nonce(16) | ct | tag(32)."""
    data = plaintext.encode("utf-8")
    salt = os.urandom(16)
    nonce = os.urandom(16)
    enc_key, mac_key = _derive(salt)
    ct = bytes(b ^ k for b, k in zip(data, _keystream(enc_key, nonce, len(data))))
    body = _MAGIC + salt + nonce + ct
    tag = hmac.new(mac_key, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + tag).decode("ascii")


def decrypt(token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    if raw[:4] != _MAGIC:
        raise ValueError("unrecognized ciphertext format")
    body, tag = raw[:-32], raw[-32:]
    salt, nonce, ct = body[4:20], body[20:36], body[36:]
    enc_key, mac_key = _derive(salt)
    if not hmac.compare_digest(tag, hmac.new(mac_key, body, hashlib.sha256).digest()):
        raise ValueError("authentication failed — wrong secret or tampered data")
    pt = bytes(b ^ k for b, k in zip(ct, _keystream(enc_key, nonce, len(ct))))
    return pt.decode("utf-8")


def mask(secret: str) -> str:
    """Short, safe preview for display, e.g. 'sk-...b1F0' (never the full key).
    ASCII-only so it renders the same in the dashboard and any terminal."""
    s = secret.strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:3]}...{s[-4:]}"
