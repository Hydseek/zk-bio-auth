"""
crypto_client.py - Encryption & Fragmentation
Student 2: Encryption & Fragmentation

Provides:
  - SHA-256 hashing for integrity checks
  - AES-256-GCM authenticated encryption / decryption
  - Template fragmentation (split vector into N parts)
  - Fragment reconstruction
  - Secure key derivation (PBKDF2)

NOTE (academic simulation): Keys are derived from a passphrase and stored
in memory. Production systems must use a proper HSM / key management service.
"""

import os
import json
import base64
import hashlib
import hmac
import logging
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
KEY_LEN      = 32          # 256 bits for AES-256
NONCE_LEN    = 12          # 96 bits (NIST recommended for GCM)
SALT_LEN     = 16          # 128-bit salt for PBKDF2
PBKDF2_ITER  = 100_000     # iterations (OWASP minimum)

# Hard-coded passphrases (simulation only – never do this in production!)
CLIENT_PASSPHRASE = b"client-super-secret-passphrase-2024"
SERVER_PASSPHRASE = b"server-super-secret-passphrase-2024"


# ─────────────────────────────────────────────
# KEY DERIVATION
# ─────────────────────────────────────────────
def derive_key(passphrase: bytes, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.

    Returns (key_bytes, salt_bytes).  If salt is None, a fresh random salt
    is generated (enrollment).  Pass an existing salt to reproduce the same
    key (authentication).
    """
    if salt is None:
        salt = os.urandom(SALT_LEN)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    key = kdf.derive(passphrase)
    return key, salt


# ─────────────────────────────────────────────
# SHA-256 HASHING
# ─────────────────────────────────────────────
def sha256_hash(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    digest = hashlib.sha256(data).hexdigest()
    logger.debug(f"SHA-256: {digest[:16]}…")
    return digest


def verify_integrity(data: bytes, expected_hash: str) -> bool:
    """Constant-time comparison of computed vs expected SHA-256."""
    computed = sha256_hash(data)
    return hmac.compare_digest(computed, expected_hash)


# ─────────────────────────────────────────────
# AES-256-GCM ENCRYPTION / DECRYPTION
# ─────────────────────────────────────────────
def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns a dict that can be JSON-serialised and stored:
      {
        "ciphertext": <base64>,
        "nonce":      <base64>,
        "tag_included": true   # GCM tag is appended by cryptography library
      }
    """
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # tag appended
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag_included": True,
    }


def aes_decrypt(encrypted: dict, key: bytes) -> bytes:
    """
    Decrypt an *encrypted* dict produced by aes_encrypt().
    Raises an exception if the GCM tag check fails (tamper detection).
    """
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ─────────────────────────────────────────────
# FRAGMENT HELPERS
# ─────────────────────────────────────────────
def _features_to_bytes(features: list) -> bytes:
    """Serialise a float list to bytes via JSON for portable storage."""
    return json.dumps(features).encode()


def _bytes_to_features(raw: bytes) -> list:
    return json.loads(raw.decode())


# ─────────────────────────────────────────────
# FRAGMENTATION
# ─────────────────────────────────────────────
def fragment_template(features: list, n_fragments: int = 2) -> list:
    """
    Split a feature vector into *n_fragments* approximately equal parts.

    Specification (Section 5.2):
      - n_fragments=2 → Fragment A = first half, Fragment B = second half
      - n_fragments=3 → thirds
    """
    total = len(features)
    size = total // n_fragments
    fragments = []
    for i in range(n_fragments):
        start = i * size
        # Last fragment gets any remainder
        end = start + size if i < n_fragments - 1 else total
        fragments.append(features[start:end])

    logger.info(
        f"Fragmented {total}-D vector into {n_fragments} parts: "
        + ", ".join(f"{len(f)}-D" for f in fragments)
    )
    return fragments


def reconstruct_template(fragments: list) -> list:
    """Concatenate ordered fragments back into the full feature vector."""
    full = []
    for f in fragments:
        full.extend(f)
    logger.info(f"Reconstructed template: {len(full)}-D vector")
    return full


# ─────────────────────────────────────────────
# HIGH-LEVEL ENROLLMENT HELPERS
# ─────────────────────────────────────────────
def encrypt_fragment_client(fragment: list) -> dict:
    """
    Encrypt Fragment A with the client key.
    Returns: {encrypted_data, salt, hash}
    """
    key, salt = derive_key(CLIENT_PASSPHRASE)
    plaintext = _features_to_bytes(fragment)
    encrypted = aes_encrypt(plaintext, key)
    return {
        "encrypted": encrypted,
        "salt": base64.b64encode(salt).decode(),
        "hash": sha256_hash(plaintext),
    }


def decrypt_fragment_client(payload: dict) -> list:
    """Decrypt a Fragment-A payload using the client passphrase."""
    salt = base64.b64decode(payload["salt"])
    key, _ = derive_key(CLIENT_PASSPHRASE, salt)
    plaintext = aes_decrypt(payload["encrypted"], key)
    assert verify_integrity(plaintext, payload["hash"]), "Integrity check FAILED!"
    return _bytes_to_features(plaintext)


def encrypt_fragment_server(fragment: list) -> dict:
    """
    Encrypt Fragment B with the server key.
    Returns: {encrypted_data, salt, hash}
    """
    key, salt = derive_key(SERVER_PASSPHRASE)
    plaintext = _features_to_bytes(fragment)
    encrypted = aes_encrypt(plaintext, key)
    return {
        "encrypted": encrypted,
        "salt": base64.b64encode(salt).decode(),
        "hash": sha256_hash(plaintext),
    }


def decrypt_fragment_server(payload: dict) -> list:
    """Decrypt a Fragment-B payload using the server passphrase."""
    salt = base64.b64decode(payload["salt"])
    key, _ = derive_key(SERVER_PASSPHRASE, salt)
    plaintext = aes_decrypt(payload["encrypted"], key)
    assert verify_integrity(plaintext, payload["hash"]), "Integrity check FAILED!"
    return _bytes_to_features(plaintext)


# ─────────────────────────────────────────────
# CLI DEMO
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from client.capture import simulate_biometric_vector

    features = simulate_biometric_vector("demo_user")
    print(f"Original vector (first 5): {features[:5]}")

    # Hash
    raw = _features_to_bytes(features)
    print(f"SHA-256: {sha256_hash(raw)}")

    # Fragment
    frags = fragment_template(features, n_fragments=2)
    print(f"Fragment A (len={len(frags[0])}): {frags[0][:3]}...")
    print(f"Fragment B (len={len(frags[1])}): {frags[1][:3]}...")

    # Encrypt/decrypt Fragment A
    enc_a = encrypt_fragment_client(frags[0])
    dec_a = decrypt_fragment_client(enc_a)
    print(f"Fragment A round-trip OK: {dec_a[:3] == frags[0][:3]}")

    # Reconstruct
    reconstructed = reconstruct_template([dec_a, frags[1]])
    print(f"Reconstruction matches: {reconstructed[:5] == features[:5]}")
