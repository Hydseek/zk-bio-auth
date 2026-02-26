"""
crypto_server.py - Server-side Cryptographic Helpers
Student 2: Encryption & Fragmentation (server side)

The server only ever sees Fragment B (encrypted).
This module provides the server's decrypt capability.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Re-export server-side helpers from the shared crypto module
from client.crypto_client import (
    encrypt_fragment_server,
    decrypt_fragment_server,
    sha256_hash,
    verify_integrity,
    aes_encrypt,
    aes_decrypt,
    derive_key,
)

__all__ = [
    "encrypt_fragment_server",
    "decrypt_fragment_server",
    "sha256_hash",
    "verify_integrity",
    "aes_encrypt",
    "aes_decrypt",
    "derive_key",
]
