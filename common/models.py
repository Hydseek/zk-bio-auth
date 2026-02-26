"""
models.py - Shared Data Models
Common: Shared utilities and models
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import time
import json


@dataclass
class BiometricTemplate:
    user_id: str
    features: list
    timestamp: int = field(default_factory=lambda: int(time.time()))
    version: str = "1.0"

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "BiometricTemplate":
        return BiometricTemplate(
            user_id=d["user_id"],
            features=d["features"],
            timestamp=d.get("timestamp", int(time.time())),
            version=d.get("version", "1.0"),
        )


@dataclass
class EncryptedFragment:
    """Represents one AES-256-GCM encrypted fragment."""
    ciphertext: str    # base64
    nonce: str         # base64
    salt: str          # base64 (PBKDF2 salt)
    hash: str          # SHA-256 of plaintext (integrity)
    tag_included: bool = True

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "EncryptedFragment":
        return EncryptedFragment(**d)


@dataclass
class AuthResult:
    authenticated: bool
    cosine_distance: float
    euclidean_distance: float
    decision_basis: str
    user_id: Optional[str] = None
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self):
        return asdict(self)
