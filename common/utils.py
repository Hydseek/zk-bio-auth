"""
utils.py - Common Utility Functions
"""

import time
import os
import uuid
import json
import logging

logger = logging.getLogger(__name__)


def current_timestamp() -> int:
    return int(time.time())


def generate_nonce() -> str:
    """Generate a cryptographically random nonce (UUID4)."""
    return str(uuid.uuid4())


def pretty_json(obj) -> str:
    return json.dumps(obj, indent=2, default=str)


def mask_sensitive(data: dict, keys=("features", "fragment_b", "ciphertext")) -> dict:
    """
    Return a copy of *data* with sensitive fields replaced by a placeholder.
    Useful for safe logging.
    """
    masked = {}
    for k, v in data.items():
        if k in keys:
            masked[k] = f"<{k}: {len(str(v))} chars>"
        elif isinstance(v, dict):
            masked[k] = mask_sensitive(v, keys)
        else:
            masked[k] = v
    return masked


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
