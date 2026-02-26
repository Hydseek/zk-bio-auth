"""
config.py - Server Configuration
Student 3: Architecture & Communication
"""

import os
import secrets

# ─────────────────────────────────────────────
# JWT CONFIG
# ─────────────────────────────────────────────
JWT_SECRET_KEY = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM  = "HS256"
JWT_EXPIRY_SEC = 300       # 5 minutes

# ─────────────────────────────────────────────
# SERVER
# ─────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000          # plain HTTP - easy to open in any browser
DEBUG       = False

# ─────────────────────────────────────────────
# TLS - set USE_HTTPS = True to re-enable HTTPS (requires setup.py certs)
# ─────────────────────────────────────────────
USE_HTTPS = False
CERT_DIR  = os.path.join(os.path.dirname(__file__), "certs")
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE  = os.path.join(CERT_DIR, "server.key")

# ─────────────────────────────────────────────
# SECURITY PARAMS
# ─────────────────────────────────────────────
NONCE_TTL_SEC = 60
MAX_AUTH_ATTEMPTS = 5
