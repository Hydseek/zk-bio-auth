"""
client_app.py - Client Application Interface
Orchestrates Enrollment and Authentication flows.

Usage:
  python client_app.py enroll  --user alice
  python client_app.py auth    --user alice
  python client_app.py list
"""

import sys
import os
import json
import argparse
import logging
import requests
import urllib3

# Allow self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.capture import capture_biometric
from client.template import verify_match
from client.crypto_client import (
    fragment_template,
    encrypt_fragment_client,
    decrypt_fragment_client,
    encrypt_fragment_server,
    decrypt_fragment_server,
    reconstruct_template,
    sha256_hash,
    _features_to_bytes,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

SERVER_URL  = "http://127.0.0.1:5000"
CLIENT_STORE = os.path.join(os.path.dirname(__file__), "client_store.json")

# ──────────────────────────────────────────────
# LOCAL CLIENT STORAGE (Fragment A)
# ──────────────────────────────────────────────
def load_client_store() -> dict:
    if os.path.exists(CLIENT_STORE):
        with open(CLIENT_STORE) as f:
            return json.load(f)
    return {}


def save_client_store(store: dict):
    with open(CLIENT_STORE, "w") as f:
        json.dump(store, f, indent=2)


# ──────────────────────────────────────────────
# JWT HELPERS
# ──────────────────────────────────────────────
def get_token(user_id: str) -> str:
    """Obtain a short-lived JWT from the server (pre-auth step)."""
    try:
        resp = requests.post(
            f"{SERVER_URL}/api/token",
            json={"user_id": user_id},
            verify=False,
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()["token"]
    except requests.exceptions.ConnectionError:
        logger.error("=" * 55)
        logger.error("CANNOT CONNECT TO SERVER at %s", SERVER_URL)
        logger.error("Make sure the server is running first:")
        logger.error("  python server/api.py")
        logger.error("(open a separate terminal and keep it running)")
        logger.error("=" * 55)
        sys.exit(1)


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────────────────────────
# ENROLLMENT
# ──────────────────────────────────────────────
def enroll(user_id: str, use_simulation: bool = True):
    logger.info("=" * 55)
    logger.info(f"PHASE 1 – ENROLLMENT  (user='{user_id}')")
    logger.info("=" * 55)

    # Step 1: Capture biometric
    template = capture_biometric(user_id, use_simulation=use_simulation)
    features = template["features"]
    logger.info(f"✔ Template captured ({len(features)}-D vector)")

    # Step 2: Fragment
    fragments = fragment_template(features, n_fragments=2)
    frag_a, frag_b = fragments[0], fragments[1]
    logger.info(f"✔ Template fragmented → A({len(frag_a)}-D) | B({len(frag_b)}-D)")

    # Step 3: Encrypt both fragments
    enc_a = encrypt_fragment_client(frag_a)
    enc_b = encrypt_fragment_server(frag_b)
    logger.info("✔ Fragments encrypted (AES-256-GCM)")

    # Step 4: Store Fragment A locally
    store = load_client_store()
    store[user_id] = enc_a
    save_client_store(store)
    logger.info("✔ Fragment A stored locally (client_store.json)")

    # Step 5: Send Fragment B to server
    token = get_token(user_id)
    resp = requests.post(
        f"{SERVER_URL}/api/enroll",
        json={"user_id": user_id, "fragment_b": enc_b},
        headers=auth_headers(token),
        timeout=10,
    )
    resp.raise_for_status()
    logger.info(f"✔ Fragment B sent to server → {resp.json()['message']}")
    logger.info("-" * 55)
    logger.info("Enrollment complete. Server has NEVER seen Fragment A.")
    logger.info("=" * 55)


# ──────────────────────────────────────────────
# AUTHENTICATION
# ──────────────────────────────────────────────
def authenticate(user_id: str, use_simulation: bool = True):
    logger.info("=" * 55)
    logger.info(f"PHASE 2 – AUTHENTICATION  (user='{user_id}')")
    logger.info("=" * 55)

    # Step 1: Fresh biometric capture
    new_template = capture_biometric(user_id, use_simulation=use_simulation)
    new_features = new_template["features"]
    logger.info(f"✔ New biometric captured ({len(new_features)}-D)")

    # Step 2: Retrieve Fragment B from server
    token = get_token(user_id)
    resp = requests.get(
        f"{SERVER_URL}/api/fragment/{user_id}",
        headers=auth_headers(token),
        timeout=10,
    )
    resp.raise_for_status()
    enc_b = resp.json()["fragment_b"]
    logger.info("✔ Encrypted Fragment B retrieved from server")

    # Step 3: Load local Fragment A
    store = load_client_store()
    if user_id not in store:
        logger.error(f"No local fragment for user '{user_id}'. Enroll first.")
        return

    enc_a = store[user_id]

    # Step 4: Decrypt both fragments
    frag_a = decrypt_fragment_client(enc_a)
    frag_b = decrypt_fragment_server(enc_b)
    logger.info("✔ Fragments decrypted")

    # Step 5: Reconstruct full template
    reconstructed = reconstruct_template([frag_a, frag_b])
    logger.info(f"✔ Template reconstructed ({len(reconstructed)}-D)")

    # Step 6: Integrity check
    ref_hash = enc_a["hash"]  # hash of Fragment A (proxy for reference)
    logger.info(f"✔ Fragment A SHA-256 integrity: {ref_hash[:20]}…")

    # Step 7: Verify match
    result = verify_match(new_features, reconstructed)

    logger.info("-" * 55)
    if result["authenticated"]:
        logger.info("🟢 AUTHENTICATION SUCCESS")
    else:
        logger.warning("🔴 AUTHENTICATION FAILED")

    logger.info(f"   Cosine distance   : {result['cosine_distance']:.6f}")
    logger.info(f"   Euclidean distance: {result['euclidean_distance']:.6f}")
    logger.info("=" * 55)

    # Report result to server - get a FRESH token (nonce already consumed above)
    token2 = get_token(user_id)
    requests.post(
        f"{SERVER_URL}/api/auth_result",
        json={
            "user_id": user_id,
            "authenticated": result["authenticated"],
            "cosine_distance": result["cosine_distance"],
        },
        headers=auth_headers(token2),
        timeout=5,
    )

    return result


# ──────────────────────────────────────────────
# LIST ENROLLED USERS
# ──────────────────────────────────────────────
def list_users():
    store = load_client_store()
    if not store:
        print("No users enrolled locally.")
        return
    print("Locally enrolled users:")
    for uid in store:
        print(f"  • {uid}")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZK Biometric Auth Client")
    sub = parser.add_subparsers(dest="cmd")

    p_enroll = sub.add_parser("enroll", help="Enroll a new user")
    p_enroll.add_argument("--user", required=True)
    p_enroll.add_argument("--webcam", action="store_true")

    p_auth = sub.add_parser("auth", help="Authenticate a user")
    p_auth.add_argument("--user", required=True)
    p_auth.add_argument("--webcam", action="store_true")

    sub.add_parser("list", help="List enrolled users")

    args, unknown = parser.parse_known_args()
    if unknown:
        logger.error("Unrecognized arguments ignored: %s", unknown)
        logger.error("Tip: make sure you run only ONE command at a time.")

    if args.cmd == "enroll":
        enroll(args.user, use_simulation=not args.webcam)
    elif args.cmd == "auth":
        authenticate(args.user, use_simulation=not args.webcam)
    elif args.cmd == "list":
        list_users()
    else:
        parser.print_help()
