"""
template.py - Template Utilities
Student 1: Biometric Capture & Template

Provides helpers for:
  - Converting template dicts to/from raw float lists
  - Computing similarity scores (cosine & Euclidean)
  - Deciding authentication accept/reject
"""

import numpy as np
import logging

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# THRESHOLDS
# ─────────────────────────────────────────────
COSINE_THRESHOLD   = 0.15   # lower is more similar; < threshold → match
EUCLIDEAN_THRESHOLD = 5.0   # lower is more similar; < threshold → match


# ─────────────────────────────────────────────
# CONVERSION HELPERS
# ─────────────────────────────────────────────
def template_to_vector(template: dict) -> np.ndarray:
    """Extract the numpy feature array from a template dict."""
    return np.array(template["features"], dtype=np.float64)


def vector_to_list(arr: np.ndarray) -> list:
    """Convert numpy array to a plain Python list (JSON-serialisable)."""
    return arr.tolist()


# ─────────────────────────────────────────────
# DISTANCE METRICS
# ─────────────────────────────────────────────
def cosine_distance(v1: list, v2: list) -> float:
    """
    Cosine distance = 1 – cosine_similarity.
    Range: [0, 2].  Perfect match → 0.
    """
    a = np.array(v1, dtype=np.float64)
    b = np.array(v2, dtype=np.float64)
    norm_a, norm_b = np.linalg.norm(a), np.linalg.norm(b)
    if norm_a < 1e-9 or norm_b < 1e-9:
        return 2.0
    return float(1.0 - np.dot(a, b) / (norm_a * norm_b))


def euclidean_distance(v1: list, v2: list) -> float:
    """
    Euclidean (L2) distance between two feature vectors.
    """
    a = np.array(v1, dtype=np.float64)
    b = np.array(v2, dtype=np.float64)
    return float(np.linalg.norm(a - b))


# ─────────────────────────────────────────────
# MATCHING DECISION
# ─────────────────────────────────────────────
def verify_match(new_features: list, reference_features: list) -> dict:
    """
    Compare a freshly-captured feature vector against the stored reference.

    Returns
    -------
    dict with keys:
        authenticated (bool)
        cosine_distance (float)
        euclidean_distance (float)
        decision_basis (str)   – which metric drove the decision
    """
    cos = cosine_distance(new_features, reference_features)
    euc = euclidean_distance(new_features, reference_features)

    # Primary: cosine; secondary: euclidean cross-check
    auth_cos = cos < COSINE_THRESHOLD
    auth_euc = euc < EUCLIDEAN_THRESHOLD
    authenticated = auth_cos and auth_euc

    logger.info(
        f"Verification → cosine={cos:.4f} (th={COSINE_THRESHOLD}), "
        f"euclidean={euc:.4f} (th={EUCLIDEAN_THRESHOLD}) → "
        f"{'MATCH ✓' if authenticated else 'NO MATCH ✗'}"
    )

    return {
        "authenticated": authenticated,
        "cosine_distance": cos,
        "euclidean_distance": euc,
        "decision_basis": "cosine+euclidean"
    }


# ─────────────────────────────────────────────
# CLI DEMO
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from client.capture import simulate_biometric_vector

    v1 = simulate_biometric_vector("alice", noise_std=0.0)
    v2 = simulate_biometric_vector("alice", noise_std=0.02)   # same user, noise
    v3 = simulate_biometric_vector("bob",   noise_std=0.0)    # different user

    print("Same user (low noise):", verify_match(v1, v2))
    print("Different users:      ", verify_match(v1, v3))
