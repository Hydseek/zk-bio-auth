"""
capture.py - Biometric Capture & Template Extraction
Student 1: Biometric Capture & Template

Captures biometric data via webcam (OpenCV) OR generates a simulated
biometric template vector for environments without a camera.
"""

import numpy as np
import hashlib
import time
import json
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
TEMPLATE_DIM = 128        # feature vector dimensions
SIMULATION_SEED = 42      # reproducible seed for demo

try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False
    logger.warning("OpenCV not installed – falling back to simulation mode.")

try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False
    logger.warning("face_recognition not installed – falling back to simulation mode.")


# ─────────────────────────────────────────────
# TEMPLATE FORMAT
# ─────────────────────────────────────────────
def build_template(user_id: str, features: list) -> dict:
    """Wrap a feature vector in the standard template envelope."""
    return {
        "user_id": user_id,
        "features": features,          # list of 128 floats
        "timestamp": int(time.time()),
        "version": "1.0"
    }


# ─────────────────────────────────────────────
# NORMALISATION
# ─────────────────────────────────────────────
def normalize_vector(vector: list) -> list:
    """
    Min-max normalisation → all values in [0, 1].
    Prevents one dimension from dominating distance metrics.
    """
    arr = np.array(vector, dtype=np.float64)
    mn, mx = arr.min(), arr.max()
    if mx - mn < 1e-9:
        logger.warning("Constant vector detected; returning zero vector.")
        return [0.0] * len(vector)
    normed = (arr - mn) / (mx - mn)
    return normed.tolist()


# ─────────────────────────────────────────────
# SIMULATION MODE (fallback)
# ─────────────────────────────────────────────
def simulate_biometric_vector(user_id: str, noise_std: float = 0.02) -> list:
    """
    Deterministically generates a TEMPLATE_DIM feature vector for a given
    user_id.  A small amount of Gaussian noise (noise_std) is added so that
    consecutive captures of the same user differ slightly – just like a real
    biometric sensor.
    """
    seed_int = int(hashlib.sha256(user_id.encode()).hexdigest(), 16) % (2**31)
    rng = np.random.default_rng(seed_int)
    base_vector = rng.random(TEMPLATE_DIM)

    # Add sensor noise
    noise = np.random.default_rng().normal(0, noise_std, TEMPLATE_DIM)
    noisy = base_vector + noise
    return normalize_vector(noisy.tolist())


# ─────────────────────────────────────────────
# WEBCAM CAPTURE (real mode)
# ─────────────────────────────────────────────
def capture_from_webcam(user_id: str) -> Optional[list]:
    """
    Opens the default webcam, captures one frame, detects a face, and
    returns its 128-D encoding.  Returns None if no face is detected.
    """
    if not (OPENCV_AVAILABLE and FACE_RECOGNITION_AVAILABLE):
        logger.error("Webcam capture requires opencv-python and face_recognition.")
        return None

    logger.info("Opening webcam – please look at the camera …")
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        logger.error("Cannot open webcam.")
        return None

    ret, frame = cap.read()
    cap.release()

    if not ret:
        logger.error("Failed to read frame from webcam.")
        return None

    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    face_locations = face_recognition.face_locations(rgb_frame)

    if not face_locations:
        logger.warning("No face detected in webcam frame.")
        return None

    encodings = face_recognition.face_encodings(rgb_frame, face_locations)
    if not encodings:
        return None

    logger.info("Face encoding extracted successfully.")
    return normalize_vector(encodings[0].tolist())


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────
def capture_biometric(user_id: str, use_simulation: bool = True) -> dict:
    """
    Main entry point.

    Parameters
    ----------
    user_id       : unique identifier for the user
    use_simulation: if True, skip webcam and use deterministic simulation

    Returns
    -------
    Template dict with 'user_id', 'features', 'timestamp', 'version'.
    """
    logger.info(f"=== Biometric Capture for user '{user_id}' ===")

    if use_simulation:
        logger.info("Mode: SIMULATION (deterministic random vector)")
        features = simulate_biometric_vector(user_id)
    else:
        logger.info("Mode: WEBCAM")
        features = capture_from_webcam(user_id)
        if features is None:
            logger.warning("Webcam capture failed – falling back to simulation.")
            features = simulate_biometric_vector(user_id)

    template = build_template(user_id, features)
    logger.info(f"Template created: {TEMPLATE_DIM}-D vector, "
                f"timestamp={template['timestamp']}")
    return template


# ─────────────────────────────────────────────
# CLI DEMO
# ─────────────────────────────────────────────
if __name__ == "__main__":
    t = capture_biometric("alice", use_simulation=True)
    print(json.dumps({**t, "features": t["features"][:5]}, indent=2))
    print(f"  … ({TEMPLATE_DIM} dimensions total)")
