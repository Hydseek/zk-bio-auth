"""
test_fragmentation.py - Unit Tests
Tests for: biometric capture, fragmentation, encryption, reconstruction, matching
"""

import sys
import os
import unittest
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.capture import simulate_biometric_vector, build_template, normalize_vector
from client.template import cosine_distance, euclidean_distance, verify_match
from client.crypto_client import (
    fragment_template,
    reconstruct_template,
    sha256_hash,
    verify_integrity,
    encrypt_fragment_client,
    decrypt_fragment_client,
    encrypt_fragment_server,
    decrypt_fragment_server,
    aes_encrypt,
    aes_decrypt,
    derive_key,
    _features_to_bytes,
)


# ─────────────────────────────────────────────
class TestBiometricCapture(unittest.TestCase):

    def test_simulate_produces_128d_vector(self):
        v = simulate_biometric_vector("alice")
        self.assertEqual(len(v), 128)

    def test_simulate_is_deterministic(self):
        v1 = simulate_biometric_vector("alice", noise_std=0.0)
        v2 = simulate_biometric_vector("alice", noise_std=0.0)
        self.assertEqual(v1, v2)

    def test_different_users_differ(self):
        v1 = simulate_biometric_vector("alice", noise_std=0.0)
        v2 = simulate_biometric_vector("bob", noise_std=0.0)
        self.assertNotEqual(v1, v2)

    def test_normalized_range(self):
        v = simulate_biometric_vector("test_user")
        self.assertGreaterEqual(min(v), -1e-6)
        self.assertLessEqual(max(v), 1 + 1e-6)

    def test_build_template_structure(self):
        v = simulate_biometric_vector("alice")
        t = build_template("alice", v)
        self.assertIn("user_id", t)
        self.assertIn("features", t)
        self.assertIn("timestamp", t)
        self.assertEqual(t["user_id"], "alice")
        self.assertEqual(len(t["features"]), 128)


# ─────────────────────────────────────────────
class TestFragmentation(unittest.TestCase):

    def setUp(self):
        self.features = simulate_biometric_vector("test")

    def test_two_fragments(self):
        frags = fragment_template(self.features, n_fragments=2)
        self.assertEqual(len(frags), 2)
        self.assertEqual(len(frags[0]) + len(frags[1]), 128)

    def test_three_fragments(self):
        frags = fragment_template(self.features, n_fragments=3)
        self.assertEqual(len(frags), 3)
        total = sum(len(f) for f in frags)
        self.assertEqual(total, 128)

    def test_reconstruction_exact(self):
        frags = fragment_template(self.features, n_fragments=2)
        reconstructed = reconstruct_template(frags)
        self.assertEqual(reconstructed, self.features)

    def test_single_fragment_alone_is_incomplete(self):
        frags = fragment_template(self.features, n_fragments=2)
        # Fragment A alone does not match the full template
        self.assertNotEqual(frags[0], self.features)
        self.assertNotEqual(frags[1], self.features)


# ─────────────────────────────────────────────
class TestHashing(unittest.TestCase):

    def test_sha256_deterministic(self):
        data = b"hello world"
        h1 = sha256_hash(data)
        h2 = sha256_hash(data)
        self.assertEqual(h1, h2)

    def test_sha256_length(self):
        h = sha256_hash(b"test")
        self.assertEqual(len(h), 64)   # 256 bits = 64 hex chars

    def test_integrity_passes(self):
        data = b"biometric data"
        h = sha256_hash(data)
        self.assertTrue(verify_integrity(data, h))

    def test_integrity_fails_on_tamper(self):
        data = b"biometric data"
        h = sha256_hash(data)
        self.assertFalse(verify_integrity(b"tampered data", h))


# ─────────────────────────────────────────────
class TestEncryption(unittest.TestCase):

    def setUp(self):
        self.key, self.salt = derive_key(b"test-passphrase")
        self.plaintext = b"This is sensitive biometric fragment data"

    def test_encrypt_decrypt_roundtrip(self):
        enc = aes_encrypt(self.plaintext, self.key)
        dec = aes_decrypt(enc, self.key)
        self.assertEqual(dec, self.plaintext)

    def test_ciphertext_differs_each_time(self):
        enc1 = aes_encrypt(self.plaintext, self.key)
        enc2 = aes_encrypt(self.plaintext, self.key)
        # Random nonce means ciphertext should differ
        self.assertNotEqual(enc1["ciphertext"], enc2["ciphertext"])

    def test_wrong_key_raises(self):
        enc = aes_encrypt(self.plaintext, self.key)
        wrong_key, _ = derive_key(b"wrong-passphrase")
        with self.assertRaises(Exception):
            aes_decrypt(enc, wrong_key)

    def test_tamper_raises(self):
        import base64
        enc = aes_encrypt(self.plaintext, self.key)
        # Corrupt ciphertext
        raw = base64.b64decode(enc["ciphertext"])
        corrupted = bytes([raw[0] ^ 0xFF]) + raw[1:]
        enc["ciphertext"] = base64.b64encode(corrupted).decode()
        with self.assertRaises(Exception):
            aes_decrypt(enc, self.key)


# ─────────────────────────────────────────────
class TestFragmentEncryption(unittest.TestCase):

    def setUp(self):
        features = simulate_biometric_vector("alice")
        frags = fragment_template(features, n_fragments=2)
        self.frag_a = frags[0]
        self.frag_b = frags[1]

    def test_client_fragment_roundtrip(self):
        enc = encrypt_fragment_client(self.frag_a)
        dec = decrypt_fragment_client(enc)
        self.assertAlmostEqual(dec[0], self.frag_a[0], places=10)

    def test_server_fragment_roundtrip(self):
        enc = encrypt_fragment_server(self.frag_b)
        dec = decrypt_fragment_server(enc)
        self.assertAlmostEqual(dec[0], self.frag_b[0], places=10)

    def test_cross_key_fails(self):
        """Fragment A encrypted with client key cannot be decrypted with server key."""
        enc = encrypt_fragment_client(self.frag_a)
        with self.assertRaises(Exception):
            decrypt_fragment_server(enc)


# ─────────────────────────────────────────────
class TestVerification(unittest.TestCase):

    def test_same_user_matches(self):
        v1 = simulate_biometric_vector("alice", noise_std=0.0)
        v2 = simulate_biometric_vector("alice", noise_std=0.005)  # tiny noise
        result = verify_match(v1, v2)
        self.assertTrue(result["authenticated"])

    def test_different_users_do_not_match(self):
        v1 = simulate_biometric_vector("alice", noise_std=0.0)
        v2 = simulate_biometric_vector("bob", noise_std=0.0)
        result = verify_match(v1, v2)
        self.assertFalse(result["authenticated"])

    def test_cosine_perfect_match(self):
        v = simulate_biometric_vector("alice")
        d = cosine_distance(v, v)
        self.assertAlmostEqual(d, 0.0, places=9)

    def test_euclidean_perfect_match(self):
        v = simulate_biometric_vector("alice")
        d = euclidean_distance(v, v)
        self.assertAlmostEqual(d, 0.0, places=9)

    def test_full_pipeline(self):
        """End-to-end: capture → fragment → encrypt → decrypt → reconstruct → verify."""
        user_id = "pipeline_test_user"
        features = simulate_biometric_vector(user_id, noise_std=0.0)

        # Enrollment
        frags = fragment_template(features, n_fragments=2)
        enc_a = encrypt_fragment_client(frags[0])
        enc_b = encrypt_fragment_server(frags[1])

        # Authentication
        new_features = simulate_biometric_vector(user_id, noise_std=0.008)
        dec_a = decrypt_fragment_client(enc_a)
        dec_b = decrypt_fragment_server(enc_b)
        reconstructed = reconstruct_template([dec_a, dec_b])

        result = verify_match(new_features, reconstructed)
        self.assertTrue(result["authenticated"], "Full pipeline should authenticate same user")


# ─────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main(verbosity=2)
