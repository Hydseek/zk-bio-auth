"""
setup.py - Project Setup
Installs Python dependencies and generates self-signed TLS certificate.
"""

import subprocess
import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format="[SETUP] %(message)s")
logger = logging.getLogger(__name__)

REQUIREMENTS = [
    "flask>=2.3",
    "cryptography>=41.0",
    "PyJWT>=2.8",
    "numpy>=1.24",
    "requests>=2.31",
]

CERT_DIR = os.path.join(os.path.dirname(__file__), "server", "certs")


def install_requirements():
    logger.info("Installing Python requirements …")
    for pkg in REQUIREMENTS:
        # --user works on Windows/Linux without admin; skipped inside venvs (that's fine)
        ret = subprocess.call(
            [sys.executable, "-m", "pip", "install", pkg, "-q", "--user"]
        )
        if ret != 0:
            # Inside a venv --user is not needed; retry without it
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pkg, "-q"]
            )
    logger.info("All requirements installed.")


def generate_tls_cert():
    """Generate self-signed certificate using the cryptography library."""
    os.makedirs(CERT_DIR, exist_ok=True)
    cert_file = os.path.join(CERT_DIR, "server.crt")
    key_file = os.path.join(CERT_DIR, "server.key")

    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info("TLS certificate already exists – skipping generation.")
        return

    logger.info("Generating self-signed TLS certificate …")

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZK-Auth Academic"),
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Certificate written to {cert_file}")
    logger.info(f"Private key written to {key_file}")


def create_init_files():
    """Ensure all directories are Python packages."""
    for d in ["client", "server", "common", "tests", "docs"]:
        path = os.path.join(os.path.dirname(__file__), d, "__init__.py")
        if not os.path.exists(path):
            open(path, "w").close()
    logger.info("__init__.py files created.")


if __name__ == "__main__":
    install_requirements()
    create_init_files()
    generate_tls_cert()
    logger.info("")
    logger.info("=" * 55)
    logger.info("  Setup complete!")
    logger.info("  Start server:  python server/api.py")
    logger.info("  Enroll user:   python client/client_app.py enroll --user alice")
    logger.info("  Authenticate:  python client/client_app.py auth --user alice")
    logger.info("  Run tests:     python -m pytest tests/ -v")
    logger.info("=" * 55)
