# Zero-Knowledge Biometric Authentication
### Mini-Project N°2 — Academic Prototype
*Inspired by the Keyless Zero-Knowledge Biometrics™ model*

---

## Overview

A decentralized biometric authentication system where **no single entity ever
holds the complete biometric template**. The template is split into two fragments:
Fragment A stays on the client, Fragment B is stored (encrypted) on the server.
Neither party can reconstruct the full biometric alone.

```
CLIENT                              SERVER
────────────────────────            ──────────────────────
[Capture] → [Fragment A] ←──────── Never reaches server
             [Fragment B] ─────────→ Stored encrypted
                                     (cannot be used alone)
```

---

## Team Structure

| Role | Student | Responsibility |
|------|---------|---------------|
| 1 | Student A | `client/capture.py`, `client/template.py` |
| 2 | Student B | `client/crypto_client.py`, `server/crypto_server.py` |
| 3 | Student C | `server/api.py`, `server/database.py`, `server/config.py` |
| 4 | Student D | `docs/risk_analysis.md`, `docs/mapping_standards.md` |

---

## Project Structure

```
zero_knowledge_auth/
├── client/
│   ├── capture.py          # Biometric capture & simulation
│   ├── template.py         # Feature vector utilities & matching
│   ├── crypto_client.py    # AES-256-GCM + fragmentation
│   └── client_app.py       # CLI: enroll / authenticate
├── server/
│   ├── api.py              # Flask REST API (HTTPS + JWT)
│   ├── database.py         # SQLite data layer
│   ├── crypto_server.py    # Server-side crypto helpers
│   ├── config.py           # Configuration constants
│   └── certs/              # TLS certificates (auto-generated)
├── common/
│   ├── models.py           # Shared data classes
│   └── utils.py            # Helper utilities
├── docs/
│   ├── risk_analysis.md    # EBIOS risk analysis (Student 4)
│   └── mapping_standards.md # ISO 27001/27018/FIDO2 mapping
├── tests/
│   └── test_fragmentation.py  # Unit tests (all modules)
├── setup.py                # Dependency installer + cert generator
└── README.md               # This file
```

---

## Quick Start

### 1. Install dependencies & generate TLS certificate
```bash
cd zero_knowledge_auth
python setup.py
```

### 2. Start the server (Terminal 1)
```bash
python server/api.py
# Server runs on https://127.0.0.1:5443
```

### 3. Enroll a user (Terminal 2)
```bash
python client/client_app.py enroll --user alice
```

### 4. Authenticate
```bash
python client/client_app.py auth --user alice
```

### 5. List enrolled users
```bash
python client/client_app.py list
```

### 6. Run tests
```bash
python -m pytest tests/ -v
```

---

## Authentication Flow

### Phase 1 — Enrollment
```
1. [Client] Capture biometric → 128-D feature vector
2. [Client] Fragment vector → Fragment A (64-D) + Fragment B (64-D)
3. [Client] Encrypt Fragment A with client AES-256-GCM key → store locally
4. [Client] Encrypt Fragment B with server AES-256-GCM key → send to server
5. [Server] Store encrypted Fragment B in SQLite
           ⚠ Server NEVER sees Fragment A
           ⚠ Server cannot reconstruct the full template
```

### Phase 2 — Authentication
```
1. [Client] Capture new biometric → new 128-D vector
2. [Client] Request Fragment B from server (JWT required)
3. [Server] Return encrypted Fragment B
4. [Client] Decrypt Fragment A (local) + Fragment B (received)
5. [Client] Reconstruct full reference template
6. [Client] Compare new vector vs reference (cosine + Euclidean distance)
7. [Client] Report result to server → logged in audit trail
           ⚠ Server NEVER decrypts Fragment B itself
           ⚠ Full template reconstructed only momentarily in client RAM
```

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/health` | None | Health check |
| POST | `/api/token` | None | Issue JWT token |
| POST | `/api/enroll` | JWT | Store Fragment B |
| GET | `/api/fragment/<id>` | JWT | Retrieve Fragment B |
| POST | `/api/auth_result` | JWT | Log auth decision |
| GET | `/api/users` | None | List users (admin) |
| GET | `/api/logs` | None | Audit logs (admin) |
| DELETE | `/api/user/<id>` | JWT | Right to be forgotten |

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256-GCM authenticated encryption |
| Key derivation | PBKDF2-HMAC-SHA256 (100,000 iterations) |
| Integrity | SHA-256 hash per fragment |
| Transport | TLS 1.2+ (self-signed certificate) |
| API Auth | JWT Bearer tokens (5-min expiry) |
| Replay protection | Per-token nonce, server-side consumed list |
| Audit trail | SQLite log with timestamp + client IP |
| Privacy | Fragment A never transmitted; no complete template at rest |

---

## Accepted Academic Simplifications

| Aspect | Simplification | Production Alternative |
|--------|---------------|----------------------|
| Biometrics | Random vector simulation | Certified ISO 19794 algorithm |
| Keys | Passphrase in code | HSM / KMS |
| Secret sharing | Vector split (not Shamir) | Shamir's Secret Sharing / MPC |
| HTTPS | Self-signed certificate | Trusted CA certificate |
| Distribution | Same machine, different ports | Separate physical servers |
| Database | SQLite, no encryption at rest | PostgreSQL + FDE |
| ZKP | No true ZKP (fragmentation only) | Verifiable credentials + ZKP |

---

## Standards Compliance

- **ISO 27001:2022** – Controls A.8, A.9, A.10, A.12, A.13, A.16, A.18
- **ISO 27018:2019** – No plain-text, data minimisation, right to erasure
- **FIDO2** – Inspired by; not certified; alignment documented in `docs/`
- **GDPR** – Special category handling; consent at enrollment; Art. 17 erasure

See `docs/risk_analysis.md` and `docs/mapping_standards.md` for full details.

---

## References

| Resource | URL |
|----------|-----|
| cryptography (Python) | https://cryptography.io/ |
| face_recognition | https://github.com/ageitgey/face_recognition |
| Flask | https://flask.palletsprojects.com/ |
| PyJWT | https://pyjwt.readthedocs.io/ |
| ISO 27001 | https://www.iso.org/isoiec-27001-information-security.html |
| ISO 27018 | https://www.iso.org/standard/76559.html |
| FIDO2 | https://fidoalliance.org/fido2/ |
| Keyless | https://keyless.io/ |
