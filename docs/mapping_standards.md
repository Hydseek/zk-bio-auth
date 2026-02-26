# Standards Mapping Document
## ISO 27001 | ISO 27018 | FIDO2 — Compliance Alignment
### Student 4: Security & Compliance Analysis

This document provides a detailed mapping between project implementation choices
and the relevant controls in ISO 27001:2022, ISO 27018:2019, and FIDO2 specifications.

---

## ISO 27001:2022 – Information Security Management System

| Clause / Annex A | Requirement | Project Implementation | Evidence |
|------------------|-------------|------------------------|----------|
| 6.1.2 – Risk Assessment | Identify and evaluate risks | EBIOS-simplified risk analysis | risk_analysis.md §3-4 |
| 6.1.3 – Risk Treatment | Apply controls | AES-256, TLS, JWT, fragmentation | crypto_client.py, api.py |
| A.5.12 – Classification | Data classification scheme | CRITICAL / HIGH / MEDIUM taxonomy | risk_analysis.md §2 |
| A.5.33 – Privacy | Data protection controls | Fragmentation, no plain-text storage | All modules |
| A.8.24 – Cryptography | Policy on use of cryptography | AES-256-GCM mandatory; SHA-256 for integrity | crypto_client.py |
| A.8.7 – Malware | Protection against malware | Out of scope (academic) | N/A |
| A.9.2 – Access Management | User access provisioning | JWT per-user tokens; enrollment required | api.py |
| A.9.4 – Authentication | Secure authentication | Biometric + fragment reconstruction | client_app.py |
| A.12.7 – Audit Logging | Logging of activities | auth_logs table with timestamps + IP | database.py |
| A.13.1 – Network Security | Manage network services | TLS 1.2+; self-signed certificate | config.py, setup.py |
| A.16.1 – Incident Management | Manage security incidents | Simulated IR procedure | risk_analysis.md §10 |
| A.18.1 – Legal Compliance | Legal and regulatory | GDPR consent; DPA notification procedure | mini_dpia.md |

---

## ISO 27018:2019 – PII Protection in Public Cloud

| Article | Requirement | Implementation |
|---------|-------------|----------------|
| 5.1 – Consent | Lawful basis established before processing | Enrollment flow records implicit consent |
| 5.2 – Purpose limitation | PII processed only for stated purpose | Biometric data used only for authentication |
| 5.6 – Erasure | Timely deletion upon request | DELETE /api/user/<id> removes Fragment B |
| 6.1 – No plain-text storage | PII must not be stored in clear | AES-256-GCM on all fragments |
| 9.2 – Data minimisation | Collect minimum necessary | Only 128-D feature vector; raw images not stored |
| 10.1 – Transparency | Inform users about processing | Documentation + enrollment logs |
| 11.1 – Subprocessor | Control data sharing | Client/server split simulates processor boundary |
| 12.1 – Return / deletion | Right to data portability | Fragment deletion endpoint |

---

## FIDO2 / WebAuthn Specification Alignment

| FIDO2 Mechanism | Standard Behaviour | Our Prototype |
|-----------------|-------------------|----------------|
| Authenticator | Generates key pair; stores private key on device | Fragment A stored encrypted on client |
| Registration (enrollment) | Authenticator sends public key credential | Client sends encrypted Fragment B to server |
| Assertion (authentication) | Authenticator signs challenge; server verifies | Client reconstructs template; verifies locally |
| User Verification | PIN, biometric on authenticator | Biometric capture + similarity threshold |
| Attestation | Cryptographic proof of authenticator type | Not implemented (academic scope) |
| Resident Credentials | Stored discoverable credentials | client_store.json (Fragment A) |
| rpId binding | Origin-bound credentials | Simulated via JWT sub claim |
| Phishing resistance | Credential bound to origin | TLS certificate + JWT nonce |

**Note**: Our prototype is FIDO2-**inspired**, not FIDO2-**compliant**. 
Full compliance requires WebAuthn API, CBOR encoding, and FIDO Metadata Service.

---

## GDPR Article Mapping

| GDPR Article | Requirement | Implementation |
|--------------|-------------|----------------|
| Art. 5 – Principles | Lawfulness, fairness, transparency | Documented processing; consent at enrollment |
| Art. 9 – Special categories | Biometric data requires explicit consent | Enrollment = explicit consent action |
| Art. 15 – Access right | Users can access their data | GET /api/fragment returns encrypted blob |
| Art. 17 – Erasure | Right to be forgotten | DELETE endpoint removes Fragment B |
| Art. 25 – Privacy by design | Data protection by default | Fragmentation architecture, no honey pot |
| Art. 32 – Security | Technical & organisational measures | AES-256, TLS, JWT, audit logs |
| Art. 33 – Breach notification | Notify DPA within 72h | IR procedure in risk_analysis.md §10 |
| Art. 35 – DPIA | Impact assessment for high-risk | Mini-DPIA completed (risk_analysis.md §9) |
