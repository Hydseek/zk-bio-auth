# Risk Analysis – Zero-Knowledge Biometric Authentication
## Student 4: Security & Compliance Analysis
### Method: Simplified EBIOS Risk Manager

---

## 1. SCOPE AND CONTEXT

| Item | Detail |
|------|--------|
| System | Decentralized ZK Biometric Authentication Prototype |
| Scope | Client application + REST API server + SQLite database |
| Data assets | Biometric templates (fragmented, encrypted), JWT tokens, audit logs |
| Regulation | GDPR (biometric data = special category), ISO 27001, ISO 27018 |

---

## 2. ASSET INVENTORY (ISO 27001 A.8)

| ID | Asset | Type | Owner | Sensitivity |
|----|-------|------|-------|-------------|
| A1 | Fragment A (client) | Biometric data | User | CRITICAL |
| A2 | Fragment B (server DB) | Biometric data | Server | CRITICAL |
| A3 | AES Encryption Keys | Cryptographic | System | CRITICAL |
| A4 | JWT Secret Key | Cryptographic | Server | HIGH |
| A5 | Audit Logs | Operational | Server | MEDIUM |
| A6 | SQLite Database file | Storage | Server | HIGH |
| A7 | TLS Certificates | Infrastructure | Server | HIGH |
| A8 | Source Code | Intellectual | Team | MEDIUM |

---

## 3. THREAT IDENTIFICATION

### T1 – Server Database Theft (SQL Injection / Physical Access)
- **Target**: Asset A2 (Fragment B), A6 (SQLite file)  
- **Threat actor**: External hacker, rogue insider  
- **Impact**: CRITICAL – attacker obtains Fragment B  
- **Probability**: LOW (fragment alone is cryptographically useless)  
- **Residual risk**: ACCEPTABLE – AES-256-GCM encryption + integrity tag  
- **Countermeasure**: Fragment B is AES-256-GCM encrypted; without Fragment A (client-side) and the decryption key, it cannot be used.

### T2 – Man-In-The-Middle (MITM) Attack
- **Target**: Network communication  
- **Threat actor**: Network adversary, ISP, rogue Wi-Fi  
- **Impact**: HIGH – eavesdropping on Fragment B in transit  
- **Probability**: MEDIUM (open networks)  
- **Countermeasure**: TLS 1.2+ enforced; self-signed certificate (production → trusted CA); Fragment B encrypted at application layer (double encryption).

### T3 – Client Device Compromise
- **Target**: Asset A1 (Fragment A), A3 (Keys)  
- **Threat actor**: Malware, physical theft  
- **Impact**: CRITICAL – attacker obtains Fragment A  
- **Probability**: LOW  
- **Residual risk**: MEDIUM – Fragment A alone insufficient without server Fragment B  
- **Countermeasure**: Fragment A encrypted with AES-256-GCM; keys derived via PBKDF2 (100,000 iterations).

### T4 – Replay Attack
- **Target**: JWT token interception and reuse  
- **Threat actor**: Network attacker  
- **Impact**: MEDIUM – unauthorized session reuse  
- **Probability**: MEDIUM  
- **Countermeasure**: JWT nonce embedded in each token; server maintains consumed-nonce list with TTL; token expiry set to 300 seconds.

### T5 – Biometric Spoofing (Liveness Attack)
- **Target**: Capture module  
- **Threat actor**: Impersonator with photo/3D model  
- **Impact**: HIGH  
- **Probability**: MEDIUM (simulation context: LOW)  
- **Countermeasure**: Outside academic scope; production would require liveness detection (ISO 30107-3 PAD).

### T6 – Key Compromise
- **Target**: Asset A3, A4  
- **Threat actor**: Insider threat, code repository exposure  
- **Impact**: CRITICAL  
- **Probability**: LOW (academic simulation – keys in code)  
- **Countermeasure (production)**: HSM, environment variables, HashiCorp Vault.

---

## 4. RISK GRID (EBIOS-style)

| Threat | Impact | Probability | Risk Level | Countermeasure |
|--------|--------|-------------|------------|----------------|
| T1 – DB theft | Critical | Low | MEDIUM | AES-256-GCM encryption of Fragment B |
| T2 – MITM | High | Medium | HIGH | HTTPS/TLS + application-layer encryption |
| T3 – Client compromise | Critical | Low | MEDIUM | Encrypted Fragment A; PBKDF2 key derivation |
| T4 – Replay attack | Medium | Medium | MEDIUM | JWT nonce + 5-min expiry |
| T5 – Bio spoofing | High | Low | MEDIUM | Out of scope (liveness detection) |
| T6 – Key compromise | Critical | Low | HIGH | Production: HSM required |

**Risk Levels**: LOW (<4) | MEDIUM (4–8) | HIGH (>8) — Impact × Probability (1–3 scale)

---

## 5. ISO 27001 CONTROL MAPPING

| ISO 27001 Control | Implementation |
|-------------------|----------------|
| A.8.1 – Asset inventory | Asset table above; data classified by sensitivity |
| A.8.2 – Information classification | Biometric = CRITICAL; logs = MEDIUM |
| A.9.1 – Access control policy | JWT Bearer tokens on all sensitive endpoints |
| A.9.4 – System access control | RBAC: users access only their own fragments |
| A.10.1 – Cryptographic policy | AES-256-GCM + SHA-256 mandatory; PBKDF2 key derivation |
| A.12.4 – Logging and monitoring | auth_logs table; all events timestamped with IP |
| A.13.1 – Network controls | TLS 1.2+; self-signed cert (simulation) |
| A.14.2 – Secure development | Threat modelling; OWASP Top-10 awareness |
| A.16.1 – Incident management | Simulated response plan (see section 6) |
| A.18.1 – Regulatory compliance | GDPR mapping; ISO 27018 application |

---

## 6. ISO 27018 APPLICATION (Cloud Data Protection)

| ISO 27018 Principle | Project Implementation |
|---------------------|------------------------|
| Lawful basis | Explicit consent assumed during enrollment |
| Purpose limitation | Biometric data used exclusively for authentication |
| No plain-text storage | All fragments stored encrypted (AES-256-GCM) |
| Data minimisation | Only feature vectors stored, never raw images |
| Transparency | Enrollment flow clearly disclosed to user |
| Right to be forgotten | DELETE /api/user/<id> endpoint removes Fragment B |
| Subprocessor management | Simulated client/server split (different processes) |

---

## 7. FIDO2 ALIGNMENT

| FIDO2 Concept | Project Equivalent |
|---------------|--------------------|
| Authenticator (private key) | Fragment A stored on client device |
| Server (public key / relying party) | Fragment B on server; match on client |
| No password | Authentication based solely on biometric vector |
| Attestation | Cosine + Euclidean distance verification |
| Phishing resistance | Cryptographic binding client ↔ server (TLS + JWT) |
| Unlinkability | Fragmented storage prevents cross-site linkage |

**Key Difference from FIDO2**: In standard FIDO2, the match is done on-device 
and a digital signature is sent to the server. Our prototype reconstructs the 
template on the client and performs the comparison locally – the server never 
learns the match score until the client reports it, preserving zero-knowledge intent.

---

## 8. KEYLESS MODEL COMPARISON

| Aspect | Keyless (Production) | Our Prototype (Academic) |
|--------|---------------------|--------------------------|
| ZKP | True Zero-Knowledge Proofs (mathematical) | Simulated (fragmentation + no reconstruction on server) |
| Template storage | Multi-party computation, no reconstruction | Client reconstructs locally |
| Biometrics | Certified algorithms (ISO 19794) | face_recognition / simulation |
| Key management | HSM / cloud KMS | Passphrase in code (simulation) |
| Liveness detection | Yes (ISO 30107-3) | Not implemented |
| Standards compliance | FIDO2 certified, GDPR certified | Educational alignment only |
| Architecture | Distributed cloud servers | Local processes (different ports) |
| Cryptography | MPC / homomorphic | AES-256-GCM + fragmentation |

**Learning takeaway**: The fundamental privacy design principle is shared — no 
single party ever holds the complete biometric template. Keyless implements this 
with industrial-grade MPC; our prototype achieves the same conceptual property 
through fragment separation.

---

## 9. MINI-DPIA (Data Protection Impact Assessment)

**Processing purpose**: Biometric authentication without central storage  
**Data controller**: Educational institution / project team  
**Legal basis**: Explicit consent (Art. 9(2)(a) GDPR)  
**Special category data**: Yes — biometric data (Art. 9 GDPR)  
**Necessity**: Authentication cannot be achieved without biometric data  

### Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Re-identification from fragments | High | Cryptographic encryption + separation |
| Data breach on server | High | Fragment B alone cryptographically useless |
| Unauthorised access | Medium | JWT authentication + audit logs |
| Data retention beyond purpose | Medium | Right-to-be-forgotten endpoint |
| Consent withdrawal | Low | Deletion cascade removes all fragments |

**DPIA Conclusion**: Risk is acceptable for an academic prototype given the 
implemented safeguards. Production deployment would require DPA consultation.

---

## 10. INCIDENT RESPONSE PROCEDURE (Simulated)

1. **Detection**: Anomalous auth_logs entries (multiple failures, off-hours access)  
2. **Containment**: Revoke all active JWT tokens; take server offline  
3. **Assessment**: Determine if Fragment B was exfiltrated  
4. **Notification**: GDPR Art. 33 – notify DPA within 72 hours if breach confirmed  
5. **Remediation**: Re-key server encryption; force re-enrollment  
6. **Post-mortem**: Update threat model; patch vulnerability  

*Note: Since each fragment is cryptographically useless alone, even a confirmed 
breach of Fragment B has limited impact – the attacker cannot reconstruct biometric 
templates without Fragment A.*
