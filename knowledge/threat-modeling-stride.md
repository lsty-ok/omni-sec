# Threat Modeling Engine (STRIDE & MITRE ATT&CK Mapping)

> Domain: Architectural Threat Analysis & Risk Quantification
> Classification: AUTHORITATIVE KNOWLEDGE BASE
> Aligned with: Microsoft STRIDE Framework, MITRE ATT&CK v14

---

## 1. STRIDE Threat Modeling Matrix

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                          STRIDE THREAT MATRIX                           │
├─────────────────┬──────────────────────┬────────────────────────────────┤
│ Threat Category │ Security Property    │ Standard Mitigation Pattern    │
├─────────────────┼──────────────────────┼────────────────────────────────┤
│ S - Spoofing    │ Authenticity         │ MFA, Mutual TLS, Signed JWT    │
│ T - Tampering   │ Integrity            │ HMAC, Digital Signatures, TLS  │
│ R - Repudiation │ Non-repudiation      │ Tamper-evident Audit Logging   │
│ I - Info Leak   │ Confidentiality      │ AES-GCM, TLS 1.3, Secret Vault │
│ D - Denial (DoS)│ Availability         │ Rate Limiting, CDN, Caching    │
│ E - Escalation  │ Authorization        │ Strict RBAC/ABAC, Least Priv.  │
└─────────────────┴──────────────────────┴────────────────────────────────┘
```

---

## 2. Threat Modeling Workflow (4 Steps)

```text
1. DECOMPOSE SYSTEM (DFD: Data Flow Diagram)
   Identify Processes, Data Stores, Data Flows, and External Entities.
   Locate all TRUST BOUNDARIES (e.g., Browser ↔ API Gateway ↔ Microservice ↔ DB).

2. MAP THREATS (Apply STRIDE to Each Element)
   - At External Entity: Spoofing, Repudiation
   - At Data Flow: Tampering, Info Disclosure, DoS
   - At Data Store: Tampering, Info Disclosure, Repudiation, DoS
   - At Process: All 6 STRIDE threats apply.

3. EVALUATE RISK (DREAD or CVSS Scoring)
   Damage, Reproducibility, Exploitability, Affected Users, Discoverability.

4. DEFINE REMEDIATIONS & ACCEPTANCE CRITERIA
   Assign concrete engineering mitigations before code is written.
```

---

## 3. Threat Model Review Checklist

```markdown
### Target Architecture Component: [e.g. User Profile API]
- [ ] **Trust Boundary Crossed**: Public Internet -> API Gateway -> Internal DB.
- [ ] **S (Spoofing)**: Can an unauthenticated caller forge the `X-User-Id` header?
  -> Mitigation: Gateway verifies JWT and overwrites `X-User-Id` before forwarding.
- [ ] **T (Tampering)**: Can payload parameters be modified in transit?
  -> Mitigation: Enforce HTTPS TLS 1.3 only; sign critical webhook payloads.
- [ ] **R (Repudiation)**: Can an admin deny deleting a user account?
  -> Mitigation: Immutable append-only audit log with timestamp & actor ID.
- [ ] **I (Info Disclosure)**: Are passwords or internal stack traces exposed in error responses?
  -> Mitigation: Global error handler returning generic JSON error without stack traces.
- [ ] **D (Denial of Service)**: Can an attacker exhaust memory via huge file uploads or query loops?
  -> Mitigation: Max payload limit (10MB) and query timeout (3000ms).
- [ ] **E (Elevation of Privilege)**: Can a regular user pass `role: "admin"` in profile update?
  -> Mitigation: Strict DTO schema whitelisting.
```
