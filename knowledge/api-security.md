# API Security Audit (OWASP API Security Top 10)

> Domain: REST, GraphQL, RPC & Webhook Endpoint Security
> Classification: AUTHORITATIVE KNOWLEDGE BASE
> Aligned with: OWASP API Security Top 10 (2023)

---

## 1. High-Frequency API Vulnerability Matrix

| OWASP API Vector | Mechanism / Vulnerability Signature | Triage / Verification Pattern | Defensive Remediation |
|---|---|---|---|
| **API1: BOLA (Broken Object Level Auth)** | User A requests `/api/orders/{user_b_id}` | Tamper resource ID with another user's UUID | Enforce tenant/user ownership check in DB query (`where id = :id and user_id = :current_user`) |
| **API2: Broken Authentication** | Missing token validation, weak JWT secret, predictable API tokens | Tamper JWT alg (`none` or HS256 with weak secret) | Validate signature strictly with RS256/Ed25519; verify `exp` & `aud` claims |
| **API3: Broken Object Property Level Auth (Mass Assignment)** | Request body `{ "role": "admin", "is_verified": true }` accepted blindly | Submit admin fields in profile update endpoint | Strict DTO/Schema whitelisting (strip unexpected payload fields) |
| **API4: Unrestricted Resource Consumption** | Missing rate limits on `/api/login`, `/api/reset-password`, large pagination `?limit=1000000` | Send burst requests or huge limit query | Sliding-window rate limiting (Redis/Cloudflare) + max pagination cap (e.g. max 50) |
| **API5: BFLA (Broken Function Level Auth)** | Normal user sending `POST /api/admin/delete_user` | Send admin endpoint requests from standard user token | Strict RBAC/ABAC middleware on all administrative route handlers |
| **API8: Security Misconfiguration (GraphQL Introspection)** | GraphQL endpoint exposing full schema via `__schema` query in production | Run GraphQL introspection query | Disable `introspection: false` in production environment |
| **API9: Improper Inventory Management** | Zombie / shadow APIs (e.g. `/api/v1/auth` unpatched vs `/api/v2/auth`) | Probe older API version prefixes | Deprecate and actively decommission unmaintained route versions |

---

## 2. API Audit Grep & Inspection One-Liners

```bash
# Grep for mass assignment / blind ORM update
git grep -rn "update(.*req\.body" .
git grep -rn "findUnique.*params\.id" . # Check if tenant filter is missing

# Grep for hardcoded secrets or JWT verification bypass
git grep -rn "jwt\.verify.*algorithms.*none" .
git grep -rn "verify\(.*secretOrPublicKey.*['\"][^'\"]+" .
```
