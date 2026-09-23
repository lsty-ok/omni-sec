# JWT & OAuth 2.0 Attack Vectors & Defensive Hardening

> Domain: Modern Authentication & Token Cryptanalysis
> Classification: AUTHORITATIVE KNOWLEDGE BASE
> Aligned with: RFC 7519 (JWT), RFC 6749 (OAuth 2.0), OWASP API Security Top 10

---

## 1. JWT (JSON Web Token) Attack Surface

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           JWT ATTACK MATRIX                             │
├───────────────────┬───────────────────┬──────────────────┬──────────────┤
│ 1. Algorithm      │ 2. Key Injection  │ 3. Key Confusion │ 4. Header    │
│    Flaws          │    (JWK / JKU)    │    (RS256→HS256) │    Injection │
├───────────────────┼───────────────────┼──────────────────┼──────────────┤
│ • alg: "none"     │ • Embedded JWK    │ • Verifying      │ • kid path   │
│   bypass          │   accepted from   │   RS256 token    │   traversal  │
│ • Weak secret     │   untrusted header│   with HMAC and  │ • SQLi / cmd │
│   bruteforce      │ • SSRF via JKU    │   public RSA key │   in kid     │
└───────────────────┴───────────────────┴──────────────────┴──────────────┘
```

### Attack 1: Algorithm Confusion (RS256 to HS256)
- **Vulnerability**: Backend expects RS256 (Asymmetric) with public key $K_{pub}$, but blindly accepts `alg: "HS256"` (Symmetric) and uses $K_{pub}$ as the HMAC secret key.
- **Exploit Logic**: Attacker signs token using standard HMAC-SHA256 with the server's public key (which is publicly visible).
- **Remediation**: Explicitly pin expected algorithms in verification middleware:
  ```python
  jwt.decode(token, public_key, algorithms=["RS256"]) # NEVER allow dynamic algorithms from token header
  ```

### Attack 2: None Algorithm & Null Signature
- **Vulnerability**: Header set to `{"alg": "none", "typ": "JWT"}` and signature stripped (`header.payload.`).
- **Remediation**: Completely disable `none` algorithm in production JWT parsers.

### Attack 3: `kid` (Key ID) Parameter Injection
- **Path Traversal**: Setting `"kid": "../../../dev/null"` or `"../../public/css/style.css"` so server loads a known or empty file as the HMAC secret.
- **SQLi in `kid`**: `"kid": "key' UNION SELECT 'attacker_secret' --"`
- **Remediation**: Use strict regex validation on `kid` (e.g. `^[a-zA-Z0-9_-]{1,64}$`) or map keys via dictionary lookup instead of raw filesystem/database concatenation.

---

## 2. OAuth 2.0 & OpenID Connect Attack Surface

| Vulnerability | Attack Vector | Impact | Defensive Countermeasure |
|---|---|---|---|
| **Missing `state` / CSRF** | Attacker intercepts auth code and forces victim to link attacker account | Account Takeover | Generate cryptographically random, unguessable `state` bound to session cookie |
| **`redirect_uri` Poisoning** | Attacker tampers `redirect_uri=https://evil.com` or bypasses regex (e.g. `victim.com.evil.com`) | Authorization Code Theft | Exact string matching against strict server-side client redirect whitelist |
| **Authorization Code Replay** | Code used multiple times | Replayed login sessions | Single-use codes with short TTL (max 60 seconds); revoke tokens if code reused |
| **PKCE Downgrade** | Public clients (SPA/Mobile) without PKCE (`code_challenge` / `code_verifier`) | Auth Code Interception | Enforce mandatory PKCE (S256) for all OAuth clients |
