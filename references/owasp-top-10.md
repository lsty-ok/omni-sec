# OWASP Top 10 Security Reference (2021/2025)

> Standard: Open Web Application Security Project (OWASP) Top 10
> Classification: AUTHORITATIVE REFERENCE

## 1. A01:2021 — Broken Access Control
- **Description:** Kegagalan menegakkan pembatasan apa yang boleh dilakukan oleh pengguna yang diautentikasi (IDOR, privilege escalation, bypass metadata/CORS).
- **Checks:** Verifikasi bahwa setiap query database memfilter berdasarkan `session.user_id`, bukan parameter yang dikontrol user.

## 2. A02:2021 — Cryptographic Failures
- **Description:** Penggunaan algoritma hash lemah (MD5/SHA1 untuk password), kunci simetris yang dapat diprediksi, transmisi cleartext (HTTP/FTP), atau mode cipher rentan (ECB mode).
- **Checks:** Gunakan Argon2id/bcrypt untuk password, AES-GCM untuk data rest/transit.

## 3. A03:2021 — Injection
- **Description:** Data yang disuplai pengguna tidak divalidasi/difilter sebelum dimasukkan ke interpreter (SQL, NoSQL, OS Command, ORM, LDAP, SSTI).
- **Checks:** Selalu gunakan parameterized queries dan safe execution arrays (`subprocess.run(shell=False)`).

## 4. A04:2021 — Insecure Design
- **Description:** Celah pada tahap perancangan arsitektur dan threat modeling (misal: ketiadaan rate limiting pada reset password, alur bisnis tanpa validasi batas transaksi).
- **Checks:** Terapkan defense-in-depth dan rate limiters pada endpoint autentikasi.

## 5. A05:2021 — Security Misconfiguration
- **Description:** Penggunaan kredensial default, debug mode aktif di production (`DEBUG=True`), direktori terbuka (*directory listing*), header keamanan hilang (CSP, HSTS).
- **Checks:** Matikan debug mode, pasang security headers, audit file konfigurasi.

## 6. A06:2021 — Vulnerable and Outdated Components
- **Description:** Menggunakan library, framework, atau package pihak ketiga yang memiliki CVE publik yang belum ditambal.
- **Checks:** Jalankan `npm audit` / `pip audit` / `trivy` secara berkala di pipeline CI.

## 7. A07:2021 — Identification and Authentication Failures
- **Description:** Mengizinkan credential stuffing, password lemah, session fixation, atau token timeout yang terlalu panjang.
- **Checks:** Wajibkan MFA jika memungkinkan, session invalidation saat logout.

## 8. A08:2021 — Software and Data Integrity Failures
- **Description:** Memuat kode/plugin dari sumber yang tidak tepercaya tanpa verifikasi hash, atau deserialisasi objek yang tidak aman (`pickle.loads`, `yaml.unsafe_load`).
- **Checks:** Gunakan signed packages dan hindari unsafe serialization.

## 9. A09:2021 — Security Logging and Monitoring Failures
- **Description:** Kegagalan mencatat upaya login mencurigakan, error transaksi, atau ketiadaan audit trail.
- **Checks:** Log event penting secara terpusat tanpa menyimpan data sensitif (password/PII) di file log.

## 10. A10:2021 — Server-Side Request Forgery (SSRF)
- **Description:** Aplikasi web mengambil resource dari URL yang dikontrol pengguna tanpa membatasi akses ke jaringan internal/cloud metadata.
- **Checks:** Validasi URL dengan whitelist domain dan blokir akses ke private IP ranges (RFC 1918 / 169.254.169.254).
