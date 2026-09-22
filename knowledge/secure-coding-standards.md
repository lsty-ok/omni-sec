# Secure Coding Standards & Defensive Remediation

> Domain: Application Security, Secure Code Review & Vulnerability Mitigation
> Standard: OWASP ASVS (Application Security Verification Standard), CWE/SANS Top 25
> Classification: SECURITY KNOWLEDGE BASE

## Purpose

Panduan perbaikan kode (*defensive patching*), sanitasi input, dan penguatan arsitektur keamanan perangkat lunak. Setiap temuan celah keamanan pada `omni-sec` harus dipasangkan dengan pola perbaikan aman di bawah ini.

---

## 1. Defensive Remediation Patterns by Vulnerability

### A. SQL Injection $\to$ Parameterized Queries
```python
# ❌ VULNERABLE (Concatenation / String Interpolation)
cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")

# ✅ SECURE (Parameterized Binding)
cursor.execute("SELECT id, username, role FROM users WHERE username = %s AND password_hash = %s", (username, password_hash))
```

### B. Command Injection $\to$ Safe Process Execution
```python
# ❌ VULNERABLE (Shell evaluation)
os.system("ping -c 1 " + host_ip)

# ✅ SECURE (Array arguments, no shell expansion, strict validation)
import ipaddress, subprocess
ip = ipaddress.ip_address(host_ip) # Validates legitimate IP structure
subprocess.run(["ping", "-c", "1", str(ip)], shell=False, check=True, timeout=5)
```

### C. Cross-Site Scripting (XSS) $\to$ Contextual Escaping
```javascript
// ❌ VULNERABLE (DOM Injection)
document.getElementById('profile').innerHTML = userBio;

// ✅ SECURE (Safe DOM property / textContent)
document.getElementById('profile').textContent = userBio;
```

### D. Path Traversal $\to$ Strict Basename & Whitelist Resolution
```python
# ❌ VULNERABLE
filepath = os.path.join(UPLOAD_DIR, user_filename)
return open(filepath, 'rb').read()

# ✅ SECURE (Safe basename + Path.resolve boundary verification)
from pathlib import Path
base_path = Path(UPLOAD_DIR).resolve()
target_file = (base_path / Path(user_filename).name).resolve()

if not target_file.is_relative_to(base_path) or not target_file.is_file():
    raise PermissionError("Access denied: Path traversal detected.")
return target_file.read_bytes()
```

---

## 2. Cryptographic Security Standards

1. **Password Hashing:**
   - Gunakan algoritma memory-hard: `Argon2id` (rekomendasi utama), `bcrypt` (work factor $\ge 12$), atau `PBKDF2` ($\ge 600.000$ iterations).
   - Dilarang keras menggunakan hash cepat seperti MD5, SHA1, SHA256 biasa untuk password tanpa salt & work factor.

2. **Symmetric Encryption:**
   - Gunakan Authenticated Encryption with Associated Data (AEAD): `AES-GCM` atau `ChaCha20-Poly1305`.
   - Hindari mode `ECB` dan pastikan `IV / Nonce` bersifat acak dan **tidak pernah digunakan ulang**.

3. **Random Number Generation:**
   - Gunakan CSPRNG (Cryptographically Secure Pseudo-Random Number Generator):
     - Python: `secrets.token_bytes()`, `secrets.token_hex()` (bukan modul `random`).
     - Node.js: `crypto.randomBytes()`.
     - C/C++: `getrandom()`, `/dev/urandom`.

---

## 3. Defense-in-Depth Checklist

- [ ] **Least Privilege:** Layanan berjalan dengan user non-root dan hak akses direktori minimal.
- [ ] **Content Security Policy (CSP):** Header CSP ketat untuk memblokir inline script dan sumber eksternal tak dikenal.
- [ ] **Rate Limiting & Anti-Bruteforce:** Pembatasan frekuensi request pada endpoint login dan reset password.
- [ ] **Safe Deserialization:** Hindari `pickle.loads()`, `yaml.load()` tanpa `SafeLoader`, atau `unserialize()` PHP pada input pengguna yang tidak tepercaya.
