# Stage 4 & 5: Defensive Remediation & Write-up Engine

> Domain: Security Remediation, Patch Engineering & CTF Documentation
> Standard: omni-sec 5-Stage Security Reasoning Pipeline (Stage 4 & 5)
> Classification: REASONING PROCESS + REPORTING

## Purpose

Menyediakan solusi penambalan kode (*patching*) yang aman dan teruji, serta menyusun laporan write-up CTF / security advisory yang profesional.

---

## 1. Remediation Patch Engineering

Setiap temuan kerentanan harus disertai dengan **Production-Ready Patch**:

### Aturan Pembuatan Patch:
1. **Target the Root Cause:** Perbaiki kelemahan arsitektur dasar, bukan hanya menambal string blacklist yang mudah dibypass (*don't just blacklist characters*).
2. **Minimal & Non-Destructive:** Patch tidak boleh merusak fungsionalitas bisnis aplikasi yang sah (*no business logic regression*).
3. **Defense-in-Depth:** Terapkan validasi input ketat (whitelist) + output encoding + mekanisme otorisasi berlapis.

### Format Diff Patch:
```diff
--- vulnerable_app.py
+++ secure_app.py
@@ -14,3 +14,3 @@
-    query = f"SELECT * FROM users WHERE id = {user_id}"
-    cursor.execute(query)
+    query = "SELECT id, username, email FROM users WHERE id = %s"
+    cursor.execute(query, (user_id,))
```

---

## 2. CTF Write-Up Standard Structure

Sebuah write-up CTF yang baik harus mendidik dan dapat direproduksi oleh orang lain:

1. **Challenge Overview:** Nama soal, kategori, poin, deskripsi singkat, dan file tantangan yang diberikan.
2. **Reconnaissance & Initial Analysis:** Temuan awal, struktur kode, titik masuk input yang mencurigakan.
3. **Vulnerability Root Cause:** Penjelasan matematis atau teknis mengapa celah keamanan tersebut ada.
4. **Exploitation & Solver Script:** Kode skrip Python solver lengkap beserta cara menjalankannya.
5. **Extracted Flag:** Format flag akhir (`flag{...}`).
6. **Key Takeaway & Remediation:** Pelajaran konsep keamanan yang dapat dipetik dan cara membuat kode tersebut aman.
