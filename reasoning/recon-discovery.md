# Stage 1: Reconnaissance & Target Discovery Engine

> Domain: Security Analysis & Attack Surface Mapping
> Standard: omni-sec 5-Stage Security Reasoning Pipeline (Stage 1)
> Classification: REASONING PROCESS

## Purpose

Protokol pengumpulan informasi (*reconnaissance*), identifikasi arketipe tantangan CTF / target audit, pemetaan vektor input, dan deteksi anomali multimodal secara sistematis.

---

## 1. Target Classification Matrix

Sebelum melakukan analisis teknis, petakan target ke salah satu domain utama:

```text
INPUT TARGET
  ├─ URL / Web Source Code / HTTP Request → [WEB SECURITY]
  ├─ Math Formula / Key Parameters (N, e, c) / Ciphertext → [CRYPTOGRAPHY]
  ├─ Image / Audio / PCAP / Disk Dump → [MULTIMODAL FORENSICS]
  ├─ Compiled Binary (ELF, PE, APK, WASM) → [REVERSE ENGINEERING]
  └─ Binary with Network Port / Vulnerable Buffer → [BINARY EXPLOITATION]
```

---

## 2. Reconnaissance Protocols by Domain

### A. Web Recon Protocol
1. **Tech Stack Fingerprinting:** Deteksi framework (Flask, Express, Django, Laravel, Spring), database engine (MySQL, PostgreSQL, SQLite, MongoDB), dan web server.
2. **Endpoint Enumeration:** Catat semua route, query params, form fields, headers, cookies, dan WebSocket connections.
3. **Role & Privilege Mapping:** Identifikasi batasan otorisasi antar level user (Anonymous $\to$ Regular User $\to$ Admin).

### B. Multimodal Image / Forensics Recon Protocol
1. **Visual Scan:** Identifikasi ada tidaknya noise anomali, teks tersembunyi, barcode, atau pesan visual di latar belakang.
2. **File Signature Verification:** Cocokkan 16 byte pertama dengan *Magic Bytes Table* (lihat `knowledge/forensics-multimodal.md`).
3. **Trailing Data Scan:** Cari data yang disisipkan setelah End-of-File (EOF) marker.

### C. Cryptanalysis Recon Protocol
1. **Cipher Identification:**
   - Base64 / Hex format?
   - Block size (8 bytes / 16 bytes)?
   - Karakter set (alphanumeric, ASCII printable, binary stream)?
2. **Statistical Characteristics:** Hitung Index of Coincidence (IoC), entropi karakter, dan frekuensi distribusi huruf.

---

## 3. Output Contract: Attack Surface Map

Setiap tahap Reconnaissance harus menghasilkan rangkuman ringkas:

```markdown
### 🔍 Reconnaissance Summary:
- **Target Category:** [Web / Crypto / Forensics / Rev / Pwn]
- **Technology Stack:** [e.g. Node.js + SQLite + EJS]
- **Primary Input Vectors:** [e.g. `/profile?theme=...`, POST `/api/export`]
- **Suspicious Indicators:** [e.g. Unescaped template variable at line 42]
```
