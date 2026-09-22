# Multimodal Forensics & Steganography Analysis

> Domain: Digital Forensics, Image/Audio Steganography & Network Packet Analysis
> Standard: DFIR & CTF Forensics Protocols
> Classification: SECURITY KNOWLEDGE BASE

## Purpose

Panduan inspeksi multimodal (gambar, audio, arsip, memori, network traffic) untuk menemukan data tersembunyi, memperbaiki file rusak, dan merekonstruksi aliran data CTF.

---

## 1. File Signatures & Magic Bytes Lookup Table

Ketika file CTF rusak (*corrupted header*) atau sengaja di-rename dengan ekstensi palsu:

| Format | Header (Magic Bytes / Hex) | Footer (Trailer Hex) |
|---|---|---|
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` (`IEND`) |
| **JPEG / JPG** | `FF D8 FF E0` s/d `FF D8 FF EE` | `FF D9` |
| **GIF87a / 89a**| `47 49 46 38 37 61` / `47 49 46 38 39 61` | `00 3B` |
| **ZIP** | `50 4B 03 04` (Local) / `50 4B 05 06` (End) | `50 4B 05 06` |
| **PDF** | `25 50 44 46 2D` (`%PDF-`) | `25 25 45 4F 46` (`%%EOF`) |
| **ELF (Linux)**| `7F 45 4C 46` (`.ELF`) | N/A |
| **PE (Windows)**| `4D 5A` (`MZ` DOS Header) | N/A |
| **SQLite3** | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74` | N/A |
| **WAV (Audio)**| `52 49 46 46 .... 57 41 56 45` (`RIFF...WAVE`) | N/A |

### Triage Protocol untuk File Rusak:
1. Baca 16 byte pertama menggunakan hex reader.
2. Jika header tidak cocok dengan ekstensi, periksa apakah ada byte yang tergeser (*shifted*) atau terhapus 4-byte pertamanya.
3. Periksa apakah ada file archive tersembunyi setelah EOF marker (misal zip yang di-append setelah `FF D9` pada JPEG).

---

## 2. Image Steganography Protocols

### A. Metadata & EXIF Examination
- **Target:** Komentar EXIF, Author, GPS coordinates, Camera serial, Base64 strings di Thumbnail metadata.
- **Commands:**
  - `exiftool image.jpg`
  - `strings -n 8 image.png | grep -iE "flag|ctf|key|pass"`

### B. Least Significant Bit (LSB) Stego
- **Konsep:** Nilai byte warna Red, Green, Blue diubah bit terendahnya ($0$ atau $1$) untuk menyisipkan pesan biner tanpa merusak visual gambar secara kasat mata.
- **Pola Channels:** Red 0, Green 0, Blue 0, Alpha 0.
- **Tooling:** `zsteg -a image.png` (deteksi otomatis LSB/MSB/PRIME channels).

### C. PNG Chunk Manipulation (IHDR / IDAT / eXIf)
- **PNG Height Alteration (CRC32 Mismatch):**
  - Pembuat soal CTF sengaja mengecilkan tinggi gambar pada header `IHDR` agar flag yang terletak di bagian bawah gambar terpotong.
  - **Tanda:** Pesan error CRC checksum mismatch saat dibuka di editor.
  - **Solusi:** Hitung balik tinggi yang benar berdasarkan CRC32 chunk IHDR menggunakan Python script.

---

## 3. Network Traffic Analysis (PCAP / PCAPNG)

### Extraction Checklist:
1. **HTTP Objects:** File gambar, binary, script yang di-download selama sesi capture (`tshark --export-objects http,dir`).
2. **Cleartext Credentials:** Pencarian username/password di protokol `HTTP POST`, `FTP`, `Telnet`, `SMTP`, `POP3`, `IMAP`.
3. **DNS Exfiltration:** Subdomain DNS yang berisi hex/Base64 query panjang secara berulang (`tshark -r file.pcap -Y "dns" -T fields -e dns.qry.name`).
4. **ICMP Tunneling:** Data payload tersembunyi di dalam ICMP Echo Request/Reply data bytes.
5. **TCP Follow Stream:** Rekonstruksi percakapan socket mentah.

---

## 4. Audio Steganography & Spectrogram

- **Spectrogram Visuals:** Flag tersembunyi dalam frekuensi audio tinggi yang hanya terlihat saat dianalisis menggunakan grafik spektrogram (Sonic Visualiser).
- **DTMF Tones:** Rekaman nada telepon (Dual-Tone Multi-Frequency) yang diterjemahkan menjadi deretan angka tombol dialer.
- **Morse Code Audio:** Deteksi ritme dot (.) dan dash (-) dari modulasi amplitude/pitch gelombang audio.
