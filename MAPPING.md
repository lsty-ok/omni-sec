# omni-sec — Architecture & Module Mapping

## System Architecture

`omni-sec` is organized into a clean modular taxonomy:

```text
omni-sec/
├── SKILL.md                          # Master Orchestrator, Mode Dispatcher & Safety Boundaries
├── MAPPING.md                        # Architecture blueprint & knowledge index
├── README.md                         # Project documentation & usage guide
│
├── knowledge/                        # Domain Knowledge Bases & Attack Vectors
│   ├── web-vulnerabilities.md        # OWASP Top 10, logic bugs, SQLi, XSS, SSRF, IDOR, SSTI
│   ├── crypto-attacks.md             # RSA (Wiener, small e), XOR, AES modes, ECC basics, PRNG flaws
│   ├── forensics-multimodal.md       # Magic bytes, EXIF, LSB stego, PCAP dissection, audio spectrum
│   ├── reverse-engineering.md        # x86/x64 assembly, Ghidra/GDB tips, packing, anti-reversing
│   ├── binary-exploitation.md        # Buffer overflows, format strings, shellcoding, ROP, heap basics
│   └── secure-coding-standards.md    # Defensive remediation, input sanitization, safe frameworks
│
├── reasoning/                        # 5-Stage Security Reasoning Pipelines
│   ├── recon-discovery.md            # Reconnaissance & Attack Surface Mapping
│   ├── vulnerability-triage.md       # Root Cause & Weakness Classification (CWE/CVSS)
│   ├── exploit-reasoning.md          # Deterministic Solver Construction & Payload Engineering
│   └── defensive-remediation.md      # Patching, Hardening & Security Advisory Formulation
│
├── scripts/                          # Zero-Heavy-Dependency Python Security Tools
│   ├── __init__.py                   # Package marker
│   ├── cipher_toolkit.py             # Multi-layer encoding/decoding & hash analyzer
│   ├── stego_inspector.py            # File header, magic byte, EXIF & trailing byte scanner
│   └── pcap_dissector.py             # Minimalist PCAP protocol stream & credential extractor
│
├── templates/                        # Structured Output Templates
│   ├── ctf-writeup-template.md       # Professional, publishable CTF challenge write-up
│   ├── vulnerability-advisory.md     # Formal security audit finding report
│   └── secure-patch-template.md      # Before/After patch diff with validation tests
│
├── tests/                            # Unit Test Suite for Tools
│   ├── test_cipher_toolkit.py        # Verification of crypto decoding logic
│   └── test_stego_inspector.py       # Verification of file header & stego checks
│
└── references/                       # Authoritative Security Standards & Cheatsheets
    ├── owasp-top-10.md               # Summary of OWASP 2021/2025 categories
    └── ctf-cheatsheet.md             # High-frequency CTF payload formulas & one-liners
```

---

## File Purpose & Responsibility Matrix

| Module | Core Responsibility |
|---|---|
| `knowledge/web-vulnerabilities.md` | Catalog of web attack primitives, injection vectors, and detection signatures. |
| `knowledge/crypto-attacks.md` | Mathematical formulas and solver recipes for classical and modern cryptanalysis. |
| `knowledge/forensics-multimodal.md` | Multimodal image/audio inspection protocols, magic bytes lookup table, and packet analysis. |
| `knowledge/reverse-engineering.md` | Control flow reconstruction, decompiler pattern recognition, and register tracing. |
| `knowledge/binary-exploitation.md` | Memory corruption exploitation patterns (stack, format string, ROP gadgets). |
| `scripts/cipher_toolkit.py` | Command-line utility for instant multi-round decoding (Hex, Base32/64/85, Rot13, XOR, ASCII). |
| `scripts/stego_inspector.py` | Inspects binary file headers, detects polyglot/embedded ZIPs, and scans visual anomalies. |
