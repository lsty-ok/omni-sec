# omni-sec

**Context-Aware Cybersecurity & CTF Engineering Intelligence for AI Coding Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: OpenCode](https://img.shields.io/badge/Platform-OpenCode-purple.svg)](https://github.com/obra/opencode)
[![Security: Responsible](https://img.shields.io/badge/Ethical-Responsible%20Security-emerald.svg)](#ethical-boundaries)
[![Domain: CTF & AppSec](https://img.shields.io/badge/Focus-CTF%20%7C%20AppSec%20%7C%20Forensics-indigo.svg)](#core-capabilities)

`omni-sec` is an autonomous security analysis skill and CTF engineering copilot. It transforms AI coding assistants into skilled security analysts capable of diagnosing vulnerabilities, constructing deterministic CTF solver scripts, dissecting multimodal forensics files, and providing defensive code remediation.

---

## Why omni-sec?

Standard LLMs often struggle with security tasks by:
- ❌ **Hallucinating non-existent vulnerability exploits** or guessing arbitrary flags.
- ❌ **Missing complex encoding layers** (nested Base64 $\to$ Hex $\to$ XOR $\to$ Custom Cipher).
- ❌ **Failing to inspect file headers** or multimodal visual steganography anomalies.
- ❌ **Providing exploits without defensive patches**, failing to teach secure development.

**omni-sec** solves this with a disciplined **5-Stage Security Reasoning Pipeline**:

```text
RECON & DISCOVERY → ROOT CAUSE TRIAGE → EXPLOIT / SOLVER → VERIFICATION → REMEDIATION & WRITE-UP
```

---

## Core Capabilities

| Capability | Scope & Focus |
|---|---|
| **Web Security & Logic Flaws** | SQLi, XSS, SSRF, IDOR, SSTI, Prototype Pollution, JWT cracking, Race Conditions |
| **Cryptanalysis** | Classical ciphers, RSA (Wiener, small $e$, Pollard's $p-1$), AES padding oracle, XOR cryptanalysis |
| **Multimodal Forensics & Stego** | Image metadata (EXIF), magic byte repair, LSB steganography, audio spectrums, PCAP stream dissection |
| **Reverse Engineering** | Disassembly triage (x86/x64/ARM), decompiler code analysis, license keygen logic |
| **Binary Exploitation (PWN)** | Stack buffer overflows, format string vulnerabilities, return-to-libc, basic ROP chains |
| **Defensive Remediation** | Production-grade code patches, parameterized queries, WAF rules, secure config |

---

## Quick Start & Usage

### 1. Interactive CTF Challenge Solving
```text
/omni-sec
Here is a challenge file 'chall.py' and an encrypted ciphertext 'output.txt'.
Help me analyze the cryptographic vulnerability, explain the mathematical root cause, and write a Python solver script.
```

### 2. Web Vulnerability Code Audit
```text
/omni-sec
Perform a security audit on this Express.js authentication middleware. Identify any OWASP Top 10 vulnerabilities, prove exploitability in a local lab, and supply a secure patch.
```

### 3. Multimodal Forensics & Image Inspection
```text
/omni-sec
Analyze this forensic image 'flag.png'. Inspect for hidden EXIF metadata, trailing bytes after the PNG IEND marker, and embedded zip archives.
```

---

## CLI Security Toolkit

`omni-sec` includes built-in standalone Python utilities with zero external dependencies:

```bash
# Decode multi-layer encoding / cipher
python scripts/cipher_toolkit.py --decode "4a4b4c313233..." --mode hex

# Inspect image headers, magic bytes, and embedded archives
python scripts/stego_inspector.py --file challenges/mystery.png
```

---

## Architecture Overview

```text
omni-sec/
├── SKILL.md                          # Master Orchestrator, Mode Dispatcher & Safety Boundaries
├── MAPPING.md                        # Architecture blueprint & knowledge index
├── knowledge/                        # Domain Knowledge Bases (Web, Crypto, Forensics, Rev, Pwn)
├── reasoning/                        # 5-Stage Security Reasoning Pipelines
├── scripts/                          # Zero-Heavy-Dependency Python Security Tools
├── templates/                        # Structured Output Templates (Write-ups, Security Advisories)
└── tests/                            # Unit Test Suite
```

---

## Ethical Boundaries & Responsible Disclosure

`omni-sec` is strictly designed for **educational CTF training**, **authorized local lab verification**, and **defensive source code auditing**. It strictly refuses to participate in unauthorized attacks against live third-party infrastructure. Every vulnerability analysis includes remediation guidance.

---

## License

This project is licensed under the [MIT License](LICENSE).
