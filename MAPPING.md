# omni-sec Architecture & Knowledge Mapping

> Comprehensive index of cybersecurity knowledge bases, reasoning pipelines, standalone utility scripts, and output templates.
> Enriched with patterns from: pwntools, RsaCtfTool, zsteg, PayloadsAllTheThings, and briiirussell/cybersecurity-skills.

```
omni-sec/
├── SKILL.md                          # Master Orchestrator, Mode Dispatcher & Safety Boundaries
├── MAPPING.md                        # This architecture blueprint & knowledge index
├── README.md                         # Quick start & toolchain documentation
├── LICENSE                           # MIT License
├── CONTRIBUTING.md                   # Ethical guidelines & contribution standard
├── .gitignore                        # Python / OS filters
├── .github/workflows/ci.yml          # Automated Pytest CI Workflow
│
├── knowledge/                        # Domain Knowledge Bases & Attack Vectors
│   ├── web-vulnerabilities.md        # OWASP Top 10, SQLi, XSS, SSRF, IDOR, SSTI, Prototype Pollution
│   ├── api-security.md               # OWASP API Top 10 (BOLA, BFLA, Mass Assignment, GraphQL)
│   ├── ai-llm-security.md            # OWASP LLM Top 10, Prompt Injection, RAG Poisoning, Agent Guardrails
│   ├── crypto-attacks.md             # RSA (Wiener, small e, Fermat), XOR, AES ECB/CBC, LCG PRNG
│   ├── forensics-multimodal.md       # Magic bytes lookup, EXIF, LSB Stego, PCAP, Audio Spectrogram
│   ├── reverse-engineering.md        # x86/x64 assembly, Ghidra/GDB tips, bytecode (pyc/apk/wasm)
│   ├── binary-exploitation.md        # Stack buffer overflows, ret2win, ret2libc, format string, pwntools
│   └── secure-coding-standards.md    # Defensive patching, sanitasi input, password hashing (Argon2id)
│
├── reasoning/                        # 5-Stage Security Reasoning Pipelines
│   ├── recon-discovery.md            # Stage 1: Target classification & multimodal surface mapping
│   ├── vulnerability-triage.md       # Stage 2: Root cause analysis (Symptom vs Cause) & CVSS
│   ├── exploit-reasoning.md          # Stage 3: Python deterministic solver generation
│   └── defensive-remediation.md      # Stages 4 & 5: Patch engineering diffs & CTF write-ups
│
├── scripts/                          # Standalone Python 3 Toolkits (Zero External Dependencies)
│   ├── __init__.py                   # Package marker
│   ├── sec_scanner.py                # Static secret & code vulnerability scanner CLI
│   ├── cipher_toolkit.py             # Multi-layer decoder (Base64, Hex, ROT13, Caesar, XOR, Hash ID)
│   ├── rsa_toolkit.py                # Pure-Python RSA Solvers (Wiener, Fermat, Small e, Common Modulus)
│   ├── stego_inspector.py            # Magic bytes, trailing EOF data, polyglot ZIP, PNG LSB extractor
│   ├── pwn_helper.py                 # Pwn utilities (p32/p64/u32/u64, De Bruijn cyclic offset generator)
│   └── pcap_dissector.py             # PCAP parser, cleartext credential & HTTP request extractor
│
├── templates/                        # Standardized Output Formats
│   ├── ctf-writeup-template.md       # Competitive CTF write-up template
│   └── vulnerability-advisory.md     # Production Application Security Advisory
│
├── tests/                            # Pytest Test Suite (100% Passing)
│   ├── conftest.py                   # Test path configuration
│   ├── test_sec_scanner.py           # Secret & static vulnerability detection tests
│   ├── test_cipher_toolkit.py        # Decoding & hash identification tests
│   ├── test_rsa_toolkit.py           # RSA factoring & mathematical solver tests
│   ├── test_pwn_helper.py            # Packing, cyclic offset, and ELF parser tests
│   └── test_stego_inspector.py       # Header binary & trailing data tests
│
└── references/                       # Industry References & Cheatsheets
    ├── owasp-top-10.md               # Summary of OWASP vulnerabilities & remediations
    └── ctf-cheatsheet.md             # Curated payloads & solver formulas (Awesome-CTF & PayloadsAllTheThings)
```
