# Professional CTF Challenge Write-Up Template

---

# [Challenge Title] — CTF Write-Up

**CTF Event:** [e.g. PicoCTF / DEF CON CTF / HackTheBox / Local Campus CTF]  
**Category:** [Web / Cryptography / Forensics / Reverse Engineering / Binary Exploitation (PWN)]  
**Difficulty:** [Easy / Medium / Hard / Insane]  
**Points:** [e.g. 250 pts]  
**Author:** [Your Handle / omni-sec]  
**Date:** [YYYY-MM-DD]  

---

## 1. Challenge Description

> [Paste the raw challenge prompt, story, clues, connection string, or attachment details here.]

---

## 2. Reconnaissance & Surface Discovery

### Initial Inspection:
- Target IP / URL / File format: `...`
- Key findings from static or header inspection:
  - File signature / Magic bytes: `...`
  - Visible parameters & endpoints: `...`
  - Technologies detected: `...`

---

## 3. Vulnerability Root Cause Analysis

- **Vulnerability Type:** [e.g. CWE-89 SQL Injection / RSA Small Exponent e=3 / LSB Steganography]
- **Technical Explanation:**
  [Explain WHY the vulnerability exists at the source code / mathematical level. Reference specific code lines or formulas.]

```python
# Vulnerable snippet / formula:
# ...
```

---

## 4. Exploitation & Solver Implementation

### Solver Script (`solve.py`):

```python
#!/usr/bin/env python3
"""
omni-sec CTF Solver Script for [Challenge Title]
"""
import sys
# [Include clean, reproducible solver code here]

def main():
    # 1. Connect / Load Payload
    # 2. Trigger vulnerability
    # 3. Extract flag
    pass

if __name__ == '__main__':
    main()
```

### Execution Output:
```text
$ python solve.py
[+] Connected to target
[+] Payload sent: ...
[+] FLAG FOUND: flag{example_flag_extracted_here}
```

---

## 5. Captured Flag

```text
flag{...}
```

---

## 6. Key Takeaways & Defensive Remediation

### Key Lessons:
1. `...`
2. `...`

### How to Fix (Defensive Patch):
[Provide the secure code implementation or mitigation strategy so the challenge is educational for defense.]
