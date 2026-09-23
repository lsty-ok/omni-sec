# Digital Forensics, Incident Response (DFIR) & YARA Threat Hunting

> Domain: Incident Investigation, Memory/Disk Forensics & Detection Engineering
> Classification: AUTHORITATIVE KNOWLEDGE BASE
> Aligned with: NIST SP 800-86 (Forensics Guide), SANS DFIR, YARA Specification

---

## 1. YARA Rule Development for Threat Hunting

YARA rules identify malware samples, webshells, and obfuscated scripts based on binary and textual patterns.

### Production YARA Rule Anatomy:
```yara
rule WebShell_PHP_Obfuscated_Eval {
    meta:
        description = "Detects obfuscated PHP webshells using eval(base64_decode)"
        author = "omni-sec threat hunting"
        severity = "HIGH"
        date = "2026-09-23"
    strings:
        $tag = "<?php" nocase
        $eval = "eval" fullword nocase
        $b64 = "base64_decode" fullword nocase
        $gz = "gzinflate" fullword nocase
        $post = "$_POST" fullword
    condition:
        $tag at 0 and ($eval and ($b64 or $gz)) and $post and filesize < 50KB
}
```

---

## 2. Windows Forensics Artifact Matrix

| Artifact Location | Forensics Evidence & Value | Parser / Triage Action |
|---|---|---|
| **`$MFT` (Master File Table)** | File creation, deletion, timestamps ($STANDARD_INFO vs $FILE_NAME to detect timestomping) | Analyze with `MFTECmd` |
| **`Amcache.hve` & `Shimcache`** | Executed application paths, file hashes, timestamps | Analyze with `AmcacheParser` |
| **`Prefetch` (`C:\Windows\Prefetch\*.pf`)** | Proof of execution, execution count, last 8 run timestamps | Analyze with `PECmd` |
| **Event Logs (`*.evtx`)** | Event ID 4624 (Logon), 4688 (Process Creation), 7045 (Service Install) | Analyze with `EvtxECmd` |

---

## 3. SQLite Database Forensics (WAL & Freespace Recovery)

### Architecture:
- SQLite databases often hold sensitive chat logs, browser history, and app state.
- Changes are committed first to the **Write-Ahead Log (`database.db-wal`)** and rollback journal (`database.db-journal`).

### Forensics Triage Workflow:
1. Always acquire all three files together: `app.db`, `app.db-wal`, `app.db-shm`.
2. Inspect WAL frames for deleted records before a checkpoint merge occurs.
3. Carve free-list pages for unallocated raw text and deleted string fragments.
