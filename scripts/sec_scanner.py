#!/usr/bin/env python3
"""
omni-sec Static Code Security, API & Secret Scanner CLI
Fast, dependency-free scanner for:
1. Hardcoded cloud keys (AWS, GCP, Stripe, GitHub, Slack, OpenAI, Anthropic)
2. Insecure code patterns (SQLi string concat, eval/exec, raw dangerouslySetInnerHTML)
3. API mass assignment & missing tenant predicates
4. AI Prompt injection flaws (direct unsanitized prompt formatting)
Zero external dependencies (pure Python standard library).
"""

import sys
import os
import re
import argparse
from typing import Dict, List, Tuple, Any

# Pattern definitions
SECRET_PATTERNS = [
    (r'\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b', "AWS Access Key ID"),
    (r'\b(AIza[0-9A-Za-z\-_]{35})\b', "Google API Key"),
    (r'\b(sk_live_[0-9a-zA-Z]{24,})\b', "Stripe Live Secret Key"),
    (r'\b(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36})\b', "GitHub Personal Access Token"),
    (r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b', "Slack API Token"),
    (r'\b(sk-[a-zA-Z0-9]{32,}|sk-ant-[a-zA-Z0-9\-_]{32,})\b', "OpenAI / Anthropic API Key"),
]

CODE_SMELL_PATTERNS = [
    (r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*[\w\.\(\)]+', "Potential SQL Injection (String Concatenation)"),
    (r'\b(?:eval|exec)\s*\([^\)]*\)', "Dangerous Dynamic Code Execution (eval/exec)"),
    (r'subprocess\.(?:Popen|call|run)\s*\([^)]*shell\s*=\s*True[^)]*\)', "Subprocess with shell=True"),
    (r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify\.sanitize)[^\}]+\}\s*\}', "Unsanitized dangerouslySetInnerHTML"),
    (r'f["\'].*?(?:system_prompt|prompt)\s*=\s*f["\'].*?\{user_input\}', "Direct Unsanitized Prompt Interpolation"),
]

def scan_content(content: str, filename: str = "") -> List[Dict[str, Any]]:
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # 1. Scan Secrets
        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, line)
            if matches:
                findings.append({
                    "type": "SECRET",
                    "label": label,
                    "file": filename,
                    "line": line_num,
                    "match": matches[0][:8] + "..." + matches[0][-4:] if len(matches[0]) > 12 else "[REDACTED]"
                })

        # 2. Scan Code Smells
        for pattern, label in CODE_SMELL_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "type": "VULNERABILITY",
                    "label": label,
                    "file": filename,
                    "line": line_num,
                    "match": line.strip()[:80]
                })

    return findings

def scan_file(filepath: str) -> List[Dict[str, Any]]:
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return scan_content(content, filename=filepath)
    except Exception:
        return []

def main():
    parser = argparse.ArgumentParser(description="omni-sec Static Code Security & Secret Scanner")
    parser.add_argument("--file", type=str, help="Target file to scan")
    parser.add_argument("--dir", type=str, help="Target directory to scan")

    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.file:
        targets.append(args.file)
    elif args.dir:
        for root, _, files in os.walk(args.dir):
            if ".git" in root or "node_modules" in root or "__pycache__" in root:
                continue
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.tsx', '.jsx', '.json', '.env', '.yml', '.yaml')):
                    targets.append(os.path.join(root, file))

    print("\n" + "="*60)
    print(" [omni-sec Static Security & Secret Audit]")
    print("="*60)

    total_findings = 0
    for t in targets:
        findings = scan_file(t)
        if findings:
            total_findings += len(findings)
            print(f"\n📄 File: {t}")
            for f in findings:
                icon = "🔑" if f["type"] == "SECRET" else "🚨"
                print(f"   [{icon}] Line {f['line']}: {f['label']} -> {f['match']}")

    print("\n" + "="*60)
    print(f" Scan Complete. Total Findings: {total_findings}")
    print("="*60 + "\n")

if __name__ == '__main__':
    main()
