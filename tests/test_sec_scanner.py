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


def test_scan_clean_code():
    code = """
    import os
    db.query("SELECT * FROM users WHERE id = :id", {"id": user_id})
    """
    findings = scan_content(code, filename="clean.py")
    assert len(findings) == 0
