import pytest
from safeinput import clean_null_bytes, normalize_text, strip_xss, sanitize_html, SQLiDetector

# --- UTILS TESTS ---
def test_null_byte_removal():
    assert clean_null_bytes("hello\x00world") == "helloworld"
    assert clean_null_bytes("no_null_bytes") == "no_null_bytes"
    with pytest.raises(TypeError):
        clean_null_bytes(12345)

def test_unicode_normalization():
    # Full-width Latin text bypass attempt normalization
    full_width = "ＳＥＬＥＣＴ"
    assert normalize_text(full_width) == "SELECT"


# --- XSS TESTS ---
def test_strip_xss_removes_scripts():
    payload = "<script>alert('xss')</script>Hello"
    assert strip_xss(payload) == "Hello"

def test_strip_xss_nested_bypass():
    # If the parser works linearly, it handles nested tags safely
    payload = "<scr<script>ipt>alert(1)</script>"
    assert "script" not in strip_xss(payload)

def test_sanitize_html_allows_specifics():
    html_input = "<p>Click <a href='javascript:alert(1)' onclick='bad()'>here</a> <b>User</b></p>"
    allowed_tags = {"p", "b", "a"}
    allowed_attrs = {"href"}
    
    cleaned = sanitize_html(html_input, allowed_tags, allowed_attrs)
    # Inline javascript and event attributes must be stripped even if tags/attrs are allowed
    assert "javascript:" not in cleaned
    assert "onclick" not in cleaned
    assert "<b>User</b>" in cleaned


# --- SQLI DETECTION TESTS ---
def test_sqli_legitimate_text():
    detector = SQLiDetector()
    # Legitimate conversational references shouldn't trigger high flags
    res = detector.analyze("Please back up your files, or users will complain.")
    assert res["is_malicious"] is False

def test_sqli_attack_payloads():
    detector = SQLiDetector()
    
    # Classic Tautology bypass
    res1 = detector.analyze("' OR 1=1 --")
    assert res1["is_malicious"] is True
    
    # Union attack
    res2 = detector.analyze("1 UNION SELECT username, password FROM users")
    assert res2["is_malicious"] is True
    assert "union_select_pattern" in res2["matched_indicators"]
    
    # Stacked updates
    res3 = detector.analyze("invalid_input; DROP TABLE orders;")
    assert res3["is_malicious"] is True

