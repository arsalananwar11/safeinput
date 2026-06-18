import pytest
from safeinput import clean_null_bytes, normalize_text, strip_xss, sanitize_html, SQLiDetector

# ==============================================================================
# 1. CORE UTILS & OBFUSCATION TESTS (OWASP ASVS 5.1.2 & 5.1.4)
# ==============================================================================

def test_null_byte_removal():
    assert clean_null_bytes("hello\x00world") == "helloworld"
    assert clean_null_bytes("no_null_bytes") == "no_null_bytes"
    with pytest.raises(TypeError):
        clean_null_bytes(12345)

def test_null_byte_edge_cases():
    # Continuous null bytes and boundary handling
    assert clean_null_bytes("\x00\x00\x00") == ""
    assert clean_null_bytes("leading\x00") == "leading"
    assert clean_null_bytes("\x00trailing") == "trailing"

def test_unicode_normalization():
    # Full-width Latin text bypass attempt normalization
    full_width = "ＳＥＬＥＣＴ"
    assert normalize_text(full_width) == "SELECT"

def test_unicode_normalization_homoglyphs():
    # Testing character variations that mimic symbols or spaces
    assert "UNION" in normalize_text("ＵＮＩＯＮ")
    # Clean text with emojis shouldn't break or distort
    assert normalize_text("Hello World 🛡️") == "Hello World 🛡️"


# ==============================================================================
# 2. XSS & HTML SANITIZATION TESTS
# ==============================================================================

def test_strip_xss_removes_scripts():
    payload = "<script>alert('xss')</script>Hello"
    assert strip_xss(payload) == "Hello"

def test_strip_xss_nested_bypass():
    # If the parser works linearly, it handles nested tags safely
    payload = "<scr<script>ipt>alert(1)</script>"
    assert "script" not in strip_xss(payload)

def test_strip_xss_malformed_html():
    assert strip_xss("<script src=http://evil.com") == ""
    assert strip_xss("<<SCRIPT>alert(1);//<</SCRIPT>") == "<"
    assert strip_xss("<iframe/src='javascript:alert(1)'>") == ""

def test_sanitize_html_allows_specifics():
    html_input = "<p>Click <a href='javascript:alert(1)' onclick='bad()'>here</a> <b>User</b></p>"
    allowed_tags = {"p", "b", "a"}
    allowed_attrs = {"href"}
    
    cleaned = sanitize_html(html_input, allowed_tags, allowed_attrs)
    # Inline javascript and event attributes must be stripped even if tags/attrs are allowed
    assert "javascript:" not in cleaned
    assert "onclick" not in cleaned
    assert "<b>User</b>" in cleaned

def test_sanitize_html_banned_containers():
    # Ensure raw code injection tags reject text payloads completely
    for tag in ["style", "object", "embed", "iframe"]:
        payload = f"<{tag}>harmful data payload</{tag}>Keep Me"
        assert "harmful data payload" not in sanitize_html(payload, allowed_tags={tag})


# ==============================================================================
# 3. SQLI HEURISTIC DETECTION TESTS
# ==============================================================================

def test_sqli_legitimate_text():
    detector = SQLiDetector()
    # Legitimate conversational references shouldn't trigger high flags
    res = detector.analyze("Please back up your files, or users will complain.")
    assert res["is_malicious"] is False

def test_sqli_legitimate_text_with_special_characters():
    detector = SQLiDetector()
    text = "The user's score is 100% and they should be happy."
    # Legitimate conversational references shouldn't change original text when sanitized
    res = detector.sanitize(text)
    assert res == text

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

def test_sqli_evasion_techniques():
    detector = SQLiDetector(high_risk_threshold=0.60)
    
    # Case variation evasion strategies
    assert detector.analyze("1 uNiOn sElEcT 1,2,3")["is_malicious"] is True
    
    # Multi-line statement injection separation
    assert detector.analyze("admin'\nOR\n1=1\n--")["is_malicious"] is True
    
    # Inline SQL code comment block masking
    assert detector.analyze("UNION/*comment*/SELECT")["is_malicious"] is True

def test_sqli_legitimate_comparison_operators():
    detector = SQLiDetector()
    # Ensure standard comparison operators in normal text are not treated as malicious
    expressions = [
        "if x > 5 and y < 10:",
        "The price is >= $50 but <= $100",
        "Make sure total != 0",
        "Score = 100 points"
    ]
    for expr in expressions:
        res = detector.analyze(expr)
        assert res["is_malicious"] is False
        assert res["risk_score"] < detector.threshold


# ==============================================================================
# 4. SURGICAL SANITIZATION & REDACTION TESTS
# ==============================================================================

def test_sanitize_type_safety_and_overrides():
    detector = SQLiDetector()
    
    # Graceful fallback mechanisms for non-string types
    # Raise TypeError for non-string inputs instead of silently returning them
    with pytest.raises(TypeError):
        detector.sanitize(None)
    with pytest.raises(TypeError):
        detector.sanitize(42.0)
    with pytest.raises(TypeError):
        detector.sanitize(["UNION SELECT"])
    
    # Test overriding the default placeholder token text entirely
    payload = "1 UNION SELECT password FROM users"
    assert detector.sanitize(payload, replacement="[STRIPPED]") == "1 [STRIPPED] password FROM users"

def test_readme_examples():
    detector = SQLiDetector(high_risk_threshold=0.50)

    # 1. Test Legitimate text with SQL keywords (Should be exactly 0.0)
    legit_text = "I need to select a plan and update my account billing profile."
    result = detector.analyze(legit_text)
    assert result["is_malicious"] is False
    assert result["risk_score"] == 0.0
    assert result["matched_indicators"] == []

    # 2. Test Active exploit pattern (Now correctly evaluates to 1.0)
    exploit_text = "1 UNION SELECT username, password FROM users"
    result = detector.analyze(exploit_text)
    assert result["is_malicious"] is True
    assert result["risk_score"] == 1.0
    assert "union_select_pattern" in result["matched_indicators"]

    # 3. Test Surgical Redaction
    mixed_text = "Hello admin' OR '1'='1' -- please drop the tables; DROP TABLE users"
    clean_text = detector.sanitize(mixed_text)
    
    assert clean_text != mixed_text
    assert "DROP TABLE" not in clean_text
    assert "'1'='1'" not in clean_text
    assert "[REDACTED]" in clean_text
