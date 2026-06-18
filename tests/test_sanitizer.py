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
