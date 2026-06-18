import unicodedata

def clean_null_bytes(text: str) -> str:
    """
    Removes null bytes completely to prevent file system poisoning
    and database truncation vulnerabilities.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")
    return text.replace("\x00", "")

def normalize_text(text: str, form: str = "NFKC") -> str:
    """
    Normalizes Unicode characters to their standard compatibility form.
    Prevents homoglyph bypasses (e.g., using full-width Latin characters).
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")
    return unicodedata.normalize(form, text)