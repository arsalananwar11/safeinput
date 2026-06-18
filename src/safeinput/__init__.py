"""
SafeInput: A production-grade input validation and sanitization library.
"""

from .xss import sanitize_html, strip_xss
from .sqli import SQLiDetector
from .utils import clean_null_bytes, normalize_text

__version__ = "0.1.0"
__all__ = [
    "sanitize_html",
    "strip_xss",
    "SQLiDetector",
    "clean_null_bytes",
    "normalize_text",
]