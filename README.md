## ```safeinput```

A robust, lightweight, and high-reliability Python utility package for input validation, contextual XSS sanitization, and SQL injection heuristic detection.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![OWASP Compliance](https://img.shields.io/badge/OWASP-ASVS%20v4.0.3-orange.svg)](https://owasp.org/www-project-application-security-verification-standard/)

`safeinput` offers an engineered, multi-tiered approach to input cleansing and threat scoring aligned with the [OWASP Application Security Verification Standard (ASVS) Chapter 5](https://owasp.org/www-project-application-security-verification-standard/). It shifts focus from destructive string manipulation to structural tokenization, preventing common evasion vectors like nested-tag bypasses and homoglyph normalization attacks without breaking legitimate textual communications.

---

## Features

- **Null Byte Cleansing (OWASP ASVS 5.1.2):** Eliminates file-system poisoning and database truncation risks.
- **Unicode Normalization (OWASP ASVS 5.1.4):** Automatically converts full-width and compatibility characters (`NFKC` form) to standard representation to block lookalike/homoglyph bypass tricks.
- **Contextual HTML/XSS Sanitizer (OWASP XSS Guidelines):** Uses standard token streams (`html.parser`) rather than fragile regular expressions to safely allow specific markup while filtering out dangerous attributes and protocols (`javascript:`, `onclick`, etc.).
- **Heuristic SQLi Detection:** A non-destructive, multi-signature evaluation engine that computes a risk score based on structural queries and tautologies instead of blindly stripping text.

## Installation

Install `safeinput` directly via `pip`:

```bash
pip install safeinput
```

For developmental environments (running tests):

```bash
pip install safeinput[dev]
```

## Architecture Flow

To maximize security while maintaining high usability for legitimate user text, safeinput handles input processing systematically across independent specialized layers:

```bash
    [ User Input String ]
              │
              ▼
   ┌──────────────────────┐
   │  utils.clean_bytes   │ ──► Removes \x00 Null Bytes
   └──────────────────────┘
              │
              ▼
   ┌──────────────────────┐
   │  utils.normalize     │ ──► Normalizes Unicode Homoglyphs
   └──────────────────────┘
              │
       ┌──────┴──────┐
       ▼             ▼
 ┌───────────┐ ┌───────────┐
 │   XSS     │ │   SQLi    │
 │ Sanitizer │ │ Detector  │
 └───────────┘ └───────────┘
       │             │
       ▼             ▼
 [Clean Text/  [Risk Score
    HTML]       & Indicators]
```


## Usage Guide
1. Basic String Utility & Normalization
Eliminate hidden characters and force consistency before sending string payloads to deeper parsing rules.

    ```python
    from safeinput import clean_null_bytes, normalize_text

    # Remove dangerous null bytes that poison file systems or databases
    poisoned_input = "profile_photo.jpg\x00.exe"
    clean_path = clean_null_bytes(poisoned_input)
    print(clean_path)  # Output: "profile_photo.jpg.exe"

    # Normalize homoglyph bypasses (e.g., full-width uppercase characters)
    bypass_attempt = "ＳＥＬＥＣＴ"
    normalized = normalize_text(bypass_attempt)
    print(normalized)  # Output: "SELECT"
    ```


2. XSS and HTML Sanitization
safeinput gives you absolute precision. You can either completely strip out markup or safely pass explicit formatting parameters.

    ```python
    from safeinput import strip_xss, sanitize_html

    # Aggressive approach: Strip all tags to extract plain text
    html_payload = "<script>alert('xss')</script>Welcome, <b>User</b>!"
    plain_text = strip_xss(html_payload)
    print(plain_text)  # Output: "Welcome, User!"

    # Contextual approach: Allow structured design while isolating active execution vectors
    rich_text = "<p>Click <a href='javascript:alert(1)' onclick='bad()'>here</a> for your <b>profile</b></p>"
    allowed_tags = {"p", "b", "a"}
    allowed_attrs = {"href"}

    safe_html = sanitize_html(rich_text, allowed_tags=allowed_tags, allowed_attrs=allowed_attrs)
    print(safe_html)
    # Output: "<p>Click <a>here</a> for your <b>profile</b></p>"
    # Note: JavaScript protocols and inline handling macros were strictly dropped!
    ```

3. Non-Destructive SQLi Risk Telemetry
Instead of changing the input text (which breaks common human language syntax), the package scores the risk of the structural grammar based on completely decoupled numeric and string tautology matching.

    ```python
    from safeinput import SQLiDetector

    detector = SQLiDetector(high_risk_threshold=0.60)

    # Legitimate text with SQL keywords
    legit_text = "I need to select a plan and update my account billing profile."
    result = detector.analyze(legit_text)
    print(result["is_malicious"])  # Output: False
    print(result["risk_score"])     # Output: 0.0

    # Active exploit pattern
    exploit_text = "admin' OR '1'='1' --"
    result = detector.analyze(exploit_text)
    print(result["is_malicious"])       # Output: True
    print(result["risk_score"])          # Output: 0.70 (Crosses threshold metrics due to tautology + comment)
    print(result["matched_indicators"])  # Output: ['boolean_tautology', 'sql_comment_syntax']
    ```

### Running Project Tests
Validation logic is maintained inside `tests/test_sanitizer.py`. To execute the test suite locally, ensure your environment handles pytest

```bash
pytest tests/
```

## Security Disclaimer & OWASP Best Practices

`safeinput` acts as an analytical application gatekeeper layer. It is engineered to satisfy proactive defense-in-depth measures, but it is **not a substitute for architecture-wide security foundations**. 

To remain fully secure and compliant with global enterprise standards:

1. **SQL Injection:** This library is an intrusion detection and telemetry engine. It **must not** replace **Parameterized Queries / Prepared Statements**. In accordance with the [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), always enforce strict parameter separation inside your database drivers or native ORM architecture.
2. **Cross-Site Scripting (XSS):** While input scrubbing is vital for rich text fields, your primary defense against XSS must always be **Contextual Output Encoding**. Ensure your application framework escapes data at the exact layer it is rendered to the DOM, following the rules laid out in the [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).


## License
Distributed under the terms of the MIT License.