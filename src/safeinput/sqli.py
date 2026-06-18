import re
from typing import Dict, Any

class SQLiDetector:
    def __init__(self, high_risk_threshold: float = 0.50):
        # Since scores are now binary (0.0 or 1.0), any match crosses 0.50 instantly
        self.threshold = high_risk_threshold
        
        self.patterns = {
            "numeric_tautology": re.compile(r"\b(\d+)\s*=\s*\1\b"),
            "string_tautology": re.compile(r"(['\"])(.*?)\1\s*=\s*\1\2\1"),
            "union_attack": re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.IGNORECASE),
            "stacked_queries": re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE)\b", re.IGNORECASE),
            "sql_comments": re.compile(r"(--|/\*|\*/|#)"),
            "exec_procedures": re.compile(r"\b(EXEC|XP_CMDSHELL|SP_EXECUTESQL)\b", re.IGNORECASE)
        }

    def analyze(self, text: str) -> Dict[str, Any]:
        if not isinstance(text, str):
            return {"risk_score": 0.0, "is_malicious": False, "matched_indicators": []}

        matched_indicators = []

        # Map patterns to their human-readable indicator names
        pattern_mapping = {
            "numeric_tautology": "boolean_tautology",
            "string_tautology": "boolean_tautology",
            "union_attack": "union_select_pattern",
            "stacked_queries": "stacked_command_execution",
            "sql_comments": "sql_comment_syntax",
            "exec_procedures": "stored_procedure_call"
        }

        # Check for any pattern execution matches
        for internal_key, indicator_name in pattern_mapping.items():
            if self.patterns[internal_key].search(text):
                if indicator_name not in matched_indicators:
                    matched_indicators.append(indicator_name)

        # Binary Scoring Strategy: Any match drops a maximum threat score
        has_matches = len(matched_indicators) > 0
        final_score = 1.0 if has_matches else 0.0

        return {
            "risk_score": final_score,
            "is_malicious": final_score >= self.threshold,
            "matched_indicators": matched_indicators
        }

    def sanitize(self, text: str, replacement: str = "[REDACTED]") -> str:
        if not isinstance(text, str):
            raise TypeError(f"Input must be a string. Received {type(text).__name__} instead.")

        analysis = self.analyze(text)
        if not analysis["is_malicious"]:
            return text
        
        sanitized = text
        for _, regex in self.patterns.items():
            sanitized = regex.sub(replacement, sanitized)

        return sanitized
