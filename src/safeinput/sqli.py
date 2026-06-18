import re
from typing import Dict, Any

class SQLiDetector:
    def __init__(self, high_risk_threshold: float = 0.01):
        self.threshold = high_risk_threshold
        
        # Compiled patterns looking for query structures and boolean tautologies
        self.patterns = {
            "tautology": re.compile(r"(\d+)\s*=\s*\1|(['\"]?)(\w+)\2\s*=\s*\2\3\2", re.IGNORECASE),
            "union_attack": re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
            "stacked_queries": re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE)\b", re.IGNORECASE),
            "sql_comments": re.compile(r"(--|/\*|\*/|#)", re.IGNORECASE),
            "exec_procedures": re.compile(r"\b(EXEC|XP_CMDSHELL|SP_EXECUTESQL)\b", re.IGNORECASE)
        }

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyzes text contextually and calculates a malicious SQL structure risk score.
        """
        if not isinstance(text, str):
            return {"risk_score": 0.0, "is_malicious": False, "matched_indicators": []}

        matched_indicators = []
        score = 0.00

        # Heuristic weighing based on attack signatures
        if self.patterns["tautology"].search(text):
            score += 0.50
            matched_indicators.append("boolean_tautology")
            
        if self.patterns["union_attack"].search(text):
            score += 0.60
            matched_indicators.append("union_select_pattern")
            
        if self.patterns["stacked_queries"].search(text):
            score += 0.70
            matched_indicators.append("stacked_command_execution")
            
        if self.patterns["sql_comments"].search(text):
            score += 0.75
            matched_indicators.append("sql_comment_syntax")
            
        if self.patterns["exec_procedures"].search(text):
            score += 0.80
            matched_indicators.append("stored_procedure_call")

        # Normalize score maximum
        final_score = min(score, 1.0)

        return {
            "risk_score": final_score,
            "is_malicious": final_score >= self.threshold,
            "matched_indicators": matched_indicators
        }
