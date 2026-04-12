"""Finding data model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Finding:
    """Represents a single scanner finding."""

    rule_id: str
    rule_name: str
    description: str
    category: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    match_preview: str
    remediation: str = ""
    cwe: str = ""

    def to_dict(self) -> dict:
        """Convert finding to JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "match_preview": self.match_preview,
            "remediation": self.remediation,
            "cwe": self.cwe,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "Finding":
        """Create a Finding from a dictionary."""
        return cls(
            rule_id=payload.get("rule_id", ""),
            rule_name=payload.get("rule_name", ""),
            description=payload.get("description", ""),
            category=payload.get("category", ""),
            severity=payload.get("severity", "Low"),
            confidence=float(payload.get("confidence", 0.0)),
            file_path=payload.get("file_path", ""),
            line_number=int(payload.get("line_number", 0)),
            match_preview=payload.get("match_preview", ""),
            remediation=payload.get("remediation", ""),
            cwe=payload.get("cwe", ""),
        )
