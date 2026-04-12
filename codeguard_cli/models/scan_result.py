"""Scan result model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .finding import Finding


@dataclass(slots=True)
class ScanResult:
    """Aggregated scan output and metadata."""

    target_path: str
    findings: list[Finding] = field(default_factory=list)
    total_files_discovered: int = 0
    total_files_scanned: int = 0
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0

    def severity_counts(self) -> dict[str, int]:
        """Count findings grouped by severity."""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
            else:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def rule_counts(self) -> dict[str, int]:
        """Count findings grouped by rule id."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))

    def to_dict(self) -> dict:
        """Serialize scan result for JSON export."""
        return {
            "target_path": self.target_path,
            "metadata": {
                "total_files_discovered": self.total_files_discovered,
                "total_files_scanned": self.total_files_scanned,
                "total_findings": len(self.findings),
                "severity_counts": self.severity_counts(),
                "rule_counts": self.rule_counts(),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "duration_seconds": round(self.duration_seconds, 3),
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "ScanResult":
        """Build a ScanResult from a loaded JSON dictionary."""
        metadata = payload.get("metadata", {})
        findings_payload = payload.get("findings", [])
        return cls(
            target_path=payload.get("target_path", ""),
            findings=[Finding.from_dict(item) for item in findings_payload],
            total_files_discovered=int(metadata.get("total_files_discovered", 0)),
            total_files_scanned=int(metadata.get("total_files_scanned", 0)),
            started_at=metadata.get("started_at", ""),
            finished_at=metadata.get("finished_at", ""),
            duration_seconds=float(metadata.get("duration_seconds", 0.0)),
        )
