"""Threat-intel data models shared by VirusTotal, Hybrid Analysis, and MetaDefender."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VendorFinding:
    vendor: str
    category: str
    label: str


@dataclass
class FileIntel:
    sha256: str
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    engine_total: int = 0
    labels: list[str] = field(default_factory=list)
    vendors: list[VendorFinding] = field(default_factory=list)
    vt_found: bool = False
    vt_error: str | None = None
    hybrid_verdict: str | None = None
    hybrid_score: int | None = None
    hybrid_family: str | None = None
    hybrid_error: str | None = None
    metadefender_detected: int | None = None
    metadefender_total: int | None = None
    metadefender_result: str | None = None
    metadefender_error: str | None = None
    vt_uploaded: bool = False
    vt_upload_error: str | None = None
    sandbox_verdict: str | None = None
    sandbox_family: str | None = None
    sandbox_tags: list[str] = field(default_factory=list)
    sandbox_behaviors: list[str] = field(default_factory=list)
    ai_synthesis: str | None = None
    ai_plain_what: str | None = None
    ai_plain_why: str | None = None
    ai_plain_bottom: str | None = None
    ai_error: str | None = None

    @property
    def is_threat(self) -> bool:
        if self.malicious > 0 or self.suspicious > 0:
            return True
        verdict = (self.hybrid_verdict or "").lower()
        if verdict in {"malicious", "suspicious"}:
            return True
        if (self.metadefender_detected or 0) > 0:
            return True
        result = (self.metadefender_result or "").lower()
        if result in {"infected", "suspicious", "malicious"}:
            return True
        sandbox = (self.sandbox_verdict or "").lower()
        if sandbox in {"malicious", "suspicious"}:
            return True
        return False

    @property
    def threat_level(self) -> str:
        if self.malicious >= 20:
            return "CRITICAL"
        if self.malicious >= 5:
            return "HIGH"
        if self.malicious >= 1:
            return "MEDIUM"
        if self.suspicious > 0 or (self.hybrid_verdict or "").lower() == "suspicious":
            return "LOW"
        sandbox = (self.sandbox_verdict or "").lower()
        if sandbox == "malicious":
            return "MEDIUM"
        if sandbox == "suspicious":
            return "LOW"
        if self.is_threat:
            return "MEDIUM"
        return "CLEAN"

    def add_label(self, label: str | None) -> None:
        if not label:
            return
        cleaned = label.strip()
        if not cleaned or cleaned.lower() in {"none", "null", "n/a", "undetected"}:
            return
        if cleaned not in self.labels:
            self.labels.append(cleaned)
