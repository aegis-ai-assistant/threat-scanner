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
    hash_unseen: bool = False
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
        if self.hash_unseen and sandbox in {"malicious", "suspicious"}:
            return True
        return False

    @property
    def service_error(self) -> str | None:
        """API failures for this file. A hash miss is not an error."""
        parts = [
            text
            for text in (self.vt_error, self.hybrid_error, self.metadefender_error)
            if text
        ]
        return "; ".join(parts) or None

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
        if self.hash_unseen and sandbox == "malicious":
            return "MEDIUM"
        if self.hash_unseen and sandbox == "suspicious":
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

    @property
    def ai_summary_ready(self) -> bool:
        return any(
            (value or "").strip()
            for value in (
                self.ai_synthesis,
                self.ai_plain_what,
                self.ai_plain_why,
                self.ai_plain_bottom,
            )
        )

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "undetected": self.undetected,
            "harmless": self.harmless,
            "engine_total": self.engine_total,
            "labels": list(self.labels),
            "vendors": [
                {"vendor": item.vendor, "category": item.category, "label": item.label}
                for item in self.vendors
            ],
            "vt_found": self.vt_found,
            "vt_error": self.vt_error,
            "hybrid_verdict": self.hybrid_verdict,
            "hybrid_score": self.hybrid_score,
            "hybrid_family": self.hybrid_family,
            "hybrid_error": self.hybrid_error,
            "metadefender_detected": self.metadefender_detected,
            "metadefender_total": self.metadefender_total,
            "metadefender_result": self.metadefender_result,
            "metadefender_error": self.metadefender_error,
            "vt_uploaded": self.vt_uploaded,
            "vt_upload_error": self.vt_upload_error,
            "hash_unseen": self.hash_unseen,
            "sandbox_verdict": self.sandbox_verdict,
            "sandbox_family": self.sandbox_family,
            "sandbox_tags": list(self.sandbox_tags),
            "sandbox_behaviors": list(self.sandbox_behaviors),
            "ai_synthesis": self.ai_synthesis,
            "ai_plain_what": self.ai_plain_what,
            "ai_plain_why": self.ai_plain_why,
            "ai_plain_bottom": self.ai_plain_bottom,
            "ai_error": self.ai_error,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> FileIntel:
        intel = cls(sha256=str(raw.get("sha256") or ""))
        for name in ("malicious", "suspicious", "undetected", "harmless", "engine_total"):
            try:
                setattr(intel, name, int(raw.get(name) or 0))
            except (TypeError, ValueError):
                setattr(intel, name, 0)
        intel.labels = [str(item) for item in raw.get("labels") or [] if str(item).strip()]
        vendors: list[VendorFinding] = []
        for item in raw.get("vendors") or []:
            if not isinstance(item, dict):
                continue
            vendors.append(
                VendorFinding(
                    vendor=str(item.get("vendor") or ""),
                    category=str(item.get("category") or ""),
                    label=str(item.get("label") or ""),
                )
            )
        intel.vendors = vendors
        intel.vt_found = bool(raw.get("vt_found"))
        intel.vt_error = _optional_str(raw.get("vt_error"))
        intel.hybrid_verdict = _optional_str(raw.get("hybrid_verdict"))
        intel.hybrid_family = _optional_str(raw.get("hybrid_family"))
        intel.hybrid_error = _optional_str(raw.get("hybrid_error"))
        score = raw.get("hybrid_score")
        try:
            intel.hybrid_score = int(score) if score is not None else None
        except (TypeError, ValueError):
            intel.hybrid_score = None
        for name in ("metadefender_detected", "metadefender_total"):
            value = raw.get(name)
            try:
                setattr(intel, name, int(value) if value is not None else None)
            except (TypeError, ValueError):
                setattr(intel, name, None)
        intel.metadefender_result = _optional_str(raw.get("metadefender_result"))
        intel.metadefender_error = _optional_str(raw.get("metadefender_error"))
        intel.vt_uploaded = bool(raw.get("vt_uploaded"))
        intel.vt_upload_error = _optional_str(raw.get("vt_upload_error"))
        intel.hash_unseen = bool(raw.get("hash_unseen"))
        intel.sandbox_verdict = _optional_str(raw.get("sandbox_verdict"))
        intel.sandbox_family = _optional_str(raw.get("sandbox_family"))
        intel.sandbox_tags = [str(item) for item in raw.get("sandbox_tags") or []]
        intel.sandbox_behaviors = [str(item) for item in raw.get("sandbox_behaviors") or []]
        intel.ai_synthesis = _optional_str(raw.get("ai_synthesis"))
        intel.ai_plain_what = _optional_str(raw.get("ai_plain_what"))
        intel.ai_plain_why = _optional_str(raw.get("ai_plain_why"))
        intel.ai_plain_bottom = _optional_str(raw.get("ai_plain_bottom"))
        intel.ai_error = _optional_str(raw.get("ai_error"))
        return intel


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
