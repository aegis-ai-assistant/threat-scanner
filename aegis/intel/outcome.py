"""Typed hash-lookup results shared by VirusTotal and Hybrid Analysis."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.intel import FileIntel

ENGINE_VIRUSTOTAL = "virustotal"
ENGINE_HYBRID = "hybrid"

VERDICT_CLEAN = "clean"
VERDICT_MALICIOUS = "malicious"
STATUS_UNKNOWN_HASH = "unknown_hash"
STATUS_API_ERROR = "api_error"

CONCLUSIVE = frozenset({VERDICT_CLEAN, VERDICT_MALICIOUS})


@dataclass
class EngineResult:
    engine: str
    status: str
    intel: FileIntel
    detail: str = ""

    @property
    def conclusive(self) -> bool:
        return self.status in CONCLUSIVE


def classify_virustotal(intel: FileIntel) -> str:
    """Classify one VirusTotal file report. Sandbox categories on that report count."""
    if intel.vt_error:
        return STATUS_API_ERROR
    if not intel.vt_found:
        return STATUS_UNKNOWN_HASH
    if intel.malicious > 0 or intel.suspicious > 0:
        return VERDICT_MALICIOUS
    sandbox = (intel.sandbox_verdict or "").lower()
    if sandbox in {"malicious", "suspicious"}:
        return VERDICT_MALICIOUS
    return VERDICT_CLEAN


def classify_hybrid(intel: FileIntel) -> str:
    """Classify one Hybrid Analysis response. A missing record is an unknown hash."""
    if intel.hybrid_error:
        return STATUS_API_ERROR
    verdict = (intel.hybrid_verdict or "").strip().lower()
    if not verdict:
        return STATUS_UNKNOWN_HASH
    if verdict in {"malicious", "suspicious"} or "malicious" in verdict:
        return VERDICT_MALICIOUS
    return VERDICT_CLEAN
