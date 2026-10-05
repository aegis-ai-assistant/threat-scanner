"""Query VirusTotal first. A known clean hash stops there; other services run only when needed."""

from __future__ import annotations

from pathlib import Path

from aegis.config import AppConfig
from aegis.intel import FileIntel
from aegis.intel.hybrid import query_hybrid_analysis
from aegis.intel.metadefender import query_metadefender
from aegis.intel.virustotal import enrich_virustotal, query_virustotal
from aegis.rate_limit import RateLimiter


def known_clean_hash(intel: FileIntel) -> bool:
    """True when the VirusTotal file report already exists and is not a threat.

    That report is the first hash lookup. Sandbox, Hybrid Analysis, and
    MetaDefender are separate calls and are not consulted for this decision.
    """
    return bool(intel.vt_found) and not intel.is_threat


def lookup_hash(
    sha256: str,
    config: AppConfig,
    limiter: RateLimiter,
    log,
    file_path: Path | None = None,
) -> FileIntel:
    log("  Querying VirusTotal v3...")
    intel = query_virustotal(sha256, config.virustotal_api_key, limiter, log)

    if known_clean_hash(intel):
        log(
            f"  VirusTotal: malicious={intel.malicious} suspicious={intel.suspicious} "
            f"undetected={intel.undetected} harmless={intel.harmless}"
        )
        log("  VirusTotal: hash is known and clean — moving to the next file.")
        return intel

    if intel.vt_found:
        log(
            f"  VirusTotal: malicious={intel.malicious} suspicious={intel.suspicious} "
            f"undetected={intel.undetected} harmless={intel.harmless}"
        )
    elif intel.vt_error:
        log(f"  VirusTotal: {intel.vt_error}")
    else:
        log("  VirusTotal: hash not found (no prior analysis).")

    intel = enrich_virustotal(
        intel,
        file_path,
        config.virustotal_api_key,
        limiter,
        log,
        auto_upload=config.vt_auto_upload,
        sandbox=config.vt_sandbox,
        analysis_timeout=config.vt_analysis_timeout_seconds,
    )

    if config.query_hybrid():
        log("  Querying Hybrid Analysis v2...")
        query_hybrid_analysis(intel, config.hybrid_analysis_api_key, limiter, log)
        if intel.hybrid_error:
            pass
        elif intel.hybrid_verdict:
            extra = f", score={intel.hybrid_score}" if intel.hybrid_score is not None else ""
            log(f"  Hybrid Analysis: {intel.hybrid_verdict}{extra}")

    if config.query_metadefender():
        log("  Querying MetaDefender...")
        query_metadefender(intel, config.metadefender_api_key, limiter, log)
        if intel.metadefender_result:
            det = intel.metadefender_detected
            tot = intel.metadefender_total
            counts = f" ({det}/{tot})" if det is not None and tot is not None else ""
            log(f"  MetaDefender: {intel.metadefender_result}{counts}")

    return intel
