"""Query VirusTotal first (upload if unknown), then secondary engines, then optional Gemini."""

from __future__ import annotations

from pathlib import Path

from aegis.config import AppConfig
from aegis.intel import FileIntel
from aegis.intel.hybrid import query_hybrid_analysis
from aegis.intel.metadefender import query_metadefender
from aegis.intel.virustotal import enrich_virustotal, query_virustotal
from aegis.rate_limit import RateLimiter


def lookup_hash(
    sha256: str,
    config: AppConfig,
    limiter: RateLimiter,
    log,
    file_path: Path | None = None,
) -> FileIntel:
    log("  Querying VirusTotal v3...")
    try:
        intel = query_virustotal(sha256, config.virustotal_api_key, limiter, log)
    except RuntimeError as exc:
        intel = FileIntel(sha256=sha256, vt_found=False, vt_error=str(exc))
        log(f"  VirusTotal error: {exc}")

    if intel.vt_found:
        log(
            f"  VirusTotal: malicious={intel.malicious} suspicious={intel.suspicious} "
            f"undetected={intel.undetected} harmless={intel.harmless}"
        )
    elif not intel.vt_error:
        log("  VirusTotal: hash not found (no prior analysis).")

    try:
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
    except RuntimeError as exc:
        log(f"  VirusTotal enrich error: {exc}")

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
