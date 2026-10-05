"""Alternate VirusTotal and Hybrid Analysis, and stop when one engine is conclusive."""

from __future__ import annotations

from pathlib import Path

from aegis.config import AppConfig
from aegis.intel import FileIntel
from aegis.intel.hybrid import query_hybrid_analysis
from aegis.intel.metadefender import query_metadefender
from aegis.intel.outcome import (
    ENGINE_HYBRID,
    ENGINE_VIRUSTOTAL,
    CONCLUSIVE,
    STATUS_API_ERROR,
    STATUS_UNKNOWN_HASH,
    EngineResult,
)
from aegis.intel.transport import LookupInterrupted
from aegis.intel.virustotal import enrich_virustotal, query_virustotal
from aegis.rate_limit import RateLimiter

_ENGINE_LABEL = {
    ENGINE_VIRUSTOTAL: "VirusTotal",
    ENGINE_HYBRID: "Hybrid Analysis",
}


def known_clean_hash(intel: FileIntel) -> bool:
    """True when VirusTotal already has the file and that report is not a threat."""
    return bool(intel.vt_found) and not intel.vt_error and not _virustotal_threat(intel)


def engine_order(file_index: int, hybrid_enabled: bool) -> list[str]:
    """File 1 starts on VirusTotal, file 2 on Hybrid Analysis, then they alternate."""
    if not hybrid_enabled:
        return [ENGINE_VIRUSTOTAL]
    if file_index % 2 == 0:
        return [ENGINE_VIRUSTOTAL, ENGINE_HYBRID]
    return [ENGINE_HYBRID, ENGINE_VIRUSTOTAL]


def lookup_hash(
    sha256: str,
    config: AppConfig,
    limiter: RateLimiter,
    log,
    file_path: Path | None = None,
    file_index: int = 0,
) -> FileIntel:
    order = engine_order(file_index, config.query_hybrid())
    primary = order[0]
    log(f"  Primary engine: {_ENGINE_LABEL[primary]}")
    intel = FileIntel(sha256=sha256)
    statuses: dict[str, str] = {}

    for step, engine in enumerate(order):
        result = _query_engine(engine, intel, sha256, config, limiter, log)
        intel = result.intel
        statuses[engine] = result.status
        if result.conclusive and step == 0:
            _log_verdict(result, log)
            log(f"  {_ENGINE_LABEL[engine]}: conclusive verdict — moving to the next file.")
            return intel
        if result.status == STATUS_API_ERROR:
            if step == 0 and len(order) > 1:
                other = _ENGINE_LABEL[order[1]]
                log(f"  {_ENGINE_LABEL[engine]} API error — asking {other}.")
            continue
        if result.status == STATUS_UNKNOWN_HASH and step == 0 and len(order) > 1:
            other = _ENGINE_LABEL[order[1]]
            log(f"  {_ENGINE_LABEL[engine]}: hash not found — asking {other}.")
            continue
        if result.status == STATUS_UNKNOWN_HASH:
            log(f"  {_ENGINE_LABEL[engine]}: hash not found.")
        if result.conclusive:
            _log_verdict(result, log)
            break

    any_error = STATUS_API_ERROR in statuses.values() or bool(intel.service_error)
    if not _has_conclusive(statuses) and not intel.is_threat and config.query_metadefender():
        any_error = _query_metadefender(intel, config, limiter, log) or any_error

    if any_error:
        log("  Lookup incomplete — not uploading, and this file is not a clean result.")
        return intel

    if intel.is_threat:
        return intel

    if _eligible_for_upload(statuses, config) and file_path is not None and _sandbox_follow_up(config):
        intel.hash_unseen = True
        log(
            "  Hash not found on every configured engine. "
            "The file has not been seen — submitting it for a sandbox test."
        )
        try:
            intel = enrich_virustotal(
                intel,
                file_path,
                config.virustotal_api_key,
                limiter,
                log,
                auto_upload=True,
                sandbox=config.vt_sandbox,
                analysis_timeout=config.vt_analysis_timeout_seconds,
            )
        except LookupInterrupted as exc:
            intel.vt_error = str(exc)
            log(f"  VirusTotal upload: {exc}")
            log("  Lookup incomplete — not treating this file as clean.")
        else:
            _log_sandbox_follow_up(intel, log)
    return intel


def _query_engine(
    engine: str,
    intel: FileIntel,
    sha256: str,
    config: AppConfig,
    limiter: RateLimiter,
    log,
) -> EngineResult:
    if engine == ENGINE_VIRUSTOTAL:
        result = query_virustotal(sha256, config.virustotal_api_key, limiter, log)
        merged = _merge_virustotal(intel, result.intel)
        return EngineResult(result.engine, result.status, merged, result.detail)
    log("  Querying Hybrid Analysis v2...")
    return query_hybrid_analysis(intel, config.hybrid_analysis_api_key, limiter, log)


def _query_metadefender(intel: FileIntel, config: AppConfig, limiter: RateLimiter, log) -> bool:
    """Return True when MetaDefender itself fails. A hash miss is not a failure."""
    log("  Querying MetaDefender...")
    try:
        query_metadefender(intel, config.metadefender_api_key, limiter, log)
    except LookupInterrupted as exc:
        intel.metadefender_error = str(exc)
        log(f"  MetaDefender: {exc}")
        return True
    if intel.metadefender_error:
        log(f"  MetaDefender: {intel.metadefender_error}")
        return True
    if intel.metadefender_result and intel.metadefender_result != "not_found":
        det = intel.metadefender_detected
        tot = intel.metadefender_total
        counts = f" ({det}/{tot})" if det is not None and tot is not None else ""
        log(f"  MetaDefender: {intel.metadefender_result}{counts}")
    return False


def _sandbox_follow_up(config: AppConfig) -> bool:
    """An unseen hash is submitted when sandbox follow-up or automatic upload is on."""
    return config.vt_sandbox or config.vt_auto_upload


def _log_sandbox_follow_up(intel: FileIntel, log) -> None:
    verdict = (intel.sandbox_verdict or "").lower()
    if verdict in {"malicious", "suspicious"}:
        log(
            f"  Sandbox follow-up: {intel.sandbox_verdict}. "
            "The hash lookup had no record of this file."
        )
        return
    if intel.vt_error or intel.vt_upload_error:
        return
    log("  Sandbox follow-up did not indicate a virus. The hash lookup had no record of this file.")


def _eligible_for_upload(statuses: dict[str, str], config: AppConfig) -> bool:
    """Upload only after every configured hash engine reports a real hash miss."""
    if not statuses or STATUS_API_ERROR in statuses.values():
        return False
    if any(status in CONCLUSIVE for status in statuses.values()):
        return False
    if config.query_hybrid():
        return (
            statuses.get(ENGINE_VIRUSTOTAL) == STATUS_UNKNOWN_HASH
            and statuses.get(ENGINE_HYBRID) == STATUS_UNKNOWN_HASH
        )
    return statuses.get(ENGINE_VIRUSTOTAL) == STATUS_UNKNOWN_HASH


def _has_conclusive(statuses: dict[str, str]) -> bool:
    return any(status in CONCLUSIVE for status in statuses.values())


def _log_verdict(result: EngineResult, log) -> None:
    intel = result.intel
    if result.engine == ENGINE_VIRUSTOTAL and intel.vt_found:
        log(
            f"  VirusTotal: malicious={intel.malicious} suspicious={intel.suspicious} "
            f"undetected={intel.undetected} harmless={intel.harmless}"
        )
        return
    if result.engine == ENGINE_HYBRID and intel.hybrid_verdict:
        extra = f", score={intel.hybrid_score}" if intel.hybrid_score is not None else ""
        log(f"  Hybrid Analysis: {intel.hybrid_verdict}{extra}")


def _virustotal_threat(intel: FileIntel) -> bool:
    """Antivirus detections only. A sandbox tag on a zero-detection hash is not a threat."""
    return intel.malicious > 0 or intel.suspicious > 0


def _merge_virustotal(base: FileIntel, incoming: FileIntel) -> FileIntel:
    """Keep Hybrid and MetaDefender fields when the VirusTotal report replaces the record."""
    incoming.hybrid_verdict = base.hybrid_verdict
    incoming.hybrid_score = base.hybrid_score
    incoming.hybrid_family = base.hybrid_family
    incoming.hybrid_error = base.hybrid_error
    incoming.metadefender_detected = base.metadefender_detected
    incoming.metadefender_total = base.metadefender_total
    incoming.metadefender_result = base.metadefender_result
    incoming.metadefender_error = base.metadefender_error
    incoming.hash_unseen = incoming.hash_unseen or base.hash_unseen
    for label in base.labels:
        incoming.add_label(label)
    existing = {(item.vendor.lower(), item.label.lower()) for item in incoming.vendors}
    for vendor in base.vendors:
        key = (vendor.vendor.lower(), vendor.label.lower())
        if key not in existing:
            incoming.vendors.append(vendor)
    incoming.sha256 = incoming.sha256 or base.sha256
    return incoming
