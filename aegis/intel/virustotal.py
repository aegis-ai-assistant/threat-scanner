"""VirusTotal v3 hash lookup, file upload, and sandbox behaviour."""

from __future__ import annotations

import time
from pathlib import Path

import requests

from aegis.constants import (
    PRIORITY_VENDORS,
    USER_AGENT,
    VT_API_ANALYSES,
    VT_API_FILE,
    VT_MAX_UPLOAD_BYTES,
)
from aegis.intel import FileIntel, VendorFinding
from aegis.intel.transport import LookupInterrupted, incomplete_response, network_failure
from aegis.rate_limit import RateLimiter

_VT_HEADERS_ACCEPT = {"User-Agent": USER_AGENT, "Accept": "application/json"}
_ANALYSIS_POLL_SECONDS = 2
_SANDBOX_RANK = {"malicious": 2, "suspicious": 1}


def _headers(api_key: str) -> dict[str, str]:
    return {"x-apikey": api_key, **_VT_HEADERS_ACCEPT}


def query_virustotal(sha256: str, api_key: str, limiter: RateLimiter, log) -> FileIntel:
    limiter.wait(log)
    response = _get_file(sha256, api_key)

    if response.status_code == 429:
        log("  VirusTotal rate-limited (HTTP 429). Waiting and retrying once...")
        limiter.wait(log)
        response = _get_file(sha256, api_key)

    if response.status_code == 404:
        return _empty(sha256, found=False)
    if response.status_code in {401, 403}:
        intel = _empty(sha256, found=False)
        intel.vt_error = f"VirusTotal authentication failed (HTTP {response.status_code})"
        return intel
    if response.status_code >= 400:
        raise incomplete_response("VirusTotal", response)

    try:
        payload = response.json()
    except ValueError as exc:
        raise LookupInterrupted("VirusTotal returned non-JSON.") from exc
    try:
        return parse_virustotal(sha256, payload)
    except (TypeError, ValueError) as exc:
        raise LookupInterrupted(f"VirusTotal returned an unexpected report: {exc}") from exc


def enrich_virustotal(
    intel: FileIntel,
    file_path: Path | None,
    api_key: str,
    limiter: RateLimiter,
    log,
    *,
    auto_upload: bool,
    sandbox: bool,
    analysis_timeout: float,
) -> FileIntel:
    """If the hash is unknown, upload the file and optionally pull sandbox data."""
    if intel.vt_error:
        log(f"  VirusTotal upload skipped: {intel.vt_error}")
        return intel
    if not intel.vt_found and auto_upload and file_path is not None:
        intel = _upload_and_refresh(intel, file_path, api_key, limiter, log, analysis_timeout)
    if intel.vt_found and sandbox:
        _attach_sandbox(intel, api_key, limiter, log)
    return intel


def _get_file(sha256: str, api_key: str) -> requests.Response:
    try:
        return requests.get(f"{VT_API_FILE}{sha256}", headers=_headers(api_key), timeout=45)
    except requests.RequestException as exc:
        raise network_failure("VirusTotal", exc) from exc


def _empty(sha256: str, found: bool) -> FileIntel:
    return FileIntel(sha256=sha256, vt_found=found)


def _upload_and_refresh(
    intel: FileIntel,
    file_path: Path,
    api_key: str,
    limiter: RateLimiter,
    log,
    analysis_timeout: float,
) -> FileIntel:
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        intel.vt_upload_error = f"cannot stat file: {exc}"
        log(f"  VirusTotal upload skipped: {intel.vt_upload_error}")
        return intel
    if size > VT_MAX_UPLOAD_BYTES:
        intel.vt_upload_error = f"file is {size} bytes; public VT upload limit is {VT_MAX_UPLOAD_BYTES}"
        log(f"  VirusTotal upload skipped: {intel.vt_upload_error}")
        return intel

    log("  VirusTotal: hash unknown — uploading sample for analysis...")
    limiter.wait(log)
    try:
        with file_path.open("rb") as handle:
            response = requests.post(
                VT_API_FILE.rstrip("/"),
                headers=_headers(api_key),
                files={"file": (file_path.name, handle)},
                timeout=120,
            )
    except requests.RequestException as exc:
        raise network_failure("VirusTotal upload", exc) from exc

    if response.status_code == 409:
        log("  VirusTotal: sample already known; refreshing hash report...")
        intel.vt_uploaded = True
        return _refresh_file_report(intel, api_key, limiter, log)

    if response.status_code == 429:
        log("  VirusTotal upload rate-limited (HTTP 429). Waiting and retrying once...")
        limiter.wait(log)
        try:
            with file_path.open("rb") as handle:
                response = requests.post(
                    VT_API_FILE.rstrip("/"),
                    headers=_headers(api_key),
                    files={"file": (file_path.name, handle)},
                    timeout=120,
                )
        except requests.RequestException as exc:
            raise network_failure("VirusTotal upload", exc) from exc

    if response.status_code >= 400:
        raise incomplete_response("VirusTotal upload", response)

    try:
        payload = response.json()
    except ValueError as exc:
        raise LookupInterrupted("VirusTotal upload returned non-JSON.") from exc

    analysis_id = ((payload.get("data") or {}).get("id")) or ""
    intel.vt_uploaded = True
    if analysis_id:
        log(f"  VirusTotal: submitted analysis {analysis_id}")
        _wait_for_analysis(analysis_id, api_key, limiter, log, analysis_timeout)
    return _refresh_file_report(intel, api_key, limiter, log)


def _wait_for_analysis(
    analysis_id: str,
    api_key: str,
    limiter: RateLimiter,
    log,
    timeout: float,
) -> None:
    if timeout <= 0:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        limiter.wait(log)
        try:
            response = requests.get(
                f"{VT_API_ANALYSES}{analysis_id}",
                headers=_headers(api_key),
                timeout=45,
            )
        except requests.RequestException as exc:
            raise network_failure("VirusTotal analysis", exc) from exc
        if response.status_code == 404:
            return
        if response.status_code >= 400:
            raise incomplete_response("VirusTotal analysis", response)
        try:
            status = ((response.json().get("data") or {}).get("attributes") or {}).get("status")
        except ValueError:
            return
        log(f"  VirusTotal sandbox/analysis status: {status or 'unknown'}")
        if status == "completed":
            return
        if status not in {"queued", "in-progress", None}:
            return
        # The free-tier limiter already waits before the next request. This pause
        # still applies when that limiter is off, so the poll cannot spin.
        time.sleep(_ANALYSIS_POLL_SECONDS)


def _refresh_file_report(intel: FileIntel, api_key: str, limiter: RateLimiter, log) -> FileIntel:
    limiter.wait(log)
    refreshed = query_virustotal(intel.sha256, api_key, RateLimiter(0, enabled=False), log)
    refreshed.vt_uploaded = intel.vt_uploaded
    refreshed.vt_upload_error = intel.vt_upload_error
    if refreshed.vt_found:
        log(
            f"  VirusTotal (after upload): malicious={refreshed.malicious} "
            f"suspicious={refreshed.suspicious} undetected={refreshed.undetected}"
        )
    else:
        log("  VirusTotal: upload accepted, hash report not ready yet.")
    return refreshed


def _attach_sandbox(intel: FileIntel, api_key: str, limiter: RateLimiter, log) -> None:
    limiter.wait(log)
    url = f"{VT_API_FILE}{intel.sha256}/behaviour_summary"
    try:
        response = requests.get(url, headers=_headers(api_key), timeout=45)
    except requests.RequestException as exc:
        raise network_failure("VirusTotal sandbox", exc) from exc
    if response.status_code == 404:
        log("  VirusTotal sandbox: no behaviour report yet.")
        return
    if response.status_code >= 400:
        raise incomplete_response("VirusTotal sandbox", response)
    try:
        payload = response.json()
    except ValueError:
        return
    _parse_behaviour_summary(intel, payload)
    if intel.sandbox_verdict or intel.sandbox_behaviors:
        extra = f" ({intel.sandbox_verdict})" if intel.sandbox_verdict else ""
        log(f"  VirusTotal sandbox{extra}: {len(intel.sandbox_behaviors)} highlighted behaviours")


def _parse_behaviour_summary(intel: FileIntel, payload: dict) -> None:
    data = payload.get("data") or payload
    attributes = data.get("attributes") if isinstance(data, dict) else {}
    if not isinstance(attributes, dict):
        attributes = data if isinstance(data, dict) else {}

    tags = attributes.get("tags") or []
    if isinstance(tags, list):
        for tag in tags[:12]:
            text = str(tag).strip()
            if text and text not in intel.sandbox_tags:
                intel.sandbox_tags.append(text)
                intel.add_label(text)

    severity = attributes.get("threat_severity_level") or attributes.get("threat_severity")
    candidate = ""
    if isinstance(severity, dict):
        candidate = str(severity.get("level") or severity.get("value") or "")
    elif severity:
        candidate = str(severity)
    families = attributes.get("malware_families") or attributes.get("families") or []
    family = ""
    if isinstance(families, list) and families:
        first = families[0]
        if isinstance(first, dict):
            family = str(first.get("value") or first.get("name") or "")
        else:
            family = str(first)
    _apply_sandbox(intel, candidate, family)

    for technique in (attributes.get("mitre_attack_techniques") or [])[:8]:
        if isinstance(technique, dict):
            tid = technique.get("id") or technique.get("technique_id") or ""
            name = technique.get("signature_description") or technique.get("name") or ""
            label = " ".join(part for part in (str(tid), str(name)) if part).strip()
        else:
            label = str(technique)
        if label:
            intel.sandbox_behaviors.append(f"MITRE: {label}")

    for key, prefix in (
        ("files_dropped", "Dropped"),
        ("files_written", "Wrote"),
        ("processes_created", "Spawned"),
        ("command_executions", "Command"),
        ("dns_lookups", "DNS"),
        ("http_conversations", "HTTP"),
        ("ip_traffic", "IP"),
        ("calls_highlighted", "Call"),
    ):
        items = attributes.get(key) or []
        if not isinstance(items, list):
            continue
        for item in items[:4]:
            text = _brief_behavior(item)
            if text:
                intel.sandbox_behaviors.append(f"{prefix}: {text}")

    intel.sandbox_behaviors = intel.sandbox_behaviors[:16]


def _brief_behavior(item: object) -> str:
    if isinstance(item, str):
        return item[:180]
    if not isinstance(item, dict):
        return str(item)[:180]
    for key in ("path", "name", "hostname", "url", "command", "process_name", "destination_ip", "value"):
        value = item.get(key)
        if value:
            return str(value)[:180]
    return ""


def parse_virustotal(sha256: str, payload: dict) -> FileIntel:
    intel = FileIntel(sha256=sha256, vt_found=True)
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    intel.malicious = int(stats.get("malicious") or 0)
    intel.suspicious = int(stats.get("suspicious") or 0)
    intel.undetected = int(stats.get("undetected") or 0)
    intel.harmless = int(stats.get("harmless") or 0)
    intel.engine_total = (
        intel.malicious
        + intel.suspicious
        + intel.undetected
        + intel.harmless
        + int(stats.get("timeout") or 0)
        + int(stats.get("failure") or 0)
        + int(stats.get("type-unsupported") or 0)
    )

    classification = attributes.get("popular_threat_classification") or {}
    intel.add_label(classification.get("suggested_threat_label"))
    for item in classification.get("popular_threat_name") or []:
        if isinstance(item, dict):
            intel.add_label(item.get("value"))
        elif isinstance(item, str):
            intel.add_label(item)
    for item in classification.get("popular_threat_category") or []:
        if isinstance(item, dict):
            intel.add_label(item.get("value"))

    results = attributes.get("last_analysis_results") or {}
    flagged: list[VendorFinding] = []
    for engine, detail in results.items():
        if not isinstance(detail, dict):
            continue
        category = str(detail.get("category") or "undetected").lower()
        if category not in {"malicious", "suspicious"}:
            continue
        label = str(detail.get("result") or category).strip()
        flagged.append(VendorFinding(vendor=str(engine), category=category, label=label))
        intel.add_label(label)

    flagged.sort(key=lambda item: (_vendor_rank(item.vendor), item.vendor.lower()))
    intel.vendors = flagged

    sandbox_verdicts = attributes.get("sandbox_verdicts") or {}
    if isinstance(sandbox_verdicts, dict):
        for name, detail in sandbox_verdicts.items():
            if not isinstance(detail, dict):
                continue
            category = str(detail.get("category") or "")
            families = detail.get("malware_classification") or detail.get("malware_names") or []
            family = str(families[0]) if isinstance(families, list) and families else ""
            _apply_sandbox(intel, category, family)
            if category:
                intel.sandbox_behaviors.append(f"{name}: {category}")
    return intel


def _apply_sandbox(intel: FileIntel, category: str | None, family: str | None = None) -> None:
    """Keep the strongest sandbox category. Malicious beats suspicious and anything else."""
    cand = (category or "").strip()
    current = (intel.sandbox_verdict or "").strip()
    cand_rank = _SANDBOX_RANK.get(cand.lower(), 0)
    current_rank = _SANDBOX_RANK.get(current.lower(), 0)
    upgraded = bool(cand) and cand_rank > current_rank
    if cand and (not current or upgraded):
        intel.sandbox_verdict = cand
    chosen_family = (family or "").strip()
    if chosen_family and (upgraded or not intel.sandbox_family):
        intel.sandbox_family = chosen_family
        intel.add_label(chosen_family)


def _vendor_rank(name: str) -> int:
    key = name.lower()
    for index, preferred in enumerate(PRIORITY_VENDORS):
        if preferred.lower() == key or preferred.lower() in key or key in preferred.lower():
            return index
    return 100
