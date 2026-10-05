"""OPSWAT MetaDefender Cloud hash lookup."""

from __future__ import annotations

import requests

from aegis.constants import METADEFENDER_HASH, USER_AGENT
from aegis.intel import FileIntel, VendorFinding
from aegis.intel.transport import incomplete_response, network_failure
from aegis.rate_limit import RateLimiter


def query_metadefender(intel: FileIntel, api_key: str, limiter: RateLimiter, log) -> None:
    limiter.wait(log)
    url = f"{METADEFENDER_HASH}{intel.sha256}"
    headers = {"apikey": api_key, "User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=45)
    except requests.RequestException as exc:
        raise network_failure("MetaDefender", exc) from exc

    if response.status_code == 404:
        intel.metadefender_result = "not_found"
        return
    if response.status_code == 429:
        log("  MetaDefender rate-limited (HTTP 429). Waiting and retrying once...")
        limiter.wait(log)
        try:
            response = requests.get(url, headers=headers, timeout=45)
        except requests.RequestException as exc:
            raise network_failure("MetaDefender", exc) from exc
    if response.status_code >= 400:
        raise incomplete_response("MetaDefender", response)

    try:
        payload = response.json()
    except ValueError:
        intel.metadefender_error = "non-JSON response"
        return

    scan = payload.get("scan_results") or payload
    intel.metadefender_result = str(scan.get("scan_all_result_a") or scan.get("scan_all_result") or "unknown")
    detected = scan.get("total_detected_avs")
    total = scan.get("total_avs")
    try:
        intel.metadefender_detected = int(detected) if detected is not None else None
    except (TypeError, ValueError):
        intel.metadefender_detected = None
    try:
        intel.metadefender_total = int(total) if total is not None else None
    except (TypeError, ValueError):
        intel.metadefender_total = None

    details = scan.get("scan_details") or {}
    existing = {(item.vendor.lower(), item.label.lower()) for item in intel.vendors}
    for vendor, detail in details.items():
        if not isinstance(detail, dict):
            continue
        threat = str(detail.get("threat_found") or "").strip()
        result_i = detail.get("scan_result_i")
        if not threat and result_i not in (1, 2):
            continue
        category = "malicious" if result_i == 1 else "suspicious"
        label = threat or category
        key = (str(vendor).lower(), label.lower())
        if key in existing:
            continue
        intel.vendors.append(VendorFinding(vendor=str(vendor), category=category, label=label))
        intel.add_label(label)
        existing.add(key)
