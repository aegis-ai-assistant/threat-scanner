"""Hybrid Analysis v2 hash search.

Their Symfony validator treats a JSON body (or a dict posted with the wrong
Content-Type) as a blank `hash` field and returns HTTP 400:

    validation_errors: field=hash / "This value should not be blank."

The documented call is POST form-urlencoded with user-agent: Falcon Sandbox.
"""

from __future__ import annotations

from urllib.parse import urlencode

import requests

from aegis.constants import HYBRID_OVERVIEW, HYBRID_SEARCH_HASH, HYBRID_USER_AGENT
from aegis.intel import FileIntel
from aegis.intel.transport import incomplete_response, network_failure
from aegis.rate_limit import RateLimiter

NOT_FOUND_MESSAGE = "[Hybrid Analysis: Hash not found in database]"


def query_hybrid_analysis(intel: FileIntel, api_key: str, limiter: RateLimiter, log) -> None:
    sha256_hash = (intel.sha256 or "").strip().lower()
    if not sha256_hash:
        log(f"  {NOT_FOUND_MESSAGE}")
        return

    limiter.wait(log)
    try:
        response = search_hash(api_key, sha256_hash)
    except requests.RequestException as exc:
        raise network_failure("Hybrid Analysis", exc) from exc

    if response.status_code == 429:
        log("  Hybrid Analysis rate-limited (HTTP 429). Waiting and retrying once...")
        limiter.wait(log)
        try:
            response = search_hash(api_key, sha256_hash)
        except requests.RequestException as exc:
            raise network_failure("Hybrid Analysis", exc) from exc

    if _is_not_found(response):
        log(f"  {NOT_FOUND_MESSAGE}")
        return
    if response.status_code >= 400:
        raise incomplete_response("Hybrid Analysis", response)

    try:
        payload = response.json()
    except ValueError:
        log(f"  {NOT_FOUND_MESSAGE}")
        return

    reports = _extract_reports(payload)
    if not reports:
        log(f"  {NOT_FOUND_MESSAGE}")
        return

    best = _pick_report(reports)
    if not best:
        log(f"  {NOT_FOUND_MESSAGE}")
        return

    intel.hybrid_verdict = str(best.get("verdict") or best.get("threat_level_human") or "unknown")
    score = best.get("threat_score")
    if score is not None:
        try:
            intel.hybrid_score = int(score)
        except (TypeError, ValueError):
            intel.hybrid_score = None
    family = best.get("vx_family")
    if family not in (None, ""):
        intel.hybrid_family = str(family)
        intel.add_label(str(family))
    for extra in best.get("type") or []:
        intel.add_label(str(extra))


def search_hash(api_key: str, sha256_hash: str, timeout: float = 45) -> requests.Response:
    """Look up a hash on Hybrid Analysis.

    POST /api/v2/search/hash with form-urlencoded `data={'hash': sha256}` as
    documented. CrowdStrike's validator currently rejects that body as a blank
    hash (HTTP 400). When that happens, fall back to GET /api/v2/overview/{hash}
    which returns the same sample record with the same API key.
    """
    sha256_hash = (sha256_hash or "").strip()
    session = requests.Session()
    session.headers.clear()
    headers = {
        "api-key": (api_key or "").strip(),
        "user-agent": HYBRID_USER_AGENT,
        "accept": "application/json",
    }
    body = urlencode({"hash": sha256_hash})
    response = session.post(
        HYBRID_SEARCH_HASH,
        headers={**headers, "content-type": "application/x-www-form-urlencoded"},
        data=body,
        timeout=timeout,
    )
    if response.status_code == 400:
        response = session.post(
            HYBRID_SEARCH_HASH,
            headers=headers,
            data={"hash": sha256_hash},
            timeout=timeout,
        )
    if response.status_code == 400:
        # Return the overview status itself. A 401 or 500 here used to be
        # discarded, and the earlier HTTP 400 was then treated as "not found".
        return session.get(
            f"{HYBRID_OVERVIEW}{sha256_hash}",
            headers=headers,
            timeout=timeout,
        )
    return response


def _is_not_found(response: requests.Response) -> bool:
    if response.status_code in {204, 404}:
        return True
    if response.status_code == 200 and not (response.content or b"").strip():
        return True
    return False


def _extract_reports(payload: object) -> list:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("result", "reports", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                return [value]
        if payload.get("sha256") or payload.get("verdict") or payload.get("threat_score") is not None:
            return [payload]
    return []


def _pick_report(reports: list) -> dict:
    scored: list[tuple[int, dict]] = []
    for item in reports:
        if not isinstance(item, dict):
            continue
        try:
            score = int(item.get("threat_score") or 0)
        except (TypeError, ValueError):
            score = 0
        scored.append((score, item))
    if not scored:
        return {}
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return scored[0][1]
