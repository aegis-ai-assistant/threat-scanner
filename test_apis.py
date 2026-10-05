#!/usr/bin/env python3
"""Pre-compile API checks for Hybrid Analysis and Google Gemini 3.8 Flash.

Usage:
    python3 test_apis.py
    python3 test_apis.py /path/to/config.json

Never prints API key values. Exits 0 only if every configured test passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis.constants import GEMINI_PRIMARY_MODEL  # noqa: E402
from aegis.intel.gemini import _generate_once  # noqa: E402
from aegis.intel.hybrid import search_hash  # noqa: E402

# SHA-256 of an empty file — valid hash, typically absent from Hybrid Analysis.
DUMMY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _key(raw: dict, name: str) -> str:
    value = str(raw.get(name) or "").strip()
    if not value or value.upper().startswith("YOUR_"):
        return ""
    return value


def find_config(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Config not found: {path}")
        return path
    candidates = [
        ROOT / "config.json",
        Path.cwd() / "config.json",
        ROOT / "build_output" / "config.json",
        ROOT / "build_output_save" / "config.json",
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(
        "No config.json found. Copy config.example.json to config.json and add API keys."
    )


def report(ok: bool, name: str, detail: str) -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}: {detail}")
    return ok


def test_hybrid(api_key: str) -> bool:
    name = "Hybrid Analysis /api/v2/search/hash"
    if not api_key:
        return report(False, name, "hybrid_analysis_api_key is missing")
    try:
        response = search_hash(api_key, DUMMY_SHA256, timeout=45)
    except Exception as exc:
        return report(False, name, f"request failed ({exc})")

    status = response.status_code
    if status == 400:
        body = (response.text or "").replace("\n", " ")[:180]
        return report(False, name, f"HTTP 400 (hash still blank / validation failed): {body}")
    if status in {401, 403}:
        return report(False, name, f"HTTP {status} — API key rejected")
    if status == 200:
        try:
            payload = response.json()
        except ValueError:
            return report(False, name, "HTTP 200 but body was not JSON")
        kind = "list" if isinstance(payload, list) else type(payload).__name__
        count = len(payload) if isinstance(payload, list) else 1
        via = ""
        if isinstance(payload, dict) and payload.get("sha256") and not isinstance(payload, list):
            via = " (sample overview)"
        return report(True, name, f"HTTP 200{via} ({kind}, {count} record(s))")
    if status in {204, 404}:
        return report(True, name, f"HTTP {status} structured not-found")
    return report(False, name, f"HTTP {status}")


def test_gemini(api_key: str) -> bool:
    name = f"Google Gemini {GEMINI_PRIMARY_MODEL}"
    if not api_key:
        return report(False, name, "google_api_key is missing")
    try:
        status, text, error = _generate_once(
            api_key,
            GEMINI_PRIMARY_MODEL,
            "Reply with exactly the word PONG and nothing else.",
            "Health check. Reply with exactly PONG.",
            timeout=60,
        )
        if not text and status in {404, 503}:
            from aegis.constants import GEMINI_FALLBACK_MODEL

            status, text, error = _generate_once(
                api_key,
                GEMINI_FALLBACK_MODEL,
                "Reply with exactly the word PONG and nothing else.",
                "Health check. Reply with exactly PONG.",
                timeout=60,
            )
            name = f"Google Gemini {GEMINI_FALLBACK_MODEL} (fallback)"
    except Exception as exc:
        return report(False, name, f"request failed ({exc})")
    if text:
        preview = text.replace("\n", " ")[:80]
        return report(True, name, f"HTTP {status} generated: {preview!r}")
    if status == 404:
        return report(False, name, f"HTTP 404 model not found ({error})")
    if status == 503:
        return report(False, name, f"HTTP 503 model overloaded after retries ({error})")
    return report(False, name, error or f"HTTP {status}")


def main(argv: list[str]) -> int:
    try:
        path = find_config(argv[1] if len(argv) > 1 else None)
    except FileNotFoundError as exc:
        print(f"[FAIL] config: {exc}")
        return 1
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        print(f"[FAIL] config: {path} is not a JSON object")
        return 1
    print(f"Using config: {path}")
    print(f"Gemini primary model: {GEMINI_PRIMARY_MODEL}")
    print()
    results = [
        test_hybrid(_key(raw, "hybrid_analysis_api_key")),
        test_gemini(_key(raw, "google_api_key")),
    ]
    print()
    passed = sum(1 for item in results if item)
    print(f"{passed}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
