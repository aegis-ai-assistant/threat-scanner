"""Google Gemini 3.x Flash synthesis of multi-engine threat findings."""

from __future__ import annotations

import json
import time

import requests

from aegis.constants import GEMINI_FALLBACK_MODEL, GEMINI_GENERATE, GEMINI_PRIMARY_MODEL
from aegis.intel import FileIntel

_SYSTEM_PROMPT = """You are a defensive malware analyst. Use only the supplied evidence.
Do not provide exploit, cracking, piracy, or DRM-bypass instructions. You may say a file
looks like a crack or DRM bypass when the evidence supports that.

Return ONLY valid JSON with this exact shape:
{
  "technical_summary": "markdown string",
  "plain_english": {
    "what": "one sentence",
    "why_flagged": "one sentence",
    "bottom_line": "one sentence"
  }
}

Section mapping:
- technical_summary = Technical Telemetry Summary for advanced users. Include AV flags,
  family/role, MITRE ATT&CK techniques if present, sandbox/heuristics, and defensive follow-up.
  If evidence is thin, say so. Keep under 180 words.
- plain_english = In Plain English for gamers. Zero jargon. Exactly three sentences:
  1. what: What is this file?
  2. why_flagged: Why did the antivirus flag it?
  3. bottom_line: Bottom Line Safety Call (stealers/trojans vs likely false positive, plus caution).
"""


def synthesize_threats(
    threats: list,
    api_key: str,
    model: str,
    log,
    on_record=None,
) -> None:
    if not threats:
        return
    resolved = model or GEMINI_PRIMARY_MODEL
    log(f"Synthesizing {len(threats)} threat note(s) with Google AI ({resolved})...")
    for record in threats:
        record.intel.ai_error = None
        try:
            raw = generate_text(
                api_key,
                _SYSTEM_PROMPT,
                _evidence_block(record),
                log=log,
                model=resolved,
            )
            if raw:
                apply_synthesis(record.intel, raw)
                if record.intel.ai_summary_ready:
                    record.intel.ai_error = None
                    log(f"  Google AI synthesis ready for {record.payload.display_name}")
                elif not record.intel.ai_error:
                    record.intel.ai_error = "model response did not include a summary"
            elif not record.intel.ai_error:
                record.intel.ai_error = "empty model response"
        except Exception as exc:
            record.intel.ai_error = str(exc)
            log(f"  Google AI error for {record.payload.display_name}: {exc}")
        if on_record is not None:
            on_record(record)


def apply_synthesis(intel: FileIntel, raw: str) -> None:
    technical, what, why, bottom = parse_synthesis(raw)
    intel.ai_synthesis = technical or raw.strip()
    intel.ai_plain_what = what
    intel.ai_plain_why = why
    intel.ai_plain_bottom = bottom


def parse_synthesis(raw: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Split a Gemini JSON or markdown reply into technical + three plain-English sentences."""
    text = (raw or "").strip()
    if not text:
        return None, None, None, None
    payload = _load_json_blob(text)
    if isinstance(payload, dict):
        technical = _as_text(payload.get("technical_summary") or payload.get("technical"))
        plain = payload.get("plain_english") or payload.get("in_plain_english") or {}
        if isinstance(plain, dict):
            return (
                technical,
                _as_text(plain.get("what") or plain.get("what_is_this_file")),
                _as_text(plain.get("why_flagged") or plain.get("why")),
                _as_text(plain.get("bottom_line") or plain.get("bottom")),
            )
        if isinstance(plain, str) and plain.strip():
            return technical, None, None, plain.strip()
    return _parse_markdown_sections(text)


def _as_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _load_json_blob(text: str) -> object | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        return json.loads(stripped)
    except ValueError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(stripped[start : end + 1])
            except ValueError:
                return None
    return None


def _parse_markdown_sections(text: str) -> tuple[str | None, str | None, str | None, str | None]:
    lowered = text.lower()
    split_at = -1
    for marker in ("in plain english", "gamers' summary", "section 2", "plain english"):
        idx = lowered.find(marker)
        if idx >= 0:
            split_at = idx
            break
    if split_at < 0:
        return text.strip(), None, None, None
    technical = text[:split_at].strip()
    rest = text[split_at:].strip()
    sentences = [part.strip() for part in rest.replace("\n", " ").split(".") if part.strip()]
    what = f"{sentences[0]}." if sentences else rest
    why = f"{sentences[1]}." if len(sentences) > 1 else None
    bottom = f"{sentences[2]}." if len(sentences) > 2 else None
    if len(sentences) > 3 and bottom:
        bottom = bottom + " " + ". ".join(sentences[3:]) + ("." if not sentences[-1].endswith(".") else "")
    return technical or None, what, why, bottom


def generate_text(
    api_key: str,
    system_prompt: str,
    user_text: str,
    *,
    log=None,
    model: str | None = None,
    timeout: float = 60,
) -> str | None:
    """Call Gemini generateContent. Primary 3.8-flash, fallback 3.7-flash.

    Paid Gemini calls are not held to the free-tier pause used by the hash engines.
    """
    models = _model_chain(model)
    last_error = None
    for index, candidate in enumerate(models):
        status, text, error = _generate_once(api_key, candidate, system_prompt, user_text, timeout)
        if text:
            return text
        last_error = error or f"HTTP {status}"
        if status in {404, 503} and index < len(models) - 1:
            if log:
                reason = "not found" if status == 404 else "overloaded"
                log(f"  Google AI model {candidate} {reason}; retrying {models[index + 1]}...")
            continue
        break
    if log and last_error:
        log(f"  Google AI error: {last_error}")
    return None


def _model_chain(model: str | None) -> list[str]:
    primary = model or GEMINI_PRIMARY_MODEL
    chain = [primary]
    for extra in (GEMINI_PRIMARY_MODEL, GEMINI_FALLBACK_MODEL):
        if extra not in chain:
            chain.append(extra)
    return chain


def _generate_once(
    api_key: str,
    model: str,
    system_prompt: str,
    user_text: str,
    timeout: float,
) -> tuple[int, str | None, str | None]:
    url = GEMINI_GENERATE.format(model=model)
    base = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
    }
    payloads = [
        {
            **base,
            "generationConfig": {
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json",
                "thinkingConfig": {"thinkingLevel": "low"},
            },
        },
        {
            **base,
            "generationConfig": {
                "maxOutputTokens": 2048,
                "responseMimeType": "application/json",
            },
        },
        {**base, "generationConfig": {"maxOutputTokens": 2048}},
    ]
    last_status = 0
    last_error = None
    for payload in payloads:
        for attempt in range(3):
            try:
                response = requests.post(
                    url,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "x-goog-api-key": api_key,
                    },
                    json=payload,
                    timeout=timeout,
                )
            except requests.RequestException as exc:
                return 0, None, str(exc)
            last_status = response.status_code
            if response.status_code == 503 and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            break
        if response.status_code == 400 and payload is not payloads[-1]:
            continue
        if response.status_code >= 400:
            snippet = (response.text or "")[:240].replace("\n", " ")
            return response.status_code, None, f"HTTP {response.status_code}: {snippet}"
        try:
            body = response.json()
        except ValueError:
            return response.status_code, None, "non-JSON response"
        text = _extract_text(body)
        if not text:
            return response.status_code, None, "empty model response"
        return response.status_code, text.strip(), None
    return last_status, None, last_error


def _evidence_block(record) -> str:
    intel: FileIntel = record.intel
    lines = [
        f"File: {record.payload.display_name}",
        f"Internal path: {record.payload.internal_path}",
        f"SHA-256: {intel.sha256}",
        f"Threat level: {intel.threat_level}",
        f"VirusTotal: malicious={intel.malicious} suspicious={intel.suspicious} "
        f"undetected={intel.undetected} harmless={intel.harmless} engines={intel.engine_total}",
        f"Labels: {', '.join(intel.labels[:12]) or 'n/a'}",
    ]
    if intel.hash_unseen:
        lines.append(
            "Hash lookup: no record of this file. It had not been seen, so it was submitted for a sandbox test."
        )
    elif intel.vt_uploaded:
        lines.append("VirusTotal: sample was auto-uploaded because the hash was unknown.")
    if intel.hybrid_verdict:
        extra = f", score={intel.hybrid_score}" if intel.hybrid_score is not None else ""
        family = f", family={intel.hybrid_family}" if intel.hybrid_family else ""
        lines.append(f"Hybrid Analysis: {intel.hybrid_verdict}{extra}{family}")
    if intel.metadefender_result:
        lines.append(
            f"MetaDefender: {intel.metadefender_result} "
            f"({intel.metadefender_detected}/{intel.metadefender_total})"
        )
    if intel.sandbox_verdict or intel.sandbox_behaviors:
        lines.append(f"Sandbox verdict: {intel.sandbox_verdict or 'n/a'}")
        if intel.sandbox_family:
            lines.append(f"Sandbox family: {intel.sandbox_family}")
        if intel.sandbox_tags:
            lines.append(f"Sandbox tags: {', '.join(intel.sandbox_tags[:12])}")
        if intel.sandbox_behaviors:
            lines.append("Sandbox behaviours:")
            lines.extend(f"  - {item}" for item in intel.sandbox_behaviors[:12])
    vendors = intel.vendors[:10]
    if vendors:
        lines.append("Vendor detections:")
        lines.extend(f"  - {item.vendor}: {item.category} ({item.label})" for item in vendors)
    return "\n".join(lines)


def _extract_text(payload: dict) -> str:
    candidates = payload.get("candidates") or []
    parts: list[str] = []
    for candidate in candidates:
        content = candidate.get("content") or {}
        for part in content.get("parts") or []:
            if part.get("thought"):
                continue
            text = part.get("text")
            if text:
                parts.append(str(text))
    return "\n".join(parts).strip()
