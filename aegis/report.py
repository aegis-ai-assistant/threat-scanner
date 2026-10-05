"""Generate HTML and RTF threat reports on the user's Desktop."""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from aegis.constants import APP_NAME, HYBRID_GUI_SAMPLE, METADEFENDER_GUI, REPORT_TITLE, VT_GUI_FILE
from aegis.intel import FileIntel
from aegis.paths import desktop_dir
from aegis.walker import PayloadFile

LEVEL_COLORS = {
    "CRITICAL": ("#7f1d1d", "#fecaca"),
    "HIGH": ("#991b1b", "#fecaca"),
    "MEDIUM": ("#9a3412", "#fed7aa"),
    "LOW": ("#854d0e", "#fef08a"),
}

RTF_LEVEL = {
    "CRITICAL": r"\cf2\b",
    "HIGH": r"\cf2\b",
    "MEDIUM": r"\cf3\b",
    "LOW": r"\cf4\b",
}


class ThreatRecord:
    def __init__(self, payload: PayloadFile, intel: FileIntel) -> None:
        self.payload = payload
        self.intel = intel


def write_reports(
    target: Path,
    scanned_at: datetime,
    evaluated: int,
    threats: list[ThreatRecord],
    formats: str,
) -> list[Path]:
    stamp = scanned_at.strftime("%Y%m%d_%H%M%S")
    out_dir = desktop_dir()
    written: list[Path] = []
    if formats in {"html", "both"}:
        html_path = out_dir / f"Aegis_Threat_Report_{stamp}.html"
        html_path.write_text(render_html(target, scanned_at, evaluated, threats), encoding="utf-8")
        written.append(html_path)
    if formats in {"rtf", "both"}:
        rtf_path = out_dir / f"Aegis_Threat_Report_{stamp}.rtf"
        rtf_path.write_text(render_rtf(target, scanned_at, evaluated, threats), encoding="utf-8")
        written.append(rtf_path)
    return written


def render_html(target: Path, scanned_at: datetime, evaluated: int, threats: list[ThreatRecord]) -> str:
    cards = "\n".join(_html_card(item) for item in threats)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(REPORT_TITLE)}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #121a2b;
      --line: #243049;
      --text: #e8eefc;
      --muted: #93a0bb;
      --accent: #38bdf8;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Calibri, Arial, sans-serif;
      line-height: 1.45;
    }}
    .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
    header {{
      border: 1px solid var(--line);
      background: linear-gradient(180deg, #18233a, #121a2b);
      padding: 24px 28px;
      border-radius: 10px;
    }}
    h1 {{
      margin: 0 0 8px;
      letter-spacing: 0.12em;
      font-size: 1.15rem;
    }}
    .meta {{ color: var(--muted); font-size: 0.95rem; }}
    .meta strong {{ color: var(--text); }}
    .summary {{
      margin: 18px 0 0;
      color: #fecaca;
      font-weight: 600;
    }}
    article {{
      margin-top: 18px;
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 10px;
      overflow: hidden;
    }}
    .banner {{
      padding: 10px 18px;
      font-weight: 700;
      letter-spacing: 0.08em;
    }}
    dl {{
      display: grid;
      grid-template-columns: 160px 1fr;
      gap: 6px 12px;
      margin: 0;
      padding: 16px 18px 8px;
    }}
    dt {{ color: var(--muted); }}
    dd {{ margin: 0; word-break: break-all; }}
    .hash {{ font-family: Consolas, "Cascadia Mono", monospace; font-size: 0.9rem; }}
    ul {{ margin: 0; padding: 0 18px 16px 178px; }}
    li {{ margin: 2px 0; }}
    a {{ color: var(--accent); }}
    .rule {{ height: 1px; background: var(--line); margin: 0 18px 12px; }}
    footer {{ margin-top: 28px; color: var(--muted); font-size: 0.85rem; }}
    .ai, .sandbox {{
      margin: 0 18px 16px;
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #0e1626;
      white-space: pre-wrap;
    }}
    .ai h2, .sandbox h2, .gamer h2 {{
      margin: 0 0 8px;
      font-size: 0.85rem;
      letter-spacing: 0.06em;
      color: var(--accent);
    }}
    .gamer {{
      margin: 0 18px 16px;
      padding: 16px 18px 8px;
      border-radius: 10px;
      border: 2px solid #a3e635;
      background: linear-gradient(165deg, #14532d 0%, #1a3a12 42%, #3f3d12 100%);
      color: #ecfccb;
    }}
    .gamer.warn {{
      border-color: #facc15;
      background: linear-gradient(165deg, #713f12 0%, #3f2e0a 45%, #1c1917 100%);
      color: #fef9c3;
    }}
    .gamer h2 {{
      color: #fde047;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    .gamer p {{
      margin: 0 0 10px;
    }}
    .gamer strong {{
      color: #facc15;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>{html.escape(REPORT_TITLE)}</h1>
      <div class="meta">Target Archive/Path: <strong>{html.escape(str(target))}</strong></div>
      <div class="meta">Scan Time: <strong>{html.escape(scanned_at.strftime("%Y-%m-%d %H:%M:%S"))}</strong></div>
      <div class="meta">Engine: {html.escape(APP_NAME)} &middot; Evaluated execution files: {evaluated}</div>
      <div class="summary">{len(threats)} threat{"s" if len(threats) != 1 else ""} detected</div>
    </header>
    {cards}
    <footer>Hash lookup, optional VirusTotal upload/sandbox, and Google AI synthesis. Clean/undetected files are omitted. Not a substitute for a full antivirus engine.</footer>
  </div>
</body>
</html>
"""


def _html_card(record: ThreatRecord) -> str:
    intel = record.intel
    level = intel.threat_level
    bg, fg = LEVEL_COLORS.get(level, ("#1e293b", "#e2e8f0"))
    flagged = intel.malicious + intel.suspicious
    labels = ", ".join(html.escape(label) for label in intel.labels[:8]) or "n/a"
    vendors = "".join(
        f"<li>{html.escape(item.vendor)}: {html.escape(item.category.title())}"
        f" ({html.escape(item.label)})</li>"
        for item in intel.vendors[:16]
    ) or "<li>No vendor labels returned</li>"
    extra_rows = ""
    if intel.vt_uploaded:
        extra_rows += "<dt>VirusTotal Upload</dt><dd>Sample submitted because the hash was unknown</dd>"
    if intel.hybrid_verdict:
        score = f" (score {intel.hybrid_score})" if intel.hybrid_score is not None else ""
        extra_rows += (
            f"<dt>Hybrid Analysis</dt><dd>{html.escape(intel.hybrid_verdict)}{html.escape(score)}</dd>"
        )
    if intel.metadefender_result:
        counts = ""
        if intel.metadefender_detected is not None and intel.metadefender_total is not None:
            counts = f" ({intel.metadefender_detected}/{intel.metadefender_total})"
        extra_rows += (
            f"<dt>MetaDefender</dt><dd>{html.escape(intel.metadefender_result)}{html.escape(counts)}</dd>"
        )
    if intel.sandbox_verdict or intel.sandbox_behaviors:
        extra_rows += (
            f"<dt>Sandbox</dt><dd>{html.escape(intel.sandbox_verdict or 'behaviour available')}"
            f"{' / ' + html.escape(intel.sandbox_family) if intel.sandbox_family else ''}</dd>"
        )
    sha = intel.sha256
    links = [
        f'<li>VirusTotal: <a href="{VT_GUI_FILE}{sha}">{VT_GUI_FILE}{sha}</a></li>',
        f'<li>Hybrid Analysis: <a href="{HYBRID_GUI_SAMPLE}{sha}">{HYBRID_GUI_SAMPLE}{sha}</a></li>',
        f'<li>MetaDefender: <a href="{METADEFENDER_GUI}{sha}">{METADEFENDER_GUI}{sha}</a></li>',
    ]
    return f"""
    <article>
      <div class="banner" style="background:{bg};color:{fg};">[THREAT DETECTED] &mdash; {html.escape(level)}</div>
      <dl>
        <dt>File Name</dt><dd>{html.escape(record.payload.display_name)}</dd>
        <dt>Internal Path</dt><dd>{html.escape(record.payload.internal_path)}</dd>
        <dt>SHA-256</dt><dd class="hash">{html.escape(sha)}</dd>
        <dt>Threat Level</dt><dd>{html.escape(level)} ({flagged}/{intel.engine_total or flagged} AV engines flagged)</dd>
        <dt>Primary Labels</dt><dd>{labels}</dd>
        {extra_rows}
      </dl>
      <div class="rule"></div>
      <dl><dt>Vendor Breakdown</dt><dd></dd></dl>
      <ul>{vendors}</ul>
      {_html_sandbox(intel)}
      {_html_ai(intel)}
      <dl><dt>Scan Links</dt><dd></dd></dl>
      <ul>{"".join(links)}</ul>
    </article>
    """


def _html_sandbox(intel: FileIntel) -> str:
    if not intel.sandbox_behaviors and not intel.sandbox_tags:
        return ""
    tags = ", ".join(html.escape(tag) for tag in intel.sandbox_tags[:12])
    items = "".join(f"<li>{html.escape(item)}</li>" for item in intel.sandbox_behaviors[:16])
    tag_line = f"<p>Tags: {tags}</p>" if tags else ""
    return f'<div class="sandbox"><h2>VirusTotal Sandbox</h2>{tag_line}<ul>{items}</ul></div>'


def _html_ai(intel: FileIntel) -> str:
    blocks: list[str] = []
    if intel.ai_synthesis:
        blocks.append(
            '<div class="ai"><h2>Technical Telemetry Summary</h2>'
            f"{html.escape(intel.ai_synthesis)}</div>"
        )
    if intel.ai_plain_what or intel.ai_plain_why or intel.ai_plain_bottom:
        tone = "warn" if intel.threat_level in {"HIGH", "CRITICAL"} else "ok"
        rows = []
        if intel.ai_plain_what:
            rows.append(
                f"<p><strong>What is this file?</strong> {html.escape(intel.ai_plain_what)}</p>"
            )
        if intel.ai_plain_why:
            rows.append(
                f"<p><strong>Why did the antivirus flag it?</strong> {html.escape(intel.ai_plain_why)}</p>"
            )
        if intel.ai_plain_bottom:
            rows.append(
                f"<p><strong>Bottom Line Safety Call:</strong> {html.escape(intel.ai_plain_bottom)}</p>"
            )
        blocks.append(
            f'<div class="gamer {tone}"><h2>Gamers\' Summary</h2>{"".join(rows)}</div>'
        )
    if not blocks and intel.ai_error:
        return (
            '<div class="ai"><h2>Google AI Threat Synthesis</h2>'
            f"Unavailable: {html.escape(intel.ai_error)}</div>"
        )
    return "".join(blocks)


def render_rtf(target: Path, scanned_at: datetime, evaluated: int, threats: list[ThreatRecord]) -> str:
    body = [_rtf_escape("=" * 80), r"\par "]
    body.append(_rtf_escape(REPORT_TITLE) + r"\par ")
    body.append(_rtf_escape(f"Target Archive/Path: {target}") + r"\par ")
    body.append(_rtf_escape(f"Scan Time: {scanned_at.strftime('%Y-%m-%d %H:%M:%S')}") + r"\par ")
    body.append(_rtf_escape(f"Evaluated execution files: {evaluated}") + r"\par ")
    body.append(_rtf_escape("=" * 80) + r"\par\par ")
    for record in threats:
        body.append(_rtf_threat(record))
        body.append(_rtf_escape("-" * 80) + r"\par\par ")
    inner = "".join(body)
    return (
        r"{\rtf1\ansi\deff0"
        r"{\fonttbl{\f0\fmodern\fcharset0 Consolas;}{\f1\fswiss\fcharset0 Calibri;}}"
        r"{\colortbl ;\red232\green238\green252;\red185\green28\green28;\red194\green65\green12;\red161\green98\green7;}"
        r"\paperw12240\paperh15840\margl720\margr720\margt720\margb720"
        r"\f0\fs20 "
        f"{inner}"
        r"}"
    )


def _rtf_threat(record: ThreatRecord) -> str:
    intel = record.intel
    level = intel.threat_level
    flagged = intel.malicious + intel.suspicious
    color = RTF_LEVEL.get(level, r"\b")
    labels = ", ".join(intel.labels[:8]) or "n/a"
    lines = [
        rf"{color}[THREAT DETECTED]\b0\cf0\par ",
        _rtf_escape(f"File Name:       {record.payload.display_name}") + r"\par ",
        _rtf_escape(f"Internal Path:   {record.payload.internal_path}") + r"\par ",
        _rtf_escape(f"SHA-256:         {intel.sha256}") + r"\par ",
        _rtf_escape(
            f"Threat Level:    {level} ({flagged}/{intel.engine_total or flagged} AV engines flagged)"
        )
        + r"\par ",
        _rtf_escape(f"Primary Labels:  {labels}") + r"\par ",
    ]
    if intel.vt_uploaded:
        lines.append(_rtf_escape("VirusTotal Upload: sample submitted (hash was unknown)") + r"\par ")
    if intel.hybrid_verdict:
        extra = f" (score {intel.hybrid_score})" if intel.hybrid_score is not None else ""
        lines.append(_rtf_escape(f"Hybrid Analysis: {intel.hybrid_verdict}{extra}") + r"\par ")
    if intel.metadefender_result:
        counts = ""
        if intel.metadefender_detected is not None and intel.metadefender_total is not None:
            counts = f" ({intel.metadefender_detected}/{intel.metadefender_total})"
        lines.append(_rtf_escape(f"MetaDefender:    {intel.metadefender_result}{counts}") + r"\par ")
    if intel.sandbox_verdict or intel.sandbox_behaviors:
        family = f" / {intel.sandbox_family}" if intel.sandbox_family else ""
        lines.append(_rtf_escape(f"Sandbox:         {intel.sandbox_verdict or 'behaviour available'}{family}") + r"\par ")
        for item in intel.sandbox_behaviors[:10]:
            lines.append(_rtf_escape(f"  - {item}") + r"\par ")
    if intel.ai_synthesis:
        lines.append(_rtf_escape("Technical Telemetry Summary:") + r"\par ")
        for line in intel.ai_synthesis.splitlines() or [intel.ai_synthesis]:
            lines.append(_rtf_escape(line) + r"\par ")
    if intel.ai_plain_what or intel.ai_plain_why or intel.ai_plain_bottom:
        lines.append(_rtf_escape("Gamers' Summary (In Plain English):") + r"\par ")
        if intel.ai_plain_what:
            lines.append(_rtf_escape(f" What is this file? {intel.ai_plain_what}") + r"\par ")
        if intel.ai_plain_why:
            lines.append(_rtf_escape(f" Why did the antivirus flag it? {intel.ai_plain_why}") + r"\par ")
        if intel.ai_plain_bottom:
            lines.append(_rtf_escape(f" Bottom Line Safety Call: {intel.ai_plain_bottom}") + r"\par ")
    lines.append(_rtf_escape("Vendor Breakdown:") + r"\par ")
    if intel.vendors:
        for item in intel.vendors[:16]:
            lines.append(
                _rtf_escape(f" - {item.vendor}: {item.category.title()} ({item.label})") + r"\par "
            )
    else:
        lines.append(_rtf_escape(" - No vendor labels returned") + r"\par ")
    lines.append(_rtf_escape("Scan Links:") + r"\par ")
    lines.append(_rtf_escape(f" - VirusTotal:   {VT_GUI_FILE}{intel.sha256}") + r"\par ")
    lines.append(_rtf_escape(f" - Hybrid Analysis: {HYBRID_GUI_SAMPLE}{intel.sha256}") + r"\par ")
    lines.append(_rtf_escape(f" - MetaDefender: {METADEFENDER_GUI}{intel.sha256}") + r"\par ")
    return "".join(lines)


def _rtf_escape(text: str) -> str:
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char in {"\\", "{", "}"}:
            out.append("\\" + char)
        elif char == "\n":
            out.append(r"\par ")
        elif code < 128:
            out.append(char)
        else:
            out.append(f"\\u{code}?")
    return "".join(out)
