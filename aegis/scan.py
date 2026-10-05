"""End-to-end scan: extract, identify payloads, hash, query intel, write report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aegis.archive import ArchiveError, extract_archive, extract_nested, find_archives, is_archive
from aegis.config import AppConfig
from aegis.hashing import sha256_file
from aegis.intel.lookup import lookup_hash
from aegis.paths import cleanup_workspace, prepare_workspace
from aegis.progress import ProgressTracker
from aegis.rate_limit import RateLimiter
from aegis.report import ThreatRecord, write_reports
from aegis.walker import PayloadFile, find_payloads


@dataclass
class ScanResult:
    target: Path
    evaluated: int
    threats: list[ThreatRecord]
    report_paths: list[Path]
    clean_message: str | None
    scanned_at: datetime
    errors: list[str] = field(default_factory=list)

    @property
    def threat_count(self) -> int:
        return len(self.threats)


def run_scan(target: Path, config: AppConfig, log, progress=None) -> ScanResult:
    scanned_at = datetime.now()
    resolved = target.expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Path not found: {resolved}")

    workspace = prepare_workspace()
    errors: list[str] = []
    try:
        log(f"Aegis Threat Scanner — target: {resolved}")
        payloads = _collect_payloads(resolved, workspace, log)
        return _scan_payloads(resolved, payloads, config, log, scanned_at, errors, progress)
    except ArchiveError as exc:
        raise RuntimeError(str(exc)) from exc
    finally:
        cleanup_workspace(workspace)


def _collect_payloads(resolved: Path, workspace: Path, log) -> list[PayloadFile]:
    if resolved.is_file() and is_archive(resolved):
        extract_root = workspace / "root"
        log(f"Extracting archive to workspace...")
        extract_archive(resolved, extract_root)
        extract_nested(extract_root, log)
        return find_payloads(extract_root, path_prefix=resolved.name)

    if resolved.is_file():
        from aegis.constants import PAYLOAD_EXTENSIONS

        if resolved.suffix.lower() not in PAYLOAD_EXTENSIONS:
            log(f"{resolved.name} is not a listed execution-vector extension; nothing to hash.")
            return []
        return [
            PayloadFile(
                full_path=resolved,
                display_name=resolved.name,
                internal_path=resolved.name,
                extension=resolved.suffix.lower(),
            )
        ]

    payloads = find_payloads(resolved, path_prefix=resolved.name)
    nested = find_archives(resolved)
    if nested:
        log(f"Found {len(nested)} nested archive(s); extracting into workspace...")
    for index, archive in enumerate(nested, start=1):
        dest = workspace / "nested" / f"{index}_{archive.stem}"
        try:
            log(f"  Extracting {archive.name}")
            extract_archive(archive, dest)
            extract_nested(dest, log)
            relative = archive.relative_to(resolved).as_posix()
            prefix = f"{resolved.name}/{relative}"
            payloads.extend(find_payloads(dest, path_prefix=prefix))
        except ArchiveError as exc:
            log(f"  Warning: skipped archive {archive.name}: {exc}")
    return payloads


def _scan_payloads(
    target: Path,
    payloads: list[PayloadFile],
    config: AppConfig,
    log,
    scanned_at: datetime,
    errors: list[str],
    progress=None,
) -> ScanResult:
    log(f"Found {len(payloads)} matching execution file(s).")
    if not payloads:
        message = "Scan Complete: 0 threats detected across 0 evaluated execution files."
        log(message)
        return ScanResult(target, 0, [], [], message, scanned_at, errors)

    tracker = ProgressTracker(len(payloads), emit=progress)
    limiter = RateLimiter(
        config.request_delay_seconds,
        enabled=config.free_tier,
        on_tick=tracker.waiting,
    )
    threats: list[ThreatRecord] = []
    for index, payload in enumerate(payloads, start=1):
        tracker.begin_file(index, payload.display_name)
        log(f"[{index}/{len(payloads)}] {payload.internal_path}")
        try:
            sha = sha256_file(payload.full_path)
        except OSError as exc:
            msg = f"Could not hash {payload.display_name}: {exc}"
            errors.append(msg)
            log(f"  {msg}")
            tracker.end_file()
            continue
        log(f"  SHA-256: {sha}")
        intel = lookup_hash(sha, config, limiter, log, file_path=payload.full_path)
        if intel.is_threat:
            threats.append(ThreatRecord(payload, intel))
            log(
                f"  THREAT: {intel.threat_level} "
                f"({intel.malicious} malicious / {intel.suspicious} suspicious)"
            )
        else:
            log("  Clean/undetected — omitted from report.")
        tracker.end_file()

    if config.has_google and threats:
        from aegis.intel.gemini import synthesize_threats

        synthesize_threats(threats, config.google_api_key, config.google_model, limiter, log)

    if not threats:
        message = (
            f"Scan Complete: 0 threats detected across {len(payloads)} evaluated execution files."
        )
        log(message)
        return ScanResult(target, len(payloads), [], [], message, scanned_at, errors)

    reports = write_reports(target, scanned_at, len(payloads), threats, config.report_format)
    for path in reports:
        log(f"Report saved: {path}")
    return ScanResult(target, len(payloads), threats, reports, None, scanned_at, errors)
