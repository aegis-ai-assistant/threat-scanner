"""End-to-end scan: extract, identify payloads, hash, query intel, write report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aegis.archive import (
    ArchiveError,
    ExtractBudget,
    extract_archive,
    extract_nested,
    find_archives,
    find_symlink_archives,
    is_archive,
)
from aegis.checkpoint import (
    PHASE_AI,
    PHASE_SCANNING,
    ScanCheckpoint,
    clear_checkpoint,
    load_checkpoint,
    same_target,
)
from aegis.config import AppConfig
from aegis.hashing import sha256_file
from aegis.intel.lookup import lookup_hash
from aegis.intel.transport import LookupInterrupted
from aegis.paths import cleanup_workspace, prepare_workspace
from aegis.progress import ProgressTracker
from aegis.rate_limit import RateLimiter
from aegis.report import ThreatRecord, write_reports
from aegis.walker import PayloadFile, find_payloads


class ScanPaused(Exception):
    """The scan stopped before it finished. Progress is saved on disk."""

    def __init__(self, message: str, completed: int, payload_count: int) -> None:
        super().__init__(message)
        self.completed = completed
        self.payload_count = payload_count


@dataclass
class ScanResult:
    target: Path
    evaluated: int
    threats: list[ThreatRecord]
    report_paths: list[Path]
    clean_message: str | None
    scanned_at: datetime
    errors: list[str] = field(default_factory=list)
    ai_pending: bool = False

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    def dialog_text(self) -> str:
        """Finish-dialog text. A clean bill of health is only returned when nothing failed."""
        if self.clean_message and not self.errors:
            return self.clean_message
        if self.errors and self.threat_count == 0:
            head = (
                f"Scan incomplete across {self.evaluated} evaluated execution files. "
                f"{len(self.errors)} item(s) could not be fully checked."
            )
        else:
            head = (
                f"Scan complete: {self.threat_count} threat(s) across "
                f"{self.evaluated} evaluated execution files."
            )
            if self.errors:
                head += f" {len(self.errors)} item(s) could not be fully checked."
        if not self.errors:
            return head
        shown = self.errors[:12]
        lines = [head, "", "Could not fully check:"]
        lines.extend(f"• {item}" for item in shown)
        if len(self.errors) > len(shown):
            lines.append(f"• … and {len(self.errors) - len(shown)} more in the report.")
        return "\n".join(lines)


def run_scan(
    target: Path,
    config: AppConfig,
    log,
    progress=None,
    *,
    resume: bool = False,
    on_extract_limit=None,
) -> ScanResult:
    resolved = target.expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Path not found: {resolved}")

    if resume:
        checkpoint = load_checkpoint()
        if checkpoint is None or not same_target(checkpoint.target, resolved):
            raise RuntimeError("No saved scan matches this target.")
        if checkpoint.phase == PHASE_AI:
            return complete_saved_ai(config, log, checkpoint)
        log(
            f"Continuing saved scan — {checkpoint.completed_count} file(s) already checked."
        )
    else:
        clear_checkpoint()
        checkpoint = ScanCheckpoint.create(resolved)
        checkpoint.save()

    workspace = prepare_workspace()
    try:
        log(f"Aegis Threat Scanner — target: {resolved}")
        payloads = _collect_payloads(
            resolved,
            workspace,
            log,
            checkpoint,
            on_extract_limit=on_extract_limit,
        )
        return _scan_payloads(resolved, payloads, config, log, checkpoint, progress)
    except ArchiveError as exc:
        checkpoint.stopped_reason = str(exc)
        checkpoint.phase = PHASE_SCANNING
        checkpoint.save()
        raise ScanPaused(
            f"Scan paused: {exc}. {checkpoint.completed_count} file(s) already checked. "
            "Choose Continue to resume, or Restart to begin again.",
            checkpoint.completed_count,
            checkpoint.payload_count,
        ) from exc
    finally:
        cleanup_workspace(workspace)


def complete_saved_ai(config: AppConfig, log, checkpoint: ScanCheckpoint | None = None) -> ScanResult:
    """Run only the plain-English summary for a scan whose file lookups already finished."""
    saved = checkpoint or load_checkpoint()
    if saved is None or saved.phase != PHASE_AI:
        raise RuntimeError("No saved scan is waiting on the plain-English summary.")
    target = Path(saved.target)
    threats = saved.threat_records()
    scanned_at = saved.scanned_at_dt()
    if not threats:
        if saved.errors:
            return _publish(target, saved, [], config, log)
        clear_checkpoint()
        message = "Scan Complete: 0 threats detected across 0 evaluated execution files."
        log(message)
        return ScanResult(target, saved.payload_count, [], [], message, scanned_at, list(saved.errors))

    log(f"File lookups for {target} are already saved.")
    if _summarize(saved, threats, config, log):
        return _publish(target, saved, threats, config, log)
    return _publish_with_failed_summary(target, saved, threats, config, log)


def _note_issues(checkpoint: ScanCheckpoint, messages: list[str]) -> None:
    changed = False
    for message in messages:
        if message and message not in checkpoint.errors:
            checkpoint.errors.append(message)
            changed = True
    if changed:
        checkpoint.save()


def unknown_because(message: str) -> str:
    """Turn an API failure into the report flag for that file."""
    labels: list[str] = []
    for part in message.split(";"):
        label = _unknown_reason(part)
        if label not in labels:
            labels.append(label)
    return "; ".join(labels)


def _unknown_reason(message: str) -> str:
    text = message.lower()
    if any(token in text for token in ("authentication", "unauthorized", "forbidden", "http 401", "http 403")):
        return "Unknown because of authentication failure"
    if any(token in text for token in ("429", "rate-limit", "rate limit", "rate limited")):
        return "Unknown because of rate limit"
    if any(
        token in text
        for token in ("request failed", "network", "timed out", "timeout", "connection", "name resolution")
    ):
        return "Unknown because of network error"
    return "Unknown because of a service error"


def _set_file_issue(checkpoint: ScanCheckpoint, internal_path: str, issue: str | None) -> None:
    prefix = f"{internal_path}: "
    kept = [item for item in checkpoint.errors if not item.startswith(prefix)]
    if issue:
        kept.append(prefix + issue)
    checkpoint.errors = kept


def _collect_payloads(
    resolved: Path,
    workspace: Path,
    log,
    checkpoint: ScanCheckpoint,
    on_extract_limit=None,
) -> list[PayloadFile]:
    budget = ExtractBudget()

    def allow_limit(message: str) -> bool:
        log(f"  {message}")
        if on_extract_limit is None or not on_extract_limit(message):
            return False
        log("  Extraction cap ignored. Extracting this archive anyway.")
        return True

    if resolved.is_file() and is_archive(resolved):
        extract_root = workspace / "root"
        log("Extracting archive to workspace...")
        extract_archive(resolved, extract_root, budget, on_limit=allow_limit)
        _note_issues(checkpoint, extract_nested(extract_root, log, budget=budget, on_limit=allow_limit))
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
    _note_issues(
        checkpoint,
        [f"Skipped symlink archive {link.name}" for link in find_symlink_archives(resolved)],
    )
    nested = find_archives(resolved)
    if nested:
        log(f"Found {len(nested)} nested archive(s); extracting into workspace...")
    for index, archive in enumerate(nested, start=1):
        dest = workspace / "nested" / f"{index}_{archive.name}"
        try:
            log(f"  Extracting {archive.name}")
            extract_archive(archive, dest, budget, on_limit=allow_limit)
            _note_issues(checkpoint, extract_nested(dest, log, budget=budget, on_limit=allow_limit))
            relative = archive.relative_to(resolved).as_posix()
            prefix = f"{resolved.name}/{relative}"
            payloads.extend(find_payloads(dest, path_prefix=prefix))
        except ArchiveError as exc:
            message = f"Skipped archive {archive.name}: {exc}"
            log(f"  Warning: {message}")
            _note_issues(checkpoint, [message])
    return payloads


def _scan_payloads(
    target: Path,
    payloads: list[PayloadFile],
    config: AppConfig,
    log,
    checkpoint: ScanCheckpoint,
    progress=None,
) -> ScanResult:
    log(f"Found {len(payloads)} matching execution file(s).")
    checkpoint.payload_count = len(payloads)
    checkpoint.phase = PHASE_SCANNING
    checkpoint.stopped_reason = ""
    checkpoint.save()
    scanned_at = checkpoint.scanned_at_dt()

    if not payloads:
        if checkpoint.errors:
            return _publish(target, checkpoint, [], config, log)
        clear_checkpoint()
        message = "Scan Complete: 0 threats detected across 0 evaluated execution files."
        log(message)
        return ScanResult(target, 0, [], [], message, scanned_at, list(checkpoint.errors))

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
            issue = f"could not hash: {exc}"
            _set_file_issue(checkpoint, payload.internal_path, issue)
            checkpoint.save()
            log(f"  Incomplete: {issue}")
            tracker.end_file()
            continue
        log(f"  SHA-256: {sha}")
        saved = checkpoint.files.get(sha)
        if saved is not None and not saved.intel.service_error:
            log("  Already checked before the interruption — skipping lookups.")
            intel = saved.intel
            _set_file_issue(checkpoint, payload.internal_path, None)
            checkpoint.save()
        else:
            try:
                intel = lookup_hash(
                    sha,
                    config,
                    limiter,
                    log,
                    file_path=payload.full_path,
                    file_index=index - 1,
                )
            except LookupInterrupted as exc:
                checkpoint.stopped_reason = str(exc)
                checkpoint.phase = PHASE_SCANNING
                checkpoint.save()
                raise ScanPaused(
                    f"Scan paused: {exc}. {checkpoint.completed_count} file(s) already checked. "
                    "Choose Continue to resume, or Restart to begin again.",
                    checkpoint.completed_count,
                    checkpoint.payload_count,
                ) from exc
            checkpoint.remember_file(payload, intel)
            issue = unknown_because(intel.service_error) if intel.service_error else None
            _set_file_issue(checkpoint, payload.internal_path, issue)
            checkpoint.save()
            saved = checkpoint.files[sha]
            intel = saved.intel
        if intel.service_error:
            log(f"  {unknown_because(intel.service_error)}")
        if intel.is_threat:
            threats.append(ThreatRecord(payload, intel))
            log(
                f"  THREAT: {intel.threat_level} "
                f"({intel.malicious} malicious / {intel.suspicious} suspicious)"
            )
        elif not intel.service_error:
            log("  Clean/undetected — omitted from report.")
        tracker.end_file()

    if config.has_google and threats:
        checkpoint.phase = PHASE_AI
        checkpoint.save()
        if not _summarize(checkpoint, threats, config, log):
            return _publish_with_failed_summary(target, checkpoint, threats, config, log)

    return _publish(target, checkpoint, threats, config, log)


def _summarize(checkpoint: ScanCheckpoint, threats: list[ThreatRecord], config: AppConfig, log) -> bool:
    """Return True when every threat has a plain-English summary, or AI is not configured."""
    if not config.has_google or not threats:
        return True
    pending = [record for record in threats if not record.intel.ai_summary_ready]
    if not pending:
        return True
    from aegis.intel.gemini import synthesize_threats

    def remember(record: ThreatRecord) -> None:
        checkpoint.update_intel(record.intel)
        checkpoint.phase = PHASE_AI
        checkpoint.save()

    synthesize_threats(
        pending,
        config.google_api_key,
        config.google_model,
        log,
        on_record=remember,
    )
    return all(record.intel.ai_summary_ready for record in threats)


def _publish_with_failed_summary(
    target: Path,
    checkpoint: ScanCheckpoint,
    threats: list[ThreatRecord],
    config: AppConfig,
    log,
) -> ScanResult:
    """Write the report with the explanation marked failed, and keep Retry available."""
    checkpoint.phase = PHASE_AI
    checkpoint.stopped_reason = "The plain-English summary did not complete."
    checkpoint.save()
    log(
        "Plain-English summary did not complete. "
        "The report marks that explanation as failed. Use Retry AI summary to try again."
    )
    reports = write_reports(
        target,
        checkpoint.scanned_at_dt(),
        checkpoint.payload_count,
        threats,
        config.report_format,
        list(checkpoint.errors),
    )
    for path in reports:
        log(f"Report saved: {path}")
    return ScanResult(
        target,
        checkpoint.payload_count,
        threats,
        reports,
        None,
        checkpoint.scanned_at_dt(),
        list(checkpoint.errors),
        ai_pending=True,
    )


def _publish(
    target: Path,
    checkpoint: ScanCheckpoint,
    threats: list[ThreatRecord],
    config: AppConfig,
    log,
) -> ScanResult:
    scanned_at = checkpoint.scanned_at_dt()
    evaluated = checkpoint.payload_count
    errors = list(checkpoint.errors)
    if not threats and not errors:
        clear_checkpoint()
        message = f"Scan Complete: 0 threats detected across {evaluated} evaluated execution files."
        log(message)
        return ScanResult(target, evaluated, [], [], message, scanned_at, errors)

    reports = write_reports(target, scanned_at, evaluated, threats, config.report_format, errors)
    for path in reports:
        log(f"Report saved: {path}")
    result = ScanResult(target, evaluated, threats, reports, None, scanned_at, errors)
    for line in result.dialog_text().splitlines():
        if line.strip():
            log(line)
    clear_checkpoint()
    return result
