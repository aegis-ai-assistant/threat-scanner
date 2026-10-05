"""Persist an unfinished scan so a later launch can continue it."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aegis.constants import CHECKPOINT_FILENAME
from aegis.intel import FileIntel
from aegis.paths import application_dir
from aegis.report import ThreatRecord
from aegis.walker import PayloadFile

PHASE_SCANNING = "scanning"
PHASE_AI = "ai_pending"

_path_override: Path | None = None


def set_checkpoint_path(path: Path | None) -> None:
    """Test hook. Production keeps the file beside config.json."""
    global _path_override
    _path_override = path


def checkpoint_path() -> Path:
    if _path_override is not None:
        return _path_override
    return application_dir() / CHECKPOINT_FILENAME


def same_target(saved: str, candidate: Path) -> bool:
    try:
        return Path(saved).expanduser().resolve() == candidate.expanduser().resolve()
    except OSError:
        return str(Path(saved)) == str(candidate)


@dataclass
class SavedFile:
    sha256: str
    display_name: str
    internal_path: str
    extension: str
    intel: FileIntel

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "display_name": self.display_name,
            "internal_path": self.internal_path,
            "extension": self.extension,
            "intel": self.intel.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> SavedFile:
        intel_raw = raw.get("intel") if isinstance(raw.get("intel"), dict) else {}
        sha = str(raw.get("sha256") or intel_raw.get("sha256") or "")
        intel = FileIntel.from_dict(intel_raw)
        intel.sha256 = intel.sha256 or sha
        return cls(
            sha256=sha,
            display_name=str(raw.get("display_name") or ""),
            internal_path=str(raw.get("internal_path") or ""),
            extension=str(raw.get("extension") or ""),
            intel=intel,
        )

    def as_threat(self, payload: PayloadFile | None = None) -> ThreatRecord:
        used = payload or PayloadFile(
            full_path=Path(self.internal_path or self.display_name),
            display_name=self.display_name,
            internal_path=self.internal_path or self.display_name,
            extension=self.extension,
        )
        return ThreatRecord(used, self.intel)


@dataclass
class ScanCheckpoint:
    target: str
    phase: str = PHASE_SCANNING
    scanned_at: str = ""
    payload_count: int = 0
    stopped_reason: str = ""
    files: dict[str, SavedFile] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    version: int = 1

    @classmethod
    def create(cls, target: Path, scanned_at: datetime | None = None) -> ScanCheckpoint:
        moment = scanned_at or datetime.now()
        return cls(target=str(target), scanned_at=moment.isoformat(timespec="seconds"))

    @property
    def completed_count(self) -> int:
        return len(self.files)

    def scanned_at_dt(self) -> datetime:
        if not self.scanned_at:
            return datetime.now()
        try:
            return datetime.fromisoformat(self.scanned_at)
        except ValueError:
            return datetime.now()

    def remember_file(self, payload: PayloadFile, intel: FileIntel) -> None:
        sha = intel.sha256
        self.files[sha] = SavedFile(
            sha256=sha,
            display_name=payload.display_name,
            internal_path=payload.internal_path,
            extension=payload.extension,
            intel=intel,
        )
        if sha not in self.order:
            self.order.append(sha)

    def update_intel(self, intel: FileIntel) -> None:
        saved = self.files.get(intel.sha256)
        if saved is None:
            return
        saved.intel = intel

    def threat_records(self) -> list[ThreatRecord]:
        records: list[ThreatRecord] = []
        for sha in self.order:
            saved = self.files.get(sha)
            if saved is not None and saved.intel.is_threat:
                records.append(saved.as_threat())
        return records

    def threats_needing_ai(self) -> list[ThreatRecord]:
        return [record for record in self.threat_records() if not record.intel.ai_summary_ready]

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "phase": self.phase,
            "target": self.target,
            "scanned_at": self.scanned_at,
            "payload_count": self.payload_count,
            "stopped_reason": self.stopped_reason,
            "order": list(self.order),
            "errors": list(self.errors),
            "files": {sha: item.to_dict() for sha, item in self.files.items()},
        }

    @classmethod
    def from_dict(cls, raw: dict) -> ScanCheckpoint:
        if not isinstance(raw, dict):
            raise TypeError("checkpoint must be an object")
        target = str(raw.get("target") or "").strip()
        if not target:
            raise ValueError("checkpoint is missing a target")
        phase = str(raw.get("phase") or PHASE_SCANNING)
        if phase not in {PHASE_SCANNING, PHASE_AI}:
            phase = PHASE_SCANNING
        files: dict[str, SavedFile] = {}
        raw_files = raw.get("files") or {}
        if isinstance(raw_files, dict):
            for sha, item in raw_files.items():
                if isinstance(item, dict):
                    saved = SavedFile.from_dict(item)
                    files[str(sha or saved.sha256)] = saved
        order = [str(sha) for sha in raw.get("order") or [] if str(sha) in files]
        for sha in files:
            if sha not in order:
                order.append(sha)
        try:
            payload_count = int(raw.get("payload_count") or 0)
        except (TypeError, ValueError):
            payload_count = 0
        errors = [str(item) for item in raw.get("errors") or []]
        return cls(
            target=target,
            phase=phase,
            scanned_at=str(raw.get("scanned_at") or ""),
            payload_count=payload_count,
            stopped_reason=str(raw.get("stopped_reason") or ""),
            files=files,
            order=order,
            errors=errors,
            version=1,
        )

    def save(self) -> None:
        path = checkpoint_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(path)


def load_checkpoint() -> ScanCheckpoint | None:
    path = checkpoint_path()
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return ScanCheckpoint.from_dict(raw)
    except (OSError, json.JSONDecodeError, TypeError, ValueError, KeyError):
        return None


def clear_checkpoint() -> None:
    path = checkpoint_path()
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.unlink(missing_ok=True)
    except OSError:
        pass
