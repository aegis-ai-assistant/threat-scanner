"""Extract zip / rar / 7z / tar.gz into a local workspace with zip-slip protection."""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import py7zr
import rarfile
from py7zr.io import Py7zIO, WriterFactory

from aegis.constants import (
    ARCHIVE_EXTENSIONS,
    MAX_ARCHIVE_DEPTH,
    MAX_EXTRACT_BYTES,
    MAX_EXTRACT_FILES,
    TAR_GZ_SUFFIXES,
)

_CHUNK = 1024 * 1024


class ArchiveError(RuntimeError):
    pass


@dataclass
class ExtractBudget:
    """Shared cap for one scan, including nested archives."""

    max_files: int = MAX_EXTRACT_FILES
    max_bytes: int = MAX_EXTRACT_BYTES
    files: int = 0
    bytes_written: int = 0

    def claim_file(self) -> None:
        if self.files >= self.max_files:
            raise ArchiveError(f"Extraction stopped: more than {self.max_files} files.")
        self.files += 1

    def claim_bytes(self, count: int) -> None:
        if count <= 0:
            return
        if self.bytes_written + count > self.max_bytes:
            raise ArchiveError(
                f"Extraction stopped: uncompressed data exceeds {self.max_bytes} bytes."
            )
        self.bytes_written += count

    def reject_declared(self, declared: int | None) -> None:
        if declared is None or declared <= 0:
            return
        if self.bytes_written + declared > self.max_bytes:
            raise ArchiveError(
                f"Extraction stopped: a member declares {declared} uncompressed bytes, "
                f"over the {self.max_bytes} byte limit."
            )


def is_archive(path: Path) -> bool:
    name = path.name.lower()
    if any(name.endswith(suffix) for suffix in TAR_GZ_SUFFIXES):
        return True
    return path.suffix.lower() in ARCHIVE_EXTENSIONS


def archive_kind(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(TAR_GZ_SUFFIXES):
        return "tar.gz"
    suffix = path.suffix.lower()
    if suffix in ARCHIVE_EXTENSIONS:
        return suffix.lstrip(".")
    return None


def _safe_target(base: Path, member: str) -> Path:
    base_resolved = base.resolve()
    cleaned = member.replace("\\", "/").lstrip("/")
    if len(cleaned) >= 2 and cleaned[1] == ":":
        raise ArchiveError(f"Unsafe archive member path: {member}")
    target = (base / cleaned).resolve()
    try:
        target.relative_to(base_resolved)
    except ValueError as exc:
        raise ArchiveError(f"Unsafe archive member path: {member}") from exc
    return target


def extract_archive(archive_path: Path, dest: Path, budget: ExtractBudget | None = None) -> None:
    if archive_path.is_symlink():
        raise ArchiveError(f"Refusing symlink archive: {archive_path.name}")
    budget = budget or ExtractBudget()
    dest.mkdir(parents=True, exist_ok=True)
    kind = archive_kind(archive_path)
    if kind is None:
        raise ArchiveError(f"Unsupported archive type: {archive_path}")
    try:
        if kind == "zip":
            _extract_zip(archive_path, dest, budget)
        elif kind == "7z":
            _extract_7z(archive_path, dest, budget)
        elif kind == "rar":
            _extract_rar(archive_path, dest, budget)
        elif kind == "tar.gz":
            _extract_tar_gz(archive_path, dest, budget)
    except ArchiveError:
        raise
    except Exception as exc:
        raise ArchiveError(f"Failed to extract {archive_path.name}: {exc}") from exc


def find_archives(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if is_archive(path):
            found.append(path)
    return found


def find_symlink_archives(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() and is_archive(path):
            found.append(path)
    return found


def extract_nested(
    root: Path,
    log,
    depth: int = 0,
    budget: ExtractBudget | None = None,
) -> list[str]:
    """Extract nested archives under root. Returns messages for archives that were skipped."""
    budget = budget or ExtractBudget()
    skipped: list[str] = []
    if depth >= MAX_ARCHIVE_DEPTH:
        return skipped
    nested: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not is_archive(path):
            continue
        if path.is_symlink():
            message = f"Skipped symlink archive {path.name}"
            log(f"  Warning: {message}")
            skipped.append(message)
            continue
        if path.is_file():
            nested.append(path)
    for archive in nested:
        out_dir = _nested_destination(archive)
        try:
            log(f"  Extracting nested archive: {archive.name}")
            extract_archive(archive, out_dir, budget)
            skipped.extend(extract_nested(out_dir, log, depth + 1, budget))
        except ArchiveError as exc:
            message = f"Skipped archive {archive.name}: {exc}"
            log(f"  Warning: {message}")
            skipped.append(message)
    return skipped


def _nested_destination(archive: Path) -> Path:
    """A unique folder beside the archive, so two archives that share a stem both open."""
    parent = archive.parent
    label = archive.name
    candidate = parent / f"{label}_extracted"
    index = 2
    while candidate.exists():
        candidate = parent / f"{label}_extracted_{index}"
        index += 1
    return candidate


def _stream_member(src, target: Path, budget: ExtractBudget, declared: int | None) -> None:
    budget.reject_declared(declared)
    budget.claim_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("wb") as out:
            while True:
                block = src.read(_CHUNK)
                if not block:
                    break
                budget.claim_bytes(len(block))
                out.write(block)
    except Exception:
        target.unlink(missing_ok=True)
        raise


def _extract_zip(archive_path: Path, dest: Path, budget: ExtractBudget) -> None:
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                _safe_target(dest, info.filename).mkdir(parents=True, exist_ok=True)
                continue
            target = _safe_target(dest, info.filename)
            with zf.open(info, "r") as src:
                _stream_member(src, target, budget, info.file_size)


def _extract_7z(archive_path: Path, dest: Path, budget: ExtractBudget) -> None:
    with py7zr.SevenZipFile(archive_path, mode="r") as archive:
        files: list[str] = []
        planned_files = budget.files
        planned_bytes = budget.bytes_written
        for info in archive.list():
            if info.is_symlink:
                raise ArchiveError(f"Refusing symlink member in {archive_path.name}: {info.filename}")
            if info.is_directory:
                _safe_target(dest, info.filename).mkdir(parents=True, exist_ok=True)
                continue
            if not info.is_file:
                raise ArchiveError(f"Refusing special member in {archive_path.name}: {info.filename}")
            _safe_target(dest, info.filename)
            planned_files += 1
            planned_bytes += max(0, int(info.uncompressed or 0))
            if planned_files > budget.max_files:
                raise ArchiveError(f"Extraction stopped: more than {budget.max_files} files.")
            if planned_bytes > budget.max_bytes:
                raise ArchiveError(
                    f"Extraction stopped: uncompressed data exceeds {budget.max_bytes} bytes."
                )
            files.append(info.filename)
        if not files:
            return
        archive.extract(path=dest, targets=files, factory=_SevenFactory(dest, budget))


class _FileSink(Py7zIO):
    def __init__(self, path: Path, budget: ExtractBudget) -> None:
        self.path = path
        self.budget = budget
        self._handle = None
        self._claimed = False

    def _ensure(self) -> None:
        if self._claimed:
            return
        self.budget.claim_file()
        self._claimed = True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("wb")

    def _discard(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        self.path.unlink(missing_ok=True)

    def write(self, s: bytes | bytearray) -> int:
        data = bytes(s)
        self._ensure()
        try:
            self.budget.claim_bytes(len(data))
        except ArchiveError:
            self._discard()
            raise
        assert self._handle is not None
        return self._handle.write(data)

    def read(self, size: int | None = None) -> bytes:
        return b""

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._handle is None:
            return 0
        return self._handle.seek(offset, whence)

    def flush(self) -> None:
        if self._handle is not None:
            self._handle.flush()

    def size(self) -> int:
        if self._handle is None:
            return 0
        return self._handle.tell()

    def close(self) -> None:
        if not self._claimed:
            self._ensure()
        if self._handle is not None:
            self._handle.close()
            self._handle = None


class _SevenFactory(WriterFactory):
    def __init__(self, dest: Path, budget: ExtractBudget) -> None:
        self.dest = dest.resolve()
        self.budget = budget

    def create(self, filename: str) -> Py7zIO:
        target = Path(filename).resolve()
        try:
            target.relative_to(self.dest)
        except ValueError as exc:
            raise ArchiveError(f"Unsafe archive member path: {filename}") from exc
        return _FileSink(target, self.budget)


def _extract_rar(archive_path: Path, dest: Path, budget: ExtractBudget) -> None:
    if not rarfile.is_rarfile(archive_path):
        raise ArchiveError(f"Not a valid RAR archive: {archive_path.name}")
    try:
        with rarfile.RarFile(archive_path) as rf:
            for info in rf.infolist():
                name = info.filename
                if info.is_dir():
                    _safe_target(dest, name).mkdir(parents=True, exist_ok=True)
                    continue
                if getattr(info, "is_symlink", lambda: False)():
                    raise ArchiveError(f"Refusing symlink member in {archive_path.name}: {name}")
                target = _safe_target(dest, name)
                declared = getattr(info, "file_size", None)
                with rf.open(info) as src:
                    _stream_member(src, target, budget, declared)
    except rarfile.RarCannotExec as exc:
        raise ArchiveError(
            "RAR extraction requires UnRAR. Install UnRAR from https://www.rarlab.com/rar_add.htm "
            "and ensure UnRAR.exe is on PATH."
        ) from exc


def _extract_tar_gz(archive_path: Path, dest: Path, budget: ExtractBudget) -> None:
    with tarfile.open(archive_path, mode="r:*") as tf:
        for member in tf.getmembers():
            if member.isdir():
                _safe_target(dest, member.name).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target = _safe_target(dest, member.name)
            handle = tf.extractfile(member)
            if handle is None:
                continue
            with handle:
                _stream_member(handle, target, budget, member.size)
