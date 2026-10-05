"""Extract zip / rar / 7z / tar.gz into a local workspace with zip-slip protection."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import py7zr
import rarfile

from aegis.constants import ARCHIVE_EXTENSIONS, MAX_ARCHIVE_DEPTH, TAR_GZ_SUFFIXES


class ArchiveError(RuntimeError):
    pass


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


def extract_archive(archive_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    kind = archive_kind(archive_path)
    if kind is None:
        raise ArchiveError(f"Unsupported archive type: {archive_path}")
    try:
        if kind == "zip":
            _extract_zip(archive_path, dest)
        elif kind == "7z":
            _extract_7z(archive_path, dest)
        elif kind == "rar":
            _extract_rar(archive_path, dest)
        elif kind == "tar.gz":
            _extract_tar_gz(archive_path, dest)
    except ArchiveError:
        raise
    except Exception as exc:
        raise ArchiveError(f"Failed to extract {archive_path.name}: {exc}") from exc


def find_archives(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and is_archive(path):
            found.append(path)
    return found


def extract_nested(root: Path, log, depth: int = 0) -> None:
    """Extract nested archives found under root, up to MAX_ARCHIVE_DEPTH."""
    if depth >= MAX_ARCHIVE_DEPTH:
        return
    nested: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and is_archive(path):
            nested.append(path)
    for archive in nested:
        out_dir = archive.parent / f"{archive.stem}_extracted"
        if out_dir.exists():
            continue
        try:
            log(f"  Extracting nested archive: {archive.name}")
            extract_archive(archive, out_dir)
            extract_nested(out_dir, log, depth + 1)
        except ArchiveError as exc:
            log(f"  Warning: skipped nested archive {archive.name}: {exc}")


def _extract_zip(archive_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                _safe_target(dest, info.filename).mkdir(parents=True, exist_ok=True)
                continue
            target = _safe_target(dest, info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, target.open("wb") as out:
                out.write(src.read())


def _extract_7z(archive_path: Path, dest: Path) -> None:
    with py7zr.SevenZipFile(archive_path, mode="r") as archive:
        names = archive.getnames()
        for name in names:
            _safe_target(dest, name)
        archive.extractall(path=dest)


def _extract_rar(archive_path: Path, dest: Path) -> None:
    if not rarfile.is_rarfile(archive_path):
        raise ArchiveError(f"Not a valid RAR archive: {archive_path.name}")
    try:
        with rarfile.RarFile(archive_path) as rf:
            for info in rf.infolist():
                name = info.filename
                if info.is_dir():
                    _safe_target(dest, name).mkdir(parents=True, exist_ok=True)
                    continue
                target = _safe_target(dest, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with rf.open(info) as src, target.open("wb") as out:
                    out.write(src.read())
    except rarfile.RarCannotExec as exc:
        raise ArchiveError(
            "RAR extraction requires UnRAR. Install UnRAR from https://www.rarlab.com/rar_add.htm "
            "and ensure UnRAR.exe is on PATH."
        ) from exc


def _extract_tar_gz(archive_path: Path, dest: Path) -> None:
    with tarfile.open(archive_path, mode="r:*") as tf:
        for member in tf.getmembers():
            target = _safe_target(dest, member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            handle = tf.extractfile(member)
            if handle is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with handle, target.open("wb") as out:
                out.write(handle.read())
