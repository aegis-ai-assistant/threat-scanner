"""Walk a directory tree and collect files matching payload extensions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegis.constants import PAYLOAD_EXTENSIONS


@dataclass(frozen=True)
class PayloadFile:
    full_path: Path
    display_name: str
    internal_path: str
    extension: str


def _is_payload(path: Path) -> bool:
    return path.suffix.lower() in PAYLOAD_EXTENSIONS


def find_payloads(scan_root: Path, path_prefix: str = "") -> list[PayloadFile]:
    found: list[PayloadFile] = []
    root_resolved = scan_root.resolve()
    for path in sorted(scan_root.rglob("*")):
        if path.is_symlink() or not path.is_file() or not _is_payload(path):
            continue
        try:
            path.resolve().relative_to(root_resolved)
        except ValueError:
            continue
        relative = path.relative_to(scan_root).as_posix()
        internal = f"{path_prefix}/{relative}" if path_prefix else relative
        found.append(
            PayloadFile(
                full_path=path,
                display_name=path.name,
                internal_path=internal,
                extension=path.suffix.lower(),
            )
        )
    return found
