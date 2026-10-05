"""Resolve application directories, temp workspace, and Desktop output path."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

from aegis.constants import WORKSPACE_DIRNAME


def application_dir() -> Path:
    """Directory that contains the executable or project root (for config.json)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def bundled_resource(name: str) -> Path | None:
    """File packed by PyInstaller --add-data (sys._MEIPASS)."""
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return None
    path = Path(meipass) / name
    return path if path.is_file() else None


def executable_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(__file__).resolve().parent.parent / "threat_scanner.py"


def temp_base() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("TEMP") or tempfile.gettempdir())
    return Path(tempfile.gettempdir())


def workspace_dir() -> Path:
    return temp_base() / WORKSPACE_DIRNAME


def prepare_workspace() -> Path:
    path = workspace_dir()
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup_workspace(path: Path | None = None) -> None:
    target = path or workspace_dir()
    shutil.rmtree(target, ignore_errors=True)


def desktop_dir() -> Path:
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import create_unicode_buffer

            buf = create_unicode_buffer(260)
            # CSIDL_DESKTOPDIRECTORY = 0x0010
            result = ctypes.windll.shell32.SHGetFolderPathW(None, 0x0010, None, 0, buf)
            if result == 0 and buf.value:
                desktop = Path(buf.value)
                if desktop.is_dir():
                    return desktop
        except Exception:
            pass
        for candidate in (
            Path.home() / "Desktop",
            Path.home() / "OneDrive" / "Desktop",
        ):
            if candidate.is_dir():
                return candidate
    desktop = Path.home() / "Desktop"
    if desktop.is_dir():
        return desktop
    return Path.home()


def open_file(path: Path) -> None:
    if os.name == "nt":
        os.startfile(path)  # type: ignore[attr-defined]
        return
    opener = shutil.which("xdg-open") or shutil.which("open")
    if opener:
        os.spawnv(os.P_NOWAIT, opener, [opener, str(path)])
