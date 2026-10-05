"""Windows HKCU context-menu registration for files and folders."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from aegis.constants import CONTEXT_MENU_KEY, CONTEXT_MENU_LABEL
from aegis.paths import executable_path


class ContextMenuError(RuntimeError):
    pass


def _command_string() -> str:
    target = executable_path()
    if getattr(sys, "frozen", False):
        return f'"{target}" "%1"'
    python = Path(sys.executable).resolve()
    return f'"{python}" "{target}" "%1"'


def install_context_menu() -> str:
    if os.name != "nt":
        raise ContextMenuError("Context menu registration is only available on Windows.")
    import winreg

    command = _command_string()
    icon = str(executable_path()) if getattr(sys, "frozen", False) else str(Path(sys.executable).resolve())
    roots = (
        r"Software\Classes\*\shell\{}".format(CONTEXT_MENU_KEY),
        r"Software\Classes\Directory\shell\{}".format(CONTEXT_MENU_KEY),
    )
    for root in roots:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, root)
        try:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, CONTEXT_MENU_LABEL)
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)
            cmd_key = winreg.CreateKey(key, "command")
            try:
                winreg.SetValueEx(cmd_key, None, 0, winreg.REG_SZ, command)
            finally:
                winreg.CloseKey(cmd_key)
        finally:
            winreg.CloseKey(key)
    return command


def uninstall_context_menu() -> None:
    if os.name != "nt":
        raise ContextMenuError("Context menu removal is only available on Windows.")
    import winreg

    paths = (
        rf"Software\Classes\*\shell\{CONTEXT_MENU_KEY}\command",
        rf"Software\Classes\*\shell\{CONTEXT_MENU_KEY}",
        rf"Software\Classes\Directory\shell\{CONTEXT_MENU_KEY}\command",
        rf"Software\Classes\Directory\shell\{CONTEXT_MENU_KEY}",
    )
    for path in paths:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ContextMenuError(f"Could not remove registry key {path}: {exc}") from exc
