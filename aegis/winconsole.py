"""Attach a real console for --cli when the Windows exe is built with --noconsole."""

from __future__ import annotations

import os
import sys

attached_new_window = False
console_ready = False


def wants_cli(argv: list[str]) -> bool:
    return "--cli" in argv


def attach_if_cli(argv: list[str]) -> bool:
    """If --cli was passed on a frozen Windows build, attach or allocate a console.

    Returns True when a brand-new console window was created (caller should pause).
    """
    global attached_new_window, console_ready
    if not wants_cli(argv):
        return False
    if os.name != "nt" or not getattr(sys, "frozen", False):
        console_ready = True
        return False

    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    attach_parent = -1  # ATTACH_PARENT_PROCESS
    if kernel32.AttachConsole(attach_parent):
        _rebind_stdio()
        console_ready = True
        attached_new_window = False
        return False
    if kernel32.AllocConsole():
        _rebind_stdio()
        console_ready = True
        attached_new_window = True
        return True
    return False


def _rebind_stdio() -> None:
    sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
    sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
    sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)


def pause_if_new_console() -> None:
    if not attached_new_window:
        return
    try:
        input("\nPress Enter to close...")
    except EOFError:
        pass
