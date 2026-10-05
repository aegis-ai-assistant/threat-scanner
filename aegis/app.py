"""CLI and GUI entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegis.config import ConfigError, load_config
from aegis.constants import APP_NAME, APP_VERSION
from aegis.context_menu import ContextMenuError, install_context_menu, uninstall_context_menu
from aegis.paths import open_file
from aegis.scan import run_scan
from aegis import winconsole


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ThreatScanner",
        description=(
            "Extract archives, identify execution-vector files, look up SHA-256 hashes "
            "on VirusTotal and a secondary intel API, and write an HTML/RTF report."
        ),
    )
    parser.add_argument("target", nargs="?", help="File, folder, or archive to scan")
    parser.add_argument("--cli", action="store_true", help="Force console mode (no GUI window)")
    parser.add_argument(
        "--install-context-menu",
        action="store_true",
        help="Register the Windows Explorer right-click item (HKCU)",
    )
    parser.add_argument(
        "--uninstall-context-menu",
        action="store_true",
        help="Remove the Windows Explorer right-click item",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    winconsole.attach_if_cli(argv_list)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.install_context_menu:
        try:
            command = install_context_menu()
        except ContextMenuError as exc:
            _emit(str(exc), error=True)
            return 1
        _emit(f'Registered "{APP_NAME}" context menu.\nCommand: {command}')
        return 0

    if args.uninstall_context_menu:
        try:
            uninstall_context_menu()
        except ContextMenuError as exc:
            _emit(str(exc), error=True)
            return 1
        _emit("Removed ThreatScanner context menu keys from HKCU.")
        return 0

    target = Path(args.target).expanduser() if args.target else None
    if args.cli:
        if target is None:
            _emit("Pass a target path when using --cli, or omit --cli to open the file picker.", error=True)
            winconsole.pause_if_new_console()
            return 2
        code = _run_cli(target)
        winconsole.pause_if_new_console()
        return code

    if _gui_available():
        from aegis.gui import launch_gui

        launch_gui(initial_target=target)
        return 0

    if target is None:
        _emit("Tkinter GUI is unavailable. Re-run with a target path and --cli.", error=True)
        return 2
    return _run_cli(target)


def _run_cli(target: Path) -> int:
    try:
        config = load_config()
    except ConfigError as exc:
        _emit(str(exc), error=True)
        return 2
    try:
        result = run_scan(target, config, log=print)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        _emit(str(exc), error=True)
        return 1
    if result.clean_message:
        return 0
    if config.open_report and result.report_paths:
        try:
            open_file(result.report_paths[0])
        except OSError:
            pass
    return 0


def _gui_available() -> bool:
    try:
        import tkinter  # noqa: F401
    except Exception:
        return False
    return True


def _emit(message: str, error: bool = False) -> None:
    if not getattr(sys, "frozen", False) or winconsole.console_ready:
        stream = sys.stderr if error else sys.stdout
        print(message, file=stream)
        return
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        if error:
            messagebox.showerror(APP_NAME, message)
        else:
            messagebox.showinfo(APP_NAME, message)
        root.destroy()
    except Exception:
        stream = sys.stderr if error else sys.stdout
        try:
            print(message, file=stream)
        except OSError:
            pass
