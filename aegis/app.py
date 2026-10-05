"""CLI and GUI entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegis.checkpoint import PHASE_AI, clear_checkpoint, load_checkpoint, same_target
from aegis.config import ConfigError, load_config
from aegis.constants import APP_NAME, APP_VERSION
from aegis.context_menu import ContextMenuError, install_context_menu, uninstall_context_menu
from aegis.paths import open_file
from aegis.scan import ScanPaused, run_scan
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
    resume = _cli_resume_choice(target)
    if resume is None:
        return 0
    try:
        result = run_scan(target, config, log=print, resume=resume, on_extract_limit=_cli_ignore_limit)
    except ScanPaused as exc:
        _emit(str(exc), error=True)
        return 3
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        _emit(str(exc), error=True)
        return 1
    if result.ai_pending:
        _emit(
            "The plain-English summary did not complete. "
            "The report marks that explanation as failed. "
            "Run this scan again and choose to retry it."
        )
        if config.open_report and result.report_paths:
            try:
                open_file(result.report_paths[0])
            except OSError:
                pass
        return 0
    if result.clean_message:
        return 0
    if config.open_report and result.report_paths:
        try:
            open_file(result.report_paths[0])
        except OSError:
            pass
    return 0


def _cli_resume_choice(target: Path) -> bool | None:
    """Return True to continue, False to start over, or None to leave the saved scan alone."""
    saved = load_checkpoint()
    if saved is None:
        return False
    resolved = target.expanduser()
    if not same_target(saved.target, resolved):
        _emit(
            f"A saved scan of {saved.target} is unfinished.\n"
            "Restart discards it and scans the path you passed. Continue keeps the saved scan."
        )
        answer = _prompt("Restart and scan this target instead? [y/N] ")
        if answer.lower().startswith("y"):
            clear_checkpoint()
            return False
        _emit("Left the saved scan in place.")
        return None
    if saved.phase == PHASE_AI:
        _emit("File lookups finished. The plain-English summary did not complete.")
        answer = _prompt("Retry AI summary now? [Y/n] ")
        if answer.lower().startswith("n"):
            _emit("Saved scan kept. Start again and use Retry AI summary.")
            return None
        return True
    reason = saved.stopped_reason or "The scan stopped before it finished."
    total = saved.payload_count or saved.completed_count
    _emit(f"{reason}\n{saved.completed_count} of {total} file(s) already checked.")
    answer = _prompt("Continue or Restart? [C/r] ")
    if answer.lower().startswith("r"):
        clear_checkpoint()
        return False
    return True


def _cli_ignore_limit(message: str) -> bool:
    _emit(message)
    _emit("Ignoring the cap extracts the archive anyway and can use a lot of disk space.")
    answer = _prompt("Ignore the extraction cap? [y/N] ")
    return answer.lower().startswith("y")


def _prompt(text: str) -> str:
    if not sys.stdin or not sys.stdin.isatty():
        return ""
    try:
        return input(text).strip()
    except EOFError:
        return ""


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
