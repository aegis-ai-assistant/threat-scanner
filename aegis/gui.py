"""Tkinter file/folder picker, live scan log, and ETA status bar."""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from aegis.checkpoint import PHASE_AI, PHASE_SCANNING, clear_checkpoint, load_checkpoint, same_target
from aegis.config import AppConfig, ConfigError, load_config
from aegis.constants import APP_NAME, APP_VERSION
from aegis.paths import open_file
from aegis.scan import ScanPaused, ScanResult, complete_saved_ai, run_scan

ARCHIVE_TYPES = [
    ("Archives and all files", "*.zip *.rar *.7z *.tgz *"),
    ("ZIP", "*.zip"),
    ("RAR", "*.rar"),
    ("7z", "*.7z"),
    ("gzip tarball", "*.tar.gz *.tgz"),
    ("All files", "*.*"),
]


class ScannerApp:
    def __init__(self, root: tk.Tk, initial_target: Path | None = None) -> None:
        self.root = root
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.minsize(780, 540)
        self.root.geometry("920x620")
        self._queue: queue.Queue[tuple] = queue.Queue()
        self._busy = False
        self._eta_anchor = 0.0
        self._eta_seconds = 0.0
        self._initial_target = initial_target
        self.target_var = tk.StringVar(value=str(initial_target) if initial_target else "")
        self.status_var = tk.StringVar(value="Select a folder or archive, then start the scan.")
        self.counter_var = tk.StringVar(value="0 / 0")
        self.eta_var = tk.StringVar(value="ETA: --:--")
        self.bar_status_var = tk.StringVar(value="Idle")

        self._build()
        self.root.after(120, self._drain_queue)
        self.root.after(200, self._tick_eta)
        self.root.after(250, self._offer_saved_work)

    def _build(self) -> None:
        pad = {"padx": 12, "pady": 8}
        header = ttk.Frame(self.root)
        header.pack(fill="x", **pad)
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            header,
            text="Extract archives, hash execution vectors, and look up SHA-256 threat intel.",
        ).pack(anchor="w")

        row = ttk.Frame(self.root)
        row.pack(fill="x", padx=12)
        ttk.Label(row, text="Target").pack(side="left")
        entry = ttk.Entry(row, textvariable=self.target_var)
        entry.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row, text="File / Archive…", command=self._pick_file).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Folder…", command=self._pick_folder).pack(side="left")

        actions = ttk.Frame(self.root)
        actions.pack(fill="x", padx=12, pady=10)
        self.scan_btn = ttk.Button(actions, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.extra_actions = ttk.Frame(actions)
        self.extra_actions.pack(side="left")
        self.continue_btn = ttk.Button(self.extra_actions, text="Continue", command=self.continue_scan)
        self.restart_btn = ttk.Button(self.extra_actions, text="Restart", command=self.restart_saved)
        self.ai_btn = ttk.Button(self.extra_actions, text="Retry AI summary", command=self.retry_ai)
        ttk.Label(actions, textvariable=self.status_var).pack(side="left", padx=12)

        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.log = tk.Text(log_frame, wrap="word", height=18, font=("Consolas", 10), state="disabled")
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        status = ttk.Frame(self.root, padding=(12, 4, 12, 12))
        status.pack(fill="x", side="bottom")
        meta = ttk.Frame(status)
        meta.pack(fill="x")
        ttk.Label(meta, textvariable=self.counter_var, width=12).pack(side="left")
        ttk.Label(meta, textvariable=self.eta_var, width=14).pack(side="left", padx=(8, 12))
        ttk.Label(meta, textvariable=self.bar_status_var).pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(status, mode="determinate", maximum=100, value=0)
        self.progress.pack(fill="x", pady=(6, 0))

    def _pick_file(self) -> None:
        chosen = filedialog.askopenfilename(title="Select archive or file", filetypes=ARCHIVE_TYPES)
        if chosen:
            self.target_var.set(chosen)

    def _pick_folder(self) -> None:
        chosen = filedialog.askdirectory(title="Select folder to scan")
        if chosen:
            self.target_var.set(chosen)

    def _append(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _refresh_saved_actions(self) -> None:
        for button in (self.continue_btn, self.restart_btn, self.ai_btn):
            button.pack_forget()
        saved = load_checkpoint()
        if saved is None or self._busy:
            return
        if saved.phase == PHASE_SCANNING:
            self.continue_btn.pack(side="left", padx=(8, 0))
        self.restart_btn.pack(side="left", padx=(8, 0))
        if saved.phase == PHASE_AI:
            self.ai_btn.pack(side="left", padx=(8, 0))

    def _set_busy(self, busy: bool, status: str) -> None:
        self._busy = busy
        self.scan_btn.configure(state="disabled" if busy else "normal")
        if busy:
            for button in (self.continue_btn, self.restart_btn, self.ai_btn):
                button.pack_forget()
        else:
            self._refresh_saved_actions()
        self.status_var.set(status)

    def _offer_saved_work(self) -> None:
        saved = load_checkpoint()
        self._refresh_saved_actions()
        if saved is None:
            if self._initial_target is not None:
                self.start_scan(resume=False)
            return
        self.target_var.set(saved.target)
        if saved.phase == PHASE_AI:
            self.status_var.set("File lookups finished. The plain-English summary did not complete.")
            self.bar_status_var.set("Waiting on the plain-English summary")
            self._append(
                "A previous scan finished every file lookup. "
                "The plain-English summary did not complete. Use Retry AI summary."
            )
            other = self._initial_target
            if other is not None and not same_target(saved.target, other):
                choice = ask_continue_or_restart(
                    self.root,
                    f"A plain-English summary is still waiting for:\n{saved.target}\n\n"
                    f"Retry that summary, or Restart and scan:\n{other}",
                    continue_label="Retry AI summary",
                )
                if choice == "continue":
                    self.retry_ai()
                elif choice == "restart":
                    clear_checkpoint()
                    self.target_var.set(str(other))
                    self._refresh_saved_actions()
                    self.start_scan(resume=False)
                return
            messagebox.showinfo(
                APP_NAME,
                "File lookups already finished.\n\n"
                "The plain-English summary did not complete. "
                "Use Retry AI summary to try again.",
            )
            return
        choice = self._ask_scan_choice(saved, self._initial_target)
        if choice == "continue":
            self.start_scan(resume=True)
        elif choice == "restart":
            clear_checkpoint()
            self._refresh_saved_actions()
            if self._initial_target is not None:
                self.target_var.set(str(self._initial_target))
                self.start_scan(resume=False)
            else:
                self.status_var.set("Saved scan discarded. Choose a target and start the scan.")

    def _ask_scan_choice(self, saved, other: Path | None) -> str | None:
        done = saved.completed_count
        total = saved.payload_count or done
        reason = saved.stopped_reason or "The scan stopped before it finished."
        if other is not None and not same_target(saved.target, other):
            message = (
                f"A scan of this path stopped before it finished:\n{saved.target}\n\n"
                f"{done} of {total} file(s) already checked.\n{reason}\n\n"
                f"Continue that scan, or Restart and scan:\n{other}"
            )
        else:
            message = (
                f"A scan of this path stopped before it finished:\n{saved.target}\n\n"
                f"{done} of {total} file(s) already checked.\n{reason}\n\n"
                "Continue resumes at the next file. Restart discards that progress."
            )
        return ask_continue_or_restart(self.root, message)

    def continue_scan(self) -> None:
        self.start_scan(resume=True)

    def restart_saved(self) -> None:
        if self._busy:
            return
        if load_checkpoint() is None:
            return
        if not messagebox.askyesno(APP_NAME, "Discard the saved scan and start over?"):
            return
        clear_checkpoint()
        self._refresh_saved_actions()
        self.status_var.set("Saved scan discarded.")
        raw = self.target_var.get().strip().strip('"')
        if raw and Path(raw).exists():
            self.start_scan(resume=False)

    def retry_ai(self) -> None:
        if self._busy:
            return
        saved = load_checkpoint()
        if saved is None or saved.phase != PHASE_AI:
            messagebox.showinfo(APP_NAME, "No plain-English summary is waiting to be retried.")
            return
        try:
            config = load_config()
        except ConfigError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.target_var.set(saved.target)
        self._begin_worker("Retrying the plain-English summary…", lambda log, _progress: complete_saved_ai(config, log), config)

    def start_scan(self, resume: bool = False) -> None:
        if self._busy:
            return
        if not resume:
            saved = load_checkpoint()
            if saved is not None and saved.phase == PHASE_AI:
                messagebox.showinfo(
                    APP_NAME,
                    "File lookups for the saved scan already finished.\n\n"
                    "Use Retry AI summary to try the plain-English explanation again, "
                    "or Restart to discard the saved scan.",
                )
                return
            if saved is not None and saved.phase == PHASE_SCANNING:
                choice = self._ask_scan_choice(saved, None)
                if choice == "continue":
                    resume = True
                elif choice == "restart":
                    clear_checkpoint()
                    self._refresh_saved_actions()
                else:
                    return
        if resume:
            saved = load_checkpoint()
            if saved is None:
                messagebox.showerror(APP_NAME, "No saved scan to continue.")
                return
            if saved.phase == PHASE_AI:
                self.retry_ai()
                return
            target = Path(saved.target)
            self.target_var.set(str(target))
        else:
            raw = self.target_var.get().strip().strip('"')
            if not raw:
                messagebox.showwarning(APP_NAME, "Choose a file, archive, or folder first.")
                return
            target = Path(raw)
        if not target.exists():
            messagebox.showerror(APP_NAME, f"Path not found:\n{target}")
            return
        try:
            config = load_config()
        except ConfigError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        def work(log, progress) -> ScanResult:
            return run_scan(target, config, log, progress=progress, resume=resume)

        self._begin_worker("Scanning…", work, config)

    def _begin_worker(self, status: str, work, config: AppConfig) -> None:
        self._set_busy(True, status)
        self.bar_status_var.set(status)
        self.counter_var.set("0 / 0")
        self.eta_var.set("ETA: --:--")
        self.progress.configure(value=0)
        self._eta_seconds = 0.0
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

        def worker() -> None:
            def log(line: str) -> None:
                self._queue.put(("log", line))

            def progress(event: dict) -> None:
                self._queue.put(("progress", event))

            try:
                result = work(log, progress)
                self._queue.put(("done", result, config))
            except ScanPaused as exc:
                self._queue.put(("paused", str(exc)))
            except Exception as exc:
                self._queue.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_progress(self, event: dict) -> None:
        total = int(event.get("total") or 0)
        index = int(event.get("index") or 0)
        self.counter_var.set(f"{index} / {total}")
        self.progress.configure(maximum=max(total, 1), value=index)
        status = str(event.get("status") or "")
        if status:
            self.bar_status_var.set(status)
        eta = event.get("eta_seconds")
        if eta is not None:
            self._eta_seconds = max(float(eta), 0.0)
            self._eta_anchor = time.monotonic()
            self._render_eta(self._eta_seconds)

    def _render_eta(self, seconds: float) -> None:
        whole = max(int(seconds), 0)
        self.eta_var.set(f"ETA: {whole // 60:02d}:{whole % 60:02d}")

    def _tick_eta(self) -> None:
        if self._busy and self._eta_seconds > 0 and self._eta_anchor:
            remaining = max(self._eta_seconds - (time.monotonic() - self._eta_anchor), 0.0)
            self._render_eta(remaining)
        self.root.after(200, self._tick_eta)

    def _drain_queue(self) -> None:
        try:
            while True:
                item = self._queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._append(item[1])
                elif kind == "progress":
                    self._apply_progress(item[1])
                elif kind == "paused":
                    self._set_busy(False, "Scan paused.")
                    self.bar_status_var.set("Scan paused")
                    self.eta_var.set("ETA: --:--")
                    self._append(item[1])
                    saved = load_checkpoint()
                    if saved is not None and saved.phase == PHASE_SCANNING:
                        choice = self._ask_scan_choice(saved, None)
                        if choice == "continue":
                            self.start_scan(resume=True)
                        elif choice == "restart":
                            clear_checkpoint()
                            self._refresh_saved_actions()
                            self.status_var.set("Saved scan discarded.")
                elif kind == "error":
                    self._set_busy(False, "Scan failed.")
                    self.bar_status_var.set("Scan failed")
                    self.eta_var.set("ETA: --:--")
                    self._append(f"ERROR: {item[1]}")
                    messagebox.showerror(APP_NAME, item[1])
                elif kind == "done":
                    self._set_busy(False, self.status_var.get())
                    result: ScanResult = item[1]
                    config: AppConfig = item[2]
                    self.progress.configure(value=self.progress.cget("maximum"))
                    self.eta_var.set("ETA: 00:00")
                    self._finish(result, config)
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    def _finish(self, result: ScanResult, config: AppConfig) -> None:
        self._refresh_saved_actions()
        if result.ai_pending:
            self.status_var.set("File lookups finished. The plain-English summary did not complete.")
            self.bar_status_var.set("Waiting on the plain-English summary")
            messagebox.showwarning(
                APP_NAME,
                "The plain-English summary did not complete.\n\nUse Retry AI summary to try again.",
            )
            return
        text = result.dialog_text()
        headline = text.splitlines()[0]
        self.status_var.set(headline)
        self.bar_status_var.set(headline)
        if result.clean_message and not result.errors:
            messagebox.showinfo(APP_NAME, text)
            return
        if result.report_paths:
            self._append("Open the report from your Desktop, or click OK to open it now.")
            if config.open_report:
                try:
                    open_file(result.report_paths[0])
                except OSError:
                    pass
        messagebox.showwarning(APP_NAME, text)


def ask_continue_or_restart(
    parent: tk.Misc,
    message: str,
    *,
    continue_label: str = "Continue",
    restart_label: str = "Restart",
) -> str | None:
    dialog = tk.Toplevel(parent)
    dialog.title(APP_NAME)
    dialog.transient(parent)
    dialog.resizable(False, False)
    choice: dict[str, str | None] = {"value": None}

    frame = ttk.Frame(dialog, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=message, wraplength=460, justify="left").pack(anchor="w")
    buttons = ttk.Frame(frame)
    buttons.pack(anchor="e", pady=(16, 0))

    def choose(value: str) -> None:
        choice["value"] = value
        dialog.destroy()

    ttk.Button(buttons, text=continue_label, command=lambda: choose("continue")).pack(side="left", padx=(0, 8))
    ttk.Button(buttons, text=restart_label, command=lambda: choose("restart")).pack(side="left")
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    dialog.update_idletasks()
    parent.wait_window(dialog)
    return choice["value"]


def launch_gui(initial_target: Path | None = None) -> None:
    try:
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")
    except tk.TclError:
        pass
    ScannerApp(root, initial_target=initial_target)
    root.mainloop()
