"""Tkinter file/folder picker, live scan log, and ETA status bar."""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from aegis.config import AppConfig, ConfigError, load_config
from aegis.constants import APP_NAME, APP_VERSION
from aegis.paths import open_file
from aegis.scan import ScanResult, run_scan

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
        self.target_var = tk.StringVar(value=str(initial_target) if initial_target else "")
        self.status_var = tk.StringVar(value="Select a folder or archive, then start the scan.")
        self.counter_var = tk.StringVar(value="0 / 0")
        self.eta_var = tk.StringVar(value="ETA: --:--")
        self.bar_status_var = tk.StringVar(value="Idle")

        self._build()
        self.root.after(120, self._drain_queue)
        self.root.after(200, self._tick_eta)
        if initial_target is not None:
            self.root.after(250, self.start_scan)

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

    def start_scan(self) -> None:
        if self._busy:
            return
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

        self._busy = True
        self.scan_btn.configure(state="disabled")
        self.status_var.set("Scanning…")
        self.bar_status_var.set("Starting scan…")
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
                result = run_scan(target, config, log, progress=progress)
                self._queue.put(("done", result, config))
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
                elif kind == "error":
                    self._busy = False
                    self.scan_btn.configure(state="normal")
                    self.status_var.set("Scan failed.")
                    self.bar_status_var.set("Scan failed")
                    self.eta_var.set("ETA: --:--")
                    self._append(f"ERROR: {item[1]}")
                    messagebox.showerror(APP_NAME, item[1])
                elif kind == "done":
                    self._busy = False
                    self.scan_btn.configure(state="normal")
                    result: ScanResult = item[1]
                    config: AppConfig = item[2]
                    self.progress.configure(value=self.progress.cget("maximum"))
                    self.eta_var.set("ETA: 00:00")
                    self._finish(result, config)
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    def _finish(self, result: ScanResult, config: AppConfig) -> None:
        if result.clean_message:
            self.status_var.set(result.clean_message)
            self.bar_status_var.set(result.clean_message)
            messagebox.showinfo(APP_NAME, result.clean_message)
            return
        summary = (
            f"Scan complete: {result.threat_count} threat(s) across "
            f"{result.evaluated} evaluated execution files."
        )
        self.status_var.set(summary)
        self.bar_status_var.set(summary)
        if result.report_paths:
            self._append("Open the report from your Desktop, or click OK to open it now.")
            if config.open_report:
                try:
                    open_file(result.report_paths[0])
                except OSError:
                    pass
        messagebox.showwarning(APP_NAME, summary)


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
