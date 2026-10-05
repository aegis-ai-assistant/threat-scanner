# Aegis Threat Scanner

Standalone Windows 11 utility that extracts archives, finds execution-vector files, looks up each file’s SHA-256 hash on VirusTotal (and optionally Hybrid Analysis or MetaDefender), and writes a Desktop HTML/RTF report of **malicious or suspicious** hits only.

This project is self-contained. It does not import or depend on any other local codebase.

## Windows 11 deployment (no Python on the target PC)

Build a single-file `ThreatScanner.exe` on this Linux machine, copy three files to a USB drive, and run the installer on Windows 11.

### 1. Cross-compile from Linux

```bash
chmod +x build_windows_exe.sh
./build_windows_exe.sh
```

The script:

1. Uses **Wine + Windows Python** when they are already installed.
2. If Wine exists but Windows Python does not, downloads a silent Python 3.12 installer into the Wine prefix.
3. Otherwise falls back to a Docker Wine/PyInstaller image (`batonogov/pyinstaller-windows`, then `cdrx/pyinstaller-windows`).

PyInstaller is invoked as a **Windows** build with:

- `--onefile` — Python runtime, dependencies, and app logic in one exe
- `--noconsole` — no console window for the GUI / Explorer context-menu launches
- `--name ThreatScanner`
- `--add-data "config.example.json;."` — bundled config template

`--cli` still works on the windowed exe: it attaches or allocates a console at runtime.

Output is staged in project-root `build_output/` (override with `OUTPUT_DIR=/build_output ./build_windows_exe.sh` if you want a filesystem-root folder).

Force Docker: `FORCE_DOCKER=1 ./build_windows_exe.sh`

### 2. USB payload

Copy everything in `build_output/` onto the USB stick:

```text
USB_DRIVE/
├── ThreatScanner.exe         (compiled binary)
├── config.json               (API keys — edit before use)
└── install_on_windows.bat    (one-click context-menu installer)
```

Edit `config.json` on the USB (or after install) and add at least a VirusTotal API key.

### 3. On the Windows 11 PC

Double-click `install_on_windows.bat` (no admin, no Python). It copies the exe and config to `%LOCALAPPDATA%\AegisThreatScanner` and registers:

- `HKCU\Software\Classes\*\shell\ThreatScanner`
- `HKCU\Software\Classes\Directory\shell\ThreatScanner`

Label: **Scan Payload with ThreatScanner**. Command: `"...\ThreatScanner.exe" "%1"`.

Uninstall the menu: `install_on_windows.bat /uninstall`

If you are already on Windows with Python, `build.bat` produces the same `build_output\` payload natively.


## What it scans

Recursive directory walks and uncompressed archives are filtered to these extensions:

`.exe` `.dll` `.bat` `.cmd` `.ps1` `.vbs` `.js` `.jse` `.wsf` `.hta` `.scr` `.pif` `.msi` `.com` `.reg` `.iso` `.img` `.lnk` `.chm` `.cpl` `.docm` `.xlsm`

Supported input archives: `.zip`, `.rar`, `.7z`, `.tar.gz`. Nested archives are extracted into a unique directory under the system temp folder (never into the original folder).

## Optional: run from source

Python 3.10+ is only needed if you are developing or running the `.py` files directly. The USB `.exe` does not require Python on Windows 11.

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
copy config.example.json config.json
```

Edit `config.json` and add at least a VirusTotal API key.

| Key | Required | Notes |
| --- | --- | --- |
| `virustotal_api_key` | Yes | [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) |
| `hybrid_analysis_api_key` | Optional | [Hybrid Analysis](https://www.hybrid-analysis.com) |
| `metadefender_api_key` | Optional | [MetaDefender Cloud](https://metadefender.opswat.com) |
| `google_api_key` | Optional | [Google AI Studio](https://aistudio.google.com/apikey) Gemini key for threat synthesis |
| `secondary_engine` | | `hybrid_analysis` (default), `metadefender`, `both`, or `none` |
| `free_tier` | | `true` enforces a 15-second pause between API calls |
| `request_delay_seconds` | | Delay used when `free_tier` is true (default `15`) |
| `vt_auto_upload` | | Upload unknown hashes to VirusTotal (default `false`, 32 MB public limit) |
| `vt_sandbox` | | Pull VirusTotal behaviour/sandbox summary (default `true`) |
| `vt_analysis_timeout_seconds` | | How long to wait after an upload (default `90`) |
| `google_model` | | Gemini model id (default `gemini-3.7-flash`, fallback `gemini-3.6-flash`) |
| `report_format` | | `html`, `rtf`, or `both` |
| `open_report` | | Open the report after a threat is found |

RAR extraction needs UnRAR on PATH ([RARLab UnRAR](https://www.rarlab.com/rar_add.htm)). ZIP, 7z, and tar.gz do not.

## Usage

```bat
python threat_scanner.py
python threat_scanner.py "D:\incoming\sample_bundle.zip"
python threat_scanner.py --cli "D:\incoming\payloads"
python threat_scanner.py --install-context-menu
python threat_scanner.py --uninstall-context-menu
```

- No arguments: GUI file/folder picker.
- A path argument (Explorer context menu or CLI): scan starts immediately.
- `--cli`: console only; prints the clean confirmation or report path.

If every hashed file is clean or unknown, and nothing failed, the tool prints:

`Scan Complete: 0 threats detected across X evaluated execution files.`

and does **not** write a report. Hash failures, skipped archives, and VirusTotal authentication errors are listed instead of that clean line, and they are included in the Desktop report. Threats are written to the Desktop as `Aegis_Threat_Report_YYYYMMDD_HHMMSS.html` and/or `.rtf`.

## Windows context menu

On a PC **without Python**, use `install_on_windows.bat` from the USB payload.

If Python is available:

```bat
python threat_scanner.py --install-context-menu
python install_menu.py --uninstall
```

This creates HKCU keys:

- `Software\Classes\*\shell\ThreatScanner`
- `Software\Classes\Directory\shell\ThreatScanner`

The frozen exe command is `ThreatScanner.exe "%1"`.

## Build ThreatScanner.exe

**From Linux (recommended for this repo):**

```bash
./build_windows_exe.sh
```

**From Windows with Python:**

```bat
build.bat
```

Then copy `build_output\` to USB, edit `config.json`, and run `install_on_windows.bat`.

Before compiling, verify live API keys:

```bash
python3 test_apis.py
```


## Workflow

1. Accept a folder or archive (CLI path or GUI picker).
2. Extract archives to a unique temp directory.
3. Collect matching payload files and compute SHA-256.
4. Query VirusTotal v3 `/api/v3/files/{hash}`. If the hash is unknown and `vt_auto_upload` is on, upload the sample, wait for analysis, then pull sandbox behaviour.
5. Query Hybrid Analysis (form-encoded `hash=`) and/or MetaDefender.
6. If `google_api_key` is set, synthesize a short defensive note for each threat.
7. Drop clean/undetected hashes from the report.
8. Write the Aegis HTML/RTF report for remaining threats.

This is a hash-lookup helper, not a local antivirus engine. Unknown hashes are treated as undetected and omitted from the report.
