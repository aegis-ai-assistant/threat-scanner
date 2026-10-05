#!/usr/bin/env bash
# Cross-compile a standalone Windows 11 ThreatScanner.exe from Linux.
# Preference order:
#   1. Local Wine + Windows Python
#   2. Docker Wine/PyInstaller images (batonogov, then cdrx)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

OUTPUT_DIR="${OUTPUT_DIR:-$ROOT/build_output}"
PYTHON_INSTALLER_VERSION="${PYTHON_INSTALLER_VERSION:-3.12.10}"
WINEDEBUG="${WINEDEBUG:--all}"
export WINEDEBUG

PYINSTALLER_FLAGS=(
  --noconfirm
  --clean
  --onefile
  --noconsole
  --name ThreatScanner
  --add-data "config.example.json;."
  --collect-submodules aegis
  --hidden-import tkinter
  --hidden-import tkinter.ttk
  --hidden-import tkinter.filedialog
  --hidden-import tkinter.messagebox
  --collect-all py7zr
  --collect-all rarfile
  threat_scanner.py
)

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

wine_cmd() {
  if have wine64; then
    command -v wine64
  elif have wine; then
    command -v wine
  else
    return 1
  fi
}

windows_python_candidates() {
  local prefix="${WINEPREFIX:-$HOME/.wine}"
  local drive_c="$prefix/drive_c"
  cat <<EOF
${WINE_PYTHON:-}
$drive_c/Python312/python.exe
$drive_c/Python311/python.exe
$drive_c/Python310/python.exe
$drive_c/Program Files/Python312/python.exe
$drive_c/Program Files/Python311/python.exe
$drive_c/Program Files/Python310/python.exe
$drive_c/Program Files/Python/python.exe
$drive_c/users/$(whoami)/AppData/Local/Programs/Python/Python312/python.exe
$drive_c/users/$(whoami)/AppData/Local/Programs/Python/Python311/python.exe
$drive_c/users/$(whoami)/AppData/Local/Programs/Python/Python310/python.exe
EOF
}

find_wine_python() {
  local candidate
  while IFS= read -r candidate; do
    [[ -z "$candidate" ]] && continue
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done < <(windows_python_candidates)
  return 1
}

install_windows_python_into_wine() {
  local winebin="$1"
  local prefix="${WINEPREFIX:-$HOME/.wine}"
  local installer="$ROOT/.cache/python-$PYTHON_INSTALLER_VERSION-amd64.exe"
  local url="https://www.python.org/ftp/python/${PYTHON_INSTALLER_VERSION}/python-${PYTHON_INSTALLER_VERSION}-amd64.exe"
  mkdir -p "$ROOT/.cache" "$prefix"
  if [[ ! -f "$installer" ]]; then
    log "Downloading Windows Python ${PYTHON_INSTALLER_VERSION} installer"
    if have curl; then
      curl -fL --retry 3 -o "$installer" "$url"
    elif have wget; then
      wget -O "$installer" "$url"
    else
      return 1
    fi
  fi
  log "Installing Windows Python into Wine (silent)"
  local wine_installer="Z:${installer}"
  if have xvfb-run; then
    xvfb-run -a "$winebin" "$wine_installer" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_tcltk=1 Include_test=0 TargetDir="C:\\Python312"
  else
    "$winebin" "$wine_installer" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_tcltk=1 Include_test=0 TargetDir="C:\\Python312"
  fi
  find_wine_python
}

run_wine_build() {
  local winebin python_exe
  winebin="$(wine_cmd)" || return 1
  log "Found Wine: $winebin"
  python_exe="$(find_wine_python || true)"
  if [[ -z "${python_exe}" ]]; then
    log "Windows Python not found in Wine prefix; attempting silent install"
    python_exe="$(install_windows_python_into_wine "$winebin" || true)"
  fi
  [[ -n "${python_exe}" && -f "${python_exe}" ]] || return 1
  log "Using Wine Windows Python: $python_exe"

  "$winebin" "$python_exe" -m pip install --upgrade pip
  "$winebin" "$python_exe" -m pip install -r "$ROOT/requirements-build-windows.txt"
  "$winebin" "$python_exe" -m PyInstaller "${PYINSTALLER_FLAGS[@]}"
}

docker_bin() {
  if have docker; then
    command -v docker
  elif have podman; then
    command -v podman
  else
    return 1
  fi
}

run_docker_build() {
  local docker
  docker="$(docker_bin)" || return 1
  local images=(
    "${PYINSTALLER_DOCKER_IMAGE:-batonogov/pyinstaller-windows:latest}"
    "cdrx/pyinstaller-windows:python3"
    "cdrx/pyinstaller-windows:latest"
  )
  local image
  for image in "${images[@]}"; do
    log "Trying Docker image: $image"
    if ! "$docker" pull "$image"; then
      warn "Could not pull $image"
      continue
    fi
    # Default entrypoints: pip install -r requirements.txt, then build ThreatScanner.spec
    # (spec encodes --onefile --noconsole --name ThreatScanner --add-data config.example.json;.)
    if "$docker" run --rm \
      -e WINEDEBUG=-all \
      -e SPECFILE=ThreatScanner.spec \
      -v "$ROOT:/src/" \
      "$image"; then
      return 0
    fi
    warn "Spec entrypoint failed on $image; retrying explicit PyInstaller flags"
    # Single-quoted --add-data so ';' is not treated as a shell command separator.
    if "$docker" run --rm \
      -e WINEDEBUG=-all \
      -v "$ROOT:/src" \
      -w /src \
      "$image" \
      "pyinstaller --noconfirm --clean --onefile --noconsole --name ThreatScanner --add-data 'config.example.json;.' --collect-submodules aegis --hidden-import tkinter --hidden-import tkinter.ttk --hidden-import tkinter.filedialog --hidden-import tkinter.messagebox --collect-all py7zr --collect-all rarfile threat_scanner.py"; then
      return 0
    fi
    warn "Docker image $image failed"
  done
  return 1
}

stage_usb_payload() {
  local exe=""
  local candidate
  for candidate in \
    "$ROOT/dist/ThreatScanner.exe" \
    "$ROOT/dist/windows/ThreatScanner.exe" \
    "$ROOT/dist/windows/ThreatScanner/ThreatScanner.exe"
  do
    if [[ -f "$candidate" ]]; then
      exe="$candidate"
      break
    fi
  done
  if [[ -z "$exe" ]]; then
    exe="$(find "$ROOT/dist" -name 'ThreatScanner.exe' -type f 2>/dev/null | head -n 1 || true)"
  fi
  [[ -n "$exe" && -f "$exe" ]] || die "Build finished but ThreatScanner.exe was not found under dist/"

  mkdir -p "$OUTPUT_DIR"
  cp -f "$exe" "$OUTPUT_DIR/ThreatScanner.exe"
  cp -f "$ROOT/install_on_windows.bat" "$OUTPUT_DIR/install_on_windows.bat"
  cp -f "$ROOT/config.example.json" "$OUTPUT_DIR/config.example.json"
  if [[ -f "$ROOT/config.json" ]]; then
    cp -f "$ROOT/config.json" "$OUTPUT_DIR/config.json"
  else
    cp -f "$ROOT/config.example.json" "$OUTPUT_DIR/config.json"
    warn "No local config.json; copied placeholders. Edit $OUTPUT_DIR/config.json before use."
  fi
  cat > "$OUTPUT_DIR/USB_README.txt" <<'EOF'
USB payload for a Windows 11 PC that does not have Python:

  USB_DRIVE/
    ThreatScanner.exe
    config.json
    install_on_windows.bat

1. Edit config.json and add your VirusTotal API key (and optional secondary keys).
2. Right-click install_on_windows.bat -> Run as the logged-in user (HKCU, no admin).
3. That copies the exe + config into %LOCALAPPDATA%\AegisThreatScanner
   and registers "Scan Payload with ThreatScanner" on files and folders.

Uninstall the context menu:
  install_on_windows.bat /uninstall
EOF
  log "USB payload staged in $OUTPUT_DIR"
  ls -lh "$OUTPUT_DIR"
}

main() {
  [[ -f "$ROOT/threat_scanner.py" ]] || die "Run this script from the Aegis Threat Scanner repo."
  [[ -f "$ROOT/config.example.json" ]] || die "Missing config.example.json"
  mkdir -p "$OUTPUT_DIR"

  local built=0
  if [[ "${FORCE_DOCKER:-}" == "1" ]]; then
    log "FORCE_DOCKER=1 — skipping Wine"
  elif wine_cmd >/dev/null; then
    if run_wine_build; then
      built=1
    else
      warn "Wine build failed; falling back to Docker"
    fi
  else
    log "Wine not available; falling back to Docker"
  fi

  if [[ "$built" -eq 0 ]]; then
    if run_docker_build; then
      built=1
    fi
  fi

  [[ "$built" -eq 1 ]] || die "Could not cross-compile. Install Wine+Windows Python, or Docker."

  stage_usb_payload
  log "Done. Copy the contents of $OUTPUT_DIR to the USB drive."
}

main "$@"
