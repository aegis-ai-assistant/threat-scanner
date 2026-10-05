@echo off
setlocal
cd /d "%~dp0"

python -m pip install -r requirements-build-windows.txt
if errorlevel 1 exit /b 1

python -m PyInstaller --noconfirm --clean --onefile --noconsole --name ThreatScanner ^
  --add-data "config.example.json;." ^
  --collect-submodules aegis ^
  --hidden-import tkinter ^
  --hidden-import tkinter.ttk ^
  --hidden-import tkinter.filedialog ^
  --hidden-import tkinter.messagebox ^
  --collect-all py7zr ^
  --collect-all rarfile ^
  threat_scanner.py

if not exist "build_output" mkdir build_output
copy /Y dist\ThreatScanner.exe build_output\ThreatScanner.exe >nul
copy /Y install_on_windows.bat build_output\install_on_windows.bat >nul
copy /Y config.example.json build_output\config.example.json >nul
if exist config.json (
    copy /Y config.json build_output\config.json >nul
) else (
    copy /Y config.example.json build_output\config.json >nul
)

echo.
echo Native Windows build staged in build_output\
echo Copy that folder to the USB drive, edit config.json, then run install_on_windows.bat
endlocal
