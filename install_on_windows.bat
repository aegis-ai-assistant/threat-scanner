@echo off
REM One-click installer for a Windows 11 PC that does not have Python.
REM Copies ThreatScanner.exe + config.json into %LOCALAPPDATA% and registers
REM the Explorer context menu. Run from the USB payload folder.
setlocal EnableExtensions
cd /d "%~dp0"

set "APP_NAME=Aegis Threat Scanner"
set "MENU_NAME=Scan Payload with ThreatScanner"
set "KEY_FILE=HKCU\Software\Classes\*\shell\ThreatScanner"
set "KEY_DIR=HKCU\Software\Classes\Directory\shell\ThreatScanner"
set "INSTALL_DIR=%LOCALAPPDATA%\AegisThreatScanner"

if /I "%~1"=="/uninstall" goto :uninstall
if /I "%~1"=="--uninstall" goto :uninstall
if /I "%~1"=="/u" goto :uninstall

if not exist "%~dp0ThreatScanner.exe" (
    echo ERROR: ThreatScanner.exe was not found next to this script.
    echo Place this .bat in the same USB folder as ThreatScanner.exe.
    pause
    exit /b 1
)

echo Installing %APP_NAME%
echo Destination: %INSTALL_DIR%
echo.

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /Y "%~dp0ThreatScanner.exe" "%INSTALL_DIR%\ThreatScanner.exe" >nul
if errorlevel 1 (
    echo ERROR: Could not copy ThreatScanner.exe to %INSTALL_DIR%
    pause
    exit /b 1
)

if exist "%~dp0config.json" (
    copy /Y "%~dp0config.json" "%INSTALL_DIR%\config.json" >nul
) else if exist "%~dp0config.example.json" (
    if not exist "%INSTALL_DIR%\config.json" (
        copy /Y "%~dp0config.example.json" "%INSTALL_DIR%\config.json" >nul
        echo NOTE: Copied config.example.json to config.json.
        echo       Edit API keys in:
        echo       %INSTALL_DIR%\config.json
        echo.
    )
) else (
    echo WARNING: No config.json found. Create one beside the installed exe
    echo          before scanning: %INSTALL_DIR%\config.json
    echo.
)

set "EXE=%INSTALL_DIR%\ThreatScanner.exe"

reg add "%KEY_FILE%" /ve /d "%MENU_NAME%" /f >nul
reg add "%KEY_FILE%" /v Icon /t REG_SZ /d "%EXE%" /f >nul
reg add "%KEY_FILE%\command" /ve /d "\"%EXE%\" \"%%1\"" /f >nul

reg add "%KEY_DIR%" /ve /d "%MENU_NAME%" /f >nul
reg add "%KEY_DIR%" /v Icon /t REG_SZ /d "%EXE%" /f >nul
reg add "%KEY_DIR%\command" /ve /d "\"%EXE%\" \"%%1\"" /f >nul

echo Context menu registered for files and folders:
echo   %MENU_NAME%
echo.
echo Installed files:
echo   %INSTALL_DIR%\ThreatScanner.exe
echo   %INSTALL_DIR%\config.json
echo.
echo You can unplug the USB drive. To uninstall the menu:
echo   install_on_windows.bat /uninstall
echo.
pause
exit /b 0

:uninstall
reg delete "%KEY_FILE%" /f >nul 2>&1
reg delete "%KEY_DIR%" /f >nul 2>&1
echo Removed Explorer context menu keys.
echo Left installed files in: %INSTALL_DIR%
echo Delete that folder manually if you want to remove the program.
echo.
pause
exit /b 0
