@echo off
setlocal
cd /d "%~dp0"

rem Hello! needs administrator rights (TUN): re-run this script elevated
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b 0
)
if not exist "node_modules\@tauri-apps\cli\package.json" call npm install
if not exist "bin\sing-box.exe" call npm run fetch-cores
if not exist "bin\libcronet.dll" type nul > "bin\libcronet.dll"
call npx tauri dev
pause
