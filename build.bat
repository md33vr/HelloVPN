@echo off
setlocal
cd /d "%~dp0"

rem electron-builder unpacks tools with symlinks: needs administrator rights
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b 0
)

set "LOG=%~dp0build.log"
echo ==== %date% %time% > "%LOG%"
set CSC_IDENTITY_AUTO_DISCOVERY=false

where node >> "%LOG%" 2>&1
if errorlevel 1 (
  echo Node.js not found. Install Node.js 22+ from https://nodejs.org
  echo NODE_MISSING >> "%LOG%"
  pause
  exit /b 1
)

echo [1/5] npm install ...
call npm install >> "%LOG%" 2>&1
if errorlevel 1 goto fail
if not exist "node_modules\electron\dist\electron.exe" call node node_modules\electron\install.js >> "%LOG%" 2>&1

echo [2/5] self-test ...
call npm test >> "%LOG%" 2>&1
if errorlevel 1 goto fail

echo [3/5] cores ...
if not exist "bin\sing-box.exe" call npm run fetch-cores >> "%LOG%" 2>&1
if not exist "bin\sing-box.exe" goto fail

echo [4/5] building installer (2-5 min) ...
call npm run dist >> "%LOG%" 2>&1
if errorlevel 1 goto fail
set "OUT="
for /f "delims=" %%F in ('dir /b /s /o:d "release\Hello-Setup-*.exe" 2^>nul') do set "OUT=%%F"
if not defined OUT goto fail

set "ZIP="
for /f "delims=" %%F in ('dir /b /s /o:d "release\Hello-*-portable.zip" 2^>nul') do set "ZIP=%%F"
echo [5/5] done:
echo      %OUT%
if defined ZIP echo      %ZIP%
echo BUILD_OK >> "%LOG%"
explorer /select,"%OUT%"
timeout /t 5 >nul
exit /b 0

:fail
echo BUILD_FAILED >> "%LOG%"
echo Build failed, see build.log
pause
exit /b 1
