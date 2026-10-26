@echo off
setlocal
cd /d "%~dp0"

rem TUN needs administrator rights: re-run this script elevated
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b 0
)
set "LOG=%~dp0setup.log"
echo ==== %date% %time% > "%LOG%"

where node >> "%LOG%" 2>&1
if errorlevel 1 goto nonode
node -v >> "%LOG%" 2>&1

echo [1/4] npm install ...
if not exist "node_modules\electron\package.json" call npm install >> "%LOG%" 2>&1
if errorlevel 1 goto npmfail
if exist "node_modules\electron\dist\electron.exe" goto test
echo      downloading Electron binary ...
call node node_modules\electron\install.js >> "%LOG%" 2>&1
if not exist "node_modules\electron\dist\electron.exe" goto npmfail

:test
echo [2/4] self-test ...
call npm test >> "%LOG%" 2>&1

echo [3/4] downloading cores ...
if exist "bin\sing-box.exe" goto launch
call npm run fetch-cores >> "%LOG%" 2>&1
if errorlevel 1 echo FETCH_CORES_FAILED >> "%LOG%"

:launch
dir /b bin >> "%LOG%" 2>&1
echo [4/4] starting launcher ...
echo SETUP_DONE >> "%LOG%"
start "" /B /D "%~dp0." "%~dp0node_modules\electron\dist\electron.exe" . > "%~dp0electron.log" 2>&1
exit /b 0

:nonode
echo NODE_MISSING >> "%LOG%"
echo Node.js not found. Install Node.js 20+ from https://nodejs.org and run run.bat again.
pause
exit /b 1

:npmfail
echo NPM_INSTALL_FAILED >> "%LOG%"
echo npm install failed, see setup.log
pause
exit /b 1
