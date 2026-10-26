@echo off
rem No EnableDelayedExpansion here: it eats the "!" in "Hello!" file names.
setlocal
cd /d "%~dp0"
set "LOG=%~dp0build.log"
echo ==== %date% %time% > "%LOG%"

echo [1/6] checking tools ...
where node >nul 2>&1
if errorlevel 1 (
  echo   Node.js not found. Install: winget install OpenJS.NodeJS.LTS
  echo NODE_MISSING >> "%LOG%"
  goto fail
)
where cargo >nul 2>&1
if errorlevel 1 (
  echo   Rust not found. Install: winget install Rustlang.Rustup
  echo RUST_MISSING >> "%LOG%"
  goto fail
)
rustup show active-toolchain >> "%LOG%" 2>&1
rustup show active-toolchain 2>nul | findstr /i "msvc" >nul
if errorlevel 1 (
  echo   Rust toolchain must be MSVC. Run: rustup default stable-x86_64-pc-windows-msvc
  echo RUST_NOT_MSVC >> "%LOG%"
  goto fail
)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSPATH="
if exist "%VSWHERE%" for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%I"
if not defined VSPATH (
  echo   Visual Studio C++ Build Tools not found. Install:
  echo   winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
  echo VS_BUILDTOOLS_MISSING >> "%LOG%"
  goto fail
)
echo   VS: %VSPATH% >> "%LOG%"
node -v >> "%LOG%" 2>&1
cargo -V >> "%LOG%" 2>&1

echo [2/6] npm install ...
if not exist "node_modules\@tauri-apps\cli\package.json" call npm install >> "%LOG%" 2>&1
if not exist "node_modules\@tauri-apps\cli\package.json" goto fail

echo [3/6] sing-box ...
if not exist "bin\sing-box.exe" call npm run fetch-cores >> "%LOG%" 2>&1
if not exist "bin\sing-box.exe" goto fail
if not exist "bin\libcronet.dll" type nul > "bin\libcronet.dll"

echo [4/6] tests ...
call cargo test -p hello-core >> "%LOG%" 2>&1
if errorlevel 1 goto fail

echo [5/6] building (first time 5-15 min) ...
if exist "target\release\bundle\nsis" rmdir /s /q "target\release\bundle\nsis"
call npx tauri build >> "%LOG%" 2>&1
if errorlevel 1 goto fail

echo [6/6] packaging ...
for /f "delims=" %%V in ('node -p "const v=require('./version.json');v.displayVersion+'-b'+v.buildNumber"') do set "VER=%%V"
set "OUTDIR=%~dp0release\%VER%"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
set "SETUP="
for %%F in ("target\release\bundle\nsis\*-setup.exe") do set "SETUP=%%~fF"
if not defined SETUP goto fail
copy /y "%SETUP%" "%OUTDIR%\Hello-Setup-%VER%-win-x64.exe" >nul

set "PORT=%TEMP%\hello-portable-%RANDOM%"
mkdir "%PORT%\bin"
copy /y "target\release\Hello.exe" "%PORT%\Hello.exe" >nul
copy /y "bin\sing-box.exe" "%PORT%\bin\" >nul
if exist "bin\libcronet.dll" copy /y "bin\libcronet.dll" "%PORT%\bin\" >nul
if exist "%OUTDIR%\Hello-%VER%-win-x64-portable.zip" del "%OUTDIR%\Hello-%VER%-win-x64-portable.zip"
powershell -NoProfile -Command "Compress-Archive -Path '%PORT%\*' -DestinationPath '%OUTDIR%\Hello-%VER%-win-x64-portable.zip'" >> "%LOG%" 2>&1
rmdir /s /q "%PORT%"

echo.
echo   done: %OUTDIR%
echo BUILD_OK >> "%LOG%"
explorer "%OUTDIR%"
timeout /t 5 >nul
exit /b 0

:fail
echo BUILD_FAILED >> "%LOG%"
echo.
echo Build failed, see build.log
pause
exit /b 1
