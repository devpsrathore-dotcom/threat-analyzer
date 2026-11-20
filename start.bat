@echo off
REM ---------------------------------------------------------------------------
REM  THREAT ANALYZER - one-click launcher (Windows)
REM
REM  Double-click this file. It will:
REM    1. reuse an instance that is already running, or
REM    2. build the C++ program if the .exe is missing or older than the sources,
REM    3. start the Crow web server on http://localhost:18080,
REM    4. open the dashboard in your default browser once the server is ready.
REM
REM  Keep this window open while you use the app.
REM  Stop it with stop.bat, Ctrl+C in this window, or by closing this window.
REM ---------------------------------------------------------------------------
setlocal
title THREAT ANALYZER - server
cd /d "%~dp0"

set "PORT=18080"
set "URL=http://localhost:%PORT%"
set "EXE=%~dp0build\threat_analyzer.exe"

set "MINGW=C:\msys64\ucrt64\bin"
if exist "%MINGW%\g++.exe" set "PATH=%MINGW%;%PATH%"

echo.
echo  ==========================================================
echo    THREAT ANALYZER launcher
echo    Dashboard URL:  %URL%
echo  ==========================================================
echo.

REM --- 1. Already running? Just open the browser. ----------------------------
where curl.exe >nul 2>nul && (
  curl.exe -s -m 2 "http://127.0.0.1:%PORT%/api/health" 2>nul | findstr /C:"THREAT ANALYZER" >nul && (
    echo  [ok]  THREAT ANALYZER is already running.
    echo        Opening %URL% in your default browser...
    start "" "%URL%"
    echo.
    echo  Run stop.bat to stop the server.
    ping -n 4 127.0.0.1 >nul
    exit /b 0
  )
)

REM --- 2. Build if necessary -------------------------------------------------
set "NEEDBUILD="
if not exist "%EXE%" (
  set "NEEDBUILD=1"
  echo  [build] No executable yet - building THREAT ANALYZER ^(about 30 seconds^)...
) else (
  powershell -NoProfile -Command "$t=(Get-Item -LiteralPath '%EXE%').LastWriteTime; if (Get-ChildItem -LiteralPath 'src' -File | Where-Object { $_.LastWriteTime -gt $t }) { exit 1 }" >nul 2>nul
  if errorlevel 1 (
    set "NEEDBUILD=1"
    echo  [build] Source files changed - rebuilding...
  )
)

if defined NEEDBUILD (
  call "%~dp0build.bat"
  if errorlevel 1 (
    echo.
    echo  [error] The build failed. See the messages above.
    echo          Requirements: MSYS2 UCRT64 g++ in C:\msys64\ucrt64\bin
    echo          ^(see README.md, section "Web dashboard"^).
    echo.
    pause
    exit /b 1
  )
  cd /d "%~dp0"
  echo.
) else (
  echo  [build] Up to date: %EXE%
)

REM --- 3. Launch the web server (it opens the browser when ready) ------------
echo  [run]  Starting server on %URL%
echo         The dashboard opens automatically in your default browser.
echo         If it does not, open %URL% manually.

"%EXE%" serve --port %PORT% --strict-port --web "%~dp0web" --rules "%~dp0rules\signatures.txt"
set "RC=%errorlevel%"

echo.
if not "%RC%"=="0" (
  echo  [error] THREAT ANALYZER exited with code %RC%. See the messages above.
  pause
  exit /b %RC%
)
echo  THREAT ANALYZER has stopped.
ping -n 3 127.0.0.1 >nul
exit /b 0
