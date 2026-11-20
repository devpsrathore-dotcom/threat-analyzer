@echo off
REM ---------------------------------------------------------------------------
REM  THREAT ANALYZER - build with MinGW g++ only (no CMake / Ninja required)
REM
REM  Usage:  build.bat          compile, link and run the self-test
REM          build.bat clean    delete compiled files
REM
REM  Needs MSYS2 MinGW-w64 UCRT64 g++ (default: C:\msys64\ucrt64\bin).
REM  Crow and Asio are vendored in third_party\ so the build works offline.
REM ---------------------------------------------------------------------------
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "MINGW=C:\msys64\ucrt64\bin"
if exist "%MINGW%\g++.exe" set "PATH=%MINGW%;%PATH%"

where g++ >nul 2>nul || (
  echo [error] g++ not found. Install MSYS2 from https://www.msys2.org and, in the
  echo         "MSYS2 UCRT64" shell, run:  pacman -S --needed mingw-w64-ucrt-x86_64-gcc
  exit /b 1
)
if not exist "third_party\crow\include\crow.h" (
  echo [error] third_party\crow is missing.
  exit /b 1
)

set "OBJ=build\obj"
if /I "%~1"=="clean" (
  if exist "%OBJ%" rmdir /s /q "%OBJ%"
  del /q build\threat_analyzer.exe 2>nul
  echo Cleaned.
  exit /b 0
)
if not exist "%OBJ%" mkdir "%OBJ%"

set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -Wpedantic"
set "DEFS=-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 -DASIO_STANDALONE -DCROW_DISABLE_STATIC_DIR"
set "INC=-Isrc -Ithird_party/crow/include -Ithird_party/asio/include"
set "LIBS=-static -pthread -liphlpapi -ladvapi32 -lshell32 -lwintrust -lws2_32 -lmswsock"

echo.
echo  THREAT ANALYZER build
echo  ----------------------------------------------

REM --- compile both sources in parallel ----------------------------------------
del /q "%OBJ%\*.done" "%OBJ%\*.failed" "%OBJ%\*.log" 2>nul
for %%f in (src\threat_analyzer.cpp src\web_server.cpp) do (
  echo  [c++] %%f
  start "" /b cmd /c "g++ %CXXFLAGS% %DEFS% %INC% -c %%f -o %OBJ%\%%~nf.o 2> %OBJ%\%%~nf.log && (echo ok> %OBJ%\%%~nf.done) || (echo fail> %OBJ%\%%~nf.failed)"
)

:wait
set /a FINISHED=0
for %%x in ("%OBJ%\*.done" "%OBJ%\*.failed") do set /a FINISHED+=1
if !FINISHED! LSS 2 (
  ping -n 2 127.0.0.1 >nul
  goto wait
)

set "FAILED="
for %%x in ("%OBJ%\*.failed") do (
  set "FAILED=1"
  echo.
  echo  [error] %%~nx.cpp failed to compile:
  type "%OBJ%\%%~nx.log"
)
if defined FAILED exit /b 1
for %%x in ("%OBJ%\*.log") do if %%~zx GTR 0 type "%%x"

REM --- link --------------------------------------------------------------------
echo  [ld ] build\threat_analyzer.exe
g++ %OBJ%\threat_analyzer.o %OBJ%\web_server.o -o build\threat_analyzer.exe %LIBS% || exit /b 1

REM --- test --------------------------------------------------------------------
echo.
build\threat_analyzer.exe selftest || (
  echo  [error] Self-test failed.
  exit /b 1
)

echo.
echo  Build complete: %~dp0build\threat_analyzer.exe
endlocal
exit /b 0
