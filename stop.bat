@echo off
REM ---------------------------------------------------------------------------
REM  THREAT ANALYZER - stop the running web server cleanly (Windows)
REM
REM  Asks the server on port 18080 to shut down through its local API
REM  (POST /api/shutdown). If it has not exited after 10 seconds, only the
REM  process that owns port 18080 is terminated as a last resort.
REM ---------------------------------------------------------------------------
setlocal EnableDelayedExpansion
set "PORT=18080"

call :findpid
if not defined PID (
  echo  THREAT ANALYZER is not running on port %PORT%.
  goto :done
)

echo  Stopping THREAT ANALYZER ^(process !PID!, port %PORT%^)...
where curl.exe >nul 2>nul && curl.exe -s -m 5 -X POST -H "X-Threat-Analyzer: shutdown" "http://127.0.0.1:%PORT%/api/shutdown" >nul 2>nul

for /L %%i in (1,1,10) do (
  call :findpid
  if not defined PID goto :stopped
  ping -n 2 127.0.0.1 >nul
)

echo  Server did not respond to the shutdown request - terminating process !PID!.
taskkill /F /PID !PID! >nul 2>nul

:stopped
echo  THREAT ANALYZER stopped.

:done
ping -n 3 127.0.0.1 >nul
exit /b 0

REM --- sets PID to the process listening on 127.0.0.1:%PORT% (empty if none) ---
:findpid
set "PID="
for /f "tokens=5" %%p in ('netstat -ano -p tcp ^| findstr /R /C:"127\.0\.0\.1:%PORT% .*LISTENING"') do set "PID=%%p"
exit /b 0
