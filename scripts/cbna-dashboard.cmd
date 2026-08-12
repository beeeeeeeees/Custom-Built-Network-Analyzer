@echo off
setlocal
title CBNA dashboard

rem Double-clickable launcher for the web dashboard.
rem
rem cbna is a command-line tool, so double-clicking cbna.exe itself runs it with
rem no arguments, prints help and exits — which looks like a window that flashes
rem and vanishes. This starts the dashboard properly and opens a browser at it.
rem
rem Drag a .pcap or .pcapng file onto this launcher to open that capture.
rem Without one it falls back to samples\demo.pcap when running from a source
rem checkout. Live capture is not offered here: it needs an interface name and
rem an elevated shell, so it belongs in a terminal.

set "PORT=8787"

rem Prefer the live-capable build, but either works for reading a file.
set "EXE=%~dp0cbna-live.exe"
if not exist "%EXE%" set "EXE=%~dp0cbna.exe"
if not exist "%EXE%" set "EXE=%~dp0..\out\cbna-live.exe"
if not exist "%EXE%" set "EXE=%~dp0..\out\cbna.exe"
if not exist "%EXE%" set "EXE=%~dp0..\target\release\cbna.exe"
if not exist "%EXE%" (
  echo Could not find cbna.exe or cbna-live.exe.
  echo.
  echo Looked next to this launcher, in out\, and in target\release\.
  echo Build one with:
  echo     cargo build --release -p cbna --features live
  echo.
  pause
  exit /b 1
)

rem A capture dragged onto the launcher wins; otherwise try the bundled demo.
set "CAPTURE=%~1"
if "%CAPTURE%"=="" set "CAPTURE=%~dp0..\samples\demo.pcap"

if not exist "%CAPTURE%" (
  echo No capture file to open.
  echo.
  echo Drag a .pcap or .pcapng file onto this launcher, or generate the demo
  echo capture from a source checkout with:
  echo     cargo run -p cbna --example make-sample -- samples\demo.pcap
  echo.
  pause
  exit /b 1
)

echo Capture:   %CAPTURE%
echo Dashboard: http://127.0.0.1:%PORT%
echo.
echo Keep this window open - it is the server. Ctrl+C stops it.
echo.

rem Open the browser shortly after, once the port is listening.
start "" /min powershell -NoProfile -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:%PORT%'"

"%EXE%" serve "%CAPTURE%" --bind 127.0.0.1:%PORT%

echo.
echo Server stopped.
pause
