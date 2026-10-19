@echo off
rem Concord, as a desktop application. Double-click this file, or run it from a terminal.
rem
rem It starts the local harness on an ephemeral loopback port and opens it in a chromeless
rem window. Closing that window stops Concord. Nothing is installed and nothing is downloaded.
setlocal
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
  echo.
  echo   Concord needs Node.js 22 or newer, and it is not on your PATH.
  echo   Install it from https://nodejs.org/ and run this again.
  echo.
  pause
  exit /b 1
)

node scripts\desktop.mjs %*
set EXITCODE=%ERRORLEVEL%

rem On a clean exit the window is already closed and there is nothing left to read. On a failure
rem the reason is on screen, so hold the console open long enough to read it.
if not "%EXITCODE%"=="0" (
  echo.
  pause
)
exit /b %EXITCODE%
