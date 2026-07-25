@echo off
REM win entry - GBK console (code page 936)
chcp 936 >nul 2>&1
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0crack.ps1" %*
set ERR=%ERRORLEVEL%
exit /b %ERR%
