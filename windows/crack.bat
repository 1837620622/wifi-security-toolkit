@echo off
chcp 65001 >nul
cd /d "%~dp0"
REM Windows 入口：转调 PowerShell 脚本
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0crack.ps1" %*
