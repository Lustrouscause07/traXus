@echo off
cd /d "%~dp0"
start "traXus Launcher" /MAX powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_isms.ps1"
exit