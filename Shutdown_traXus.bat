@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -WindowStyle Maximized -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0stop_isms.ps1""'"
exit