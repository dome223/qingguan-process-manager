@echo off
cd /d "%~dp0"
python desktop_manager.py
if errorlevel 1 pause
