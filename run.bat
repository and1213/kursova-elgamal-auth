@echo off
cd /d "%~dp0"
set PY=%LOCALAPPDATA%\Programs\Python\Python315\python.exe
if not exist "%PY%" set PY=python
"%PY%" main.py
if errorlevel 1 pause
