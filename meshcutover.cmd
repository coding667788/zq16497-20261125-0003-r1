@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"
python -m meshcutover %*
exit /b %ERRORLEVEL%
