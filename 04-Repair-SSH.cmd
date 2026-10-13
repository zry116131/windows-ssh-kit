@echo off
setlocal
set "SSH_SETUP_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "SSH_SETUP_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%SSH_SETUP_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Setup-SSH.ps1" -Action Repair -NoPause
set "SSH_KIT_EXIT=%ERRORLEVEL%"
echo.
echo Reports are in the Logs folder next to this script.
pause
exit /b %SSH_KIT_EXIT%
