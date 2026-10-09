@echo off
setlocal DisableDelayedExpansion
set "GEPHTUN_LAUNCH_DIR=%~dp0"
set "GEPHTUN_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "GEPHTUN_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%GEPHTUN_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Sta -WindowStyle Hidden -Command "& (Join-Path $env:GEPHTUN_LAUNCH_DIR 'Launch-GephTun.ps1') -InitialAction 'Disconnect'"
set "GEPHTUN_EXIT=%ERRORLEVEL%"
endlocal & exit /b %GEPHTUN_EXIT%
