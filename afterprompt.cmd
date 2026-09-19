@echo off
rem Afterprompt front door on Windows. Double-click it, or run it from cmd.exe or PowerShell.
rem
rem It exists because PowerShell refuses to run an unsigned downloaded .ps1 under the default
rem execution policy; this shim starts afterprompt.ps1 with a policy scoped to that one process,
rem so nothing about the machine's configuration is changed.
setlocal
set "HERE=%~dp0"
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%HERE%afterprompt.ps1" %*
exit /b %ERRORLEVEL%
