@echo off
setlocal
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
if not defined PYTHON set "PYTHON=python"
"%PYTHON%" "%~dp0test_libreoffice_launcher.py" %*
exit /b %ERRORLEVEL%

