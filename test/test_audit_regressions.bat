@echo off
setlocal
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
if not defined PYTHON set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
"%PYTHON%" "%~dp0test_audit_regressions.py" %*
exit /b %ERRORLEVEL%
