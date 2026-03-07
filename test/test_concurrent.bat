@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
REM ============================================================
REM Concurrent Sandy Container Test Battery
REM Launches 3 containers with different grants on the same folder
REM then checks --status while all are running.
REM
REM Launches are staggered by 5s to avoid ACL grant races on
REM the shared Python directory (TreeSetNamedSecurityInfoW on a
REM 36K-file tree takes ~2s per instance).
REM
REM Self-contained: all artifacts under %USERPROFILE%\test_concurrent
REM   scripts/  — probe script (read by all containers)
REM   data/     — shared test data folder (different access per container)
REM ============================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set TEST=%~dp0
set ROOT=%USERPROFILE%\test_concurrent
set WAIT=25

echo ============================================================
echo  Concurrent Sandy Container Test Battery
echo  3 containers, same folder, different grants
echo  (staggered 5s apart to avoid ACL grant races)
echo ============================================================
echo.

REM Cleanup stale state
"%SANDY%" --cleanup >nul 2>nul

REM Create test folder structure
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\data"
echo concurrent test seed > "%ROOT%\data\seed.txt"
copy /y "%TEST%concurrent_probe.py" "%ROOT%\scripts\concurrent_probe.py" >nul
set PROBE=%ROOT%\scripts\concurrent_probe.py
echo Created: %ROOT%
echo.

echo [1/6] Launching container 1 (READ)...
start /b "" %SANDY% -c %TEST%concurrent_read.toml -q -x %PYTHON% %PROBE% read %WAIT%
ping -n 6 127.0.0.1 >nul

echo [2/6] Launching container 2 (WRITE)...
start /b "" %SANDY% -c %TEST%concurrent_write.toml -q -x %PYTHON% %PROBE% write %WAIT%
ping -n 6 127.0.0.1 >nul

echo [3/6] Launching container 3 (ALL)...
start /b "" %SANDY% -c %TEST%concurrent_all.toml -q -x %PYTHON% %PROBE% all %WAIT%
ping -n 4 127.0.0.1 >nul

echo.
echo [4/6] Status check (all 3 should be active):
echo ============================================================
%SANDY% --status
echo ============================================================
echo.

echo [5/6] Waiting for containers to finish...
ping -n 20 127.0.0.1 >nul
echo.

echo [6/6] Post-run status and cleanup:
echo ============================================================
%SANDY% --status
echo ---
%SANDY% --cleanup
echo ============================================================
echo.
echo  Test battery complete.

REM Cleanup
%SANDY% --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"
