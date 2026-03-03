@echo off
REM ============================================================
REM Concurrent Sandy Container Test Battery
REM Launches 3 containers with different grants on the same folder
REM then checks --status while all are running.
REM
REM Launches are staggered by 5s to avoid ACL grant races on
REM the shared Python directory (TreeSetNamedSecurityInfoW on a
REM 36K-file tree takes ~2s per instance).
REM ============================================================

set SANDY=c:\repos\sandy_cli\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set TEST=c:\repos\sandy_cli\test
set PROBE=%TEST%\concurrent_probe.py
set WAIT=25

echo ============================================================
echo  Concurrent Sandy Container Test Battery
echo  3 containers, same folder, different grants
echo  (staggered 5s apart to avoid ACL grant races)
echo ============================================================
echo.

REM Ensure seed file exists for read tests
if not exist "C:\Users\H\test_RW\seed.txt" (
    echo Creating seed file...
    echo concurrent test seed > "C:\Users\H\test_RW\seed.txt"
)

echo [1/6] Launching container 1 (READ)...
start /b "" %SANDY% -c %TEST%\concurrent_read.toml -q -x %PYTHON% %PROBE% read %WAIT%
ping -n 6 127.0.0.1 >nul

echo [2/6] Launching container 2 (WRITE)...
start /b "" %SANDY% -c %TEST%\concurrent_write.toml -q -x %PYTHON% %PROBE% write %WAIT%
ping -n 6 127.0.0.1 >nul

echo [3/6] Launching container 3 (ALL)...
start /b "" %SANDY% -c %TEST%\concurrent_all.toml -q -x %PYTHON% %PROBE% all %WAIT%
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
