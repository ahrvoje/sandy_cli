@echo off
setlocal EnableDelayedExpansion
REM =====================================================================
REM Multi-Instance ACL Safety Test Battery
REM
REM Verifies that concurrent Sandy instances with overlapping grants
REM on the same folder do not interfere with each other.
REM
REM Tests:
REM   1. Two instances grant same folder — both children have access
REM   2. First instance exits — second still has full access
REM   3. Both exit — original DACL fully restored (no zombie ACEs)
REM   4. Kill + cleanup — stale ACEs properly removed
REM
REM Requires: Python 3 (for probe scripts)
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set TEST=%~dp0
set ROOT=%USERPROFILE%\test_multiinstance
set ERRORS=0

echo =====================================================================
echo  Multi-Instance ACL Safety Test Battery
echo  Overlapping grants, concurrent instances
echo =====================================================================
echo.

REM === Kill stragglers & cleanup ===
taskkill /f /im sandy.exe >nul 2>nul
"%SANDY%" --cleanup >nul 2>nul

REM === Create test folder structure ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\shared"
mkdir "%ROOT%\scripts"
echo multiinstance seed > "%ROOT%\shared\seed.txt"
copy /y "%TEST%multiinstance_probe.py" "%ROOT%\scripts\multiinstance_probe.py" >nul
echo   [OK] Folder tree created
echo.

REM === Save original DACL for later comparison ===
icacls "%ROOT%\shared" > "%ROOT%\dacl_before.txt" 2>nul

REM =====================================================================
REM TEST 1: Overlapping grants — both instances have access
REM =====================================================================
echo [TEST 1] Overlapping grants — both instances accessing same folder
echo   Starting instance A (wait=15s)...
start "" /b "%SANDY%" -c "%TEST%multiinstance_a.toml" -l "%ROOT%\log_a.txt" -x "%PYTHON%" "%ROOT%\scripts\multiinstance_probe.py" a 15 "%ROOT%\shared"
ping -n 8 127.0.0.1 >nul

echo   Starting instance B (wait=5s)...
start "" /b "%SANDY%" -c "%TEST%multiinstance_b.toml" -l "%ROOT%\log_b.txt" -x "%PYTHON%" "%ROOT%\scripts\multiinstance_probe.py" b 5 "%ROOT%\shared"
ping -n 6 127.0.0.1 >nul

REM Both should be running now
echo   Both instances running. Status:
"%SANDY%" --status
echo.

REM Wait for B to finish (5s wait + ~5s overhead)
echo   Waiting for instance B to exit (12s)...
ping -n 13 127.0.0.1 >nul

REM =====================================================================
REM TEST 2: First instance exits — second still has access
REM =====================================================================
echo [TEST 2] Instance B exited — checking instance A still has access...
echo   (Instance A should still be running with full access)

if exist "%ROOT%\shared\marker_a.txt" (
    echo   [PASS] marker_a.txt exists
) else (
    echo   [FAIL] marker_a.txt missing!
    set /a ERRORS+=1
)

if exist "%ROOT%\shared\marker_b.txt" (
    echo   [PASS] marker_b.txt exists
) else (
    echo   [FAIL] marker_b.txt missing!
    set /a ERRORS+=1
)
echo.

REM Wait for A to finish
echo   Waiting for instance A to finish (12s)...
ping -n 13 127.0.0.1 >nul

REM =====================================================================
REM TEST 3: Both exited — check DACL restored clean
REM =====================================================================
echo [TEST 3] Both exited — checking DACL restoration...
icacls "%ROOT%\shared" > "%ROOT%\dacl_after.txt" 2>nul

fc /w "%ROOT%\dacl_before.txt" "%ROOT%\dacl_after.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DACL fully restored — no zombie ACEs
) else (
    echo   [WARN] DACL differs from original — checking for zombie ACEs
    echo   --- Before: ---
    type "%ROOT%\dacl_before.txt"
    echo   --- After: ---
    type "%ROOT%\dacl_after.txt"
    set /a ERRORS+=1
)
echo.

REM Check A's log for post-wait verification
if exist "%ROOT%\log_a.txt" (
    findstr /c:"POST-WAIT READ seed -> OK" "%ROOT%\log_a.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] Instance A retained read access after B exited
    ) else (
        echo   [FAIL] Instance A lost read access when B exited!
        echo   --- log_a.txt excerpt: ---
        findstr /c:"[a]" "%ROOT%\log_a.txt"
        set /a ERRORS+=1
    )

    findstr /c:"POST-WAIT WRITE marker -> OK" "%ROOT%\log_a.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] Instance A retained write access after B exited
    ) else (
        echo   [FAIL] Instance A lost write access when B exited!
        set /a ERRORS+=1
    )
) else (
    echo   [FAIL] log_a.txt not found — instance A may not have started
    set /a ERRORS+=1
)
echo.

REM =====================================================================
REM TEST 4: Kill + cleanup — stale ACEs removed
REM =====================================================================
echo [TEST 4] Kill + cleanup — verifying stale cleanup...

REM Recreate folder if needed for this test
if not exist "%ROOT%\shared" mkdir "%ROOT%\shared"
echo kill test seed > "%ROOT%\shared\seed.txt"
icacls "%ROOT%\shared" > "%ROOT%\dacl_before_kill.txt" 2>nul

echo   Starting instance to kill...
start "" /b "%SANDY%" -c "%TEST%multiinstance_a.toml" -l "%ROOT%\log_kill.txt" -x "%PYTHON%" "%ROOT%\scripts\multiinstance_probe.py" a 60 "%ROOT%\shared"
ping -n 6 127.0.0.1 >nul

echo   Killing instance...
taskkill /f /im sandy.exe >nul 2>nul
ping -n 3 127.0.0.1 >nul

echo   Running cleanup...
"%SANDY%" --cleanup

icacls "%ROOT%\shared" > "%ROOT%\dacl_post_cleanup.txt" 2>nul
fc /w "%ROOT%\dacl_before_kill.txt" "%ROOT%\dacl_post_cleanup.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DACL restored after kill+cleanup — no stale ACEs
) else (
    echo   [WARN] DACL differs after kill+cleanup
    echo   --- Before kill: ---
    type "%ROOT%\dacl_before_kill.txt"
    echo   --- After cleanup: ---
    type "%ROOT%\dacl_post_cleanup.txt"
    set /a ERRORS+=1
)
echo.

REM =====================================================================
REM SUMMARY
REM =====================================================================
echo =====================================================================
if !ERRORS! EQU 0 (
    echo  ALL TESTS PASSED
) else (
    echo  %ERRORS% TEST^(S^) FAILED
)
echo =====================================================================
echo.
echo Logs and DACL snapshots in: %ROOT%
echo   log_a.txt, log_b.txt, dacl_before.txt, dacl_after.txt

exit /b !ERRORS!
