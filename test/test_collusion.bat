@echo off
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_collusion.bat -- Multi-instance collusion attack suite
REM
REM Two Sandy instances (Alice + Bob) run concurrently on shared folder.
REM Alice has no denies. Bob has deny.all on shared/locked/.
REM Alice reads Bob's forbidden data and relays it.
REM Alice exits FIRST — her cleanup should NOT poison Bob's state.
REM Bob exits SECOND — his cleanup should restore true originals.
REM
REM KEY BUG BEING TESTED:
REM   If B saves A's modified SDDL as "original", then when B exits,
REM   it restores with A's SID baked in = ORPHANED ACE forever.
REM =====================================================================

echo =====================================================================
echo  Collusion Test Suite -- Multi-Instance Sandbox Breach
echo  Alice (no denies) + Bob (deny.all on locked/)
echo =====================================================================

set "ROOT=%USERPROFILE%\test_collusion"
set "SHARED=%ROOT%\shared"
set "SANDY=c:\repos\sandy_cli\x64\Release\sandy.exe"
set "ALICE_CFG=c:\repos\sandy_cli\test\test_collusion_alice.toml"
set "BOB_CFG=c:\repos\sandy_cli\test\test_collusion_bob.toml"
set "ALICE_PY=c:\repos\sandy_cli\test\test_collusion_alice.py"
set "BOB_PY=c:\repos\sandy_cli\test\test_collusion_bob.py"

REM --- Clean previous run ---
if exist "%ROOT%" (
    icacls "%ROOT%" /reset /T /Q >nul 2>&1
    rmdir /S /Q "%ROOT%" 2>nul
)

REM --- Build tree ---
mkdir "%SHARED%\locked" 2>nul
mkdir "%SHARED%\relay" 2>nul
mkdir "%SHARED%\signals" 2>nul
mkdir "%ROOT%\scripts" 2>nul

REM --- Seed files ---
echo TOP_SECRET_DATA > "%SHARED%\locked\secret.txt"

REM --- Copy scripts ---
copy /Y "%ALICE_PY%" "%ROOT%\scripts\alice.py" >nul
copy /Y "%BOB_PY%" "%ROOT%\scripts\bob.py" >nul

echo.
echo   [OK] Folder tree created

REM --- Capture pre-Sandy SDDLs ---
echo.
echo --- Pre-Sandy SDDL snapshots ---
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%SHARED%').Sddl" 2^>nul') do set "PRE_SHARED=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%SHARED%\locked').Sddl" 2^>nul') do set "PRE_LOCKED=%%S"
echo   shared/:  %PRE_SHARED:~0,60%...
echo   locked/:  %PRE_LOCKED:~0,60%...

REM =====================================================================
REM Phase 1: Start Alice in background
REM =====================================================================
echo.
echo === Phase 1: Starting Alice (background) ===
start "" /b "%SANDY%" -c "%ALICE_CFG%" -x "C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe" "%ROOT%\scripts\alice.py" > "%ROOT%\alice_output.txt" 2>&1

REM Wait for Alice to initialize
ping -n 4 127.0.0.1 >nul

REM =====================================================================
REM Phase 2: Start Bob in background (while Alice is running)
REM =====================================================================
echo === Phase 2: Starting Bob (background, Alice still running) ===
start "" /b "%SANDY%" -c "%BOB_CFG%" -x "C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe" "%ROOT%\scripts\bob.py" > "%ROOT%\bob_output.txt" 2>&1

REM =====================================================================
REM Phase 3: Wait for both to finish
REM =====================================================================
echo === Phase 3: Waiting for both instances to finish ===
echo   (Alice exits first, Bob waits 8s after, then exits)
echo   (Max wait: 120 seconds)

set "WAIT_COUNT=0"
set "WAIT_MAX=60"

:wait_loop
ping -n 3 127.0.0.1 >nul
set /a WAIT_COUNT+=1
REM Check if both done (look for the output files to have summary lines)
findstr /c:"ALICE:" "%ROOT%\alice_output.txt" >nul 2>&1 && findstr /c:"BOB:" "%ROOT%\bob_output.txt" >nul 2>&1
if errorlevel 1 (
    if !WAIT_COUNT! GEQ !WAIT_MAX! (
        echo   [TIMEOUT] Waited 120s -- processes did not finish. Aborting.
        echo.
        echo   --- Alice output so far ---
        if exist "%ROOT%\alice_output.txt" type "%ROOT%\alice_output.txt"
        echo.
        echo   --- Bob output so far ---
        if exist "%ROOT%\bob_output.txt" type "%ROOT%\bob_output.txt"
        echo.
        REM Kill any remaining sandy/python processes for this test
        taskkill /f /im sandy.exe >nul 2>&1
        taskkill /f /im python.exe >nul 2>&1
        REM Cleanup
        if exist "%ROOT%" (
            icacls "%ROOT%" /reset /T /Q >nul 2>&1
            rmdir /S /Q "%ROOT%" 2>nul
        )
        exit /b 1
    )
    goto wait_loop
)

REM Give Sandy cleanup time to finish after probes exit
echo   [OK] Both probes finished (after !WAIT_COUNT! polls). Waiting for Sandy cleanup...
ping -n 11 127.0.0.1 >nul

REM =====================================================================
REM Phase 4: Results
REM =====================================================================
echo.
echo =====================================================================
echo  ALICE OUTPUT:
echo =====================================================================
type "%ROOT%\alice_output.txt"
echo.
echo =====================================================================
echo  BOB OUTPUT:
echo =====================================================================
type "%ROOT%\bob_output.txt"

REM =====================================================================
REM Phase 5: Post-Cleanup Verification
REM =====================================================================
echo.
echo =====================================================================
echo  Post-Cleanup Verification (THE CRITICAL TEST)
echo =====================================================================
echo.

set CLEANUP_PASS=0
set CLEANUP_FAIL=0

REM --- Check for ANY AppContainer SIDs (S-1-15-*) remaining ---
set "SID_FOUND=0"
for /f "delims=" %%L in ('icacls "%SHARED%" /T 2^>nul ^| findstr /i "S-1-15-"') do (
    set "SID_FOUND=1"
    echo   [DETAIL] Residual: %%L
)
if "!SID_FOUND!"=="0" (
    echo   [PASS] No AppContainer SIDs on shared/ tree
    set /a CLEANUP_PASS+=1
) else (
    echo   [FAIL] ORPHANED AppContainer SIDs found!
    echo          This proves the SDDL poisoning attack worked!
    set /a CLEANUP_FAIL+=1
)

REM --- Registry check ---
reg query "HKCU\Software\Sandy\Grants" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo   [PASS] No grant registry entries remain
    set /a CLEANUP_PASS+=1
) else (
    set "HAS_SUBKEYS=0"
    for /f "delims=" %%K in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul') do set "HAS_SUBKEYS=1"
    if "!HAS_SUBKEYS!"=="0" (
        echo   [PASS] Grants registry key empty
        set /a CLEANUP_PASS+=1
    ) else (
        echo   [FAIL] Stale grant registry entries!
        set /a CLEANUP_FAIL+=1
    )
)

REM --- SDDL fidelity (THE KEY TEST) ---
echo.
echo --- SDDL Fidelity (the forensic proof) ---
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%SHARED%').Sddl" 2^>nul') do set "POST_SHARED=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%SHARED%\locked').Sddl" 2^>nul') do set "POST_LOCKED=%%S"

if "!POST_SHARED!"=="!PRE_SHARED!" (
    echo   [PASS] shared/ DACL restored to true original
    set /a CLEANUP_PASS+=1
) else (
    echo   [FAIL] shared/ DACL mismatch -- SDDL POISONING CONFIRMED!
    echo     Pre:  !PRE_SHARED!
    echo     Post: !POST_SHARED!
    set /a CLEANUP_FAIL+=1
)

if "!POST_LOCKED!"=="!PRE_LOCKED!" (
    echo   [PASS] locked/ DACL restored to true original
    set /a CLEANUP_PASS+=1
) else (
    echo   [FAIL] locked/ DACL mismatch!
    echo     Pre:  !PRE_LOCKED!
    echo     Post: !POST_LOCKED!
    set /a CLEANUP_FAIL+=1
)

echo.
echo =====================================================================
if !CLEANUP_FAIL! EQU 0 (
    echo  ALL HELD -- Sandy survived collusion attack!
) else (
    echo  BREACH DETECTED -- !CLEANUP_FAIL! cleanup failures!
)
echo  Cleanup: !CLEANUP_PASS! passed, !CLEANUP_FAIL! failed
echo =====================================================================

REM --- Cleanup ---
if exist "%ROOT%" (
    icacls "%ROOT%" /reset /T /Q >nul 2>&1
    rmdir /S /Q "%ROOT%" 2>nul
)

if !CLEANUP_FAIL! GTR 0 exit /b 1
exit /b 0
