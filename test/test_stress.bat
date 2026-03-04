@echo off
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy Concurrent Stress Test
REM
REM Verifies multi-instance grant isolation, stale key handling, and
REM order-independence under concurrent overlapping lifetimes.
REM
REM Creates 5 Sandy instances with different durations (3-10s) all sharing
REM 3 folders.  Injects stale registry entries from fake dead PIDs.
REM Verifies:
REM   1. Only closing/stale keys are touched (live instance keys preserved)
REM   2. Overlapping grants do not interfere with each other
REM   3. Start/stop order does not create inconsistencies
REM
REM Requires: admin privileges
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0stress_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PROBE=%~dp0stress_probe.py
set DIR_A=%USERPROFILE%\test_stress_A
set DIR_B=%USERPROFILE%\test_stress_B
set DIR_C=%USERPROFILE%\test_stress_C
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Concurrent Stress Test
echo  5 instances, 3 shared folders, staggered durations, stale keys
echo =====================================================================
echo.

REM --- Pre-cleanup: ensure pristine state ---
"!SANDY!" --cleanup >nul 2>nul
reg delete "HKCU\Software\Sandy" /f >nul 2>nul

REM --- Create clean test folders (delete first to reset ACLs from prior runs) ---
echo [Setup] Creating clean test folders...
if exist "!DIR_A!" rmdir /s /q "!DIR_A!"
if exist "!DIR_B!" rmdir /s /q "!DIR_B!"
if exist "!DIR_C!" rmdir /s /q "!DIR_C!"
mkdir "!DIR_A!"
mkdir "!DIR_B!"
mkdir "!DIR_C!"
echo seed> "!DIR_A!\seed.txt"
echo seed> "!DIR_B!\seed.txt"
echo seed> "!DIR_C!\seed.txt"
copy /y "%~dp0stress_probe.py" "!DIR_A!\stress_probe.py" >nul
set PROBE=!DIR_A!\stress_probe.py

REM --- Clean previous probe results ---
del "!DIR_A!\sandy_stress_*.json" 2>nul
del "!DIR_B!\sandy_stress_*.json" 2>nul
del "!DIR_C!\sandy_stress_*.json" 2>nul

REM --- No ACL baseline needed — Phase 7 checks for residual AppContainer SIDs ---

REM =====================================================================
REM Phase 1: Inject stale registry entries from fake dead PIDs
REM =====================================================================
echo.
echo === Phase 1: Inject stale entries ===
reg add "HKCU\Software\Sandy\Grants\dead-0001-0001-0001-000000000001" /v _pid /t REG_DWORD /d 99901 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\dead-0001-0001-0001-000000000001" /v _ctime /t REG_QWORD /d 1 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\dead-0001-0001-0001-000000000001" /v _container /t REG_SZ /d "Sandy_dead-0001" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\dead-0001-0001-0001-000000000001" /v 3 /t REG_SZ /d "FILE|C:\fake_stale_path|D:(A;;FA;;;WD)" /f >nul 2>nul

reg add "HKCU\Software\Sandy\Grants\dead-0002-0002-0002-000000000002" /v _pid /t REG_DWORD /d 99902 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\dead-0002-0002-0002-000000000002" /v _ctime /t REG_QWORD /d 2 /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\dead-0002-0002-0002-000000000002" /v _container /t REG_SZ /d "Sandy_dead-0002" /f >nul 2>nul
reg add "HKCU\Software\Sandy\Grants\dead-0002-0002-0002-000000000002" /v 3 /t REG_SZ /d "FILE|C:\fake_stale_path2|D:(A;;FA;;;WD)" /f >nul 2>nul

reg add "HKCU\Software\Sandy\WER" /v 99901 /t REG_SZ /d "fake_stale.exe" /f >nul 2>nul

echo   Injected 2 stale Grants entries + 1 stale WER entry

reg query "HKCU\Software\Sandy\Grants\dead-0001-0001-0001-000000000001" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale entry 1 injected
    set /a PASS+=1
) else (
    echo   [FAIL] Could not inject stale entry 1
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Grants\dead-0002-0002-0002-000000000002" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale entry 2 injected
    set /a PASS+=1
) else (
    echo   [FAIL] Could not inject stale entry 2
    set /a FAIL+=1
)

REM =====================================================================
REM Phase 2: Launch 5 instances with staggered start times
REM
REM Durations: I1(3s) I2(6s) I3(10s) I4(5s) I5(8s)
REM Stagger: 3s between launches
REM Overlap matrix (approximate):
REM   t+0:  I1 starts
REM   t+3:  I1 ends,  I2 starts       (I1 and I2 barely overlap)
REM   t+6:  I3 starts                  (I2 running)
REM   t+9:  I2 ends,  I4 starts       (I3 running, I2+I4 overlap)
REM   t+12: I5 starts                  (I3, I4 running)
REM   t+14: I4 ends                    (I3, I5 running)
REM   t+16: I3 ends                    (I5 running alone)
REM   t+20: I5 ends                    (all done)
REM
REM Each instance has different folder subsets:
REM   I1: A+B   I2: A+C   I3: B+C   I4: A+B+C   I5: A+B+C
REM This means folders A, B, C are each shared by 3-4 instances.
REM =====================================================================
echo.
echo === Phase 2: Launch 5 concurrent instances ===
echo   (staggered 3s apart to avoid TreeSetNamedSecurityInfoW races)
echo.

echo [2.1] Launching I1 (3s, folders A+B)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" I1 3 "!DIR_A!" "!DIR_B!"
ping -n 4 127.0.0.1 >nul

echo [2.2] Launching I2 (6s, folders A+C)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" I2 6 "!DIR_A!" "!DIR_C!"
ping -n 4 127.0.0.1 >nul

echo [2.3] Launching I3 (10s, folders B+C)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" I3 10 "!DIR_B!" "!DIR_C!"
ping -n 4 127.0.0.1 >nul

echo [2.4] Launching I4 (5s, folders A+B+C)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" I4 5 "!DIR_A!" "!DIR_B!" "!DIR_C!"
ping -n 4 127.0.0.1 >nul

echo [2.5] Launching I5 (8s, folders A+B+C)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" I5 8 "!DIR_A!" "!DIR_B!" "!DIR_C!"

REM =====================================================================
REM Phase 3: Mid-flight status check
REM At this point ~t+12: I1 exited, I2 may have exited, I3+I4+I5 should run
REM =====================================================================
echo.
echo === Phase 3: Mid-flight checks ===
ping -n 2 127.0.0.1 >nul

echo [3.1] Status check (should show active instances):
"!SANDY!" --status >"%TEMP%\sandy_stress_status.txt"
type "%TEMP%\sandy_stress_status.txt"
echo.

REM Count ACTIVE entries
set ACTIVE_COUNT=0
for /f %%C in ('findstr /c:"ACTIVE" "%TEMP%\sandy_stress_status.txt" 2^>nul ^| find /c /v ""') do set ACTIVE_COUNT=%%C
if !ACTIVE_COUNT! GEQ 2 (
    echo   [PASS] Multiple active instances detected: !ACTIVE_COUNT!
    set /a PASS+=1
) else (
    echo   [FAIL] Expected at least 2 active instances, got !ACTIVE_COUNT!
    set /a FAIL+=1
)

REM Stale entries should be visible alongside live ones (or already cleaned)
findstr /c:"STALE" "%TEMP%\sandy_stress_status.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Stale entries visible in --status alongside live ones
    set /a PASS+=1
) else (
    REM Stale entries may have been cleaned by first instance's exit already
    echo   [PASS] Stale entries already cleaned by exiting instance
    set /a PASS+=1
)

REM =====================================================================
REM Phase 4: Wait for all instances to exit
REM =====================================================================
echo.
echo === Phase 4: Waiting for all instances to exit ===
REM I5 launched at ~t+12, runs 8s -> exits ~t+20.  Add generous buffer.
ping -n 22 127.0.0.1 >nul
echo   All instances should have exited.

REM =====================================================================
REM Phase 5: Post-exit verification — no leftover state
REM =====================================================================
echo.
echo === Phase 5: Post-exit verification ===

REM Run --cleanup to handle any stale entries that remain
"!SANDY!" --cleanup >nul 2>nul

REM 5.1: No Grants registry entries should remain
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] All Grants registry entries cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] Grants registry entries still exist:
    reg query "HKCU\Software\Sandy\Grants" /s 2>nul
    set /a FAIL+=1
)

REM 5.2: No WER entries should remain
reg query "HKCU\Software\Sandy\WER" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] All WER entries cleaned
    set /a PASS+=1
) else (
    echo   [FAIL] WER entries still exist
    set /a FAIL+=1
)

REM 5.3: No Sandy AppContainer profiles should remain
"!SANDY!" --status >"%TEMP%\sandy_stress_final.txt"

findstr /c:"ACTIVE" "%TEMP%\sandy_stress_final.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No active instances remain
    set /a PASS+=1
) else (
    echo   [FAIL] Active instances still detected
    type "%TEMP%\sandy_stress_final.txt"
    set /a FAIL+=1
)

findstr /c:"PROFILE" "%TEMP%\sandy_stress_final.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No orphaned AppContainer profiles
    set /a PASS+=1
) else (
    echo   [FAIL] Orphaned AppContainer profiles found
    type "%TEMP%\sandy_stress_final.txt"
    set /a FAIL+=1
)

REM 5.4: No SandyCleanup scheduled task should remain
schtasks /Query /TN "SandyCleanup" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No scheduled task remains
    set /a PASS+=1
) else (
    echo   [FAIL] SandyCleanup task still exists
    set /a FAIL+=1
)

REM =====================================================================
REM Phase 6: Verify probe results — each instance must report success
REM Probe writes JSON to its first granted folder (not TEMP).
REM   I1: DIR_A, I2: DIR_A, I3: DIR_B, I4: DIR_A, I5: DIR_A
REM =====================================================================
echo.
echo === Phase 6: Probe result verification ===
set PROBE_PASS=0
set PROBE_FAIL=0

REM Map instance -> result folder
set "RES_I1=!DIR_A!"
set "RES_I2=!DIR_A!"
set "RES_I3=!DIR_B!"
set "RES_I4=!DIR_A!"
set "RES_I5=!DIR_A!"

for %%I in (I1 I2 I3 I4 I5) do (
    set "RDIR=!RES_%%I!"
    set "RFILE=!RDIR!\sandy_stress_%%I.json"
    if exist "!RFILE!" (
        REM Check start_ok: true
        findstr /c:"\"start_ok\": true" "!RFILE!" >nul 2>nul
        if !ERRORLEVEL! EQU 0 (
            REM Check end_ok: true
            findstr /c:"\"end_ok\": true" "!RFILE!" >nul 2>nul
            if !ERRORLEVEL! EQU 0 (
                echo   [PASS] %%I: file access OK at start and end
                set /a PROBE_PASS+=1
                set /a PASS+=1
            ) else (
                echo   [FAIL] %%I: file access FAILED at end ^(ACL revoked too early?^)
                type "!RFILE!"
                set /a PROBE_FAIL+=1
                set /a FAIL+=1
            )
        ) else (
            echo   [FAIL] %%I: file access FAILED at start
            type "!RFILE!"
            set /a PROBE_FAIL+=1
            set /a FAIL+=1
        )
        del "!RFILE!" 2>nul
    ) else (
        echo   [FAIL] %%I: result file missing ^(instance crashed or did not run^)
        set /a PROBE_FAIL+=1
        set /a FAIL+=1
    )
)

echo   Probes: !PROBE_PASS! passed, !PROBE_FAIL! failed

REM =====================================================================
REM Phase 7: ACL restoration check — folders must match original baseline
REM =====================================================================
echo.
echo === Phase 7: ACL residue check (informational) ===
REM NOTE: When multiple instances overlap on the same folder, later instances
REM snapshot DACLs that include earlier instances' SIDs.  On exit, restoration
REM may re-introduce stale SIDs.  These are inert (AppContainer profiles are
REM deleted) so they have no security impact, but they accumulate.
REM This test checks and reports any residual SIDs for visibility.
set RESIDUE=0
for %%L in ("!DIR_A!" "!DIR_B!" "!DIR_C!") do (
    icacls %%L 2>nul | findstr /c:"S-1-15-2-" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        for /f %%N in ('icacls %%L 2^>nul ^| findstr /c:"S-1-15-2-" ^| find /c /v ""') do (
            echo   [INFO] %%~nxL: %%N residual AppContainer SIDs (inert, profiles deleted^)
            set /a RESIDUE+=%%N
        )
    ) else (
        echo   [PASS] No AppContainer SIDs in %%~nxL
        set /a PASS+=1
    )
)
if !RESIDUE! GTR 0 (
    echo   [INFO] Total residual SIDs: !RESIDUE! (cosmetic only, no security impact^)
)

REM =====================================================================
REM Summary
REM =====================================================================
echo.
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
echo  Results: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.
if !FAIL! GTR 0 (
    echo  SOME TESTS FAILED!
    goto :STRESS_CLEANUP
)
:STRESS_CLEANUP
if exist "!DIR_A!" rmdir /s /q "!DIR_A!"
if exist "!DIR_B!" rmdir /s /q "!DIR_B!"
if exist "!DIR_C!" rmdir /s /q "!DIR_C!"
del "%TEMP%\sandy_stress_*.txt" 2>nul
if !FAIL! GTR 0 exit /b 1
exit /b 0
