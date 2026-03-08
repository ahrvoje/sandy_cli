@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy Kill-Resilience Test Battery
REM
REM Tests the most dangerous failure scenarios that can corrupt grants,
REM leave stale tokens, or violate multi-instance isolation.
REM
REM PHILOSOPHY: Sandy must clean up after itself.  The ONLY manual
REM registry wipe is at the very start to ensure a known baseline.
REM After that, each scenario relies ONLY on Sandy's --cleanup.
REM Stale state from prior scenarios intentionally carries forward.
REM
REM   Scenario 1: Kill during active run — grants persist, --cleanup works
REM   Scenario 2: Kill with overlapping instance on same folder
REM   Scenario 3: Kill then restart same folder (stale coexistence)
REM   Scenario 4: Rapid-fire start+kill (3 killed instances)
REM   Scenario 5: Kill BOTH overlapping instances, --cleanup must recover all
REM   Scenario 6: Clean instance alongside stale entries from all prior kills
REM
REM Requires: admin privileges
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0kill_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PROBE=%~dp0kill_probe.py
set DIR_A=%USERPROFILE%\test_kill_A
set DIR_B=%USERPROFILE%\test_kill_B
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Kill-Resilience Test Battery
echo  6 scenarios — Sandy must clean up after itself, no manual help
echo =====================================================================
echo.

REM === ONE-TIME pristine baseline (only manual cleanup in the entire test) ===
"!SANDY!" --cleanup >nul 2>nul
if exist "!DIR_A!" rmdir /s /q "!DIR_A!"
if exist "!DIR_B!" rmdir /s /q "!DIR_B!"
mkdir "!DIR_A!"
mkdir "!DIR_B!"
echo seed> "!DIR_A!\seed.txt"
echo seed> "!DIR_B!\seed.txt"
copy /y "%~dp0kill_probe.py" "!DIR_A!\kill_probe.py" >nul
set PROBE=!DIR_A!\kill_probe.py

REM =====================================================================
REM Scenario 1: Kill during active run
REM Verify: grants persist in registry, ACLs modified, --cleanup recovers
REM =====================================================================
echo === Scenario 1: Kill during active run ===
echo.

start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S1 30 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S1_PID=%%P"

set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S1_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
if !READY! EQU 0 (
    echo   [FAIL] S1: Probe did not start
    set /a FAIL+=1
    goto :S1_END
)
echo   [OK] S1 probe running

taskkill /f /pid !S1_PID! >nul 2>nul
ping -n 3 127.0.0.1 >nul

REM 1a: Registry grants MUST exist (proving persistence works)
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S1: Grants registry key persisted after kill
    set /a PASS+=1
) else (
    echo   [FAIL] S1: Grants registry key missing — persistence broken
    set /a FAIL+=1
)

REM 1b: ACL MUST have AppContainer SID
set SC=0
for /f %%N in ('icacls "!DIR_A!" 2^>nul ^| findstr /c:"S-1-15-2-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SC=%%N
if !SC! GEQ 1 (
    echo   [PASS] S1: AppContainer SID in ACL after kill (!SC! SIDs^)
    set /a PASS+=1
    goto :S1_ACL_OK
)
echo   [FAIL] S1: No AppContainer SID — grant never applied
set /a FAIL+=1
:S1_ACL_OK

REM 1c: --cleanup ALONE must remove registry entries (no manual help)
"!SANDY!" --cleanup >nul 2>nul

set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] S1: --cleanup removed grant subkeys
    set /a PASS+=1
) else (
    echo   [FAIL] S1: !REMAIN! grant subkeys remain after --cleanup
    reg query "HKCU\Software\Sandy\Grants" /s 2>nul
    set /a FAIL+=1
)

REM 1d: ACL MUST be clean after --cleanup
set SC=0
for /f %%N in ('icacls "!DIR_A!" 2^>nul ^| findstr /c:"S-1-15-2-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] S1: ACLs clean after --cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] S1: !SC! residual AppContainer SIDs after --cleanup
    set /a FAIL+=1
)
:S1_END

REM =====================================================================
REM Scenario 2: Kill with overlapping instance on same folder
REM Verify: surviving instance retains access, killed instance's grants
REM         do not interfere, --cleanup recovers after all exit
REM =====================================================================
echo.
echo === Scenario 2: Kill with overlapping instance ===
echo.

echo   Starting S2a (30s, folders A+B)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S2a 30 "!DIR_A!" "!DIR_B!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S2A_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S2a_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
if !READY! EQU 0 (
    echo   [FAIL] S2: S2a did not start
    set /a FAIL+=1
    goto :S2_END
)
echo   [OK] S2a running (PID !S2A_PID!)

ping -n 4 127.0.0.1 >nul

echo   Starting S2b (15s, folder A — overlapping)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S2b 15 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S2B_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S2b_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
if !READY! EQU 0 (
    echo   [FAIL] S2: S2b did not start
    set /a FAIL+=1
    goto :S2_END
)
echo   [OK] S2b running (PID !S2B_PID!, overlapping on folder A)

REM Kill S2a by captured PID — S2b must survive
echo   Killing S2a PID !S2A_PID!
taskkill /f /pid !S2A_PID! >nul 2>nul
ping -n 2 127.0.0.1 >nul

REM Wait for S2b to finish (15s + buffer)
echo   Waiting for S2b to finish...
ping -n 18 127.0.0.1 >nul
ping -n 5 127.0.0.1 >nul

REM 2a: S2b MUST have clean exit with working access
if exist "!DIR_A!\kill_probe_S2b_result.json" (
    findstr /c:"\"end_ok\": true" "!DIR_A!\kill_probe_S2b_result.json" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] S2: Surviving instance S2b had working access through to clean exit
        set /a PASS+=1
    ) else (
        echo   [FAIL] S2: S2b lost access — killed instance corrupted shared grants
        type "!DIR_A!\kill_probe_S2b_result.json"
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] S2: S2b result file missing
    set /a FAIL+=1
)

REM 2b: S2a MUST NOT have result file
if exist "!DIR_A!\kill_probe_S2a_result.json" (
    echo   [FAIL] S2: Killed S2a has result file — was not actually killed
    set /a FAIL+=1
) else (
    echo   [PASS] S2: Killed instance S2a has no result (expected)
    set /a PASS+=1
)

REM 2c: Kill stragglers by PID, then --cleanup ALONE must recover
if defined S2A_PID taskkill /f /pid !S2A_PID! >nul 2>nul
if defined S2B_PID taskkill /f /pid !S2B_PID! >nul 2>nul
ping -n 2 127.0.0.1 >nul
"!SANDY!" --cleanup >nul 2>nul

set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] S2: --cleanup removed all grant subkeys
    set /a PASS+=1
) else (
    echo   [FAIL] S2: !REMAIN! grant subkeys remain after --cleanup
    reg query "HKCU\Software\Sandy\Grants" /s 2>nul
    set /a FAIL+=1
)
:S2_END

REM =====================================================================
REM Scenario 3: Kill then restart same folder (stale coexistence)
REM Verify: new instance runs despite stale entries, finishes cleanly
REM         --cleanup handles the killed instance's stale entries
REM =====================================================================
echo.
echo === Scenario 3: Kill then restart same folder ===
echo.

echo   Starting S3a (30s)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S3a 30 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S3A_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S3a_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
if !READY! EQU 0 (
    echo   [FAIL] S3: S3a did not start
    set /a FAIL+=1
    goto :S3_END
)
echo   [OK] S3a running (PID !S3A_PID!) — killing now
taskkill /f /pid !S3A_PID! >nul 2>nul
ping -n 2 127.0.0.1 >nul

REM 3a: Stale grants MUST exist (proves kill left state behind)
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S3: Stale grants from killed S3a
    set /a PASS+=1
) else (
    echo   [FAIL] S3: No stale grants after kill
    set /a FAIL+=1
)

REM 3b: Start new instance — MUST work despite stale state
echo   Starting S3b (8s) on same folder...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S3b 8 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S3B_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S3b_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
if !READY! EQU 0 (
    echo   [FAIL] S3: S3b did not start
    set /a FAIL+=1
    goto :S3_END
)
echo   [OK] S3b running despite stale entries
echo   Waiting for S3b to finish...
ping -n 12 127.0.0.1 >nul

if exist "!DIR_A!\kill_probe_S3b_result.json" (
    findstr /c:"\"end_ok\": true" "!DIR_A!\kill_probe_S3b_result.json" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] S3: S3b ran successfully with stale entries present
        set /a PASS+=1
    ) else (
        echo   [FAIL] S3: S3b lost access — stale state interfered
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] S3: S3b result file missing
    set /a FAIL+=1
)

REM 3c: After S3b's clean exit, its own grants should be gone.
REM     S3a's stale grants should still exist (only --cleanup removes them).
REM     Just verify --cleanup works.
if defined S3A_PID taskkill /f /pid !S3A_PID! >nul 2>nul
if defined S3B_PID taskkill /f /pid !S3B_PID! >nul 2>nul
ping -n 2 127.0.0.1 >nul
"!SANDY!" --cleanup >nul 2>nul

set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] S3: --cleanup removed all stale entries
    set /a PASS+=1
) else (
    echo   [FAIL] S3: !REMAIN! stale entries remain after --cleanup
    reg query "HKCU\Software\Sandy\Grants" /s 2>nul
    set /a FAIL+=1
)
:S3_END

REM =====================================================================
REM Scenario 4: Rapid-fire start+kill (3 in succession)
REM Verify: all 3 stale entries accumulate, --cleanup handles all of them
REM NO manual reg delete — Sandy must cope with growing stale state
REM =====================================================================
echo.
echo === Scenario 4: Rapid-fire start+kill (3 instances) ===
echo.

echo   Rapid-fire: start+kill, start+kill, start+kill

REM S4a
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S4a 60 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S4A_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S4a_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
taskkill /f /pid !S4A_PID! >nul 2>nul
ping -n 3 127.0.0.1 >nul

REM S4b
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S4b 60 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S4B_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S4b_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
taskkill /f /pid !S4B_PID! >nul 2>nul
ping -n 3 127.0.0.1 >nul

REM S4c
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S4c 60 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S4C_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S4c_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
taskkill /f /pid !S4C_PID! >nul 2>nul
ping -n 2 127.0.0.1 >nul

REM 4a: All 3 stale entries MUST exist
set STALE_COUNT=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set STALE_COUNT=%%N
if !STALE_COUNT! GEQ 3 (
    echo   [PASS] S4: !STALE_COUNT! stale entries from 3 killed instances
    set /a PASS+=1
) else (
    echo   [FAIL] S4: Expected 3+ stale entries, got !STALE_COUNT!
    set /a FAIL+=1
)

REM 4b: Single --cleanup MUST handle all of them
"!SANDY!" --cleanup >nul 2>nul

set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] S4: --cleanup cleared all 3 stale entries
    set /a PASS+=1
) else (
    echo   [FAIL] S4: !REMAIN! entries persist after --cleanup
    reg query "HKCU\Software\Sandy\Grants" /s 2>nul
    set /a FAIL+=1
)

REM =====================================================================
REM Scenario 5: Kill BOTH overlapping instances, --cleanup recovers all
REM No manual help — --cleanup ALONE must handle double-kill
REM =====================================================================
echo.
echo === Scenario 5: Kill both overlapping instances ===
echo.

echo   Starting S5a (30s, folders A+B)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S5a 30 "!DIR_A!" "!DIR_B!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S5A_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S5a_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
if !READY! EQU 0 (
    echo   [FAIL] S5: S5a did not start
    set /a FAIL+=1
    goto :S5_END
)
echo   [OK] S5a running (PID !S5A_PID!)

ping -n 4 127.0.0.1 >nul

echo   Starting S5b (30s, folder A — overlapping)...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S5b 30 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S5B_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S5b_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
if !READY! EQU 0 (
    echo   [FAIL] S5: S5b did not start
    set /a FAIL+=1
    goto :S5_END
)
echo   [OK] S5b running (PID !S5B_PID!) — killing BOTH now

taskkill /f /pid !S5A_PID! >nul 2>nul
taskkill /f /pid !S5B_PID! >nul 2>nul
ping -n 2 127.0.0.1 >nul

REM 5a: Both stale entries MUST exist
set STALE_COUNT=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set STALE_COUNT=%%N
if !STALE_COUNT! GEQ 2 (
    echo   [PASS] S5: !STALE_COUNT! stale entries from both killed instances
    set /a PASS+=1
) else (
    echo   [FAIL] S5: Expected 2+ stale entries, got !STALE_COUNT!
    set /a FAIL+=1
)

REM 5b: Both folders MUST have AppContainer SIDs
set SCA=0
for /f %%N in ('icacls "!DIR_A!" 2^>nul ^| findstr /c:"S-1-15-2-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SCA=%%N
set SCB=0
for /f %%N in ('icacls "!DIR_B!" 2^>nul ^| findstr /c:"S-1-15-2-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SCB=%%N
if !SCA! GEQ 1 if !SCB! GEQ 1 (
    echo   [PASS] S5: Both folders have AppContainer SIDs (A:!SCA! B:!SCB!)
    set /a PASS+=1
    goto :S5_SID_DONE
)
echo   [FAIL] S5: Missing SIDs (A:!SCA! B:!SCB!)
set /a FAIL+=1
:S5_SID_DONE

REM 5c: --cleanup ALONE must recover everything
"!SANDY!" --cleanup >nul 2>nul

set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] S5: --cleanup removed all stale entries
    set /a PASS+=1
) else (
    echo   [FAIL] S5: !REMAIN! entries persist after --cleanup
    reg query "HKCU\Software\Sandy\Grants" /s 2>nul
    set /a FAIL+=1
)

REM 5d: No orphaned profiles
"!SANDY!" --status >"%TEMP%\sandy_kill_s5.txt"
findstr /c:"PROFILE" "%TEMP%\sandy_kill_s5.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] S5: No orphaned AppContainer profiles
    set /a PASS+=1
) else (
    echo   [FAIL] S5: Orphaned profiles remain
    type "%TEMP%\sandy_kill_s5.txt"
    set /a FAIL+=1
)
:S5_END

REM =====================================================================
REM Scenario 6: Clean instance alongside stale entries from ALL prior kills
REM NOTE: Stale state from S1-S5 may still exist if --cleanup didn't
REM       fully clear it.  This tests real-world accumulation.
REM =====================================================================
echo.
echo === Scenario 6: Clean instance with accumulated stale state ===
echo.

REM Show what stale state exists entering this scenario
echo   [INFO] Stale state entering S6:
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [INFO] Grants key still exists (residual from prior scenarios^)
) else (
    echo   [INFO] Grants key clean
)

REM Start and kill one more (to guarantee stale entries exist)
echo   Starting and killing S6a...
start /b "" "!SANDY!" -c "!CONFIG!" -q -x "!PYTHON!" "!PROBE!" S6a 30 "!DIR_A!"
ping -n 2 127.0.0.1 >nul
for /f %%P in ('powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter ('Name='+[char]39+'sandy.exe'+[char]39) | Sort-Object ProcessId -Descending | Select-Object -First 1).ProcessId"') do set "S6A_PID=%%P"
set READY=0
for /l %%W in (1,1,30) do (
    if exist "!DIR_A!\kill_probe_S6a_ready.signal" set READY=1
    if !READY! EQU 0 ping -n 2 127.0.0.1 >nul
)
taskkill /f /pid !S6A_PID! >nul 2>nul
ping -n 2 127.0.0.1 >nul

REM 6a: Run clean instance synchronously — MUST warn about stale entries
echo   Starting S6b (8s) — should warn and run cleanly...
"!SANDY!" -c "!CONFIG!" -x "!PYTHON!" "!PROBE!" S6b 8 "!DIR_A!" 2>"%TEMP%\sandy_kill_s6.txt"

findstr /c:"WARNING" "%TEMP%\sandy_kill_s6.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] S6: Stale entry warning emitted
    set /a PASS+=1
) else (
    echo   [FAIL] S6: No stale entry warning
    set /a FAIL+=1
)

REM 6b: S6b MUST have succeeded despite stale state
if exist "!DIR_A!\kill_probe_S6b_result.json" (
    findstr /c:"\"end_ok\": true" "!DIR_A!\kill_probe_S6b_result.json" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] S6: Clean instance ran successfully with stale entries
        set /a PASS+=1
    ) else (
        echo   [FAIL] S6: S6b failed — stale state corrupted grants
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] S6: S6b result file missing
    set /a FAIL+=1
)

REM 6c: Final --cleanup MUST clear everything from the ENTIRE test
"!SANDY!" --cleanup >nul 2>nul

set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] S6: --cleanup cleared all remaining stale state
    set /a PASS+=1
) else (
    echo   [FAIL] S6: !REMAIN! entries persist — Sandy cannot fully clean itself
    reg query "HKCU\Software\Sandy\Grants" /s 2>nul
    set /a FAIL+=1
)

REM =====================================================================
REM Final: Verify Sandy left absolutely nothing behind
REM =====================================================================
echo.
echo === Final: Verify pristine state (Sandy must leave nothing) ===
echo.

REM F1: No scheduled task
schtasks /Query /TN "SandyCleanup" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No scheduled task remains
    set /a PASS+=1
) else (
    echo   [FAIL] SandyCleanup task still exists
    set /a FAIL+=1
)

REM F2: No orphaned profiles
"!SANDY!" --status >"%TEMP%\sandy_kill_final.txt"
findstr /c:"PROFILE" "%TEMP%\sandy_kill_final.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No orphaned AppContainer profiles
    set /a PASS+=1
) else (
    echo   [FAIL] Orphaned profiles remain
    type "%TEMP%\sandy_kill_final.txt"
    set /a FAIL+=1
)

REM F3: No WER entries
reg query "HKCU\Software\Sandy\WER" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No WER entries remain
    set /a PASS+=1
) else (
    echo   [FAIL] WER entries still exist
    reg query "HKCU\Software\Sandy\WER" /s 2>nul
    set /a FAIL+=1
)

REM Cleanup temp files and test folders
del "%TEMP%\sandy_kill_*.txt" 2>nul
if exist "!DIR_A!" rmdir /s /q "!DIR_A!"
if exist "!DIR_B!" rmdir /s /q "!DIR_B!"

REM === Defense-in-depth: clear stale subkeys (parent keys are permanent) ===
"!SANDY!" --cleanup >nul 2>nul
for /f "tokens=*" %%K in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\"') do (
    reg delete "%%K" /f >nul 2>nul
)
for /f "tokens=1,2,*" %%A in ('reg query "HKCU\Software\Sandy\WER" /v * 2^>nul ^| findstr REG_') do (
    reg delete "HKCU\Software\Sandy\WER" /v "%%A" /f >nul 2>nul
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
    exit /b 1
)
exit /b 0
