@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Collusion4 — 4-Actor Multi-Instance Stress Test
REM
REM Four AppContainer instances share ALL on hub/ with unique denies:
REM   Alpha: deny vault/      (exits 1st)
REM   Beta:  deny logs/       (exits 2nd)
REM   Gamma: deny drop/       (exits 3rd)
REM   Delta: deny quarantine/ (exits 4th)
REM
REM Verifies each actor's deny survives all predecessors' cleanup.
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_collude4
set HUB=%ROOT%\hub
set PASS=0
set FAIL=0

echo =====================================================================
echo  Collusion4 Test Suite -- 4-Actor Multi-Instance Stress Test
echo  Alpha (deny vault) + Beta (deny logs) +
echo  Gamma (deny drop)  + Delta (deny quarantine)
echo =====================================================================

REM === Pre-clean ===
"!SANDY!" --cleanup >nul 2>nul
if exist "!ROOT!" rmdir /s /q "!ROOT!"

REM === Create directory structure ===
mkdir "!HUB!\vault\inner"
mkdir "!HUB!\logs\archive"
mkdir "!HUB!\drop\inbox"
mkdir "!HUB!\quarantine\locked"
mkdir "!HUB!\common"
mkdir "!HUB!\signals"
mkdir "!ROOT!\scripts"

REM === Create test data ===
echo VAULT_SECRET > "!HUB!\vault\classified.txt"
echo DEEP_SECRET > "!HUB!\vault\inner\deep.txt"
echo AUDIT_RECORD > "!HUB!\logs\audit.txt"
echo OLD_RECORD > "!HUB!\logs\archive\old.txt"
echo DROP_PAYLOAD > "!HUB!\drop\payload.txt"
echo INBOX_MSG > "!HUB!\drop\inbox\msg.txt"
echo QUARANTINED > "!HUB!\quarantine\specimen.txt"
echo LOCKED_ITEM > "!HUB!\quarantine\locked\item.txt"
echo SHARED_DATA > "!HUB!\common\shared.txt"

echo.
echo   [OK] Directory tree created

REM === Copy probe script ===
copy /y "%~dp0test_collude4_probe.py" "!ROOT!\scripts\probe.py" >nul

REM === Record pre-Sandy SDDL snapshots ===
echo.
echo --- Pre-Sandy SDDL snapshots ---
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!').Sddl" 2^>nul') do set "PRE_HUB=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\vault').Sddl" 2^>nul') do set "PRE_VAULT=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\logs').Sddl" 2^>nul') do set "PRE_LOGS=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\drop').Sddl" 2^>nul') do set "PRE_DROP=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\quarantine').Sddl" 2^>nul') do set "PRE_QUAR=%%S"
echo   hub/:        %PRE_HUB:~0,50%...
echo   vault/:      %PRE_VAULT:~0,50%...
echo   logs/:       %PRE_LOGS:~0,50%...
echo   drop/:       %PRE_DROP:~0,50%...
echo   quarantine/: %PRE_QUAR:~0,50%...

REM === Launch all 4 actors ===
echo.
echo === Starting all 4 actors (staggered 3s apart) ===
start /b "" "!SANDY!" -c "%~dp0test_collude4_alpha.toml" -x "!PYTHON!" "!ROOT!\scripts\probe.py" alpha > "%TEMP%\collude4_alpha.txt" 2>&1
ping -n 4 127.0.0.1 >nul
start /b "" "!SANDY!" -c "%~dp0test_collude4_beta.toml" -x "!PYTHON!" "!ROOT!\scripts\probe.py" beta > "%TEMP%\collude4_beta.txt" 2>&1
ping -n 4 127.0.0.1 >nul
start /b "" "!SANDY!" -c "%~dp0test_collude4_gamma.toml" -x "!PYTHON!" "!ROOT!\scripts\probe.py" gamma > "%TEMP%\collude4_gamma.txt" 2>&1
ping -n 4 127.0.0.1 >nul
start /b "" "!SANDY!" -c "%~dp0test_collude4_delta.toml" -x "!PYTHON!" "!ROOT!\scripts\probe.py" delta > "%TEMP%\collude4_delta.txt" 2>&1

echo === Waiting for all 4 actors to finish (max 180s) ===
echo   (Exit order: Alpha -^> Beta -^> Gamma -^> Delta with 5s cleanup gaps)

set ALL_DONE=0
for /l %%W in (1,1,180) do (
    if !ALL_DONE! EQU 0 (
        set DONE_COUNT=0
        if exist "!HUB!\signals\alpha_done" set /a DONE_COUNT+=1
        if exist "!HUB!\signals\beta_done" set /a DONE_COUNT+=1
        if exist "!HUB!\signals\gamma_done" set /a DONE_COUNT+=1
        if exist "!HUB!\signals\delta_done" set /a DONE_COUNT+=1
        if !DONE_COUNT! GEQ 4 set ALL_DONE=1
        if !ALL_DONE! EQU 0 ping -n 2 127.0.0.1 >nul
    )
)

if !ALL_DONE! EQU 0 (
    echo   [WARN] Not all actors finished within 180s!
) else (
    echo   [OK] All 4 actors finished. Waiting for Sandy cleanup...
)
ping -n 10 127.0.0.1 >nul

REM === Print outputs ===
for %%A in (alpha beta gamma delta) do (
    echo.
    echo =====================================================================
    echo  %%A OUTPUT:
    echo =====================================================================
    type "%TEMP%\collude4_%%A.txt"
)

REM === Parse pass/fail from each actor's output ===
for %%A in (alpha beta gamma delta) do (
    for /f "tokens=2,4" %%P in ('findstr /C:"pass," "%TEMP%\collude4_%%A.txt" 2^>nul') do (
        set /a PASS+=%%P
        set /a FAIL+=%%Q
    )
)

REM === Post-Cleanup Verification ===
echo.
echo =====================================================================
echo  Post-Cleanup Verification (THE CRITICAL TEST)
echo =====================================================================

REM Check no AppContainer SIDs remain on the tree
powershell -NoProfile -Command "(Get-Acl '%HUB%').Sddl + (Get-Acl '%HUB%\vault').Sddl + (Get-Acl '%HUB%\logs').Sddl + (Get-Acl '%HUB%\drop').Sddl + (Get-Acl '%HUB%\quarantine').Sddl + (Get-Acl '%HUB%\common').Sddl" 2>nul | findstr /C:"S-1-15-2-" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No AppContainer SIDs on any directory
    set /a PASS+=1
) else (
    echo   [FAIL] Stale AppContainer SIDs found!
    set /a FAIL+=1
)

REM Check no grant registry entries remain
reg query "HKCU\Software\Sandy\Grants" /s 2>nul | findstr /C:"HKEY_CURRENT_USER\Software\Sandy\Grants\" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    echo   [FAIL] Stale grant registry entries!
    set /a FAIL+=1
)

REM === SDDL Fidelity ===
echo.
echo --- SDDL Fidelity (forensic proof) ---
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!').Sddl" 2^>nul') do set "POST_HUB=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\vault').Sddl" 2^>nul') do set "POST_VAULT=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\logs').Sddl" 2^>nul') do set "POST_LOGS=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\drop').Sddl" 2^>nul') do set "POST_DROP=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '!HUB!\quarantine').Sddl" 2^>nul') do set "POST_QUAR=%%S"

if "!POST_HUB!"=="!PRE_HUB!" (
    echo   [PASS] hub/ DACL restored to original
    set /a PASS+=1
) else (
    echo   [FAIL] hub/ DACL mismatch!
    set /a FAIL+=1
)

if "!POST_VAULT!"=="!PRE_VAULT!" (
    echo   [PASS] vault/ DACL restored to original
    set /a PASS+=1
) else (
    echo   [FAIL] vault/ DACL mismatch!
    set /a FAIL+=1
)

if "!POST_LOGS!"=="!PRE_LOGS!" (
    echo   [PASS] logs/ DACL restored to original
    set /a PASS+=1
) else (
    echo   [FAIL] logs/ DACL mismatch!
    set /a FAIL+=1
)

if "!POST_DROP!"=="!PRE_DROP!" (
    echo   [PASS] drop/ DACL restored to original
    set /a PASS+=1
) else (
    echo   [FAIL] drop/ DACL mismatch!
    set /a FAIL+=1
)

if "!POST_QUAR!"=="!PRE_QUAR!" (
    echo   [PASS] quarantine/ DACL restored to original
    set /a PASS+=1
) else (
    echo   [FAIL] quarantine/ DACL mismatch!
    set /a FAIL+=1
)

REM === Final Summary ===
echo.
echo =====================================================================
if !FAIL! EQU 0 (
    echo  ALL HELD -- Sandy survived 4-actor collusion attack
) else (
    echo  FAILURES DETECTED
)
echo  Cleanup: !PASS! passed, !FAIL! failed
echo =====================================================================

del "%TEMP%\collude4_*.txt" 2>nul

if !FAIL! NEQ 0 exit /b 1
exit /b 0
