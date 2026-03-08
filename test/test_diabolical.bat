@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_diabolical.bat -- Implementation-level adversarial tests
REM Targets Sandy's OWN CODE, not Windows kernel invariants.
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_diabolical_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_diabolical
set PASS=0
set FAIL=0

echo =====================================================================
echo  Diabolical Test Suite -- Sandy Implementation Attacks
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
copy /y "%~dp0test_diabolical.py" "%ROOT%\scripts\test_diabolical.py" >nul

REM Arena with test zones
mkdir "%ROOT%\arena\killzone"
mkdir "%ROOT%\arena\fortress"
mkdir "%ROOT%\arena\readonly_zone"
mkdir "%ROOT%\arena\playground"

REM Seed files in denied zones
echo TOP SECRET> "%ROOT%\arena\fortress\secret.txt"
echo report data> "%ROOT%\arena\readonly_zone\report.txt"

echo   [OK] Folder tree created
echo.

REM === Capture pre-Sandy SDDLs (ATTACK 8: DACL fidelity) ===
echo --- Pre-Sandy DACL snapshots ---
set SDDL_ARENA=
set SDDL_KILLZONE=
set SDDL_FORTRESS=
set SDDL_READONLY=

for /f "tokens=*" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\arena').Sddl"') do set SDDL_ARENA=%%S
for /f "tokens=*" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\arena\killzone').Sddl"') do set SDDL_KILLZONE=%%S
for /f "tokens=*" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\arena\fortress').Sddl"') do set SDDL_FORTRESS=%%S
for /f "tokens=*" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\arena\readonly_zone').Sddl"') do set SDDL_READONLY=%%S
echo   Captured 4 pre-Sandy SDDLs
echo.

REM === Run probe inside sandbox ===
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_diabolical.py"
set SANDY_EXIT=!ERRORLEVEL!
echo.

REM === Post-Cleanup Verification ===
echo === Post-Cleanup Verification ===
echo.

REM --- Check 1: AppContainer SID residue ---
set SC=0
for /f %%N in ('icacls "%ROOT%\arena" /t 2^>nul ^| findstr /c:"S-1-15-2-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No AppContainer SIDs on arena/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! AppContainer SID entries remain
    set /a FAIL+=1
)

REM --- Check 2: OID attack result ---
if exist "%ROOT%\arena\_oid_attack_done" (
    REM The probe renamed fortress -> fortress_escaped AND stripped OID
    REM Sandy's cleanup should have found it via OID or at least not left SIDs
    set FSC=0
    if exist "%ROOT%\arena\fortress_escaped" (
        for /f %%N in ('icacls "%ROOT%\arena\fortress_escaped" /t 2^>nul ^| findstr /c:"S-1-15-2-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set FSC=%%N
        if !FSC! EQU 0 (
            echo   [PASS] Renamed fortress has no residual SIDs
            set /a PASS+=1
        ) else (
            echo   [FAIL] Renamed fortress has !FSC! residual AppContainer SIDs
            set /a FAIL+=1
        )
    )
) else (
    echo   [SKIP] OID attack did not complete
)

REM --- Check 3: Registry entries cleaned ---
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    set REMAIN=0
    for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
    if !REMAIN! EQU 0 (
        echo   [PASS] No grant registry entries remain
        set /a PASS+=1
    ) else (
        echo   [FAIL] !REMAIN! grant subkeys persist
        set /a FAIL+=1
    )
)

REM --- Check 4: DACL fidelity (ATTACK 8) ---
echo.
echo --- DACL Fidelity Check ---
set SDDL_ARENA_POST=
set SDDL_KILLZONE_POST=
set SDDL_READONLY_POST=

for /f "tokens=*" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\arena').Sddl"') do set SDDL_ARENA_POST=%%S

REM killzone might have been deleted and recreated by the probe
if exist "%ROOT%\arena\killzone" (
    for /f "tokens=*" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\arena\killzone').Sddl"') do set SDDL_KILLZONE_POST=%%S
)

for /f "tokens=*" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\arena\readonly_zone').Sddl"') do set SDDL_READONLY_POST=%%S

if "!SDDL_ARENA!"=="!SDDL_ARENA_POST!" (
    echo   [PASS] arena/ DACL restored exactly
    set /a PASS+=1
) else (
    echo   [FAIL] arena/ DACL differs after cleanup!
    echo     PRE:  !SDDL_ARENA!
    echo     POST: !SDDL_ARENA_POST!
    set /a FAIL+=1
)

if "!SDDL_KILLZONE!"=="!SDDL_KILLZONE_POST!" (
    echo   [PASS] killzone/ DACL restored exactly
    set /a PASS+=1
) else (
    if "!SDDL_KILLZONE_POST!"=="" (
        echo   [INFO] killzone/ deleted by probe (expected if delete-recreate attack worked^)
    ) else (
        echo   [FAIL] killzone/ DACL differs after cleanup!
        echo     PRE:  !SDDL_KILLZONE!
        echo     POST: !SDDL_KILLZONE_POST!
        set /a FAIL+=1
    )
)

if "!SDDL_READONLY!"=="!SDDL_READONLY_POST!" (
    echo   [PASS] readonly_zone/ DACL restored exactly
    set /a PASS+=1
) else (
    echo   [FAIL] readonly_zone/ DACL differs after cleanup!
    echo     PRE:  !SDDL_READONLY!
    echo     POST: !SDDL_READONLY_POST!
    set /a FAIL+=1
)

echo.

REM === Final Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

REM === Summary ===
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
if !SANDY_EXIT! EQU 0 if !FAIL! EQU 0 (
    echo  ALL HELD -- Sandy survived implementation attacks
) else (
    echo  ISSUES FOUND -- see details above
)
echo  Probe: exited with code !SANDY_EXIT!
echo  Cleanup: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.

if !SANDY_EXIT! NEQ 0 exit /b 1
if !FAIL! GTR 0 exit /b 1
exit /b 0
