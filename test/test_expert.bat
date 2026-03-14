@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_expert.bat -- Expert adversarial test suite
REM Targets Sandy's implementation assumptions, not Windows kernel.
REM =====================================================================

echo =====================================================================
echo  Expert Adversarial Test Suite -- Sandy Implementation Attacks
echo  10 attack vectors, ~45 test cases
echo =====================================================================

set "ROOT=%USERPROFILE%\test_expert"
set "ARENA=%ROOT%\arena"
set "SANDY=c:\repos\sandy_cli\x64\Release\sandy.exe"
set "CONFIG=c:\repos\sandy_cli\test\test_expert_config.toml"
set "SCRIPT=c:\repos\sandy_cli\test\test_expert.py"

REM --- Clean previous run ---
if exist "%ROOT%" (
    icacls "%ROOT%" /reset /T /Q >nul 2>&1
    rmdir /S /Q "%ROOT%" 2>nul
)

REM --- Build tree ---
mkdir "%ARENA%\denied_zone" 2>nul
mkdir "%ARENA%\readonly_zone" 2>nul
mkdir "%ARENA%\double_deny" 2>nul
mkdir "%ARENA%\deep\a\b\c\d" 2>nul
mkdir "%ARENA%\playground" 2>nul
mkdir "%ROOT%\scripts" 2>nul

REM --- Seed files in deny zones ---
echo readonly_report > "%ARENA%\readonly_zone\report.txt"
echo double_deny_data > "%ARENA%\double_deny\data.txt"
echo deep_secret > "%ARENA%\deep\a\b\c\d\secret.txt"

REM --- Copy script ---
copy /Y "%SCRIPT%" "%ROOT%\scripts\test_expert.py" >nul

echo.
echo   [OK] Folder tree created with seed files

REM --- Capture pre-Sandy SDDLs ---
echo.
echo --- Pre-Sandy SDDL snapshots ---
set "SDDL_PATHS=arena arena\denied_zone arena\readonly_zone arena\double_deny arena\deep\a\b\c\d arena\playground"
set IDX=0
for %%P in (%SDDL_PATHS%) do (
    for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\%%P').Sddl" 2^>nul') do (
        set "PRE_SDDL_!IDX!=%%S"
        set "SDDL_PATH_!IDX!=%%P"
    )
    set /a IDX+=1
)
set "SDDL_COUNT=!IDX!"
echo   Captured %SDDL_COUNT% pre-Sandy SDDLs

REM --- Run Sandy ---
echo.
"%SANDY%" -c "%CONFIG%" -x "C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe" "%ROOT%\scripts\test_expert.py" 2>&1
set SANDY_EXIT=%ERRORLEVEL%
echo.

REM =====================================================================
REM Post-Cleanup Verification
REM =====================================================================
echo === Post-Cleanup Verification ===
echo.

set CLEANUP_PASS=0
set CLEANUP_FAIL=0

REM --- A1: Check for residual AppContainer SIDs ---
set "SID_FOUND=0"
for /f "delims=" %%L in ('icacls "%ARENA%" /T 2^>nul ^| findstr /i "S-1-15-"') do (
    set "SID_FOUND=1"
    echo   [DETAIL] Residual ACE: %%L
)
if "!SID_FOUND!"=="0" (
    echo   [PASS] No AppContainer SIDs on arena/ tree
    set /a CLEANUP_PASS+=1
) else (
    echo   [FAIL] Residual AppContainer SIDs found!
    set /a CLEANUP_FAIL+=1
)

REM --- Check runtime_storm/ cleanup ---
set "STORM_SID=0"
if exist "%ARENA%\runtime_storm" (
    for /f "delims=" %%L in ('icacls "%ARENA%\runtime_storm" /T 2^>nul ^| findstr /i "S-1-15-"') do (
        set "STORM_SID=1"
    )
    if "!STORM_SID!"=="0" (
        echo   [PASS] Runtime storm: no residual SIDs on 60 objects
        set /a CLEANUP_PASS+=1
    ) else (
        echo   [FAIL] Runtime storm: residual SIDs on created objects!
        set /a CLEANUP_FAIL+=1
    )
) else (
    echo   [PASS] Runtime storm: folder cleaned
    set /a CLEANUP_PASS+=1
)

REM --- Clean stale state before checking ---
"%SANDY%" --cleanup >nul 2>&1

REM --- Check registry ---
reg query "HKCU\Software\Sandy\Grants" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo   [PASS] No grant registry entries remain
    set /a CLEANUP_PASS+=1
) else (
    set "HAS_SUBKEYS=0"
    for /f "delims=" %%K in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\"') do set "HAS_SUBKEYS=1"
    if "!HAS_SUBKEYS!"=="0" (
        echo   [PASS] Grants registry key empty
        set /a CLEANUP_PASS+=1
    ) else (
        echo   [FAIL] Stale grant registry entries!
        set /a CLEANUP_FAIL+=1
    )
)

REM --- SDDL Fidelity Check ---
echo.
echo --- SDDL Fidelity Check ---
set IDX=0
:sddl_loop
if !IDX! GEQ !SDDL_COUNT! goto sddl_done
set "SP=!SDDL_PATH_%IDX%!"
set "EXPECTED=!PRE_SDDL_%IDX%!"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\!SP!').Sddl" 2^>nul') do set "ACTUAL=%%S"
if "!ACTUAL!"=="!EXPECTED!" (
    echo   [PASS] !SP! DACL restored exactly
    set /a CLEANUP_PASS+=1
) else (
    echo   [FAIL] !SP! DACL mismatch!
    echo     Expected: !EXPECTED!
    echo     Actual:   !ACTUAL!
    set /a CLEANUP_FAIL+=1
)
set /a IDX+=1
goto sddl_loop
:sddl_done

echo.
echo =====================================================================
if %SANDY_EXIT% EQU 0 (
    echo  ALL HELD -- Sandy survived expert attacks
) else (
    echo  Probe: exited with code %SANDY_EXIT%
)
echo  Cleanup: !CLEANUP_PASS! passed, !CLEANUP_FAIL! failed (of %CLEANUP_PASS%+%CLEANUP_FAIL%)
echo =====================================================================

REM --- Cleanup test tree ---
if exist "%ROOT%" (
    icacls "%ROOT%" /reset /T /Q >nul 2>&1
    rmdir /S /Q "%ROOT%" 2>nul
)

exit /b %SANDY_EXIT%
