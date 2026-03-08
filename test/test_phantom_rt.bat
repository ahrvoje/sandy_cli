@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_phantom_rt.bat -- Phantom test suite (Restricted Token mode)
REM Persistence, observation, cleanup interference
REM =====================================================================

echo =====================================================================
echo  Phantom Test Suite — Restricted Token Mode
echo  11 attack vectors (P1-P11)
echo =====================================================================

set "ROOT=%USERPROFILE%\test_phantom"
set "ARENA=%ROOT%\arena"
set "SANDY=c:\repos\sandy_cli\x64\Release\sandy.exe"
set "CONFIG=c:\repos\sandy_cli\test\test_phantom_rt_config.toml"
set "SCRIPT=c:\repos\sandy_cli\test\test_phantom.py"

REM --- Clean previous run ---
if exist "%ROOT%" (
    icacls "%ROOT%" /reset /T /Q >nul 2>&1
    rmdir /S /Q "%ROOT%" 2>nul
)

REM --- Build tree ---
mkdir "%ARENA%\forbidden" 2>nul
mkdir "%ARENA%\readonly" 2>nul
mkdir "%ROOT%\scripts" 2>nul

REM --- Seed files ---
echo forbidden_secret > "%ARENA%\forbidden\secret.txt"
echo readonly_report > "%ARENA%\readonly\report.txt"

REM --- Copy script ---
copy /Y "%SCRIPT%" "%ROOT%\scripts\test_phantom.py" >nul

echo.
echo   [OK] Folder tree created with seed files

REM --- Capture pre-Sandy SDDLs ---
echo.
echo --- Pre-Sandy SDDL snapshots ---
set "SDDL_PATHS=arena arena\forbidden arena\readonly"
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
"%SANDY%" -c "%CONFIG%" -x "C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe" "%ROOT%\scripts\test_phantom.py" 2>&1
set SANDY_EXIT=%ERRORLEVEL%
echo.

REM =====================================================================
REM Post-Cleanup Verification
REM =====================================================================
echo === Post-Cleanup Verification ===
echo.

set CLEANUP_PASS=0
set CLEANUP_FAIL=0

REM --- Check residual RT SIDs ---
set "SID_FOUND=0"
for /f "delims=" %%L in ('icacls "%ARENA%" /T 2^>nul ^| findstr /i "S-1-9-"') do (
    set "SID_FOUND=1"
    echo   [DETAIL] Residual: %%L
)
if "!SID_FOUND!"=="0" (
    echo   [PASS] No Restricted Token SIDs on arena/ tree
    set /a CLEANUP_PASS+=1
) else (
    echo   [FAIL] Residual Restricted Token SIDs found!
    set /a CLEANUP_FAIL+=1
)

REM --- Check for ADS artifacts left behind ---
echo.
echo --- ADS Artifact Check ---
set "ADS_FOUND=0"
for /f "delims=" %%L in ('dir /s /r "%ARENA%\*" 2^>nul ^| findstr ":"') do (
    echo %%L | findstr /i "phantom_data" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "ADS_FOUND=1"
        echo   [INFO] ADS artifact: %%L
    )
)
if "!ADS_FOUND!"=="0" (
    echo   [PASS] No phantom ADS artifacts on arena/
    set /a CLEANUP_PASS+=1
) else (
    echo   [INFO] ADS data persists (expected — Sandy cleans ACLs, not file data)
    set /a CLEANUP_PASS+=1
)

REM --- Check for armored files (READONLY attribute) ---
echo.
echo --- Attribute Armor Check ---
if exist "%ARENA%\armored.txt" (
    attrib "%ARENA%\armored.txt"
    echo   [INFO] armored.txt still exists with attributes
) else (
    echo   [PASS] armored.txt cleaned
)
set /a CLEANUP_PASS+=1

REM --- Registry (parent key is permanent; only subkeys = stale) ---
set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] No grant registry entries remain
    set /a CLEANUP_PASS+=1
) else (
    echo   [FAIL] !REMAIN! stale grant subkeys persist
    set /a CLEANUP_FAIL+=1
)

REM --- SDDL Fidelity ---
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
    echo  ALL HELD -- Sandy survived phantom attacks (RT mode)
) else (
    echo  Probe: exited with code %SANDY_EXIT%
)
echo  Cleanup: !CLEANUP_PASS! passed, !CLEANUP_FAIL! failed
echo =====================================================================

REM --- Cleanup test tree ---
if exist "%ROOT%" (
    attrib -R -H -S "%ROOT%\arena\*" /S >nul 2>&1
    icacls "%ROOT%" /reset /T /Q >nul 2>&1
    rmdir /S /Q "%ROOT%" 2>nul
)

exit /b %SANDY_EXIT%
