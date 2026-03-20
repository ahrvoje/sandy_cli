@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy --dry-run Test Suite
REM Tests: dry-run for sandboxed run AND for --create-profile
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set AC_CONFIG=%~dp0test_dryrun_ac.toml
set RT_CONFIG=%~dp0test_dryrun_rt.toml
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Dry-Run Test Suite
echo =====================================================================

REM === Pre-clean any stale profile named dr_test ===
"!SANDY!" --delete-profile dr_test >nul 2>nul

REM ===================================================================
REM DR1 — --dry-run for sandboxed run (AC config, no -x)
REM ===================================================================
echo.
echo --- DR1: --dry-run with AC config (no -x) ---

"!SANDY!" --dry-run -c "!AC_CONFIG!" >"%TEMP%\sandy_dr1.txt" 2>&1
set DR1_EC=!ERRORLEVEL!

if !DR1_EC! EQU 0 (
    echo   [PASS] DR1a: exit 0
    set /a PASS+=1
) else (
    echo   [FAIL] DR1a: exit code !DR1_EC!
    set /a FAIL+=1
)

findstr /C:"Dry Run" "%TEMP%\sandy_dr1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR1b: Output contains "Dry Run" header
    set /a PASS+=1
) else (
    echo   [FAIL] DR1b: Missing "Dry Run" header
    set /a FAIL+=1
)

findstr /C:"No system state modified" "%TEMP%\sandy_dr1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR1c: Confirms no system changes
    set /a PASS+=1
) else (
    echo   [FAIL] DR1c: Missing no-change confirmation
    set /a FAIL+=1
)

REM Verify no registry grant key was created
reg query "HKCU\Software\Sandy\Grants" /s 2>nul | findstr /C:"HKEY_CURRENT_USER\Software\Sandy\Grants\" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] DR1d: No registry grant created
    set /a PASS+=1
) else (
    echo   [FAIL] DR1d: Unexpected registry grant found
    set /a FAIL+=1
)

del "%TEMP%\sandy_dr1.txt" 2>nul

REM ===================================================================
REM DR2 — --dry-run for sandboxed run (AC config, with -x)
REM ===================================================================
echo.
echo --- DR2: --dry-run with AC config and -x ---

"!SANDY!" --dry-run -c "!AC_CONFIG!" -x cmd.exe >"%TEMP%\sandy_dr2.txt" 2>&1
set DR2_EC=!ERRORLEVEL!

if !DR2_EC! EQU 0 (
    echo   [PASS] DR2a: exit 0 with -x
    set /a PASS+=1
) else (
    echo   [FAIL] DR2a: exit code !DR2_EC!
    set /a FAIL+=1
)

findstr /C:"Executable" "%TEMP%\sandy_dr2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR2b: Executable shown in output
    set /a PASS+=1
) else (
    echo   [FAIL] DR2b: Executable missing from output
    set /a FAIL+=1
)

del "%TEMP%\sandy_dr2.txt" 2>nul

REM ===================================================================
REM DR3 — --dry-run with RT config
REM ===================================================================
echo.
echo --- DR3: --dry-run with RT config ---

"!SANDY!" --dry-run -c "!RT_CONFIG!" >"%TEMP%\sandy_dr3.txt" 2>&1
set DR3_EC=!ERRORLEVEL!

if !DR3_EC! EQU 0 (
    echo   [PASS] DR3a: exit 0 with RT config
    set /a PASS+=1
) else (
    echo   [FAIL] DR3a: exit code !DR3_EC!
    set /a FAIL+=1
)

findstr /C:"restricted" "%TEMP%\sandy_dr3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR3b: Shows restricted mode
    set /a PASS+=1
) else (
    echo   [FAIL] DR3b: Mode not shown
    set /a FAIL+=1
)

del "%TEMP%\sandy_dr3.txt" 2>nul

REM ===================================================================
REM DR4 — --dry-run --create-profile (valid AC config, name not yet existing)
REM ===================================================================
echo.
echo --- DR4: --dry-run --create-profile (valid, no prior profile) ---

"!SANDY!" --dry-run --create-profile dr_test -c "!AC_CONFIG!" >"%TEMP%\sandy_dr4.txt" 2>&1
set DR4_EC=!ERRORLEVEL!

if !DR4_EC! EQU 0 (
    echo   [PASS] DR4a: exit 0
    set /a PASS+=1
) else (
    echo   [FAIL] DR4a: exit code !DR4_EC!
    set /a FAIL+=1
)

findstr /C:"Dry Run" "%TEMP%\sandy_dr4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR4b: Output has dry-run header
    set /a PASS+=1
) else (
    echo   [FAIL] DR4b: Missing dry-run header
    set /a FAIL+=1
)

findstr /C:"dr_test" "%TEMP%\sandy_dr4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR4c: Profile name shown
    set /a PASS+=1
) else (
    echo   [FAIL] DR4c: Profile name missing
    set /a FAIL+=1
)

findstr /C:"Registry key:" "%TEMP%\sandy_dr4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR4d: Shows registry key that would be created
    set /a PASS+=1
) else (
    echo   [FAIL] DR4d: Missing registry key preview
    set /a FAIL+=1
)

findstr /C:"No system state modified" "%TEMP%\sandy_dr4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR4e: Confirms no system changes
    set /a PASS+=1
) else (
    echo   [FAIL] DR4e: Missing no-change confirmation
    set /a FAIL+=1
)

REM Verify profile was NOT actually created
reg query "HKCU\Software\Sandy\Profiles\dr_test" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] DR4f: Profile dr_test was NOT created in registry
    set /a PASS+=1
) else (
    echo   [FAIL] DR4f: Profile was incorrectly created during dry-run!
    set /a FAIL+=1
    REM Clean up so subsequent tests are not affected
    "!SANDY!" --delete-profile dr_test >nul 2>nul
)

del "%TEMP%\sandy_dr4.txt" 2>nul

REM ===================================================================
REM DR5 — --dry-run --create-profile with duplicate (after real create)
REM ===================================================================
echo.
echo --- DR5: --dry-run --create-profile (existing profile = error) ---

REM Create the profile registry key directly (--create-profile may fail on
REM System32 ACLs without admin; the dry-run check only needs the registry entry)
reg add "HKCU\Software\Sandy\Profiles\dr_test" /v _token /t REG_SZ /d "appcontainer" /f >nul 2>nul

"!SANDY!" --dry-run --create-profile dr_test -c "!AC_CONFIG!" >nul 2>"%TEMP%\sandy_dr5.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] DR5a: Existing name rejected with dry-run
    set /a PASS+=1
) else (
    echo   [FAIL] DR5a: Should have rejected duplicate name
    set /a FAIL+=1
)

findstr /C:"already exists" "%TEMP%\sandy_dr5.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR5b: Error message says already exists
    set /a PASS+=1
) else (
    echo   [FAIL] DR5b: Missing already-exists error
    set /a FAIL+=1
)

REM Clean up real profile
"!SANDY!" --delete-profile dr_test >nul 2>nul
del "%TEMP%\sandy_dr5.txt" 2>nul

REM ===================================================================
REM DR6 — --dry-run --create-profile with invalid name characters
REM ===================================================================
echo.
echo --- DR6: --dry-run --create-profile (invalid name) ---

"!SANDY!" --dry-run --create-profile "bad\name" -c "!AC_CONFIG!" >nul 2>"%TEMP%\sandy_dr6.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] DR6a: Backslash name rejected in dry-run
    set /a PASS+=1
) else (
    echo   [FAIL] DR6a: Should reject backslash name
    set /a FAIL+=1
)

findstr /C:"invalid characters" "%TEMP%\sandy_dr6.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR6b: Invalid char error shown
    set /a PASS+=1
) else (
    echo   [FAIL] DR6b: Missing invalid char error
    set /a FAIL+=1
)

del "%TEMP%\sandy_dr6.txt" 2>nul

REM ===================================================================
REM DR7 — --dry-run --create-profile with non-existent config file
REM ===================================================================
echo.
echo --- DR7: --dry-run --create-profile (bad config path) ---

"!SANDY!" --dry-run --create-profile dr_test -c "C:\nonexistent\fake.toml" >nul 2>"%TEMP%\sandy_dr7.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] DR7a: Non-existent config rejected in dry-run
    set /a PASS+=1
) else (
    echo   [FAIL] DR7a: Should reject non-existent config
    set /a FAIL+=1
)

del "%TEMP%\sandy_dr7.txt" 2>nul

REM ===================================================================
REM DR8 — --dry-run --create-profile with RT config
REM ===================================================================
echo.
echo --- DR8: --dry-run --create-profile (RT config) ---

"!SANDY!" --dry-run --create-profile dr_test -c "!RT_CONFIG!" >"%TEMP%\sandy_dr8.txt" 2>&1
set DR8_EC=!ERRORLEVEL!

if !DR8_EC! EQU 0 (
    echo   [PASS] DR8a: exit 0 for RT dry-run create-profile
    set /a PASS+=1
) else (
    echo   [FAIL] DR8a: exit code !DR8_EC!
    set /a FAIL+=1
)

findstr /C:"restricted" "%TEMP%\sandy_dr8.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR8b: Shows restricted type
    set /a PASS+=1
) else (
    echo   [FAIL] DR8b: Missing type
    set /a FAIL+=1
)

findstr /C:"Integrity" "%TEMP%\sandy_dr8.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR8c: Shows integrity level
    set /a PASS+=1
) else (
    echo   [FAIL] DR8c: Missing integrity level
    set /a FAIL+=1
)

REM Verify profile was NOT actually created
reg query "HKCU\Software\Sandy\Profiles\dr_test" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] DR8d: RT dry-run did not create registry key
    set /a PASS+=1
) else (
    echo   [FAIL] DR8d: RT dry-run incorrectly created registry key!
    "!SANDY!" --delete-profile dr_test >nul 2>nul
    set /a FAIL+=1
)

del "%TEMP%\sandy_dr8.txt" 2>nul

REM ===================================================================
REM DR9 — Old 'localhost' key must be rejected
REM ===================================================================
echo.
echo --- DR9: Old 'localhost' key rejected ---

echo [sandbox]>"%TEMP%\dr9.toml"
echo token = 'appcontainer'>>"%TEMP%\dr9.toml"
echo [privileges]>>"%TEMP%\dr9.toml"
echo localhost = true>>"%TEMP%\dr9.toml"

"!SANDY!" --dry-run -c "%TEMP%\dr9.toml" >nul 2>"%TEMP%\sandy_dr9.txt"
set DR9_EC=!ERRORLEVEL!

if !DR9_EC! EQU 128 (
    echo   [PASS] DR9a: exit 128 for old 'localhost' key
    set /a PASS+=1
) else (
    echo   [FAIL] DR9a: exit code !DR9_EC! (expected 128^)
    set /a FAIL+=1
)

findstr /C:"removed" "%TEMP%\sandy_dr9.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR9b: Error message mentions key removal
    set /a PASS+=1
) else (
    echo   [FAIL] DR9b: Missing removal guidance message
    set /a FAIL+=1
)

findstr /C:"with localhost" "%TEMP%\sandy_dr9.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR9c: Error suggests 'with localhost' replacement
    set /a PASS+=1
) else (
    echo   [FAIL] DR9c: Missing replacement suggestion
    set /a FAIL+=1
)

del "%TEMP%\dr9.toml" 2>nul
del "%TEMP%\sandy_dr9.txt" 2>nul

REM ===================================================================
REM DR10 — lan = 'with localhost' accepted
REM ===================================================================
echo.
echo --- DR10: lan = 'with localhost' accepted ---

echo [sandbox]>"%TEMP%\dr10.toml"
echo token = 'appcontainer'>>"%TEMP%\dr10.toml"
echo [privileges]>>"%TEMP%\dr10.toml"
echo lan = 'with localhost'>>"%TEMP%\dr10.toml"

"!SANDY!" --dry-run -c "%TEMP%\dr10.toml" >"%TEMP%\sandy_dr10.txt" 2>&1
set DR10_EC=!ERRORLEVEL!

if !DR10_EC! EQU 0 (
    echo   [PASS] DR10a: exit 0 for lan = 'with localhost'
    set /a PASS+=1
) else (
    echo   [FAIL] DR10a: exit code !DR10_EC!
    set /a FAIL+=1
)

findstr /C:"'with localhost'" "%TEMP%\sandy_dr10.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR10b: Dry-run output shows 'with localhost'
    set /a PASS+=1
) else (
    echo   [FAIL] DR10b: Missing 'with localhost' in output
    set /a FAIL+=1
)

del "%TEMP%\dr10.toml" 2>nul
del "%TEMP%\sandy_dr10.txt" 2>nul

REM ===================================================================
REM DR11 — lan = 'without localhost' accepted
REM ===================================================================
echo.
echo --- DR11: lan = 'without localhost' accepted ---

echo [sandbox]>"%TEMP%\dr11.toml"
echo token = 'appcontainer'>>"%TEMP%\dr11.toml"
echo [privileges]>>"%TEMP%\dr11.toml"
echo lan = 'without localhost'>>"%TEMP%\dr11.toml"

"!SANDY!" --dry-run -c "%TEMP%\dr11.toml" >"%TEMP%\sandy_dr11.txt" 2>&1
set DR11_EC=!ERRORLEVEL!

if !DR11_EC! EQU 0 (
    echo   [PASS] DR11a: exit 0 for lan = 'without localhost'
    set /a PASS+=1
) else (
    echo   [FAIL] DR11a: exit code !DR11_EC!
    set /a FAIL+=1
)

findstr /C:"'without localhost'" "%TEMP%\sandy_dr11.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR11b: Dry-run output shows 'without localhost'
    set /a PASS+=1
) else (
    echo   [FAIL] DR11b: Missing 'without localhost' in output
    set /a FAIL+=1
)

del "%TEMP%\dr11.toml" 2>nul
del "%TEMP%\sandy_dr11.txt" 2>nul

REM ===================================================================
REM DR12 — lan = true backward compat (maps to 'without localhost')
REM ===================================================================
echo.
echo --- DR12: lan = true backward compat ---

echo [sandbox]>"%TEMP%\dr12.toml"
echo token = 'appcontainer'>>"%TEMP%\dr12.toml"
echo [privileges]>>"%TEMP%\dr12.toml"
echo lan = true>>"%TEMP%\dr12.toml"

"!SANDY!" --dry-run -c "%TEMP%\dr12.toml" >"%TEMP%\sandy_dr12.txt" 2>&1
set DR12_EC=!ERRORLEVEL!

if !DR12_EC! EQU 0 (
    echo   [PASS] DR12a: exit 0 for lan = true
    set /a PASS+=1
) else (
    echo   [FAIL] DR12a: exit code !DR12_EC!
    set /a FAIL+=1
)

findstr /C:"'without localhost'" "%TEMP%\sandy_dr12.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] DR12b: lan=true maps to 'without localhost'
    set /a PASS+=1
) else (
    echo   [FAIL] DR12b: lan=true did not map to 'without localhost'
    set /a FAIL+=1
)

del "%TEMP%\dr12.toml" 2>nul
del "%TEMP%\sandy_dr12.txt" 2>nul

REM ===================================================================
REM DR13 — --print-config roundtrip preserves lan value
REM ===================================================================
echo.
echo --- DR13: --print-config roundtrip for lan ---

echo [sandbox]>"%TEMP%\dr13.toml"
echo token = 'appcontainer'>>"%TEMP%\dr13.toml"
echo [privileges]>>"%TEMP%\dr13.toml"
echo lan = 'with localhost'>>"%TEMP%\dr13.toml"

"!SANDY!" --print-config -c "%TEMP%\dr13.toml" >"%TEMP%\sandy_dr13.txt" 2>&1
set DR13_EC=!ERRORLEVEL!

if !DR13_EC! EQU 0 (
    echo   [PASS] DR13a: exit 0 for print-config
    set /a PASS+=1
) else (
    echo   [FAIL] DR13a: exit code !DR13_EC!
    set /a FAIL+=1
)

findstr /C:"lan" "%TEMP%\sandy_dr13.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    findstr /C:"'with localhost'" "%TEMP%\sandy_dr13.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] DR13b: print-config shows lan = 'with localhost'
        set /a PASS+=1
    ) else (
        echo   [FAIL] DR13b: print-config missing 'with localhost' value
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] DR13b: print-config missing lan key
    set /a FAIL+=1
)

del "%TEMP%\dr13.toml" 2>nul
del "%TEMP%\sandy_dr13.txt" 2>nul


REM ===================================================================
REM Summary
REM ===================================================================
echo.
echo =====================================================================
echo  Results: !PASS! passed, !FAIL! failed
echo =====================================================================

if !FAIL! EQU 0 (
    exit /b 0
) else (
    exit /b 1
)
