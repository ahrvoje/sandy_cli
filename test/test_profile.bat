@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy Profile Test Suite
REM Tests: create, info, status, run, delete, arg collisions, errors
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set AC_CONFIG=%~dp0test_profile_ac.toml
set RT_CONFIG=%~dp0test_profile_rt.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PASS=0
set FAIL=0
set ROOT=%USERPROFILE%\test_sandy_profile

echo =====================================================================
echo  Sandy Profile Test Suite
echo =====================================================================

REM === Pre-clean ===
"!SANDY!" --delete-profile test_ac >nul 2>nul
"!SANDY!" --delete-profile test_rt >nul 2>nul
"!SANDY!" --delete-profile dup_test >nul 2>nul
"!SANDY!" --cleanup >nul 2>nul
if exist "!ROOT!" rmdir /s /q "!ROOT!"
mkdir "!ROOT!\data"
echo test data > "!ROOT!\data\hello.txt"

REM ===================================================================
REM P1 — Create AppContainer Profile
REM ===================================================================
echo.
echo --- P1: Create AppContainer Profile ---

"!SANDY!" --create-profile test_ac -c "!AC_CONFIG!" >"%TEMP%\sandy_p1.txt" 2>&1
set P1_EC=!ERRORLEVEL!

if !P1_EC! EQU 0 (
    echo   [PASS] P1a: --create-profile exits 0
    set /a PASS+=1
) else (
    echo   [FAIL] P1a: --create-profile exit code !P1_EC!
    set /a FAIL+=1
)

findstr /C:"created successfully" "%TEMP%\sandy_p1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P1b: Output confirms creation
    set /a PASS+=1
) else (
    echo   [FAIL] P1b: Missing creation confirmation
    set /a FAIL+=1
)

findstr /C:"S-1-15-2-" "%TEMP%\sandy_p1.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P1c: Output shows AppContainer SID
    set /a PASS+=1
) else (
    echo   [FAIL] P1c: Missing AppContainer SID
    set /a FAIL+=1
)

REM Verify registry key exists
reg query "HKCU\Software\Sandy\Profiles\test_ac" /v _type >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P1d: Registry key created
    set /a PASS+=1
) else (
    echo   [FAIL] P1d: Registry key not found
    set /a FAIL+=1
)

del "%TEMP%\sandy_p1.txt" 2>nul

REM ===================================================================
REM P2 — Create Restricted Token Profile
REM ===================================================================
echo.
echo --- P2: Create Restricted Token Profile ---

"!SANDY!" --create-profile test_rt -c "!RT_CONFIG!" >"%TEMP%\sandy_p2.txt" 2>&1
set P2_EC=!ERRORLEVEL!

if !P2_EC! EQU 0 (
    echo   [PASS] P2a: RT profile created
    set /a PASS+=1
) else (
    echo   [FAIL] P2a: RT profile creation exit code !P2_EC!
    set /a FAIL+=1
)

findstr /C:"S-1-9-" "%TEMP%\sandy_p2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P2b: Output shows RT SID
    set /a PASS+=1
) else (
    echo   [FAIL] P2b: Missing RT SID
    set /a FAIL+=1
)

findstr /C:"restricted" "%TEMP%\sandy_p2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P2c: Output shows type as restricted
    set /a PASS+=1
) else (
    echo   [FAIL] P2c: Missing type identifier
    set /a FAIL+=1
)

del "%TEMP%\sandy_p2.txt" 2>nul

REM ===================================================================
REM P3 — Profile Info (AppContainer)
REM ===================================================================
echo.
echo --- P3: Profile Info ---

"!SANDY!" --profile-info test_ac >"%TEMP%\sandy_p3.txt" 2>&1
set P3_EC=!ERRORLEVEL!

if !P3_EC! EQU 0 (
    echo   [PASS] P3a: --profile-info exits 0
    set /a PASS+=1
) else (
    echo   [FAIL] P3a: --profile-info exit code !P3_EC!
    set /a FAIL+=1
)

findstr /C:"Profile: test_ac" "%TEMP%\sandy_p3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P3b: Profile name shown
    set /a PASS+=1
) else (
    echo   [FAIL] P3b: Profile name missing
    set /a FAIL+=1
)

findstr /C:"SID:" "%TEMP%\sandy_p3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P3c: SID shown
    set /a PASS+=1
) else (
    echo   [FAIL] P3c: SID missing
    set /a FAIL+=1
)

findstr /C:"Created:" "%TEMP%\sandy_p3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P3d: Creation time shown
    set /a PASS+=1
) else (
    echo   [FAIL] P3d: Creation time missing
    set /a FAIL+=1
)

findstr /C:"Allow paths:" "%TEMP%\sandy_p3.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P3e: Config summary shown
    set /a PASS+=1
) else (
    echo   [FAIL] P3e: Config summary missing
    set /a FAIL+=1
)

del "%TEMP%\sandy_p3.txt" 2>nul

REM ===================================================================
REM P4 — Status Lists Saved Profiles
REM ===================================================================
echo.
echo --- P4: Status Lists Saved Profiles ---

"!SANDY!" --status >"%TEMP%\sandy_p4.txt" 2>&1

findstr /C:"SAVED_PROFILE" "%TEMP%\sandy_p4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P4a: --status shows SAVED_PROFILE
    set /a PASS+=1
) else (
    echo   [FAIL] P4a: --status missing SAVED_PROFILE
    set /a FAIL+=1
)

findstr /C:"test_ac" "%TEMP%\sandy_p4.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P4b: --status shows test_ac profile
    set /a PASS+=1
) else (
    echo   [FAIL] P4b: test_ac not in --status
    set /a FAIL+=1
)

REM JSON output
"!SANDY!" --status --json >"%TEMP%\sandy_p4j.txt" 2>&1

findstr /C:"saved_profiles" "%TEMP%\sandy_p4j.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P4c: JSON has saved_profiles array
    set /a PASS+=1
) else (
    echo   [FAIL] P4c: JSON missing saved_profiles
    set /a FAIL+=1
)

findstr /C:"test_ac" "%TEMP%\sandy_p4j.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P4d: JSON includes test_ac
    set /a PASS+=1
) else (
    echo   [FAIL] P4d: test_ac not in JSON
    set /a FAIL+=1
)

del "%TEMP%\sandy_p4.txt" 2>nul
del "%TEMP%\sandy_p4j.txt" 2>nul

REM ===================================================================
REM P5 — Run With Profile (AppContainer)
REM ===================================================================
echo.
echo --- P5: Run With AppContainer Profile ---

"!SANDY!" -p test_ac -x "!PYTHON!" -c "import pathlib; print(pathlib.Path(r'!ROOT!\data\hello.txt').read_text().strip())" >"%TEMP%\sandy_p5.txt" 2>&1
set P5_EC=!ERRORLEVEL!

if !P5_EC! EQU 0 (
    echo   [PASS] P5a: Profile run exits 0
    set /a PASS+=1
) else (
    echo   [FAIL] P5a: Profile run exit code !P5_EC!
    set /a FAIL+=1
)

findstr /C:"test data" "%TEMP%\sandy_p5.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P5b: Child process read test data via profile ACLs
    set /a PASS+=1
) else (
    echo   [FAIL] P5b: Child process could not read data
    set /a FAIL+=1
)

del "%TEMP%\sandy_p5.txt" 2>nul

REM ===================================================================
REM P6 — Run With Profile (Restricted Token)
REM ===================================================================
echo.
echo --- P6: Run With Restricted Token Profile ---

"!SANDY!" -p test_rt -x C:\Windows\System32\cmd.exe -- /c echo profile_rt_ok >"%TEMP%\sandy_p6.txt" 2>&1
set P6_EC=!ERRORLEVEL!

if !P6_EC! EQU 0 (
    echo   [PASS] P6a: RT profile run exits 0
    set /a PASS+=1
) else (
    echo   [FAIL] P6a: RT profile run exit code !P6_EC!
    set /a FAIL+=1
)

findstr /C:"profile_rt_ok" "%TEMP%\sandy_p6.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P6b: RT child output correct
    set /a PASS+=1
) else (
    echo   [FAIL] P6b: RT child output missing
    set /a FAIL+=1
)

del "%TEMP%\sandy_p6.txt" 2>nul

REM ===================================================================
REM P7 — Flag Combinations: collision only when -x is present
REM     -p + config + -x  = COLLISION (error)
REM     -p + config (no -x) = missing -x error (not collision)
REM     --create-profile + -c = VALID (config is required for create)
REM ===================================================================
echo.
echo --- P7: Flag Combinations ---

REM P7a: -p + -c + -x = COLLISION
"!SANDY!" -p test_ac -c "!AC_CONFIG!" -x cmd.exe -- /c exit >nul 2>"%TEMP%\sandy_p7a.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P7a: -p -c -x rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P7a: -p -c -x should be rejected
    set /a FAIL+=1
)
findstr /C:"mutually exclusive" "%TEMP%\sandy_p7a.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P7b: collision error message present
    set /a PASS+=1
) else (
    echo   [FAIL] P7b: missing collision error message
    set /a FAIL+=1
)

REM P7c: -p + -s + -x = COLLISION
"!SANDY!" -p test_ac -s "[sandbox]" -x cmd.exe >nul 2>"%TEMP%\sandy_p7c.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P7c: -p -s -x rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P7c: -p -s -x should be rejected
    set /a FAIL+=1
)
findstr /C:"mutually exclusive" "%TEMP%\sandy_p7c.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P7d: -s collision message present
    set /a PASS+=1
) else (
    echo   [FAIL] P7d: missing -s collision message
    set /a FAIL+=1
)

REM P7e: -p + --config + -x = COLLISION (long form)
"!SANDY!" -p test_ac --config "!AC_CONFIG!" -x cmd.exe -- /c exit >nul 2>"%TEMP%\sandy_p7e.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P7e: -p --config -x rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P7e: -p --config -x should be rejected
    set /a FAIL+=1
)

REM P7f: -p + --string + -x = COLLISION (long form)
"!SANDY!" -p test_ac --string "[sandbox]" -x cmd.exe >nul 2>"%TEMP%\sandy_p7f.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P7f: -p --string -x rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P7f: -p --string -x should be rejected
    set /a FAIL+=1
)

REM P7g: -p + -c WITHOUT -x = collision fires first
"!SANDY!" -p test_ac -c "!AC_CONFIG!" >nul 2>"%TEMP%\sandy_p7g.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P7g: -p -c without -x rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P7g: -p -c without -x should be rejected
    set /a FAIL+=1
)
findstr /C:"mutually exclusive" "%TEMP%\sandy_p7g.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P7h: collision error even without -x
    set /a PASS+=1
) else (
    echo   [FAIL] P7h: should say mutually exclusive
    set /a FAIL+=1
)

REM P7i: -p + -s WITHOUT -x = collision fires first
"!SANDY!" -p test_ac -s "[sandbox]" >nul 2>"%TEMP%\sandy_p7i.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P7i: -p -s without -x rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P7i: -p -s without -x should be rejected
    set /a FAIL+=1
)
findstr /C:"mutually exclusive" "%TEMP%\sandy_p7i.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P7j: collision error even without -x
    set /a PASS+=1
) else (
    echo   [FAIL] P7j: should say mutually exclusive
    set /a FAIL+=1
)

REM P7k: --create-profile + -c = VALID (config required for create)
REM Already tested in P1/P2, but explicitly verify it's NOT treated as collision
"!SANDY!" --delete-profile combo_test >nul 2>nul
"!SANDY!" --create-profile combo_test -c "!RT_CONFIG!" >nul 2>"%TEMP%\sandy_p7k.txt"
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P7k: --create-profile -c is valid
    set /a PASS+=1
) else (
    echo   [FAIL] P7k: --create-profile -c should be valid
    set /a FAIL+=1
)
"!SANDY!" --delete-profile combo_test >nul 2>nul

REM P7l: -p alone without -x = missing -x
"!SANDY!" -p test_ac >nul 2>"%TEMP%\sandy_p7l.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P7l: -p alone rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P7l: -p alone should be rejected
    set /a FAIL+=1
)
findstr /C:"requires -x" "%TEMP%\sandy_p7l.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P7m: -p alone says missing -x
    set /a PASS+=1
) else (
    echo   [FAIL] P7m: should say missing -x
    set /a FAIL+=1
)

del "%TEMP%\sandy_p7*.txt" 2>nul

REM ===================================================================
REM P8 — Error: Duplicate Profile Name
REM ===================================================================
echo.
echo --- P8: Duplicate Profile Name ---

"!SANDY!" --create-profile test_ac -c "!AC_CONFIG!" >nul 2>"%TEMP%\sandy_p8.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P8a: Duplicate name rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P8a: Duplicate name should be rejected
    set /a FAIL+=1
)

findstr /C:"already exists" "%TEMP%\sandy_p8.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P8b: Error message says already exists
    set /a PASS+=1
) else (
    echo   [FAIL] P8b: Missing duplicate name error message
    set /a FAIL+=1
)

del "%TEMP%\sandy_p8.txt" 2>nul

REM ===================================================================
REM P9 — Error: Non-existent Profile
REM ===================================================================
echo.
echo --- P9: Non-existent Profile ---

"!SANDY!" -p does_not_exist -x cmd.exe -- /c exit >nul 2>"%TEMP%\sandy_p9a.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P9a: Run with missing profile rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P9a: Should reject missing profile
    set /a FAIL+=1
)

findstr /C:"not found" "%TEMP%\sandy_p9a.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P9b: Error says not found
    set /a PASS+=1
) else (
    echo   [FAIL] P9b: Missing not-found error
    set /a FAIL+=1
)

"!SANDY!" --profile-info does_not_exist >nul 2>"%TEMP%\sandy_p9c.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P9c: --profile-info with missing profile rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P9c: Should reject missing profile for --profile-info
    set /a FAIL+=1
)

"!SANDY!" --delete-profile does_not_exist >nul 2>"%TEMP%\sandy_p9d.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P9d: --delete-profile with missing profile rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P9d: Should reject missing profile for --delete-profile
    set /a FAIL+=1
)

del "%TEMP%\sandy_p9a.txt" 2>nul
del "%TEMP%\sandy_p9c.txt" 2>nul
del "%TEMP%\sandy_p9d.txt" 2>nul

REM ===================================================================
REM P10 — Error: Missing Config for --create-profile
REM ===================================================================
echo.
echo --- P10: Missing Config for --create-profile ---

"!SANDY!" --create-profile no_config_given >nul 2>"%TEMP%\sandy_p10.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P10a: --create-profile without -c rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P10a: Should require -c
    set /a FAIL+=1
)

del "%TEMP%\sandy_p10.txt" 2>nul

REM ===================================================================
REM P11 — Error: Invalid Config File
REM ===================================================================
echo.
echo --- P11: Invalid Config File ---

"!SANDY!" --create-profile badcfg -c "C:\nonexistent\fake.toml" >nul 2>"%TEMP%\sandy_p11.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P11a: Non-existent config rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P11a: Should reject non-existent config
    set /a FAIL+=1
)

del "%TEMP%\sandy_p11.txt" 2>nul

REM ===================================================================
REM P12 — Error: Invalid Profile Names
REM ===================================================================
echo.
echo --- P12: Invalid Profile Names ---

"!SANDY!" --create-profile "bad\name" -c "!AC_CONFIG!" >nul 2>"%TEMP%\sandy_p12a.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P12a: Backslash in name rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P12a: Should reject backslash in name
    set /a FAIL+=1
)

"!SANDY!" --create-profile "bad|name" -c "!AC_CONFIG!" >nul 2>"%TEMP%\sandy_p12b.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P12b: Pipe in name rejected
    set /a PASS+=1
) else (
    echo   [FAIL] P12b: Should reject pipe in name
    set /a FAIL+=1
)

del "%TEMP%\sandy_p12a.txt" 2>nul
del "%TEMP%\sandy_p12b.txt" 2>nul

REM ===================================================================
REM P14 — Cleanup Does NOT Delete Profiles
REM ===================================================================
echo.
echo --- P14: Cleanup Preserves Profiles ---

"!SANDY!" --cleanup >nul 2>nul

reg query "HKCU\Software\Sandy\Profiles\test_ac" /v _sid >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P14a: test_ac profile survives --cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] P14a: --cleanup deleted test_ac profile!
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Profiles\test_rt" /v _sid >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P14b: test_rt profile survives --cleanup
    set /a PASS+=1
) else (
    echo   [FAIL] P14b: --cleanup deleted test_rt profile!
    set /a FAIL+=1
)

REM ===================================================================
REM P15 — Delete Profiles
REM ===================================================================
echo.
echo --- P15: Delete Profiles ---

"!SANDY!" --delete-profile test_ac >"%TEMP%\sandy_p15a.txt" 2>&1
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P15a: test_ac deleted successfully
    set /a PASS+=1
) else (
    echo   [FAIL] P15a: test_ac delete failed
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Profiles\test_ac" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P15b: test_ac registry key removed
    set /a PASS+=1
) else (
    echo   [FAIL] P15b: test_ac registry key still exists
    set /a FAIL+=1
)

"!SANDY!" --delete-profile test_rt >"%TEMP%\sandy_p15c.txt" 2>&1
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] P15c: test_rt deleted successfully
    set /a PASS+=1
) else (
    echo   [FAIL] P15c: test_rt delete failed
    set /a FAIL+=1
)

reg query "HKCU\Software\Sandy\Profiles\test_rt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P15d: test_rt registry key removed
    set /a PASS+=1
) else (
    echo   [FAIL] P15d: test_rt registry key still exists
    set /a FAIL+=1
)

del "%TEMP%\sandy_p15a.txt" 2>nul
del "%TEMP%\sandy_p15c.txt" 2>nul

REM ===================================================================
REM P16 — Status Clean After Delete
REM ===================================================================
echo.
echo --- P16: Status Clean After Delete ---

"!SANDY!" --status >"%TEMP%\sandy_p16.txt" 2>&1

findstr /C:"SAVED_PROFILE" "%TEMP%\sandy_p16.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] P16a: No saved profiles in --status after delete
    set /a PASS+=1
) else (
    echo   [FAIL] P16a: Saved profiles still show in --status
    set /a FAIL+=1
)

del "%TEMP%\sandy_p16.txt" 2>nul

REM ===================================================================
REM Cleanup
REM ===================================================================
"!SANDY!" --cleanup >nul 2>nul
if exist "!ROOT!" rmdir /s /q "!ROOT!"

REM ===================================================================
REM Summary
REM ===================================================================
echo.
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
echo  Results: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.
if !FAIL! GTR 0 (
    echo Some tests FAILED!
    exit /b 1
)
exit /b 0
