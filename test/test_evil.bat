@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_evil.bat — Adversarial "Break Sandy" Test Suite
REM
REM 10 attack vectors, ~40 test cases designed to find real failures:
REM   1. Junction/symlink escape
REM   2. 8.3 short name bypass
REM   3. Path traversal via ..
REM   4. Alternate Data Streams (ADS)
REM   5. Hard link exfiltration
REM   6. Rename escape
REM   7. Case mismatch bypass
REM   8. Deep nesting / MAX_PATH
REM   9. Post-grant file creation
REM  10. Symlink process escape
REM
REM Self-contained: all artifacts under %USERPROFILE%\test_evil
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_evil_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_evil
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Adversarial Test Suite — "Break Sandy"
echo  10 attack vectors, ~40 test cases
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"

REM Scripts folder
mkdir "%ROOT%\scripts"
copy /y "%~dp0test_evil.py" "%ROOT%\scripts\test_evil.py" >nul

REM Arena — the playground (allow.all)
mkdir "%ROOT%\arena\passage"
mkdir "%ROOT%\arena\vault"
mkdir "%ROOT%\arena\LongSecretName"
mkdir "%ROOT%\arena\records"
mkdir "%ROOT%\arena\CaseSensitive"
mkdir "%ROOT%\arena\deep"

REM Seed files in denied zones
echo TOP SECRET VAULT DATA> "%ROOT%\arena\vault\secret.txt"
echo CLASSIFIED INTEL> "%ROOT%\arena\LongSecretName\classified.txt"
echo quarterly report> "%ROOT%\arena\records\report.txt"
echo hidden credentials> "%ROOT%\arena\CaseSensitive\hidden.txt"

REM === Create junction: passage/escape → vault (ATTACK 1) ===
REM Junction is created BEFORE Sandy runs, so it's part of the filesystem
mklink /J "%ROOT%\arena\passage\escape" "%ROOT%\arena\vault" >nul 2>nul
if exist "%ROOT%\arena\passage\escape" (
    echo   [OK] Junction created: passage\escape -^> vault
) else (
    echo   [WARN] Junction creation failed
)

echo   [OK] Folder tree created with seed files
echo.

REM === Run adversarial probe inside sandbox ===
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_evil.py"
set SANDY_EXIT=!ERRORLEVEL!
echo.

REM === Post-Exit Cleanup Verification ===
echo === Cleanup Verification ===
echo.

REM Check no AppContainer SIDs on arena/
set SC=0
for /f %%N in ('icacls "%ROOT%\arena" /t 2^>nul ^| findstr /c:"S-1-15-2-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No AppContainer SIDs on arena/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! AppContainer SID entries remain on arena/ tree
    set /a FAIL+=1
)

REM Check no grant registry entries
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
        echo   [FAIL] !REMAIN! grant subkeys persist after clean exit
        set /a FAIL+=1
    )
)

echo.

REM === Final Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

REM === Summary ===
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
if !SANDY_EXIT! EQU 0 if !FAIL! EQU 0 (
    echo  ALL HELD -- Sandy survived every attack
) else (
    echo  ISSUES FOUND -- see details above
)
echo  Cleanup Tests: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.

if !SANDY_EXIT! NEQ 0 exit /b 1
if !FAIL! GTR 0 exit /b 1
exit /b 0
