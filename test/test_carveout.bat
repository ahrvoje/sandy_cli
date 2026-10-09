@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy Carve-Out Test — Restricted Token Mode
REM
REM Allow grants nested UNDER a deny subtree: the nearer rule wins.
REM   allow.deep write under deny.all → write only, at every depth
REM   allow.deep all under deny.all   → full access, at every depth
REM   allow.this under deny           → that directory only
REM Verifies in-sandbox enforcement, post-exit ACE cleanup, and that host
REM access to the denied zone is restored after Sandy exits.
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_carveout_rt_config.toml
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_carveout
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Carve-Out Test — Restricted Token Mode
echo  8 zones, 23 sandbox assertions + post-exit cleanup checks
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree with seed files ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\arena\open"
mkdir "%ROOT%\arena\blocked\inner"
mkdir "%ROOT%\arena\blocked\carve\sub"
mkdir "%ROOT%\arena\blocked\full\sub"
mkdir "%ROOT%\arena\blocked\slot\inner"

echo open note>"%ROOT%\arena\open\note.txt"
echo top secret>"%ROOT%\arena\blocked\secret.txt"
echo hidden>"%ROOT%\arena\blocked\inner\hidden.txt"
echo carve seed>"%ROOT%\arena\blocked\carve\seed.txt"
echo nested>"%ROOT%\arena\blocked\carve\sub\nested.txt"
echo full seed>"%ROOT%\arena\blocked\full\seed.txt"
echo nested>"%ROOT%\arena\blocked\full\sub\nested.txt"
echo slot note>"%ROOT%\arena\blocked\slot\note.txt"
echo deep>"%ROOT%\arena\blocked\slot\inner\deep.txt"

REM --- Copy test script into the test tree ---
copy /y "%~dp0test_carveout.py" "%ROOT%\scripts\test_carveout.py" >nul
echo   [OK] Folder tree created (8 zones, 9 seed files)
echo.

REM === Run test inside sandbox ===
set TEST_ROOT=%ROOT%
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_carveout.py"
set SANDY_EXIT=!ERRORLEVEL!
echo.

REM === Post-Exit Cleanup Verification ===
echo === Cleanup Verification (after clean Sandy exit) ===
echo.

REM Check no RT SIDs remain anywhere on the tree.
set SC=0
for /f %%N in ('icacls "%ROOT%\arena" /t 2^>nul ^| findstr /c:"S-1-9-" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No Restricted Token SIDs on arena/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! Restricted Token SID entries remain on arena/ tree
    icacls "%ROOT%\arena" /t 2>nul | findstr /c:"S-1-9-"
    set /a FAIL+=1
)

REM Check host access to the denied zone is restored after Sandy exit
type "%ROOT%\arena\blocked\secret.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Host can read blocked/secret.txt again after exit
    set /a PASS+=1
) else (
    echo   [FAIL] Host still denied on blocked/secret.txt after exit
    set /a FAIL+=1
)

REM Check the carve zone is still usable by the host after exit
type "%ROOT%\arena\blocked\carve\seed.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Host can read carve/seed.txt after exit
    set /a PASS+=1
) else (
    echo   [FAIL] Host denied on carve/seed.txt after exit
    set /a FAIL+=1
)

REM Check no grant registry entries remain
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
if !SANDY_EXIT! EQU 0 (
    echo  Carve-Out Tests: ALL PASSED
) else (
    echo  Carve-Out Tests: SOME FAILED
)
echo  Cleanup Tests: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.

if !SANDY_EXIT! NEQ 0 exit /b 1
if !FAIL! GTR 0 exit /b 1
exit /b 0
