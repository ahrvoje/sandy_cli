@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy Deep ACL Test — Restricted Token Mode
REM 4-Level Nesting with Heterogeneous Grants
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_deep_acl_rt_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set TEST=%~dp0test_deep_acl_rt.py
set ROOT=%USERPROFILE%\test_deep
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Deep ACL Test — Restricted Token Mode
echo  4 Levels, 12 Zones, 50 Assertions
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create 4-level folder tree with seed files ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"

REM L1-L4 directories
mkdir "%ROOT%\app\src\core\engine"
mkdir "%ROOT%\app\src\contrib\plugins"
mkdir "%ROOT%\app\docs\public\guides"
mkdir "%ROOT%\app\docs\classified\memos"
mkdir "%ROOT%\library\stable\v1"
mkdir "%ROOT%\library\experimental\beta"
mkdir "%ROOT%\scripts\common\utils"
mkdir "%ROOT%\scripts\restricted\admin"

REM Seed files at various levels
echo source>"%ROOT%\app\src\core\core.py"
echo engine>"%ROOT%\app\src\core\engine\module.py"
echo init>"%ROOT%\app\src\contrib\init.py"
echo addon>"%ROOT%\app\src\contrib\plugins\addon.py"
echo tutorial>"%ROOT%\app\docs\public\guides\tutorial.md"
echo draft>"%ROOT%\app\docs\classified\draft.md"
echo note>"%ROOT%\app\docs\classified\memos\note.md"
echo module>"%ROOT%\library\stable\v1\mod.py"
echo beta>"%ROOT%\library\experimental\beta\beta.py"
echo helper>"%ROOT%\scripts\common\utils\helper.bat"
echo admin>"%ROOT%\scripts\restricted\admin\root.bat"

REM --- Copy test script into the test tree ---
copy /y "%~dp0test_deep_acl_rt.py" "%ROOT%\scripts\test_deep_acl.py" >nul
echo   [OK] 4-level folder tree created (11 seed files)
echo.

REM === Run test inside sandbox ===
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_deep_acl.py"
set SANDY_EXIT=!ERRORLEVEL!
echo.

REM === Post-Exit Cleanup Verification ===
echo === Cleanup Verification (after clean Sandy exit) ===
echo.

REM Check no RT SIDs on app/
set SC=0
for /f %%N in ('icacls "%ROOT%\app" /t 2^>nul ^| findstr /c:"S-1-9-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No Restricted Token SIDs on app/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! Restricted Token SID entries remain on app/ tree
    set /a FAIL+=1
)

REM Check no RT SIDs on library/
set SC=0
for /f %%N in ('icacls "%ROOT%\library" /t 2^>nul ^| findstr /c:"S-1-9-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No Restricted Token SIDs on library/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! Restricted Token SID entries remain on library/ tree
    set /a FAIL+=1
)

REM Check no RT SIDs on scripts/
set SC=0
for /f %%N in ('icacls "%ROOT%\scripts" /t 2^>nul ^| findstr /c:"S-1-9-" ^|findstr /c:"Grants\\" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No Restricted Token SIDs on scripts/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! Restricted Token SID entries remain on scripts/ tree
    set /a FAIL+=1
)

REM Check no grant registry entries
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    set REMAIN=0
    for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""|findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
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
    echo  Grant Tests: ALL PASSED
) else (
    echo  Grant Tests: SOME FAILED
)
echo  Cleanup Tests: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.

if !SANDY_EXIT! NEQ 0 exit /b 1
if !FAIL! GTR 0 exit /b 1
exit /b 0
