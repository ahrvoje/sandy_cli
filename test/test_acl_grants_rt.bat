@echo off
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy ACL Grants Test — Restricted Token Mode
REM
REM Tests nuanced permission enforcement across a multi-level folder tree
REM with overlapping allow and deny grants at different levels.
REM Same test structure as test_acl_grants.bat but using RT mode.
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_acl_grants_rt_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_acl

echo =====================================================================
echo  Sandy ACL Grants Test — Restricted Token Mode
echo  7 zones, 31 test cases
echo =====================================================================
echo.

REM === Kill stragglers & cleanup ===
taskkill /f /im sandy.exe >nul 2>nul
"%SANDY%" --cleanup >nul 2>nul

REM === Recreate folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\workspace\src"
mkdir "%ROOT%\workspace\build"
mkdir "%ROOT%\workspace\secrets"
mkdir "%ROOT%\data\public"
mkdir "%ROOT%\data\private"
mkdir "%ROOT%\logs"
mkdir "%ROOT%\tools"
mkdir "%ROOT%\scripts"

echo source code>"%ROOT%\workspace\src\code.py"
echo build artifact>"%ROOT%\workspace\build\artifact.bin"
echo secret key>"%ROOT%\workspace\secrets\key.pem"
echo public info>"%ROOT%\data\public\info.txt"
echo hidden data>"%ROOT%\data\private\hidden.txt"
echo log entry>"%ROOT%\logs\app.log"
echo @echo helper>"%ROOT%\tools\script.bat"

REM === Copy test script into the test tree ===
copy /y "%~dp0test_acl_grants_rt.py" "%ROOT%\scripts\test_acl_grants.py" >nul
echo   [OK] Folder tree created with seed files
echo.

REM === Run test inside sandbox ===
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_acl_grants.py"
set EXIT_CODE=!ERRORLEVEL!
echo.

REM === Cleanup ===
"%SANDY%" --cleanup >nul 2>nul

REM === Post-cleanup: check for residual RT SIDs (S-1-9-) ===
set PASS=0
set FAIL=0

set SC=0
for /f %%N in ('icacls "%ROOT%\workspace" /t 2^>nul ^| findstr /c:"S-1-9-" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No Restricted Token SIDs on workspace/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! Restricted Token SID entries remain on workspace/ tree
    set /a FAIL+=1
)

if exist "%ROOT%" rmdir /s /q "%ROOT%"

if !EXIT_CODE! EQU 0 (
    echo  ALL TESTS PASSED
) else (
    echo  SOME TESTS FAILED
)
exit /b !EXIT_CODE!
