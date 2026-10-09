@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy Same-Path Deny Precedence Test — Restricted Token Mode
REM
REM Regression for a security defect: when [allow.*] and [deny.*] target the
REM SAME path, the allow-side "strip inherited deny" step removes the user's
REM EXPLICIT deny, so the deny is silently discarded.  Windows deny-before-
REM allow semantics require the explicit deny to win.
REM
REM Typical intent this breaks:
REM   - read-only tree:  [allow all] + [deny write] on the same path
REM   - protect a file:  [allow all] + [deny read]  on the same path
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_deny_precedence_rt_config.toml
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_deny_prec

echo =====================================================================
echo  Sandy Same-Path Deny Precedence Test — Restricted Token Mode
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree with seed files ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\readzone"
mkdir "%ROOT%\writezone"
echo CLASSIFIED>"%ROOT%\readzone\secret.txt"
echo seed>"%ROOT%\writezone\protected.txt"

REM Seed the write target as a Low-integrity file so the write assertion is
REM gated purely by the DACL (the deny), not by the mandatory-integrity
REM NoWriteUp rule that would block writing a Medium file at integrity 'low'.
icacls "%ROOT%\writezone\protected.txt" /setintegritylevel low >nul

copy /y "%~dp0test_deny_precedence.py" "%ROOT%\scripts\test_deny_precedence.py" >nul
echo   [OK] Folder tree created (2 zones, 2 seed files)
echo.

REM === Run test inside sandbox ===
set TEST_ROOT=%ROOT%
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_deny_precedence.py"
set SANDY_EXIT=!ERRORLEVEL!
echo.

REM === Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

echo =====================================================================
if !SANDY_EXIT! EQU 0 (
    echo  Deny Precedence: ALL PASSED
    echo =====================================================================
    exit /b 0
)
echo  Deny Precedence: FAILED ^(explicit same-path deny was discarded^)
echo =====================================================================
exit /b 1
