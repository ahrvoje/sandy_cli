@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_scope.bat — Verify deep vs this scope for all grant modes
REM
REM   AC: allow.deep (multilevel) + allow.this (single object)
REM   RT: allow.deep + allow.this + deny.deep + deny.this
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set AC_CONFIG=%~dp0test_scope_ac_config.toml
set RT_CONFIG=%~dp0test_scope_rt_config.toml
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_scope

echo =====================================================================
echo  Sandy Scope Verification Test (deep vs this)
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree ===
call :BuildTree
echo   [OK] Folder tree created (5 dirs x 2 levels + seed files)
echo.

REM === Part 1: AC test ===
echo --- Part 1: AppContainer scope test ---
set TEST_ROOT=%ROOT%
set TEST_MODE=AC
"%SANDY%" -c "%AC_CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_scope.py"
set AC_EXIT=!ERRORLEVEL!
echo.

REM === Cleanup between modes ===
"%SANDY%" --cleanup >nul 2>nul

REM === Decouple Part 2 from Part 1: rebuild the tree from scratch ===
REM The RT run must not depend on files the AC run created — Part 2 has to
REM be self-sufficient and order-independent.
call :BuildTree

REM === Pre-seed RT write targets as Low-integrity files ===
REM At integrity 'low' the OS mandatory policy (NoWriteUp) blocks CREATING
REM files in implicitly-Medium directories regardless of any DACL grant.
REM The RT write assertions exercise DACL scope semantics, so the legitimate
REM write targets are seeded as existing Low-labeled files the probe can
REM open for write.  this\child\write_test.txt is deliberately NOT seeded:
REM with the user SID in the restricting list (non-strict), an existing Low
REM file would be writable via the user's own ACEs — creation-blocking is
REM the only enforceable this-scope write boundary in RT (see the P18h4
REM note in test_profile.bat).
for %%T in (
    "%ROOT%\deep\write_test.txt"
    "%ROOT%\deep\child\write_test.txt"
    "%ROOT%\deep_all\w.txt"
    "%ROOT%\deep_all\child\w.txt"
    "%ROOT%\this\write_test.txt"
) do (
    echo seed>%%T
    icacls %%T /setintegritylevel low >nul
)

REM === Part 2: RT test ===
echo --- Part 2: Restricted Token scope test ---
set TEST_MODE=RT
"%SANDY%" -c "%RT_CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_scope.py"
set RT_EXIT=!ERRORLEVEL!
echo.

REM === Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

echo =====================================================================
echo  Summary:
echo    AC test:  exit !AC_EXIT!
echo    RT test:  exit !RT_EXIT!
echo =====================================================================

if !AC_EXIT! EQU 0 if !RT_EXIT! EQU 0 (
    echo  ALL SCOPE TESTS PASSED
    exit /b 0
)
echo  SOME SCOPE TESTS FAILED
exit /b 1

REM =====================================================================
REM :BuildTree — (re)create the test tree with seed files.
REM Called before EACH part so neither part depends on the other's
REM artifacts.
REM =====================================================================
:BuildTree
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\deep\child"
mkdir "%ROOT%\deep_all\child"
mkdir "%ROOT%\this\child"
mkdir "%ROOT%\deny_deep\child"
mkdir "%ROOT%\deny_this\child"

REM Seed files at both levels
echo parent data>"%ROOT%\deep\file.txt"
echo child data>"%ROOT%\deep\child\file.txt"
echo parent data>"%ROOT%\deep_all\file.txt"
echo child data>"%ROOT%\deep_all\child\file.txt"
echo parent data>"%ROOT%\this\file.txt"
echo child data>"%ROOT%\this\child\file.txt"
echo parent data>"%ROOT%\deny_deep\file.txt"
echo child data>"%ROOT%\deny_deep\child\file.txt"
echo parent data>"%ROOT%\deny_this\file.txt"
echo child data>"%ROOT%\deny_this\child\file.txt"

REM Copy test script
copy /y "%~dp0test_scope.py" "%ROOT%\scripts\test_scope.py" >nul
exit /b 0
