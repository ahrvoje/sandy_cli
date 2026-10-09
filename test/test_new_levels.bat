@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_new_levels.bat — New access levels: run, stat, touch, create
REM
REM Tests in AppContainer mode:
REM   run_dir/   [allow] run    — execute only, no file read
REM   stat_dir/  [allow] stat   — attributes only (non-recursive)
REM   touch_dir/ [allow] touch  — modify attributes (non-recursive)
REM   create_dir/[allow] create — create new files, no overwrite
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_new_levels_config.toml
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_new_levels

echo =====================================================================
echo  Sandy New Access Levels Test (AppContainer)
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Recreate folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%"
REM A private tree (owner only, inheritance off): the access of the sandbox
REM then comes from the Sandy grants alone, whatever the parent folder gives
REM to Users or Everyone.
icacls "%ROOT%" /inheritance:r /grant:r "%USERDOMAIN%\%USERNAME%:(OI)(CI)F" >nul
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\run_dir"
mkdir "%ROOT%\stat_dir"
mkdir "%ROOT%\touch_dir"
mkdir "%ROOT%\create_dir"

REM Seed files
echo @echo hello>"%ROOT%\run_dir\hello.bat"
echo test data>"%ROOT%\stat_dir\file.txt"
echo test data>"%ROOT%\touch_dir\file.txt"
echo existing content>"%ROOT%\create_dir\existing.txt"

REM Copy test script
copy /y "%~dp0test_new_levels.py" "%ROOT%\scripts\test_new_levels.py" >nul
echo   [OK] Folder tree created with seed files
echo.

REM === Part 1: Dry-run to validate config parsing ===
echo --- Part 1: Dry-run config validation ---
"%SANDY%" --dry-run -c "%CONFIG%" -x "%PYTHON%"
set DRY_EXIT=!ERRORLEVEL!
if !DRY_EXIT! EQU 0 (
    echo   [PASS] Config parsing: all new keys accepted
) else (
    echo   [FAIL] Config parsing: dry-run failed with exit !DRY_EXIT!
)
echo.

REM === Part 2: Run test inside sandbox ===
echo --- Part 2: AC sandbox test ---
set TEST_MODE=AC
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_new_levels.py"
set AC_EXIT=!ERRORLEVEL!
echo.

REM === Part 3: RT sandbox test ===
echo --- Part 3: RT sandbox test ---
set RT_CONFIG=%~dp0test_new_levels_rt_config.toml

REM Create extra dirs for deny tests
mkdir "%ROOT%\denied\no_run"
mkdir "%ROOT%\denied\no_stat"
mkdir "%ROOT%\denied\no_touch"
mkdir "%ROOT%\denied\no_create"
echo @echo blocked>"%ROOT%\denied\no_run\blocked.bat"
echo blocked>"%ROOT%\denied\no_stat\file.txt"
echo blocked>"%ROOT%\denied\no_touch\file.txt"
echo blocked>"%ROOT%\denied\no_create\existing.txt"
REM A real program for the deny.run check: same file in an allowed and a denied folder
copy /y "%SystemRoot%\System32\whoami.exe" "%ROOT%\denied\tool.exe" >nul
copy /y "%SystemRoot%\System32\whoami.exe" "%ROOT%\denied\no_run\tool.exe" >nul

set TEST_MODE=RT
"%SANDY%" -c "%RT_CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_new_levels.py"
set RT_EXIT=!ERRORLEVEL!
echo.

REM === Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

echo =====================================================================
echo  Summary:
echo    Dry-run:  exit !DRY_EXIT!
echo    AC test:  exit !AC_EXIT!
echo    RT test:  exit !RT_EXIT!
echo =====================================================================

set FAILED=0
if !DRY_EXIT! NEQ 0 set FAILED=1
if !AC_EXIT! NEQ 0 set FAILED=1
if !RT_EXIT! NEQ 0 set FAILED=1
if !FAILED! EQU 0 (
    echo  ALL TESTS PASSED
    exit /b 0
)
echo  SOME TESTS FAILED
exit /b 1
