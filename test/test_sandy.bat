@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ---------------------------------------------------------------
REM test_sandy.bat — Set up self-contained test folder and run tests
REM
REM Creates %USERPROFILE%\test_sandy with:
REM   scripts/   — test script (read granted)
REM   R/         — read-only folder with seed file
REM   W/         — write-only folder
REM   RW/        — read+write folder
REM   file_R.txt — read-only file
REM   file_W.txt — write-only file
REM   file_RW.txt— read+write file
REM ---------------------------------------------------------------

set SANDY=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_sandy_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_sandy

echo === Sandy Test Runner ===
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Recreate test folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\R"
mkdir "%ROOT%\W"
mkdir "%ROOT%\RW"

REM --- Seed files ---
echo This is a seed file for read-only testing>"%ROOT%\R\seed.txt"
echo File-level read test content>"%ROOT%\file_R.txt"
echo placeholder>"%ROOT%\file_W.txt"
echo placeholder>"%ROOT%\file_RW.txt"

REM --- Copy test script ---
copy /y "%~dp0test_sandy.py" "%ROOT%\scripts\test_sandy.py" >nul
echo Created test folder: %ROOT%
echo.

REM === Run sandbox tests ===
echo --- Running sandbox tests ---
echo.
"%SANDY%" -c "%CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_sandy.py"
set EXIT_CODE=!ERRORLEVEL!
echo.

REM === Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

echo --- Done (exit code: !EXIT_CODE!) ---
exit /b !EXIT_CODE!
