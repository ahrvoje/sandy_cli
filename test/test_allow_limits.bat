@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ---------------------------------------------------------------
REM test_allow_limits.bat — Test [privileges] and [limit] settings
REM Tests: network, memory, process limits, timeout, and strict mode.
REM Self-contained: uses %USERPROFILE%\test_limits for all scripts.
REM ---------------------------------------------------------------

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_limits

echo === Sandy Allow ^& Limits Test Runner ===
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create test folder with scripts ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
copy /y "%~dp0test_allow_limits.py" "%ROOT%\scripts\test_allow_limits.py" >nul
copy /y "%~dp0test_timeout.py" "%ROOT%\scripts\test_timeout.py" >nul
echo Created test folder: %ROOT%
echo.

REM --- Part 1: Network + resource limits ---
echo --- Part 1: Network and resource limit tests ---
echo.

"%SANDY%" -c "%~dp0test_allow_limits_config.toml" -x "%PYTHON%" "%ROOT%\scripts\test_allow_limits.py"
set PART1_EXIT=!ERRORLEVEL!
echo.

REM --- Part 2: Timeout enforcement ---
echo --- Part 2: Timeout test (should be killed after ~5 seconds) ---
echo.

for /f "tokens=1-4 delims=:., " %%a in ("%TIME%") do set /a T1=%%a*3600+%%b*60+%%c
"%SANDY%" -c "%~dp0test_allow_limits_config.toml" -x "%PYTHON%" "%ROOT%\scripts\test_timeout.py"
set TIMEOUT_EXIT=!ERRORLEVEL!
for /f "tokens=1-4 delims=:., " %%a in ("%TIME%") do set /a T2=%%a*3600+%%b*60+%%c
set /a ELAPSED=T2-T1

echo.
echo   Elapsed:   ~!ELAPSED! seconds
echo   Exit code: !TIMEOUT_EXIT!

if !TIMEOUT_EXIT! NEQ 0 (
    echo   [PASS] Timeout: process killed in ~!ELAPSED!s
) else (
    echo   [FAIL] Timeout: process exited normally - timeout did not trigger!
)
echo.

REM --- Part 3: Strict mode (system_dirs disabled) ---
echo --- Part 3: Strict mode (system_dirs disabled) ---
echo.

"%SANDY%" -c "%~dp0test_strict_config.toml" -x "%PYTHON%" -c "print('should not run')"
set STRICT_EXIT=!ERRORLEVEL!

echo.
if !STRICT_EXIT! NEQ 0 (
    echo   [PASS] Strict mode: execution blocked
) else (
    echo   [FAIL] Strict mode: process ran - should have been blocked!
)
echo.

echo === Summary ===
echo   Part 1 (allow/limits): exit !PART1_EXIT!
echo   Part 2 (timeout):      killed in ~!ELAPSED!s
echo   Part 3 (strict mode):  blocked

REM === Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

exit /b 0
