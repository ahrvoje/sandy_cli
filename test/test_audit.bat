@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
REM ---------------------------------------------------------------
REM test_audit.bat — Run audit crash test and display results
REM Requires: Procmon on PATH, Release build
REM Auto-elevates to admin if not already running elevated.
REM ---------------------------------------------------------------

REM === Auto-elevate to admin if needed ===
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ELEVATE] Requesting administrator privileges...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\sandy_elevate.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~f0"" %*", "%~dp0", "runas", 0 >> "%TEMP%\sandy_elevate.vbs"
    cscript //nologo "%TEMP%\sandy_elevate.vbs"
    del "%TEMP%\sandy_elevate.vbs" >nul 2>&1
    exit /b 0
)

REM If we were elevated, cd back to the script's directory
cd /d "%~dp0"

set SANDY_EXE=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_audit_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_audit
set AUDIT_LOG=%ROOT%\audit_crash.log
set SESSION_LOG=%ROOT%\session_crash.log

set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Audit Crash Test
echo =====================================================================
echo.

REM === Verify prerequisites ===
if not exist "%SANDY_EXE%" (
    echo [FAIL] sandy.exe not found at %SANDY_EXE%
    echo        Build with: MSBuild sandy.sln /p:Configuration=Release /p:Platform=x64
    set /a FAIL+=1
    goto :results
)

where Procmon64.exe >nul 2>&1 || where Procmon.exe >nul 2>&1 || (
    echo [FAIL] Procmon not found on PATH.
    echo        Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
    set /a FAIL+=1
    goto :results
)

echo   [OK] Prerequisites: sandy.exe found, Procmon found, running as admin
set /a PASS+=1

REM === Create test folder and copy script ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
copy /y "%~dp0test_audit.py" "%ROOT%\scripts\test_audit.py" >nul

REM --- Clean previous results ---
if exist "%AUDIT_LOG%" del "%AUDIT_LOG%"
if exist "%SESSION_LOG%" del "%SESSION_LOG%"

echo.
echo --- Phase 1: Running sandboxed process with audit ---
echo.

"%SANDY_EXE%" -c "%CONFIG%" -l "%SESSION_LOG%" -a "%AUDIT_LOG%" -x "%PYTHON%" "%ROOT%\scripts\test_audit.py"
set TEST_EXIT=%ERRORLEVEL%

echo.
echo --- Process exit code: %TEST_EXIT% ---
echo.

REM === Verify expected crash ===
REM test_audit.py should crash with os.abort() because write access
REM is denied everywhere. Non-zero exit = expected.
if %TEST_EXIT% neq 0 (
    echo   [PASS] Process crashed as expected (exit code %TEST_EXIT%)
    set /a PASS+=1
) else (
    echo   [FAIL] Process exited cleanly -- should have crashed
    set /a FAIL+=1
)

REM === Verify session log was generated ===
if exist "%SESSION_LOG%" (
    echo   [PASS] Session log generated
    set /a PASS+=1
) else (
    echo   [FAIL] Session log not generated
    set /a FAIL+=1
)

REM === Verify audit log was generated ===
if exist "%AUDIT_LOG%" (
    echo   [PASS] Audit log generated
    set /a PASS+=1

    REM Check audit log has content (not just empty)
    for %%A in ("%AUDIT_LOG%") do (
        if %%~zA gtr 0 (
            echo   [PASS] Audit log has content (%%~zA bytes)
            set /a PASS+=1
        ) else (
            echo   [FAIL] Audit log is empty
            set /a FAIL+=1
        )
    )

    REM Check for ACCESS DENIED entries in audit log
    findstr /i "ACCESS.DENIED" "%AUDIT_LOG%" >nul 2>&1
    if not errorlevel 1 (
        echo   [PASS] Audit log contains ACCESS DENIED entries
        set /a PASS+=1
    ) else (
        echo   [INFO] Audit log does not contain ACCESS DENIED entries
        echo          (May depend on Procmon filter configuration)
    )
) else (
    echo   [FAIL] Audit log not generated
    set /a FAIL+=1
)

REM === Verify cleanup (no stale state) ===
"%SANDY_EXE%" --status >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   [PASS] No stale state after audit run
    set /a PASS+=1
) else (
    echo   [FAIL] Stale state detected after audit run
    set /a FAIL+=1
    "%SANDY_EXE%" --cleanup >nul 2>&1
)

echo.

REM === Display logs (tail via findstr — shows all lines) ===
if exist "%SESSION_LOG%" (
    echo --- SESSION LOG ---
    type "%SESSION_LOG%"
    echo.
)

if exist "%AUDIT_LOG%" (
    echo --- AUDIT LOG ---
    type "%AUDIT_LOG%"
    echo.
) else (
    echo WARNING: No audit log was generated.
)

:results
echo.
echo =====================================================================
if %FAIL% equ 0 (
    echo  ALL TESTS PASSED: %PASS% passed, %FAIL% failed
) else (
    echo  SOME TESTS FAILED: %PASS% passed, %FAIL% failed
)
echo =====================================================================

REM === Clean up test folder ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"

exit /b %FAIL%
