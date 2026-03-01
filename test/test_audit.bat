@echo off
REM ---------------------------------------------------------------
REM test_audit.bat — Run audit crash test and display results
REM Requires: admin privileges, Procmon on PATH, Release build
REM ---------------------------------------------------------------

set SANDY_EXE=%~dp0..\x64\Release\sandy.exe
set CONFIG=%~dp0test_audit_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set SCRIPT=%~dp0test_audit.py
set AUDIT_LOG=%~dp0audit_crash.log
set SESSION_LOG=%~dp0session_crash.log

echo === Sandy Audit Crash Test ===
echo.

REM --- Verify prerequisites ---
if not exist "%SANDY_EXE%" (
    echo ERROR: sandy.exe not found at %SANDY_EXE%
    echo Build with: MSBuild sandy.sln /p:Configuration=Release /p:Platform=x64
    pause
    exit /b 1
)

where Procmon64.exe >nul 2>&1 || where Procmon.exe >nul 2>&1 || (
    echo ERROR: Procmon not found on PATH.
    pause
    exit /b 1
)

REM --- Clean previous results ---
if exist "%AUDIT_LOG%" del "%AUDIT_LOG%"
if exist "%SESSION_LOG%" del "%SESSION_LOG%"

echo --- Running sandboxed process with audit ---
echo.

"%SANDY_EXE%" -c "%CONFIG%" -l "%SESSION_LOG%" -a "%AUDIT_LOG%" -x "%PYTHON%" "%SCRIPT%"
set TEST_EXIT=%ERRORLEVEL%

echo.
echo --- Process exit code: %TEST_EXIT% ---
echo.

REM --- Display results ---
if exist "%SESSION_LOG%" (
    echo === SESSION LOG ===
    type "%SESSION_LOG%"
    echo.
)

if exist "%AUDIT_LOG%" (
    echo === AUDIT LOG ===
    type "%AUDIT_LOG%"
    echo.
) else (
    echo WARNING: No audit log was generated.
)

echo === Done ===
pause
