@echo off
setlocal enabledelayedexpansion
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p

:: =====================================================================
:: test_dynamic.bat — Dynamic sandbox test (AppContainer mode)
::
:: Tests live config reload with --dynamic / -y:
::   D1: Grant addition — config reload detected and applied
::   D2: Parse error     — invalid TOML rejected, grants preserved
:: =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
for %%I in ("%PYTHON%") do set PYDIR=%%~dpI
set SCRIPTDIR=%~dp0

if not exist "%PYTHON%" (
    echo SKIP: python not found
    exit /b 0
)

set PASS=0
set FAIL=0
set BASE=%TEMP%\sandy_dynamic_test_%RANDOM%
mkdir "%BASE%" 2>nul
set DIR_A=%BASE%\dir_a
set DIR_B=%BASE%\dir_b
set DIR_M=%BASE%\markers
mkdir "%DIR_A%" 2>nul
mkdir "%DIR_B%" 2>nul
mkdir "%DIR_M%" 2>nul
echo seed > "%DIR_A%\seed.txt"

:: =====================================================================
:: D1: Grant addition — config reload detected and new grant applied
:: =====================================================================
echo.
echo === D1: Grant addition ===

set CFG=%BASE%\dynamic.toml
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow.deep]
    echo read = ['%DIR_A:\=\\%']
    echo all = ['%DIR_M:\=\\%']
    echo execute = ['%PYDIR:\=\\%', '%SCRIPTDIR:\=\\%']
) > "%CFG%"

set MARKER=%DIR_M%\d1_results.txt

:: Start sandy with --dynamic
start "" /b "%SANDY%" -y -c "%CFG%" -l "%BASE%\d1.log" -x "%PYTHON%" "%SCRIPTDIR%test_dynamic_probe.py" "%DIR_A%" "%DIR_B%" "%MARKER%"

:: Wait for watcher to start
ping -n 7 127.0.0.1 >nul

:: Modify config to add write on B
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow.deep]
    echo read = ['%DIR_A:\=\\%']
    echo write = ['%DIR_B:\=\\%']
    echo all = ['%DIR_M:\=\\%']
    echo execute = ['%PYDIR:\=\\%', '%SCRIPTDIR:\=\\%']
) > "%CFG%"
:: Force mtime update to ensure watcher detects change
powershell -NoProfile -Command "(Get-Item '%CFG%').LastWriteTime = Get-Date" 2>nul

:: Wait for probe to finish (12 cycles x 1.5s = 18s + ~7s ACL setup = ~25s total)
ping -n 26 127.0.0.1 >nul

:: D1 Check 1: marker was written (probe ran to completion)
if exist "%MARKER%" (
    echo   PASS: probe ran and wrote marker
    set /a PASS+=1
) else (
    echo   FAIL: marker not created (probe may have crashed^)
    set /a FAIL+=1
)

:: D1 Check 2: DYNAMIC reload logged (watcher detected config change)
if exist "%BASE%\d1.log" (
    findstr /c:"DYNAMIC: reload #" "%BASE%\d1.log" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   PASS: DYNAMIC reload detected and applied
        set /a PASS+=1
    ) else (
        echo   FAIL: no DYNAMIC reload in log
        set /a FAIL+=1
    )
) else (
    echo   FAIL: log file not created
    set /a FAIL+=1
)

:: D1 Check 3: the new grant was actually applied (DYNAMIC_GRANT in log)
if exist "%BASE%\d1.log" (
    findstr /c:"DYNAMIC_GRANT: [WRITE]" "%BASE%\d1.log" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   PASS: DYNAMIC_GRANT [WRITE] confirmed in log
        set /a PASS+=1
    ) else (
        echo   FAIL: DYNAMIC_GRANT [WRITE] not in log
        set /a FAIL+=1
    )
)

:: Wait for Sandy exit and cleanup
ping -n 8 127.0.0.1 >nul

:: =====================================================================
:: D2: Parse error — invalid TOML, verify grants preserved
:: =====================================================================
echo.
echo === D2: Parse error resilience ===

set CFG2=%BASE%\dynamic2.toml
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow.deep]
    echo read = ['%DIR_A:\=\\%']
    echo all = ['%DIR_M:\=\\%']
    echo execute = ['%PYDIR:\=\\%', '%SCRIPTDIR:\=\\%']
) > "%CFG2%"

set MARKER2=%DIR_M%\d2_results.txt

:: Start sandy with --dynamic
start "" /b "%SANDY%" -y -c "%CFG2%" -l "%BASE%\d2.log" -x "%PYTHON%" "%SCRIPTDIR%test_dynamic_probe.py" "%DIR_A%" "%DIR_B%" "%MARKER2%"
ping -n 7 127.0.0.1 >nul

:: Write invalid TOML and force mtime change
echo THIS IS NOT VALID TOML [[[broken > "%CFG2%"
powershell -NoProfile -Command "(Get-Item '%CFG2%').LastWriteTime = Get-Date" 2>nul
ping -n 5 127.0.0.1 >nul

:: Restore valid config
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow.deep]
    echo read = ['%DIR_A:\=\\%']
    echo all = ['%DIR_M:\=\\%']
    echo execute = ['%PYDIR:\=\\%', '%SCRIPTDIR:\=\\%']
) > "%CFG2%"

:: Wait for probe to finish (12 cycles x 1.5s = 18s + ~7s ACL setup = ~25s)
ping -n 26 127.0.0.1 >nul

:: D2 Check 1: marker written (probe survived parse error)
if exist "%MARKER2%" (
    findstr /c:"read_A=OK" "%MARKER2%" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   PASS: read_A stayed OK during parse error
        set /a PASS+=1
    ) else (
        echo   FAIL: read_A lost during parse error
        set /a FAIL+=1
    )
) else (
    echo   FAIL: marker not created
    set /a FAIL+=1
)

:: D2 Check 2: parse error logged
if exist "%BASE%\d2.log" (
    findstr /c:"DYNAMIC: config reload FAILED" "%BASE%\d2.log" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   PASS: parse error logged
        set /a PASS+=1
    ) else (
        echo   FAIL: parse error not logged
        set /a FAIL+=1
    )
) else (
    echo   FAIL: log file not created
    set /a FAIL+=1
)

:: =====================================================================
:: Cleanup
:: =====================================================================
echo.
ping -n 5 127.0.0.1 >nul
rd /s /q "%BASE%" 2>nul

echo ===========================
echo  Dynamic test: %PASS% passed, %FAIL% failed
echo ===========================

if %FAIL% gtr 0 exit /b 1
exit /b 0
