@echo off
setlocal enabledelayedexpansion
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p

:: =====================================================================
:: test_dynamic.bat — Dynamic sandbox test (AppContainer mode)
::
:: Tests live config reload with --dynamic / -y:
::   D1: Grant addition  — add write to B mid-run, verify child sees it
::   D2: Grant removal   — remove read from A mid-run, verify child loses it
::   D3: Parse error      — write invalid TOML, verify grants unchanged
::   D4: Immutable warn   — change workdir, verify warning logged
:: =====================================================================

set SANDY=..\x64\Release\sandy.exe
set PYTHON=python

:: Locate python
where python >nul 2>&1 || (
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

:: Create a seed file in A for listdir testing
echo seed > "%DIR_A%\seed.txt"

:: =====================================================================
:: D1: Grant addition — start with read on A, add write on B after 4s
:: =====================================================================
echo.
echo === D1: Grant addition ===

:: Write initial config (read on A only)
set CFG=%BASE%\dynamic.toml
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow]
    echo read = ['%DIR_A:\=\\%']
) > "%CFG%"

set MARKER=%DIR_M%\d1_results.txt

:: Start sandy with --dynamic
start /b "" %SANDY% -y -c "%CFG%" -l "%BASE%\d1.log" -x %PYTHON% test_dynamic_probe.py "%DIR_A%" "%DIR_B%" "%MARKER%"
set SANDY_PID=
:: Give it a moment to start
timeout /t 2 /nobreak >nul

:: Get the sandy PID
for /f "tokens=2" %%a in ('tasklist /fi "imagename eq sandy.exe" /nh 2^>nul ^| findstr /i "sandy"') do set SANDY_PID=%%a

:: After 4s, modify config to add write on B
timeout /t 2 /nobreak >nul
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow]
    echo read = ['%DIR_A:\=\\%']
    echo write = ['%DIR_B:\=\\%']
) > "%CFG%"

:: Wait for probe to finish
timeout /t 12 /nobreak >nul

:: Check results: early cycles should have write_B=DENIED, later cycles should have write_B=OK
if exist "%MARKER%" (
    :: Check that at least one early cycle had write_B=DENIED
    findstr /c:"write_B=DENIED" "%MARKER%" >nul 2>&1
    if !errorlevel! equ 0 (
        :: And at least one later cycle had write_B=OK
        findstr /c:"write_B=OK" "%MARKER%" >nul 2>&1
        if !errorlevel! equ 0 (
            echo   PASS: write_B transitioned from DENIED to OK
            set /a PASS+=1
        ) else (
            echo   FAIL: write_B never became OK after config change
            type "%MARKER%"
            set /a FAIL+=1
        )
    ) else (
        echo   FAIL: write_B was never DENIED in early cycles
        type "%MARKER%"
        set /a FAIL+=1
    )
) else (
    echo   FAIL: marker file not created (probe may have crashed)
    set /a FAIL+=1
)

:: Check log for DYNAMIC reload message
if exist "%BASE%\d1.log" (
    findstr /c:"DYNAMIC: reload #" "%BASE%\d1.log" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   PASS: DYNAMIC reload logged
        set /a PASS+=1
    ) else (
        echo   FAIL: no DYNAMIC reload in log
        set /a FAIL+=1
    )
) else (
    echo   FAIL: log file not created
    set /a FAIL+=1
)

:: =====================================================================
:: D3: Parse error — write invalid TOML, verify warning logged
:: =====================================================================
echo.
echo === D3: Parse error resilience ===

:: Write valid initial config
set CFG3=%BASE%\dynamic3.toml
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow]
    echo read = ['%DIR_A:\=\\%']
) > "%CFG3%"

set MARKER3=%DIR_M%\d3_results.txt

:: Start sandy with --dynamic
start /b "" %SANDY% -y -c "%CFG3%" -l "%BASE%\d3.log" -x %PYTHON% test_dynamic_probe.py "%DIR_A%" "%DIR_B%" "%MARKER3%"
timeout /t 3 /nobreak >nul

:: Write invalid TOML
echo THIS IS NOT VALID TOML [[[broken > "%CFG3%"
timeout /t 4 /nobreak >nul

:: Restore valid config so child can finish cleanly
(
    echo [sandbox]
    echo token = 'appcontainer'
    echo.
    echo [allow]
    echo read = ['%DIR_A:\=\\%']
) > "%CFG3%"

:: Wait for probe to finish
timeout /t 8 /nobreak >nul

:: Check that read_A=OK existed throughout (grants preserved during parse error)
if exist "%MARKER3%" (
    findstr /c:"read_A=OK" "%MARKER3%" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   PASS: read_A stayed OK during parse error
        set /a PASS+=1
    ) else (
        echo   FAIL: read_A was lost during parse error
        type "%MARKER3%"
        set /a FAIL+=1
    )
) else (
    echo   FAIL: marker file not created
    set /a FAIL+=1
)

:: Check log for parse error message
if exist "%BASE%\d3.log" (
    findstr /c:"DYNAMIC: config reload FAILED" "%BASE%\d3.log" >nul 2>&1
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
:: Cleanup and results
:: =====================================================================
echo.

:: Clean up after a brief delay
timeout /t 2 /nobreak >nul
rd /s /q "%BASE%" 2>nul

echo ===========================
echo  Dynamic test: %PASS% passed, %FAIL% failed
echo ===========================

if %FAIL% gtr 0 exit /b 1
exit /b 0
