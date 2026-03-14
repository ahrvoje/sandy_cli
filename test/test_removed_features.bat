@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy Removed-Feature Surface Test
REM Verifies removed Procmon and dump/WER flags are rejected and no longer
REM appear in user-facing help.
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Removed-Feature Surface Test
echo =====================================================================

if not exist "!SANDY!" (
    echo   [SKIP] sandy.exe not found at !SANDY!
    exit /b 0
)

echo.
echo --- RF1: Legacy audit / trace flags rejected ---

"!SANDY!" -a audit.log -x C:\Windows\System32\cmd.exe >nul 2>"%TEMP%\sandy_rf1a.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF1a: -a rejected
    set /a PASS+=1
) else (
    echo   [FAIL] RF1a: -a should be rejected
    set /a FAIL+=1
)
findstr /C:"Unknown option: -a" "%TEMP%\sandy_rf1a.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] RF1b: -a rejection message correct
    set /a PASS+=1
) else (
    echo   [FAIL] RF1b: -a rejection message missing
    set /a FAIL+=1
)

"!SANDY!" --audit audit.log -x C:\Windows\System32\cmd.exe >nul 2>"%TEMP%\sandy_rf1c.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF1c: --audit rejected
    set /a PASS+=1
) else (
    echo   [FAIL] RF1c: --audit should be rejected
    set /a FAIL+=1
)
findstr /C:"Unknown option: --audit" "%TEMP%\sandy_rf1c.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] RF1d: --audit rejection message correct
    set /a PASS+=1
) else (
    echo   [FAIL] RF1d: --audit rejection message missing
    set /a FAIL+=1
)

"!SANDY!" -t report.txt -x C:\Windows\System32\cmd.exe >nul 2>"%TEMP%\sandy_rf1e.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF1e: -t rejected
    set /a PASS+=1
) else (
    echo   [FAIL] RF1e: -t should be rejected
    set /a FAIL+=1
)
findstr /C:"Unknown option: -t" "%TEMP%\sandy_rf1e.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] RF1f: -t rejection message correct
    set /a PASS+=1
) else (
    echo   [FAIL] RF1f: -t rejection message missing
    set /a FAIL+=1
)

"!SANDY!" --trace report.txt -x C:\Windows\System32\cmd.exe >nul 2>"%TEMP%\sandy_rf1g.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF1g: --trace rejected
    set /a PASS+=1
) else (
    echo   [FAIL] RF1g: --trace should be rejected
    set /a FAIL+=1
)
findstr /C:"Unknown option: --trace" "%TEMP%\sandy_rf1g.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] RF1h: --trace rejection message correct
    set /a PASS+=1
) else (
    echo   [FAIL] RF1h: --trace rejection message missing
    set /a FAIL+=1
)

echo.
echo --- RF2: Legacy dump / WER flags rejected ---

"!SANDY!" -d crash.dmp -x C:\Windows\System32\cmd.exe >nul 2>"%TEMP%\sandy_rf2a.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF2a: -d rejected
    set /a PASS+=1
) else (
    echo   [FAIL] RF2a: -d should be rejected
    set /a FAIL+=1
)
findstr /C:"Unknown option: -d" "%TEMP%\sandy_rf2a.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] RF2b: -d rejection message correct
    set /a PASS+=1
) else (
    echo   [FAIL] RF2b: -d rejection message missing
    set /a FAIL+=1
)

"!SANDY!" --dump crash.dmp -x C:\Windows\System32\cmd.exe >nul 2>"%TEMP%\sandy_rf2c.txt"
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF2c: --dump rejected
    set /a PASS+=1
) else (
    echo   [FAIL] RF2c: --dump should be rejected
    set /a FAIL+=1
)
findstr /C:"Unknown option: --dump" "%TEMP%\sandy_rf2c.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] RF2d: --dump rejection message correct
    set /a PASS+=1
) else (
    echo   [FAIL] RF2d: --dump rejection message missing
    set /a FAIL+=1
)

echo.
echo --- RF3: Help surface matches simplified product ---

"!SANDY!" --help >"%TEMP%\sandy_rf2.txt" 2>&1

findstr /C:"--audit" "%TEMP%\sandy_rf2.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF3a: help omits --audit
    set /a PASS+=1
) else (
    echo   [FAIL] RF3a: help still mentions --audit
    set /a FAIL+=1
)

findstr /C:"--trace" "%TEMP%\sandy_rf2.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF3b: help omits --trace
    set /a PASS+=1
) else (
    echo   [FAIL] RF3b: help still mentions --trace
    set /a FAIL+=1
)

findstr /C:"--dump" "%TEMP%\sandy_rf2.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] RF3c: help omits --dump
    set /a PASS+=1
) else (
    echo   [FAIL] RF3c: help still mentions --dump
    set /a FAIL+=1
)

findstr /C:"--profile" "%TEMP%\sandy_rf2.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] RF3d: help still documents profile workflow
    set /a PASS+=1
) else (
    echo   [FAIL] RF3d: help lost profile workflow
    set /a FAIL+=1
)

del "%TEMP%\sandy_rf1a.txt" 2>nul
del "%TEMP%\sandy_rf1c.txt" 2>nul
del "%TEMP%\sandy_rf1e.txt" 2>nul
del "%TEMP%\sandy_rf1g.txt" 2>nul
del "%TEMP%\sandy_rf2a.txt" 2>nul
del "%TEMP%\sandy_rf2c.txt" 2>nul
del "%TEMP%\sandy_rf2.txt" 2>nul

echo.
echo =====================================================================
echo  Results: !PASS! passed, !FAIL! failed
echo =====================================================================

if !FAIL! EQU 0 (
    exit /b 0
) else (
    exit /b 1
)
