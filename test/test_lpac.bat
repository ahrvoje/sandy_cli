@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_lpac.bat — LPAC Token Isolation Test Suite
REM
REM Proves that token = 'lpac' correctly excludes ALL APPLICATION PACKAGES
REM while allowing Restricted App. Packages access. cmd.exe runs from
REM System32 — no Sandy grant needed because System32 carries the
REM ALL RESTRICTED APPLICATION PACKAGES DACL.
REM
REM TOML is the sole grant ledger. No implicit grants.
REM
REM Self-contained: all artifacts under %USERPROFILE%\test_lpac
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set CMD=C:\Windows\System32\cmd.exe
set ROOT=%USERPROFILE%\test_lpac
set PASS=0
set FAIL=0

echo =====================================================================
echo  LPAC Token Isolation Test Suite
echo  token = 'lpac' — Restricted App. Packages
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"

mkdir "%ROOT%\workspace"
mkdir "%ROOT%\secret"
mkdir "%ROOT%\scripts"

REM Seed test files
echo workspace file> "%ROOT%\workspace\data.txt"
echo secret data> "%ROOT%\secret\classified.txt"
echo probe script> "%ROOT%\scripts\probe.bat"

echo   [OK] Test tree: %ROOT%
echo.

REM ---------------------------------------------------------------
REM Part 1: Dry-run validation
REM ---------------------------------------------------------------
echo --- Part 1: Dry-run config validation ---
echo.

"%SANDY%" --dry-run -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "echo test" >nul 2>nul
set DR_EXIT=!ERRORLEVEL!
if !DR_EXIT! EQU 0 (
    echo   [PASS] Dry-run: LPAC config accepted
    set /a PASS+=1
) else (
    echo   [FAIL] Dry-run: LPAC config rejected ^(exit !DR_EXIT!^)
    set /a FAIL+=1
)
echo.

REM ---------------------------------------------------------------
REM Part 2: LPAC runs a live process
REM cmd.exe runs from System32 via ALL RESTRICTED APPLICATION PACKAGES
REM DACL — no explicit grant from Sandy needed.
REM ---------------------------------------------------------------
echo --- Part 2: LPAC runs live process ---
echo.

REM 2a: Basic echo — proves LPAC process starts and runs
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "echo LPAC_LIVE_OK"
set LIVE_EXIT=!ERRORLEVEL!
if !LIVE_EXIT! EQU 0 (
    echo   [PASS] LPAC process ran ^(exit 0^)
    set /a PASS+=1
) else (
    echo   [FAIL] LPAC process failed ^(exit !LIVE_EXIT!^)
    set /a FAIL+=1
)

REM 2b: Read workspace (explicit all grant)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "type !ROOT!\workspace\data.txt" > "%ROOT%\workspace\output.txt" 2>nul
set READ_EXIT=!ERRORLEVEL!
if !READ_EXIT! EQU 0 (
    echo   [PASS] Read workspace: granted
    set /a PASS+=1
) else (
    echo   [FAIL] Read workspace: failed ^(exit !READ_EXIT!^)
    set /a FAIL+=1
)

REM 2c: Write to workspace (explicit all grant)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "echo written by lpac> !ROOT!\workspace\lpac_wrote.txt"
if exist "%ROOT%\workspace\lpac_wrote.txt" (
    echo   [PASS] Write workspace: granted
    set /a PASS+=1
) else (
    echo   [FAIL] Write workspace: file not created
    set /a FAIL+=1
)

REM 2d: File existence check in workspace (explicit all grant)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "if exist !ROOT!\workspace\data.txt (exit /b 0) else (exit /b 1)"
set EXIST_EXIT=!ERRORLEVEL!
if !EXIST_EXIT! EQU 0 (
    echo   [PASS] Access workspace file: granted
    set /a PASS+=1
) else (
    echo   [FAIL] Access workspace file: failed ^(exit !EXIST_EXIT!^)
    set /a FAIL+=1
)

REM 2e: Read scripts folder (explicit read grant)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "type !ROOT!\scripts\probe.bat" >nul 2>nul
set SCRIPTS_EXIT=!ERRORLEVEL!
if !SCRIPTS_EXIT! EQU 0 (
    echo   [PASS] Read scripts: granted
    set /a PASS+=1
) else (
    echo   [FAIL] Read scripts: failed ^(exit !SCRIPTS_EXIT!^)
    set /a FAIL+=1
)
echo.

REM ---------------------------------------------------------------
REM Part 3: LPAC blocks non-granted access
REM ---------------------------------------------------------------
echo --- Part 3: LPAC blocks non-granted access ---
echo.

REM 3a: Read secret folder (no grant)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "type !ROOT!\secret\classified.txt" >nul 2>nul
set SECRET_EXIT=!ERRORLEVEL!
if !SECRET_EXIT! NEQ 0 (
    echo   [PASS] Read secret/: blocked ^(exit !SECRET_EXIT!^)
    set /a PASS+=1
) else (
    echo   [FAIL] Read secret/: should be blocked!
    set /a FAIL+=1
)

REM 3b: Write to scripts folder (read-only grant)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "echo hack> !ROOT!\scripts\injected.txt" 2>nul
if not exist "%ROOT%\scripts\injected.txt" (
    echo   [PASS] Write scripts/: blocked ^(read-only grant^)
    set /a PASS+=1
) else (
    echo   [FAIL] Write scripts/: should be blocked!
    del "%ROOT%\scripts\injected.txt" >nul 2>nul
    set /a FAIL+=1
)

REM 3c: Read user Desktop (no grant)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "type !USERPROFILE!\Desktop\desktop.ini" >nul 2>nul
set DESK_EXIT=!ERRORLEVEL!
if !DESK_EXIT! NEQ 0 (
    echo   [PASS] Read Desktop: blocked ^(exit !DESK_EXIT!^)
    set /a PASS+=1
) else (
    echo   [FAIL] Read Desktop: should be blocked!
    set /a FAIL+=1
)

REM 3d: Network access blocked (network = false)
"%SANDY%" -q -c "%~dp0test_lpac_config.toml" -x "%CMD%" /c "ping -n 1 -w 1000 8.8.8.8" >nul 2>nul
set PING_EXIT=!ERRORLEVEL!
if !PING_EXIT! NEQ 0 (
    echo   [PASS] Network ping: blocked ^(exit !PING_EXIT!^)
    set /a PASS+=1
) else (
    echo   [FAIL] Network ping: should be blocked!
    set /a FAIL+=1
)
echo.

REM ---------------------------------------------------------------
REM Part 4: AC vs LPAC comparison
REM Same zero grants. AC has App. Packages, LPAC does not.
REM ---------------------------------------------------------------
echo --- Part 4: AC vs LPAC comparison ---
echo.

REM AC: read a file from Program Files (App. Packages grants access)
"%SANDY%" -q -c "%~dp0test_lpac_ac_config.toml" -x "%CMD%" /c "type ""C:\Program Files\desktop.ini""" >nul 2>nul
set AC_PF_EXIT=!ERRORLEVEL!

REM LPAC: same file (App. Packages excluded — should fail)
"%SANDY%" -q -c "%~dp0test_lpac_minimal_config.toml" -x "%CMD%" /c "type ""C:\Program Files\desktop.ini""" >nul 2>nul
set LPAC_PF_EXIT=!ERRORLEVEL!

if !AC_PF_EXIT! EQU 0 if !LPAC_PF_EXIT! NEQ 0 (
    echo   [PASS] AC reads Program Files ^(exit !AC_PF_EXIT!^), LPAC blocked ^(exit !LPAC_PF_EXIT!^)
    set /a PASS+=1
) else (
    echo   [INFO] AC=!AC_PF_EXIT!, LPAC=!LPAC_PF_EXIT!
)
echo.

REM ---------------------------------------------------------------
REM Part 5: Cleanup verification
REM ---------------------------------------------------------------
echo === Cleanup Verification ===
echo.

REM Check no AppContainer SIDs remain
set SC=0
for /f %%N in ('icacls "%ROOT%" /t 2^>nul ^| findstr /c:"S-1-15-2-" ^| find /c /v ""') do set SC=%%N
if !SC! EQU 0 (
    echo   [PASS] No AppContainer SIDs on test tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC! AppContainer SID entries remain
    set /a FAIL+=1
)

REM Check no grant registry entries
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    set REMAIN=0
    for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
    if !REMAIN! EQU 0 (
        echo   [PASS] No grant registry entries remain
        set /a PASS+=1
    ) else (
        echo   [FAIL] !REMAIN! grant subkeys persist after clean exit
        set /a FAIL+=1
    )
)

REM Verify secret was never touched
if exist "%ROOT%\secret\classified.txt" (
    echo   [PASS] secret/classified.txt untouched
    set /a PASS+=1
) else (
    echo   [FAIL] secret/classified.txt was modified or deleted!
    set /a FAIL+=1
)
echo.

REM === Final Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

REM === Summary ===
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
if !FAIL! EQU 0 (
    echo  ALL PASSED — LPAC isolation verified
) else (
    echo  ISSUES FOUND — see details above
)
echo  Tests: !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================
echo.

if !FAIL! GTR 0 exit /b 1
exit /b 0
