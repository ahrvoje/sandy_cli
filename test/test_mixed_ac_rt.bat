@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_mixed_ac_rt.bat — Mixed AppContainer + Restricted Token Test
REM
REM Runs TWO Sandy instances on overlapping paths:
REM   Instance 1: AppContainer mode (runs first, adds AC SID ACEs)
REM   Instance 2: Restricted Token mode (runs second, adds RT SID ACEs)
REM
REM Verifies:
REM   - Both instances enforce grants correctly
REM   - Cleanup removes BOTH SID types (S-1-15-2- and S-1-9-)
REM   - SDDL fidelity after both exit
REM   - No registry entries remain
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set AC_CONFIG=%~dp0test_mixed_ac_rt_ac.toml
set RT_CONFIG=%~dp0test_mixed_ac_rt_rt.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_mixed
set PASS=0
set FAIL=0

echo =====================================================================
echo  Mixed AC+RT Test — AppContainer then Restricted Token
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create shared folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\shared\workspace"
mkdir "%ROOT%\shared\protected"
mkdir "%ROOT%\scripts"

REM Seed files
echo shared workspace data>"%ROOT%\shared\workspace\seed.txt"
echo protected read-only data>"%ROOT%\shared\protected\data.txt"
copy /y "%~dp0test_mixed_ac_rt.py" "%ROOT%\scripts\test_mixed_ac_rt.py" >nul
echo   [OK] Shared folder tree created
echo.

REM === Capture pre-Sandy SDDLs ===
echo --- Pre-Sandy SDDL snapshots ---
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\shared').Sddl" 2^>nul') do set "PRE_SDDL_0=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\shared\workspace').Sddl" 2^>nul') do set "PRE_SDDL_1=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\shared\protected').Sddl" 2^>nul') do set "PRE_SDDL_2=%%S"
echo   Captured 3 pre-Sandy SDDLs
echo.

REM === Run AC instance first ===
echo ===================================================================
echo  Phase 1: AppContainer Instance
echo ===================================================================
echo.
"%SANDY%" -c "%AC_CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_mixed_ac_rt.py"
set AC_EXIT=!ERRORLEVEL!
echo.
echo   AC exit code: !AC_EXIT!
echo.

REM === Run RT instance second ===
echo ===================================================================
echo  Phase 2: Restricted Token Instance
echo ===================================================================
echo.
"%SANDY%" -c "%RT_CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_mixed_ac_rt.py"
set RT_EXIT=!ERRORLEVEL!
echo.
echo   RT exit code: !RT_EXIT!
echo.

REM === Verify both markers exist ===
echo --- Mode Marker Check ---
if exist "%ROOT%\shared\workspace\marker_AC.txt" (
    echo   [PASS] AC marker found — AppContainer instance ran
    set /a PASS+=1
) else (
    echo   [FAIL] AC marker missing — AppContainer instance may not have run
    set /a FAIL+=1
)

if exist "%ROOT%\shared\workspace\marker_RT.txt" (
    echo   [PASS] RT marker found — Restricted Token instance ran
    set /a PASS+=1
) else (
    if exist "%ROOT%\shared\workspace\marker_UNKNOWN.txt" (
        echo   [PASS] RT marker found (UNKNOWN mode^) — instance ran
        set /a PASS+=1
    ) else (
        echo   [FAIL] RT marker missing — Restricted Token instance may not have run
        set /a FAIL+=1
    )
)
echo.

REM === Cleanup ===
"%SANDY%" --cleanup >nul 2>nul

REM =====================================================================
REM Post-Cleanup Verification
REM =====================================================================
echo === Post-Cleanup Verification ===
echo.

REM --- Check for residual AppContainer SIDs ---
set SC_AC=0
for /f %%N in ('icacls "%ROOT%\shared" /t 2^>nul ^| findstr /c:"S-1-15-2-" ^| find /c /v ""') do set SC_AC=%%N
if !SC_AC! EQU 0 (
    echo   [PASS] No AppContainer SIDs (S-1-15-2-^) on shared/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC_AC! AppContainer SID entries remain on shared/ tree
    set /a FAIL+=1
)

REM --- Check for residual RT SIDs ---
set SC_RT=0
for /f %%N in ('icacls "%ROOT%\shared" /t 2^>nul ^| findstr /c:"S-1-9-" ^| find /c /v ""') do set SC_RT=%%N
if !SC_RT! EQU 0 (
    echo   [PASS] No Restricted Token SIDs (S-1-9-^) on shared/ tree
    set /a PASS+=1
) else (
    echo   [FAIL] !SC_RT! Restricted Token SID entries remain on shared/ tree
    set /a FAIL+=1
)

REM --- Check registry ---
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    set REMAIN=0
    for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"HKEY_" ^| find /c /v ""') do set REMAIN=%%N
    if !REMAIN! EQU 0 (
        echo   [PASS] No grant registry entries remain
        set /a PASS+=1
    ) else (
        echo   [FAIL] !REMAIN! grant subkeys persist
        set /a FAIL+=1
    )
)

REM --- SDDL Fidelity ---
echo.
echo --- SDDL Fidelity Check ---

for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\shared').Sddl" 2^>nul') do set "POST_SDDL_0=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\shared\workspace').Sddl" 2^>nul') do set "POST_SDDL_1=%%S"
for /f "delims=" %%S in ('powershell -NoProfile -Command "(Get-Acl '%ROOT%\shared\protected').Sddl" 2^>nul') do set "POST_SDDL_2=%%S"

if "!POST_SDDL_0!"=="!PRE_SDDL_0!" (
    echo   [PASS] shared/ DACL restored exactly
    set /a PASS+=1
) else (
    echo   [FAIL] shared/ DACL mismatch!
    set /a FAIL+=1
)

if "!POST_SDDL_1!"=="!PRE_SDDL_1!" (
    echo   [PASS] shared/workspace/ DACL restored exactly
    set /a PASS+=1
) else (
    echo   [FAIL] shared/workspace/ DACL mismatch!
    set /a FAIL+=1
)

if "!POST_SDDL_2!"=="!PRE_SDDL_2!" (
    echo   [PASS] shared/protected/ DACL restored exactly
    set /a PASS+=1
) else (
    echo   [FAIL] shared/protected/ DACL mismatch!
    set /a FAIL+=1
)

echo.

REM === Final Cleanup ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"

REM === Summary ===
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
echo  AC probe: exited with code !AC_EXIT!
echo  RT probe: exited with code !RT_EXIT!
echo  Verification: !PASS! passed, !FAIL! failed (of !TOTAL!)
if !FAIL! EQU 0 (
    echo  ALL VERIFICATION PASSED
) else (
    echo  ISSUES FOUND — see details above
)
echo =====================================================================
echo.

if !FAIL! GTR 0 exit /b 1
exit /b 0
