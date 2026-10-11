@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM Sandy DACL Fidelity Test
REM
REM For a tree with current inheritance, leave each DACL as found: same ACEs, same
REM order, same protection flag.  The tree holds the cases that used to
REM go wrong: a deny on a folder with a protected DACL, a carve-out under
REM a deny, an allow on a protected folder, a deny on one file.
REM
REM   Part 1  Restricted Token run: in-sandbox probe (a denied object stays
REM           denied: no DACL rewrite, no delete, no rename), then compare
REM   Part 2  AppContainer run, then compare
REM   Part 3  Saved profile: create, delete, then compare
REM   Part 4  Moved-file inheritance: verify Windows recalculates old inheritance
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe
set TOOL=%~dp0test_dacl_fidelity.py
set ROOT=%USERPROFILE%\test_dacl_fidelity
set SNAP=%TEMP%\sandy_fid
set PROFILE=dacl_fidelity_test
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy DACL Fidelity Test
echo  Restricted Token run, AppContainer run, saved profile cycle
echo =====================================================================
echo.

REM === Cleanup stale state ===
"%SANDY%" --delete-profile %PROFILE% >nul 2>nul
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree with seed files ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"
mkdir "%ROOT%\single"
mkdir "%ROOT%\arena\secret\sub"
mkdir "%ROOT%\arena\secret\empty"
mkdir "%ROOT%\arena\frozen\carve"
mkdir "%ROOT%\arena\keep"

echo child>"%ROOT%\single\child.txt"
echo lock>"%ROOT%\arena\lockfile.txt"
echo secret>"%ROOT%\arena\secret\data.txt"
echo deep>"%ROOT%\arena\secret\sub\deep.txt"
echo note>"%ROOT%\arena\frozen\note.txt"
echo carve>"%ROOT%\arena\frozen\carve\x.txt"
echo victim>"%ROOT%\arena\keep\victim.txt"
echo other>"%ROOT%\arena\keep\other.txt"

REM The user closed these two: inheritance is off, the DACL is protected.
icacls "%ROOT%\arena\secret" /inheritance:d >nul
icacls "%ROOT%\arena\lockfile.txt" /inheritance:d >nul

copy /y "%TOOL%" "%ROOT%\scripts\test_dacl_fidelity.py" >nul
echo   [OK] Folder tree created
"%PYTHON%" "%TOOL%" snapshot "%ROOT%" "%SNAP%_before.json"
echo.

REM =====================================================================
REM Part 1: Restricted Token run
REM =====================================================================
echo === Part 1: Restricted Token (deny, carve-out, delete guard) ===
set TEST_ROOT=%ROOT%
"%SANDY%" -c "%~dp0test_dacl_fidelity_rt_config.toml" -q -x "%PYTHON%" "%ROOT%\scripts\test_dacl_fidelity.py" probe
call :verdict !ERRORLEVEL! "Part 1: in-sandbox probe"
REM The probe creates one file in carve/.  It is not part of the snapshot.
del "%ROOT%\arena\frozen\carve\created.txt" 2>nul
call :compare "Part 1"
echo.

REM =====================================================================
REM Part 2: AppContainer run
REM =====================================================================
echo === Part 2: AppContainer (allow on protected and on inheriting objects) ===
"%SANDY%" -c "%~dp0test_dacl_fidelity_ac_config.toml" -q -x "%PYTHON%" "%ROOT%\scripts\test_dacl_fidelity.py" noop
call :verdict !ERRORLEVEL! "Part 2: AppContainer run"
call :compare "Part 2"
echo.

REM =====================================================================
REM Part 3: Saved profile cycle (the grants stay until the profile is deleted)
REM =====================================================================
echo === Part 3: Saved profile create / delete ===
"%SANDY%" --create-profile %PROFILE% -c "%~dp0test_dacl_fidelity_rt_config.toml" >nul 2>nul
call :verdict !ERRORLEVEL! "Part 3: profile created"
icacls "%ROOT%\arena\secret" 2>nul | findstr /c:"S-1-9-" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] Part 3: the profile holds its deny on secret/ while it exists
    set /a PASS+=1
) else (
    echo   [FAIL] Part 3: no profile ACE on secret/ - the compare below would prove nothing
    set /a FAIL+=1
)
"%SANDY%" --delete-profile %PROFILE% >nul 2>nul
call :verdict !ERRORLEVEL! "Part 3: profile deleted"
call :compare "Part 3"
echo.

REM === Post-run state ===
set REMAIN=0
for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set REMAIN=%%N
if !REMAIN! EQU 0 (
    echo   [PASS] No grant registry entries remain
    set /a PASS+=1
) else (
    echo   [FAIL] !REMAIN! grant subkeys persist
    set /a FAIL+=1
)

REM === Moved-file inheritance exception ===
"%PYTHON%" "%TOOL%" moved "%SANDY%"
call :verdict !ERRORLEVEL! "Moved files: Windows recomputes inherited ACEs"

REM === Final Cleanup ===
"%SANDY%" --cleanup >nul 2>nul
del "%SNAP%_before.json" "%SNAP%_after.json" 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

set /a TOTAL=!PASS!+!FAIL!
echo.
echo =====================================================================
echo  DACL Fidelity: !PASS! passed, !FAIL! failed (of !TOTAL! batch checks)
echo =====================================================================
if !FAIL! GTR 0 exit /b 1
exit /b 0

REM ---------------------------------------------------------------------
REM :verdict <exit code> <label> — exit code 0 is a pass
REM ---------------------------------------------------------------------
:verdict
REM The label goes through a variable: a ")" in it must not close the block.
set "LABEL=%~2"
if %~1 EQU 0 (
    echo   [PASS] !LABEL!
    set /a PASS+=1
) else (
    echo   [FAIL] !LABEL! ^(exit code %~1^)
    set /a FAIL+=1
)
exit /b 0

REM ---------------------------------------------------------------------
REM :compare <label> — snapshot the tree and compare it with the first one
REM ---------------------------------------------------------------------
:compare
"%PYTHON%" "%TOOL%" snapshot "%ROOT%" "%SNAP%_after.json" >nul
"%PYTHON%" "%TOOL%" compare "%SNAP%_before.json" "%SNAP%_after.json"
call :verdict !ERRORLEVEL! "%~1: every DACL identical to the one before Sandy"
exit /b 0
