@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM ===================================================================
REM Sandy Cleanup-Containment Test (AppContainer)
REM
REM Scenario: a "runaway delete" script calls shutil.rmtree on the
REM entire arena tree. Sandy's ACL grants contain the damage:
REM
REM   arena/          <- read-only for AC SID (cannot be deleted)
REM     sub1/         <- full access: everything inside deleted OK
REM       a.txt
REM       b.txt
REM       subsub/
REM         c.txt
REM     sub2/         <- full access: everything inside deleted OK
REM       d.txt
REM       e.txt
REM       deep/
REM         deeper/
REM           f.txt
REM
REM Expected result:
REM   arena/ survives — kernel blocks the delete
REM   sub1/, sub2/, all contents: gone
REM ===================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set PROBE=%~dp0test_clean_probe.py
set ARENA=%TEMP%\sandy_clean_test\arena
set TOMLFILE=%TEMP%\sandy_clean_test.toml
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Cleanup-Containment Test
echo =====================================================================

REM === Detect Python ===
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
if not exist "!PYTHON!" (
    for /f "tokens=*" %%P in ('where python 2^>nul') do if not defined PYTHON set PYTHON=%%P
)
if not exist "!PYTHON!" (
    echo   [SKIP] Python not found — test requires Python
    exit /b 0
)
REM Derive PYDIR from the PYTHON executable path (strip filename)
for %%F in ("!PYTHON!") do set PYDIR=%%~dpF
REM Strip trailing backslash from PYDIR
if "!PYDIR:~-1!"=="\" set PYDIR=!PYDIR:~0,-1!
echo   Python: !PYTHON!
echo   PyDir:  !PYDIR!

REM === Pre-clean any leftover state ===
if exist "%TEMP%\sandy_clean_test" rmdir /s /q "%TEMP%\sandy_clean_test" 2>nul
if exist "!TOMLFILE!" del "!TOMLFILE!" 2>nul

REM ===================================================================
REM CL1 — Setup arena structure
REM ===================================================================
echo.
echo --- CL1: Setup arena structure ---

mkdir "%ARENA%\sub1\subsub" 2>nul
mkdir "%ARENA%\sub2\deep\deeper" 2>nul
echo content A > "%ARENA%\sub1\a.txt"
echo content B > "%ARENA%\sub1\b.txt"
echo content C > "%ARENA%\sub1\subsub\c.txt"
echo content D > "%ARENA%\sub2\d.txt"
echo content E > "%ARENA%\sub2\e.txt"
echo content F > "%ARENA%\sub2\deep\deeper\f.txt"

REM Place the probe script in arena root — it survives because root is protected
copy /y "!PROBE!" "%ARENA%\test_clean_probe.py" >nul 2>&1

if exist "%ARENA%\sub1\subsub\c.txt" (
    echo   [PASS] CL1: Arena structure created
    set /a PASS+=1
) else (
    echo   [FAIL] CL1: Arena structure creation failed
    set /a FAIL+=1
    goto :cleanup
)

REM === Write TOML to temp file (dynamic paths) ===
(
echo [sandbox]
echo token = 'appcontainer'
echo workdir = '%ARENA%'
echo.
echo [allow.deep]
echo execute = ['%PYDIR%']
echo read    = ['%ARENA%']
echo all     = ['%ARENA%\sub1', '%ARENA%\sub2']
echo.
echo [limit]
echo timeout = 30
) > "!TOMLFILE!"

REM ===================================================================
REM CL2 — Run sandboxed probe (accidental rmtree on entire tree)
REM ===================================================================
echo.
echo --- CL2: Run sandboxed rmtree probe ---

"!SANDY!" -c "!TOMLFILE!" -x "!PYTHON!" "%ARENA%\test_clean_probe.py" "%ARENA%" > "%TEMP%\sandy_cl_out.txt" 2>&1
set CL2_EC=!ERRORLEVEL!

if !CL2_EC! EQU 0 (
    echo   [PASS] CL2: Probe exited 0 (root survived, children deleted^)
    set /a PASS+=1
) else (
    echo   [FAIL] CL2: Probe exit code !CL2_EC!
    type "%TEMP%\sandy_cl_out.txt"
    set /a FAIL+=1
)

REM ===================================================================
REM CL3 — Verify probe output: ROOT_EXISTS:1
REM ===================================================================
echo.
echo --- CL3/CL4/CL5: Verify probe output ---

findstr /C:"ROOT_EXISTS:1" "%TEMP%\sandy_cl_out.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] CL3: Probe confirms arena root survived
    set /a PASS+=1
) else (
    echo   [FAIL] CL3: Probe did not confirm root survival
    type "%TEMP%\sandy_cl_out.txt"
    set /a FAIL+=1
)

findstr /C:"SUB1_EXISTS:0" "%TEMP%\sandy_cl_out.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] CL4: Probe confirms sub1 deleted
    set /a PASS+=1
) else (
    echo   [FAIL] CL4: sub1 was not deleted by probe
    set /a FAIL+=1
)

findstr /C:"SUB2_EXISTS:0" "%TEMP%\sandy_cl_out.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] CL5: Probe confirms sub2 deleted
    set /a PASS+=1
) else (
    echo   [FAIL] CL5: sub2 was not deleted by probe
    set /a FAIL+=1
)

findstr /C:"AFTER_COUNT:0" "%TEMP%\sandy_cl_out.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] CL5b: Probe confirms 0 items remain under arena
    set /a PASS+=1
) else (
    echo   [FAIL] CL5b: Items remain inside arena that should have been deleted
    set /a FAIL+=1
)

findstr /C:"BLOCKED_COUNT:0" "%TEMP%\sandy_cl_out.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo   [PASS] CL5c: Probe reports deletion was blocked on at least one path
    set /a PASS+=1
) else (
    echo   [FAIL] CL5c: No deletions were blocked — arena root should have been protected
    set /a FAIL+=1
)

REM ===================================================================
REM CL6 — Filesystem verification: arena root still on disk
REM ===================================================================
echo.
echo --- CL6-CL10: Filesystem verification ---

if exist "%ARENA%" (
    echo   [PASS] CL6: arena\ still exists on disk
    set /a PASS+=1
) else (
    echo   [FAIL] CL6: arena\ was deleted — Sandy containment FAILED
    set /a FAIL+=1
)

if not exist "%ARENA%\sub1" (
    echo   [PASS] CL7: sub1\ deleted from disk
    set /a PASS+=1
) else (
    echo   [FAIL] CL7: sub1\ still exists on disk
    set /a FAIL+=1
)

if not exist "%ARENA%\sub2" (
    echo   [PASS] CL8: sub2\ deleted from disk
    set /a PASS+=1
) else (
    echo   [FAIL] CL8: sub2\ still exists on disk
    set /a FAIL+=1
)

if not exist "%ARENA%\sub1\subsub\c.txt" (
    echo   [PASS] CL9: Deep nested file (subsub\c.txt^) deleted
    set /a PASS+=1
) else (
    echo   [FAIL] CL9: subsub\c.txt still exists
    set /a FAIL+=1
)

if not exist "%ARENA%\sub2\deep\deeper\f.txt" (
    echo   [PASS] CL10: Deep nested file (deeper\f.txt^) deleted
    set /a PASS+=1
) else (
    echo   [FAIL] CL10: deeper\f.txt still exists
    set /a FAIL+=1
)

REM ===================================================================
REM CL11 — Host can still delete arena root freely (no sandbox running)
REM Confirms protection was per-instance ACE, not permanent file lock
REM ===================================================================
echo.
echo --- CL11: Host confirms arena is deletable after sandbox exits ---

REM Sandy has exited — ACEs are removed. Host has no restriction.
REM Delete probe script first (it survived in the read-only root), then rmdir.
del "%ARENA%\test_clean_probe.py" 2>nul
rmdir /s /q "%ARENA%" 2>nul
if not exist "%ARENA%" (
    echo   [PASS] CL11: Host deleted arena root cleanly after sandbox exit
    set /a PASS+=1
) else (
    echo   [FAIL] CL11: arena still exists after host rmdir
    set /a FAIL+=1
)

:cleanup
REM === Cleanup ===
del "%TEMP%\sandy_cl_out.txt" 2>nul
del "!TOMLFILE!" 2>nul
if exist "%TEMP%\sandy_clean_test" rmdir /s /q "%TEMP%\sandy_clean_test" 2>nul

echo.
echo =====================================================================
echo  Results: !PASS! passed, !FAIL! failed
echo =====================================================================

if !FAIL! EQU 0 (
    exit /b 0
) else (
    exit /b 1
)
