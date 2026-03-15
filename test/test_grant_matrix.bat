@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion
REM =====================================================================
REM test_grant_matrix.bat — Convoluted deep/this grant combos
REM
REM   AC: allow.deep + allow.this risky overlap (5 zones, ~35 assertions)
REM   RT: same + deny interactions (9 zones, ~60 assertions)
REM
REM After each sub-test: verify grants registry is clean and no
REM sandbox SID ACEs remain on the filesystem.
REM =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
set AC_CONFIG=%~dp0test_grant_matrix_config.toml
set RT_CONFIG=%~dp0test_grant_matrix_rt_config.toml
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set ROOT=%USERPROFILE%\test_gmatrix
set PASS=0
set FAIL=0

echo =====================================================================
echo  Grant Matrix Test — deep vs this scope stress
echo =====================================================================
echo.

REM === Pre-clean ===
"%SANDY%" --cleanup >nul 2>nul

REM === Create folder tree ===
if exist "%ROOT%" rmdir /s /q "%ROOT%"
mkdir "%ROOT%\scripts"

REM Z1: overlap tree
mkdir "%ROOT%\overlap\inner\deep"
mkdir "%ROOT%\overlap\sibling"
echo data>"%ROOT%\overlap\inner\file.txt"
echo data>"%ROOT%\overlap\inner\deep\file.txt"

REM Z2: same_path tree
mkdir "%ROOT%\same_path\child"
echo data>"%ROOT%\same_path\file.txt"
echo data>"%ROOT%\same_path\child\file.txt"

REM Z3: multi_this chain
mkdir "%ROOT%\multi_this\mid\leaf\sub"
echo data>"%ROOT%\multi_this\mid\leaf\file.txt"

REM Z4: deep_hole with gap
mkdir "%ROOT%\deep_hole\gap\bottom"
echo data>"%ROOT%\deep_hole\gap\bottom\file.txt"

REM Z5: file vs dir
mkdir "%ROOT%\file_vs_dir"
echo data>"%ROOT%\file_vs_dir\other.txt"
echo data>"%ROOT%\file_vs_dir\target.txt"

REM Z6 (RT): deny_sub
mkdir "%ROOT%\deny_sub\child"
echo data>"%ROOT%\deny_sub\file.txt"
echo data>"%ROOT%\deny_sub\child\file.txt"

REM Z7 (RT): deny_parent
mkdir "%ROOT%\deny_parent\child"
echo data>"%ROOT%\deny_parent\file.txt"
echo data>"%ROOT%\deny_parent\child\file.txt"

REM Z8 (RT): deny_clash
mkdir "%ROOT%\deny_clash\child"
echo data>"%ROOT%\deny_clash\file.txt"
echo data>"%ROOT%\deny_clash\child\file.txt"

REM Z9 (RT): deny_scope
mkdir "%ROOT%\deny_scope\child"
echo data>"%ROOT%\deny_scope\file.txt"
echo data>"%ROOT%\deny_scope\child\file.txt"

REM Copy test script
copy /y "%~dp0test_grant_matrix.py" "%ROOT%\scripts\test_grant_matrix.py" >nul
echo   [OK] Folder tree created (9 zones, seed files)
echo.

REM =====================================================================
REM PART 1: AppContainer test
REM =====================================================================
echo ===================================================================
echo  Part 1: AppContainer
echo ===================================================================
echo.
set TEST_ROOT=%ROOT%
set TEST_MODE=AC
"%SANDY%" -c "%AC_CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_grant_matrix.py"
set AC_EXIT=!ERRORLEVEL!
echo.

REM --- AC ACL cleanup check ---
echo --- AC Post-Run Cleanup Verification ---
set AC_SID_CNT=0
for /f %%N in ('icacls "%ROOT%" /t 2^>nul ^| findstr /c:"S-1-15-2-" ^| find /c /v ""') do set AC_SID_CNT=%%N
if !AC_SID_CNT! EQU 0 (
    echo   [PASS] No AppContainer SIDs on test tree
    set /a PASS+=1
) else (
    echo   [FAIL] !AC_SID_CNT! AppContainer SID entries remain
    set /a FAIL+=1
)

set GC=0
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set GC=%%N
)
if !GC! EQU 0 (
    echo   [PASS] Grants registry key clean
    set /a PASS+=1
) else (
    echo   [FAIL] !GC! grant subkeys persist after AC exit
    set /a FAIL+=1
)
echo.

REM === Re-seed files for RT test ===
echo data>"%ROOT%\overlap\inner\file.txt"
echo data>"%ROOT%\overlap\inner\deep\file.txt"
echo data>"%ROOT%\same_path\file.txt"
echo data>"%ROOT%\same_path\child\file.txt"
echo data>"%ROOT%\multi_this\mid\leaf\file.txt"
echo data>"%ROOT%\deep_hole\gap\bottom\file.txt"
echo data>"%ROOT%\file_vs_dir\other.txt"
echo data>"%ROOT%\file_vs_dir\target.txt"
echo data>"%ROOT%\deny_sub\file.txt"
echo data>"%ROOT%\deny_sub\child\file.txt"
echo data>"%ROOT%\deny_parent\file.txt"
echo data>"%ROOT%\deny_parent\child\file.txt"
echo data>"%ROOT%\deny_clash\file.txt"
echo data>"%ROOT%\deny_clash\child\file.txt"
echo data>"%ROOT%\deny_scope\file.txt"
echo data>"%ROOT%\deny_scope\child\file.txt"
REM Re-copy test script (may have been deleted by write tests)
copy /y "%~dp0test_grant_matrix.py" "%ROOT%\scripts\test_grant_matrix.py" >nul 2>nul

REM =====================================================================
REM PART 2: Restricted Token test
REM =====================================================================
echo ===================================================================
echo  Part 2: Restricted Token
echo ===================================================================
echo.
set TEST_MODE=RT
"%SANDY%" -c "%RT_CONFIG%" -x "%PYTHON%" "%ROOT%\scripts\test_grant_matrix.py"
set RT_EXIT=!ERRORLEVEL!
echo.

REM --- RT ACL cleanup check ---
echo --- RT Post-Run Cleanup Verification ---
set RT_SID_CNT=0
for /f %%N in ('icacls "%ROOT%" /t 2^>nul ^| findstr /c:"S-1-9-" ^| find /c /v ""') do set RT_SID_CNT=%%N
if !RT_SID_CNT! EQU 0 (
    echo   [PASS] No Restricted Token SIDs on test tree
    set /a PASS+=1
) else (
    echo   [FAIL] !RT_SID_CNT! Restricted Token SID entries remain
    set /a FAIL+=1
)

set GC=0
reg query "HKCU\Software\Sandy\Grants" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    for /f %%N in ('reg query "HKCU\Software\Sandy\Grants" 2^>nul ^| findstr /c:"Grants\\" ^| find /c /v ""') do set GC=%%N
)
if !GC! EQU 0 (
    echo   [PASS] Grants registry key clean
    set /a PASS+=1
) else (
    echo   [FAIL] !GC! grant subkeys persist after RT exit
    set /a FAIL+=1
)
echo.

REM === Final cleanup ===
"%SANDY%" --cleanup >nul 2>nul
if exist "%ROOT%" rmdir /s /q "%ROOT%"

REM === Summary ===
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
echo  Summary:
echo    AC probe:    exit !AC_EXIT!
echo    RT probe:    exit !RT_EXIT!
echo    Cleanup:     !PASS! passed, !FAIL! failed (of !TOTAL!)
echo =====================================================================

if !AC_EXIT! EQU 0 if !RT_EXIT! EQU 0 if !FAIL! EQU 0 (
    echo  ALL GRANT MATRIX TESTS PASSED
    exit /b 0
)
echo  SOME TESTS FAILED
exit /b 1
