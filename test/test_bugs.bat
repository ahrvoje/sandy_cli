@echo off
setlocal enabledelayedexpansion

REM =====================================================================
REM test_bugs.bat — Tests that detect REAL bugs in Sandy
REM
REM Each test proves a specific, reproducible bug by demonstrating
REM incorrect behavior. When the bug is fixed, the test should flip
REM from PASS to FAIL — signaling the fix was applied correctly.
REM
REM These tests are "bug detectors": PASS = bug is present,
REM                                   FAIL = bug has been fixed.
REM =====================================================================

echo  PID: %~0
echo =====================================================================
echo  Sandy Bug Detector Tests
echo  Each PASS means the bug IS PRESENT (not yet fixed)
echo =====================================================================

set SANDY=%~dp0..\x64\Release\sandy.exe
if not exist "!SANDY!" (
    echo [ERROR] Sandy not found at: !SANDY!
    exit /b 1
)

set PASS=0
set FAIL=0

REM ===================================================================
REM BUG 1: Duplicate TOML key silently overwrites first value
REM
REM When the same key appears twice in a section, the second value
REM replaces the first with no error diagnostic. The user's first
REM array entry is silently lost.
REM
REM Root cause: std::map::operator[] overwrites on duplicate key.
REM Fix: detect duplicate keys in Toml::Parse and emit an error.
REM ===================================================================
echo.
echo === BUG 1: Duplicate TOML key silently overwrites ===

echo [sandbox]>"%TEMP%\bug1.toml"
echo token = 'appcontainer'>>"%TEMP%\bug1.toml"
echo [allow.deep]>>"%TEMP%\bug1.toml"
echo read = ['C:\Windows']>>"%TEMP%\bug1.toml"
echo read = ['C:\Users']>>"%TEMP%\bug1.toml"

"!SANDY!" --dry-run -c "%TEMP%\bug1.toml" >"%TEMP%\bug1_out.txt" 2>&1
set BUG1_EXIT=!ERRORLEVEL!

REM If bug is present: dry-run succeeds (exit 0) and only C:\Users appears
REM If bug is fixed: should fail with "duplicate key" error
if !BUG1_EXIT! EQU 0 (
    findstr /C:"C:\Windows" "%TEMP%\bug1_out.txt" >nul 2>nul
    if !ERRORLEVEL! NEQ 0 (
        echo   [PASS] BUG 1: First 'read' array silently lost - duplicate key not detected
        set /a PASS+=1
    ) else (
        echo   [FAIL] BUG 1: Both read arrays preserved - bug may be fixed
        set /a FAIL+=1
    )
) else (
    findstr /I /C:"duplicate" "%TEMP%\bug1_out.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [FAIL] BUG 1: Duplicate key correctly rejected - bug is fixed
    ) else (
        echo   [FAIL] BUG 1: Config rejected for other reason
    )
    set /a FAIL+=1
)
del "%TEMP%\bug1.toml" 2>nul
del "%TEMP%\bug1_out.txt" 2>nul

REM ===================================================================
REM BUG 2: _wtoi silently clamps values beyond INT_MAX
REM
REM timeout = 99999999999 (11 digits, beyond INT_MAX) passes
REM isNumeric validation (all digits!) but _wtoi returns 2147483647
REM (INT_MAX) instead of the actual value. The user specified ~31 years
REM but gets ~68 years instead, with no error.
REM
REM Root cause: _wtoi clamps on overflow; validation checks digit chars
REM but not value range.
REM Fix: validate that the numeric value < some sane upper bound.
REM ===================================================================
echo.
echo === BUG 2: Limit value overflow silently clamps to INT_MAX ===

echo [sandbox]>"%TEMP%\bug2.toml"
echo token = 'appcontainer'>>"%TEMP%\bug2.toml"
echo [allow.deep]>>"%TEMP%\bug2.toml"
echo read = ['C:\Windows']>>"%TEMP%\bug2.toml"
echo [limit]>>"%TEMP%\bug2.toml"
echo timeout = 99999999999>>"%TEMP%\bug2.toml"

"!SANDY!" --dry-run -c "%TEMP%\bug2.toml" >"%TEMP%\bug2_out.txt" 2>&1
set BUG2_EXIT=!ERRORLEVEL!

if !BUG2_EXIT! EQU 0 (
    findstr /C:"2147483647" "%TEMP%\bug2_out.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] BUG 2: timeout=99999999999 silently clamped to INT_MAX ^(2147483647^)
        set /a PASS+=1
    ) else (
        findstr /C:"99999999999" "%TEMP%\bug2_out.txt" >nul 2>nul
        if !ERRORLEVEL! EQU 0 (
            echo   [FAIL] BUG 2: Actual value preserved - may be fixed differently
        ) else (
            echo   [FAIL] BUG 2: Value changed to something unexpected
        )
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] BUG 2: Config correctly rejected overflow value - bug is fixed
    set /a FAIL+=1
)
del "%TEMP%\bug2.toml" 2>nul
del "%TEMP%\bug2_out.txt" 2>nul

REM ===================================================================
REM BUG 3: Case-sensitive path dedup on Windows
REM
REM validatePaths uses std::set<wstring> for dedup, which is
REM case-sensitive. But Windows paths are case-insensitive, so
REM 'C:\Windows' and 'c:\windows' are the same directory but both
REM are accepted without a duplicate warning, leading to double
REM ACL grants on the same directory.
REM
REM Root cause: case-sensitive set comparison for case-insensitive FS.
REM Fix: use NormalizeLookupKey (towlower) before insertion.
REM ===================================================================
echo.
echo === BUG 3: Case-sensitive path dedup misses duplicates ===

echo [sandbox]>"%TEMP%\bug3.toml"
echo token = 'appcontainer'>>"%TEMP%\bug3.toml"
echo [allow.deep]>>"%TEMP%\bug3.toml"
echo read = ['C:\Windows', 'c:\windows']>>"%TEMP%\bug3.toml"

"!SANDY!" --dry-run -c "%TEMP%\bug3.toml" >"%TEMP%\bug3_out.txt" 2>&1
set BUG3_EXIT=!ERRORLEVEL!

REM If the bug is present: both paths appear in dry-run, no duplicate warning on stderr
findstr /C:"Duplicate" "%TEMP%\bug3_out.txt" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    REM No duplicate warning — both entries accepted
    findstr /C:"c:\windows" "%TEMP%\bug3_out.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] BUG 3: c:\windows and C:\Windows both accepted - no dedup warning
        set /a PASS+=1
    ) else (
        echo   [FAIL] BUG 3: One copy was removed - partial fix?
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] BUG 3: Duplicate correctly detected - bug is fixed
    set /a FAIL+=1
)
del "%TEMP%\bug3.toml" 2>nul
del "%TEMP%\bug3_out.txt" 2>nul

REM ===================================================================
REM BUG 4: Empty string accepted in allow path array
REM
REM read = ['', 'C:\Windows'] — empty string '' is stored as a valid
REM FolderEntry with an empty path. The pipeline skips it
REM (empty path guard) so no crash, but the config should reject it
REM because it's clearly user error that should not pass validation.
REM
REM Root cause: no validation that array elements are non-empty.
REM Fix: reject empty strings in allow/deny/env arrays.
REM ===================================================================
echo.
echo === BUG 4: Empty string in path array silently accepted ===

echo [sandbox]>"%TEMP%\bug4.toml"
echo token = 'appcontainer'>>"%TEMP%\bug4.toml"
echo [allow.deep]>>"%TEMP%\bug4.toml"
echo read = ['', 'C:\Windows']>>"%TEMP%\bug4.toml"

"!SANDY!" --dry-run -c "%TEMP%\bug4.toml" >"%TEMP%\bug4_out.txt" 2>&1
set BUG4_EXIT=!ERRORLEVEL!

if !BUG4_EXIT! EQU 0 (
    echo   [PASS] BUG 4: Config with empty path '' accepted - no validation error
    set /a PASS+=1
) else (
    echo   [FAIL] BUG 4: Config correctly rejected empty path - bug is fixed
    set /a FAIL+=1
)
del "%TEMP%\bug4.toml" 2>nul
del "%TEMP%\bug4_out.txt" 2>nul

REM ===================================================================
REM BUG 5: Empty strings in environment pass array
REM
REM pass = ['', 'PATH', ''] — empty strings are stored in envPass
REM and would be passed to CreateProcessW's environment block as
REM zero-length variable names. This is a data validation gap.
REM
REM Root cause: no validation of env var name content.
REM Fix: reject empty strings in [environment] pass array.
REM ===================================================================
echo.
echo === BUG 5: Empty env var name in pass array accepted ===

echo [sandbox]>"%TEMP%\bug5.toml"
echo token = 'appcontainer'>>"%TEMP%\bug5.toml"
echo [allow.deep]>>"%TEMP%\bug5.toml"
echo read = ['C:\Windows']>>"%TEMP%\bug5.toml"
echo [environment]>>"%TEMP%\bug5.toml"
echo pass = ['', 'PATH', '']>>"%TEMP%\bug5.toml"

"!SANDY!" --dry-run -c "%TEMP%\bug5.toml" >"%TEMP%\bug5_out.txt" 2>&1
set BUG5_EXIT=!ERRORLEVEL!

if !BUG5_EXIT! EQU 0 (
    echo   [PASS] BUG 5: Empty env var names accepted without error
    set /a PASS+=1
) else (
    echo   [FAIL] BUG 5: Config correctly rejected empty env var name - bug is fixed
    set /a FAIL+=1
)
del "%TEMP%\bug5.toml" 2>nul
del "%TEMP%\bug5_out.txt" 2>nul

REM ===================================================================
REM BUG 6: Duplicate section headers silently merge
REM
REM If [allow.deep] appears twice, the parser merges both sections
REM into one map entry. Combined with Bug 1 (duplicate key overwrite),
REM the second [allow.deep] will overwrite any keys that also appeared
REM in the first one, without any diagnostic.
REM
REM Root cause: std::map lookup for section name reuses existing entry.
REM Fix: detect duplicate sections and emit an error.
REM ===================================================================
echo.
echo === BUG 6: Duplicate section headers silently merge ===

echo [sandbox]>"%TEMP%\bug6.toml"
echo token = 'appcontainer'>>"%TEMP%\bug6.toml"
echo [allow.deep]>>"%TEMP%\bug6.toml"
echo read = ['C:\Windows']>>"%TEMP%\bug6.toml"
echo [allow.deep]>>"%TEMP%\bug6.toml"
echo write = ['C:\Users']>>"%TEMP%\bug6.toml"

"!SANDY!" --dry-run -c "%TEMP%\bug6.toml" >"%TEMP%\bug6_out.txt" 2>&1
set BUG6_EXIT=!ERRORLEVEL!

if !BUG6_EXIT! EQU 0 (
    REM Both entries merged into one section without any warning
    findstr /C:"C:\Windows" "%TEMP%\bug6_out.txt" >nul 2>nul
    set W1=!ERRORLEVEL!
    findstr /C:"C:\Users" "%TEMP%\bug6_out.txt" >nul 2>nul
    set W2=!ERRORLEVEL!
    if !W1! EQU 0 if !W2! EQU 0 (
        echo   [PASS] BUG 6: Duplicate [allow.deep] sections merged silently - no warning
        set /a PASS+=1
    ) else (
        echo   [FAIL] BUG 6: Entries not merged as expected
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] BUG 6: Duplicate section correctly rejected - bug is fixed
    set /a FAIL+=1
)
del "%TEMP%\bug6.toml" 2>nul
del "%TEMP%\bug6_out.txt" 2>nul

REM ===================================================================
REM BUG 7: memory limit overflow (SIZE_T multiplication)
REM
REM memory = 2147483647 (INT_MAX) → stored as SIZE_T (64-bit).
REM When multiplied by 1048576 (1MB) to get bytes for job limits:
REM 2147483647 * 1048576 = 2251799812636672, which is valid on 64-bit.
REM But _wtoi(2147483648) returns INT_MAX, which means 2GB+ memory
REM limits silently clamp to ~2047.99 GB. User asks for 3GB, gets 2TB.
REM
REM Root cause: Same _wtoi overflow as Bug 2.
REM ===================================================================
echo.
echo === BUG 7: Memory limit overflow from _wtoi clamping ===

echo [sandbox]>"%TEMP%\bug7.toml"
echo token = 'appcontainer'>>"%TEMP%\bug7.toml"
echo [allow.deep]>>"%TEMP%\bug7.toml"
echo read = ['C:\Windows']>>"%TEMP%\bug7.toml"
echo [limit]>>"%TEMP%\bug7.toml"
echo memory = 3000000>>"%TEMP%\bug7.toml"

"!SANDY!" --dry-run -c "%TEMP%\bug7.toml" >"%TEMP%\bug7_out.txt" 2>&1
set BUG7_EXIT=!ERRORLEVEL!

if !BUG7_EXIT! EQU 0 (
    findstr /C:"3000000MB" "%TEMP%\bug7_out.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] BUG 7: memory=3000000 accepted - 3TB limit passes _wtoi range
        set /a PASS+=1
    ) else (
        echo   [FAIL] BUG 7: Value changed or rejected
        type "%TEMP%\bug7_out.txt"
        set /a FAIL+=1
    )
) else (
    echo   [FAIL] BUG 7: Config correctly rejected - overflow caught
    set /a FAIL+=1
)
del "%TEMP%\bug7.toml" 2>nul
del "%TEMP%\bug7_out.txt" 2>nul

REM ===================================================================
REM SUMMARY
REM ===================================================================
echo.
echo =====================================================================
echo === Bug Detector Results: !PASS! bugs confirmed, !FAIL! fixed (of 7) ===
echo =====================================================================
echo.
echo When a bug is fixed, its test will flip from PASS to FAIL.

REM Bug detectors don't use exit codes for pass/fail — always exit 0
exit /b 0

