@echo off
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
setlocal EnableDelayedExpansion

set SANDY=%~dp0..\x64\Release\sandy.exe
set PYTHON=C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe
set PASS=0
set FAIL=0

echo =====================================================================
echo  Sandy Sneaky Test Suite
echo  Adversarial tests for the 7 most fragile code paths
echo =====================================================================

REM Pre-clean
"!SANDY!" --delete-profile sneaky_rt >nul 2>nul
"!SANDY!" --delete-profile sneaky_ac >nul 2>nul
"!SANDY!" --cleanup >nul 2>nul

REM ===================================================================
REM GROUP 1: TOML Poison Configs
REM ===================================================================
echo.
echo === GROUP 1: TOML Poison Configs ===
echo.

REM 1a: Backslash before closing DQ — the \" should escape the quote,
REM      leaving the string unterminated.
echo --- 1a: Backslash-quote in DQ string ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'restricted'\nintegrity = 'low'\n[allow.deep]\nread = [\"C:\\path\\\"]" >"%TEMP%\sneaky_1a.txt" 2>&1
findstr /C:"Unterminated" "%TEMP%\sneaky_1a.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 1a: Backslash-quote unterminated string detected
    set /a PASS+=1
) else (
    echo   [FAIL] 1a: Should report unterminated string
    type "%TEMP%\sneaky_1a.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_1a.txt" 2>nul

REM 1b: Array without commas — ['a' 'b'] must be rejected
echo --- 1b: Comma-less array ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\\Windows' 'C:\\Users']" >"%TEMP%\sneaky_1b.txt" 2>&1
findstr /C:"Missing comma" "%TEMP%\sneaky_1b.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 1b: Comma-less array rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 1b: Should report missing comma
    type "%TEMP%\sneaky_1b.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_1b.txt" 2>nul

REM 1c: Trailing garbage after closing quote
echo --- 1c: Trailing garbage after quote ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'garbage" >"%TEMP%\sneaky_1c.txt" 2>&1
findstr /C:"Unterminated" "%TEMP%\sneaky_1c.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 1c: Trailing garbage detected
    set /a PASS+=1
) else (
    echo   [FAIL] 1c: Should report unterminated/trailing garbage
    type "%TEMP%\sneaky_1c.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_1c.txt" 2>nul

REM 1d: Mixed quote types in array — valid TOML
echo --- 1d: Mixed quote types in array ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\\Windows', \"C:\\Windows\\Temp\"]" >"%TEMP%\sneaky_1d.txt" 2>&1
set DRY_1D=!ERRORLEVEL!
if !DRY_1D! EQU 0 (
    echo   [PASS] 1d: Mixed quotes accepted
    set /a PASS+=1
) else (
    echo   [FAIL] 1d: Mixed quotes should be valid
    type "%TEMP%\sneaky_1d.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_1d.txt" 2>nul

REM 1e: Empty array — valid
echo --- 1e: Empty array ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = []" >"%TEMP%\sneaky_1e.txt" 2>&1
set DRY_1E=!ERRORLEVEL!
if !DRY_1E! EQU 0 (
    echo   [PASS] 1e: Empty array accepted
    set /a PASS+=1
) else (
    echo   [FAIL] 1e: Empty array should be valid
    type "%TEMP%\sneaky_1e.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_1e.txt" 2>nul

REM 1f: Unquoted stray token in array
echo --- 1f: Unquoted stray token in array ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = [C:\Windows]" >"%TEMP%\sneaky_1f.txt" 2>&1
findstr /C:"unquoted" "%TEMP%\sneaky_1f.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 1f: Unquoted token in array rejected
    set /a PASS+=1
) else (
    findstr /C:"Unexpected" "%TEMP%\sneaky_1f.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        echo   [PASS] 1f: Unquoted token in array rejected
        set /a PASS+=1
    ) else (
        echo   [FAIL] 1f: Should reject unquoted array token
        type "%TEMP%\sneaky_1f.txt"
        set /a FAIL+=1
    )
)
del "%TEMP%\sneaky_1f.txt" 2>nul

REM 1g: DQ string with valid escape sequences
echo --- 1g: Valid escape sequences in DQ ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = [\"C:\\Windows\\System32\"]" >"%TEMP%\sneaky_1g.txt" 2>&1
set DRY_1G=!ERRORLEVEL!
if !DRY_1G! EQU 0 (
    echo   [PASS] 1g: Escaped backslashes in DQ path accepted
    set /a PASS+=1
) else (
    echo   [FAIL] 1g: Escaped backslashes should be valid
    type "%TEMP%\sneaky_1g.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_1g.txt" 2>nul

REM ===================================================================
REM GROUP 2: Config Cross-Product Validation
REM ===================================================================
echo.
echo === GROUP 2: Config Cross-Product Validation ===
echo.

REM 2a: strict=true on AC — must reject
echo --- 2a: strict on appcontainer ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\nstrict = true" >"%TEMP%\sneaky_2a.txt" 2>&1
findstr /C:"strict" "%TEMP%\sneaky_2a.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2a: strict on AC rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2a: strict on AC should be rejected
    type "%TEMP%\sneaky_2a.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2a.txt" 2>nul

REM 2b: [deny.deep] on AC — must reject
echo --- 2b: deny on appcontainer ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[deny.deep]\nread = ['C:\\Windows']" >"%TEMP%\sneaky_2b.txt" 2>&1
findstr /I /C:"deny" "%TEMP%\sneaky_2b.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2b: Deny on AC rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2b: Deny on AC should be rejected
    type "%TEMP%\sneaky_2b.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2b.txt" 2>nul

REM 2c: named_pipes on AC — must reject
echo --- 2c: named_pipes on appcontainer ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[privileges]\nnamed_pipes = true" >"%TEMP%\sneaky_2c.txt" 2>&1
findstr /C:"named_pipes" "%TEMP%\sneaky_2c.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2c: named_pipes on AC rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2c: named_pipes on AC should be rejected
    type "%TEMP%\sneaky_2c.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2c.txt" 2>nul

REM 2d: desktop on AC — must reject
echo --- 2d: desktop on appcontainer ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[privileges]\ndesktop = true" >"%TEMP%\sneaky_2d.txt" 2>&1
findstr /C:"desktop" "%TEMP%\sneaky_2d.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2d: desktop on AC rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2d: desktop on AC should be rejected
    type "%TEMP%\sneaky_2d.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2d.txt" 2>nul

REM 2e: network on RT — must reject
echo --- 2e: network on restricted ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'restricted'\nintegrity = 'low'\n[privileges]\nnetwork = true" >"%TEMP%\sneaky_2e.txt" 2>&1
findstr /C:"network" "%TEMP%\sneaky_2e.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2e: network on RT rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2e: network on RT should be rejected
    type "%TEMP%\sneaky_2e.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2e.txt" 2>nul

REM 2f: [registry] on AC — must reject
echo --- 2f: registry on appcontainer ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[registry]\nread = ['HKCU\\Software']" >"%TEMP%\sneaky_2f.txt" 2>&1
findstr /C:"registry" "%TEMP%\sneaky_2f.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2f: registry on AC rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2f: registry on AC should be rejected
    type "%TEMP%\sneaky_2f.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2f.txt" 2>nul

REM 2g: Missing integrity on RT — must reject
echo --- 2g: Missing integrity on restricted ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'restricted'" >"%TEMP%\sneaky_2g.txt" 2>&1
findstr /C:"integrity" "%TEMP%\sneaky_2g.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2g: Missing integrity on RT rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2g: Missing integrity on RT should be rejected
    type "%TEMP%\sneaky_2g.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2g.txt" 2>nul

REM 2h: All 10 access levels in allow.deep — must be accepted
echo --- 2h: All 10 access levels accepted ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\\Windows']\nwrite = ['C:\\Windows\\Temp']\nexecute = ['C:\\Windows']\nappend = ['C:\\Windows\\Temp']\ndelete = ['C:\\Windows\\Temp']\nall = ['C:\\Windows\\Temp']\nrun = ['C:\\Windows']\nstat = ['C:\\Windows']\ntouch = ['C:\\Windows\\Temp']\ncreate = ['C:\\Windows\\Temp']" >"%TEMP%\sneaky_2h.txt" 2>&1
set DRY_2H=!ERRORLEVEL!
if !DRY_2H! EQU 0 (
    echo   [PASS] 2h: All 10 access levels accepted
    set /a PASS+=1
) else (
    echo   [FAIL] 2h: All 10 access levels should be valid
    type "%TEMP%\sneaky_2h.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2h.txt" 2>nul

REM 2i: Old [allow] section rejected
echo --- 2i: Old [allow] section rejected ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow]\nread = ['C:\\Windows']" >"%TEMP%\sneaky_2i.txt" 2>&1
findstr /C:"no longer supported" "%TEMP%\sneaky_2i.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2i: Old [allow] rejected with helpful message
    set /a PASS+=1
) else (
    echo   [FAIL] 2i: Old [allow] should be rejected
    type "%TEMP%\sneaky_2i.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2i.txt" 2>nul

REM 2j: Old [deny] section rejected
echo --- 2j: Old [deny] section rejected ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'restricted'\nintegrity = 'low'\n[deny]\nread = ['C:\\Windows']" >"%TEMP%\sneaky_2j.txt" 2>&1
findstr /C:"no longer supported" "%TEMP%\sneaky_2j.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2j: Old [deny] rejected with helpful message
    set /a PASS+=1
) else (
    echo   [FAIL] 2j: Old [deny] should be rejected
    type "%TEMP%\sneaky_2j.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2j.txt" 2>nul

REM 2k: Unknown section rejected
echo --- 2k: Unknown section rejected ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[hacker]\nshell = 'cmd.exe'" >"%TEMP%\sneaky_2k.txt" 2>&1
findstr /C:"Unknown config section" "%TEMP%\sneaky_2k.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2k: Unknown section rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2k: Unknown section should be rejected
    type "%TEMP%\sneaky_2k.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2k.txt" 2>nul

REM 2l: Unknown key in [sandbox] rejected
echo --- 2l: Unknown key in sandbox ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\nhack = true" >"%TEMP%\sneaky_2l.txt" 2>&1
findstr /C:"Unknown key" "%TEMP%\sneaky_2l.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2l: Unknown key in [sandbox] rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2l: Unknown key should be rejected
    type "%TEMP%\sneaky_2l.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2l.txt" 2>nul

REM 2m: integrity on AC — must reject
echo --- 2m: integrity on appcontainer ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\nintegrity = 'low'" >"%TEMP%\sneaky_2m.txt" 2>&1
findstr /C:"integrity" "%TEMP%\sneaky_2m.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2m: integrity on AC rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2m: integrity on AC should be rejected
    type "%TEMP%\sneaky_2m.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2m.txt" 2>nul

REM 2n: LPAC with deny — must reject (same as AC)
echo --- 2n: deny on LPAC ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'lpac'\n[deny.deep]\nread = ['C:\\Windows']" >"%TEMP%\sneaky_2n.txt" 2>&1
findstr /C:"deny" "%TEMP%\sneaky_2n.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 2n: Deny on LPAC rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 2n: Deny on LPAC should be rejected
    type "%TEMP%\sneaky_2n.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_2n.txt" 2>nul

REM ===================================================================
REM GROUP 3: Path Canonicalization Stress
REM ===================================================================
echo.
echo === GROUP 3: Path Canonicalization Stress ===
echo.

REM 3a: Path with forward slashes — must be accepted
echo --- 3a: Forward slash path ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:/Windows/System32']" >"%TEMP%\sneaky_3a.txt" 2>&1
set DRY_3A=!ERRORLEVEL!
if !DRY_3A! EQU 0 (
    echo   [PASS] 3a: Forward slash path accepted
    set /a PASS+=1
) else (
    echo   [FAIL] 3a: Forward slashes should be normalized
    type "%TEMP%\sneaky_3a.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_3a.txt" 2>nul

REM 3b: Path with dotdot — must be resolved and accepted
echo --- 3b: Dotdot path canonicalization ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\\Windows\\System32\\..']" >"%TEMP%\sneaky_3b.txt" 2>&1
set DRY_3B=!ERRORLEVEL!
if !DRY_3B! EQU 0 (
    echo   [PASS] 3b: Dotdot path accepted and resolved
    set /a PASS+=1
) else (
    echo   [FAIL] 3b: Dotdot path should be canonicalized
    type "%TEMP%\sneaky_3b.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_3b.txt" 2>nul

REM 3c: Path with single dot — must be resolved and accepted
echo --- 3c: Single dot path ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\\Windows\\.']" >"%TEMP%\sneaky_3c.txt" 2>&1
set DRY_3C=!ERRORLEVEL!
if !DRY_3C! EQU 0 (
    echo   [PASS] 3c: Single-dot path accepted and resolved
    set /a PASS+=1
) else (
    echo   [FAIL] 3c: Single-dot path should be canonicalized
    type "%TEMP%\sneaky_3c.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_3c.txt" 2>nul

REM 3d: Trailing backslash — C:\Windows\ -> C:\Windows
echo --- 3d: Trailing backslash stripped ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\\Windows\\']" >"%TEMP%\sneaky_3d.txt" 2>&1
set DRY_3D=!ERRORLEVEL!
if !DRY_3D! EQU 0 (
    echo   [PASS] 3d: Trailing backslash path accepted
    set /a PASS+=1
) else (
    echo   [FAIL] 3d: Trailing backslash should be stripped
    type "%TEMP%\sneaky_3d.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_3d.txt" 2>nul

REM 3e: Root path preservation — C:\ must stay C:\
echo --- 3e: Root path preserved ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:\\']" >"%TEMP%\sneaky_3e.txt" 2>&1
set DRY_3E=!ERRORLEVEL!
if !DRY_3E! EQU 0 (
    echo   [PASS] 3e: Root path accepted
    set /a PASS+=1
) else (
    echo   [FAIL] 3e: Root path should be valid
    type "%TEMP%\sneaky_3e.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_3e.txt" 2>nul

REM 3f: Mixed slashes with dotdot
echo --- 3f: Mixed slashes with dotdot ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['C:/Windows/System32/../Temp']" >"%TEMP%\sneaky_3f.txt" 2>&1
set DRY_3F=!ERRORLEVEL!
if !DRY_3F! EQU 0 (
    echo   [PASS] 3f: Mixed slashes + dotdot resolved
    set /a PASS+=1
) else (
    echo   [FAIL] 3f: Mixed slashes + dotdot should be canonicalized
    type "%TEMP%\sneaky_3f.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_3f.txt" 2>nul

REM 3g: Relative path rejected
echo --- 3g: Relative path rejected ---
"!SANDY!" --dry-run -s "[sandbox]\ntoken = 'appcontainer'\n[allow.deep]\nread = ['relative\\path']" >"%TEMP%\sneaky_3g.txt" 2>&1
findstr /C:"not an absolute" "%TEMP%\sneaky_3g.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 3g: Relative path rejected
    set /a PASS+=1
) else (
    echo   [FAIL] 3g: Relative path should be rejected
    type "%TEMP%\sneaky_3g.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_3g.txt" 2>nul

REM ===================================================================
REM GROUP 4: Profile Round-Trip Fidelity
REM ===================================================================
echo.
echo === GROUP 4: Profile Round-Trip Fidelity ===
echo.

REM Create user-owned test directories for profile grants
set SNEAKY_PROFILE_DIR=%USERPROFILE%\sneaky_profile_test
if exist "!SNEAKY_PROFILE_DIR!" rmdir /s /q "!SNEAKY_PROFILE_DIR!"
mkdir "!SNEAKY_PROFILE_DIR!\deep_read"
mkdir "!SNEAKY_PROFILE_DIR!\deep_write"
mkdir "!SNEAKY_PROFILE_DIR!\deep_exec"
mkdir "!SNEAKY_PROFILE_DIR!\deep_all"
mkdir "!SNEAKY_PROFILE_DIR!\this_stat"
mkdir "!SNEAKY_PROFILE_DIR!\this_touch"
mkdir "!SNEAKY_PROFILE_DIR!\this_run"
mkdir "!SNEAKY_PROFILE_DIR!\this_create"
mkdir "!SNEAKY_PROFILE_DIR!\this_append"
mkdir "!SNEAKY_PROFILE_DIR!\this_delete"

REM Pre-create the registry key used by RT profile's [registry] section
reg add "HKCU\Software\Sandy\Test" /f >nul 2>nul

REM Generate expanded config files from templates (PS5.x-compat: use .NET for BOM-free UTF-8)
powershell -NoProfile -Command "$c = (Get-Content '%~dp0test_sneaky_rt_profile.toml' -Raw) -replace '%%SNEAKY_PROFILE_DIR%%','!SNEAKY_PROFILE_DIR!'; [IO.File]::WriteAllText('%TEMP%\sneaky_rt_expanded.toml', $c, [Text.UTF8Encoding]::new($false))"
powershell -NoProfile -Command "$c = (Get-Content '%~dp0test_sneaky_ac_profile.toml' -Raw) -replace '%%SNEAKY_PROFILE_DIR%%','!SNEAKY_PROFILE_DIR!'; [IO.File]::WriteAllText('%TEMP%\sneaky_ac_expanded.toml', $c, [Text.UTF8Encoding]::new($false))"

REM 4a: RT profile config validation via dry-run
echo --- 4a: Dry-run RT profile validation ---
"!SANDY!" --dry-run --create-profile sneaky_rt -c "%TEMP%\sneaky_rt_expanded.toml" >"%TEMP%\sneaky_4a.txt" 2>&1
set DRY_4A=!ERRORLEVEL!
if !DRY_4A! EQU 0 (
    echo   [PASS] 4a: RT profile config validates
    set /a PASS+=1
) else (
    echo   [FAIL] 4a: RT profile config should be valid
    type "%TEMP%\sneaky_4a.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_4a.txt" 2>nul

REM 4b: Actual RT profile creation + round-trip
echo --- 4b: Create RT profile ---
"!SANDY!" --create-profile sneaky_rt -c "%TEMP%\sneaky_rt_expanded.toml" >"%TEMP%\sneaky_4b.txt" 2>&1
findstr /C:"created successfully" "%TEMP%\sneaky_4b.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 4b: RT profile created
    set /a PASS+=1
) else (
    echo   [FAIL] 4b: RT profile creation failed
    type "%TEMP%\sneaky_4b.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_4b.txt" 2>nul

REM 4b2: Verify RT profile round-trip via Python
echo --- 4b2: Verify RT profile round-trip ---
"!PYTHON!" "%~dp0test_sneaky.py" rt_roundtrip
set RT_EXIT=!ERRORLEVEL!
if !RT_EXIT! EQU 0 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
)

REM 4c: AC profile — all fields
echo --- 4c: Create AC profile ---
"!SANDY!" --create-profile sneaky_ac -c "%TEMP%\sneaky_ac_expanded.toml" >"%TEMP%\sneaky_4c.txt" 2>&1
findstr /C:"created successfully" "%TEMP%\sneaky_4c.txt" >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    echo   [PASS] 4c: AC profile created
    set /a PASS+=1
) else (
    echo   [FAIL] 4c: AC profile creation failed
    type "%TEMP%\sneaky_4c.txt"
    set /a FAIL+=1
)
del "%TEMP%\sneaky_4c.txt" 2>nul

REM 4d: Verify AC profile round-trip via Python
echo --- 4d: Verify AC profile round-trip ---
"!PYTHON!" "%~dp0test_sneaky.py" ac_roundtrip
set AC_EXIT=!ERRORLEVEL!
if !AC_EXIT! EQU 0 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
)

REM ===================================================================
REM GROUP 5: Scope Interaction (.this + .deep overlap)
REM ===================================================================
echo.
echo === GROUP 5: Scope Interaction ===
echo.

set SCOPE_ROOT=%USERPROFILE%\sneaky_scope_test
if exist "!SCOPE_ROOT!" rmdir /s /q "!SCOPE_ROOT!"
mkdir "!SCOPE_ROOT!\stat_only"
mkdir "!SCOPE_ROOT!\deep_read"
mkdir "!SCOPE_ROOT!\scripts"
echo child data>"!SCOPE_ROOT!\stat_only\child.txt"
echo child data>"!SCOPE_ROOT!\deep_read\child.txt"

REM Copy the probe script
copy /y "%~dp0test_sneaky.py" "!SCOPE_ROOT!\scripts\test_sneaky.py" >nul

REM Build scope config with resolved paths — use [environment] inherit to pass SNEAKY_SCOPE_ROOT
echo [sandbox]>"%TEMP%\sneaky_scope_run.toml"
echo token = 'appcontainer'>>"%TEMP%\sneaky_scope_run.toml"
echo [allow.this]>>"%TEMP%\sneaky_scope_run.toml"
echo stat = ['!SCOPE_ROOT!\stat_only']>>"%TEMP%\sneaky_scope_run.toml"
echo [allow.deep]>>"%TEMP%\sneaky_scope_run.toml"
echo read = ['!SCOPE_ROOT!\deep_read', '!SCOPE_ROOT!\scripts']>>"%TEMP%\sneaky_scope_run.toml"
echo execute = ['C:\Users\H\AppData\Local\Programs\Python\Python314']>>"%TEMP%\sneaky_scope_run.toml"
echo [environment]>>"%TEMP%\sneaky_scope_run.toml"
echo inherit = false>>"%TEMP%\sneaky_scope_run.toml"
echo pass = ['SNEAKY_SCOPE_ROOT', 'PATH', 'TEMP', 'SYSTEMROOT']>>"%TEMP%\sneaky_scope_run.toml"

REM Set the env var so Sandy can pass it through to the sandbox
set SNEAKY_SCOPE_ROOT=!SCOPE_ROOT!
"!SANDY!" -c "%TEMP%\sneaky_scope_run.toml" -x "!PYTHON!" "!SCOPE_ROOT!\scripts\test_sneaky.py" scope >"%TEMP%\sneaky_5.txt" 2>&1
set SCOPE_EXIT=!ERRORLEVEL!

REM Count passes and fails from probe output
set SCOPE_PASS=0
set SCOPE_FAIL=0
for /f %%n in ('findstr /C:"[PASS]" "%TEMP%\sneaky_5.txt" ^| find /c /v ""') do set SCOPE_PASS=%%n
for /f %%n in ('findstr /C:"[FAIL]" "%TEMP%\sneaky_5.txt" ^| find /c /v ""') do set SCOPE_FAIL=%%n
set /a PASS+=!SCOPE_PASS!
set /a FAIL+=!SCOPE_FAIL!

if !SCOPE_EXIT! EQU 0 (
    echo   Scope tests: all passed
) else (
    echo   Scope tests: some failures - exit code !SCOPE_EXIT!
    type "%TEMP%\sneaky_5.txt"
)

REM Cleanup
"!SANDY!" --cleanup >nul 2>nul
if exist "!SCOPE_ROOT!" rmdir /s /q "!SCOPE_ROOT!"
del "%TEMP%\sneaky_scope_run.toml" 2>nul
del "%TEMP%\sneaky_5.txt" 2>nul




REM ===================================================================
REM CLEANUP & SUMMARY
REM ===================================================================
echo.
echo --- Final Cleanup ---
"!SANDY!" --delete-profile sneaky_rt >nul 2>nul
"!SANDY!" --delete-profile sneaky_ac >nul 2>nul
"!SANDY!" --cleanup >nul 2>nul
reg delete "HKCU\Software\Sandy\Test" /f >nul 2>nul
if exist "!SNEAKY_PROFILE_DIR!" rmdir /s /q "!SNEAKY_PROFILE_DIR!"
del "%TEMP%\sneaky_rt_expanded.toml" 2>nul
del "%TEMP%\sneaky_ac_expanded.toml" 2>nul

echo.
set /a TOTAL=!PASS!+!FAIL!
echo =====================================================================
echo === Results: !PASS! passed, !FAIL! failed (of !TOTAL!) ===
echo =====================================================================
echo.
if !FAIL! GTR 0 (
    echo Some tests FAILED!
    exit /b 1
)
exit /b 0
