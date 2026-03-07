@echo off
setlocal EnableDelayedExpansion

echo ================================================================
echo  Sandy CLI — Full Test Suite
echo ================================================================
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
set PASS=0
set FAIL=0
set FAILED_TESTS=

for %%F in (
    test_sandy.bat
    test_acl_grants.bat
    test_acl_grants_rt.bat
    test_allow_limits.bat
    test_allow_limits_rt.bat
    test_deep_acl.bat
    test_deep_acl_rt.bat
    test_collusion.bat
    test_concurrent.bat
    test_diabolical.bat
    test_diabolical_rt.bat
    test_evil.bat
    test_evil_rt.bat
    test_expert.bat
    test_expert_rt.bat
    test_hardening.bat
    test_kill_resilience.bat
    test_mixed_ac_rt.bat
    test_multiinstance.bat
    test_phantom.bat
    test_phantom_rt.bat
    test_resilience.bat
    test_stress.bat
) do (
    echo ----------------------------------------------------------------
    echo  RUNNING: %%F
    echo ----------------------------------------------------------------
    call "%~dp0%%F"
    if !ERRORLEVEL! equ 0 (
        echo  [PASS] %%F
        set /a PASS+=1
    ) else (
        echo  [FAIL] %%F ^(exit code: !ERRORLEVEL!^)
        set /a FAIL+=1
        set "FAILED_TESTS=!FAILED_TESTS! %%F"
    )
    echo.
)

echo ================================================================
echo  RESULTS: !PASS! passed, !FAIL! failed out of 23
echo ================================================================
if !FAIL! gtr 0 (
    echo  Failed tests:!FAILED_TESTS!
    exit /b 1
) else (
    echo  All tests passed!
    exit /b 0
)
