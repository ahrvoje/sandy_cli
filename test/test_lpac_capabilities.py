"""Verify explicit LPAC capabilities, defaults, mode validation and persistence."""
from test_pipe_hook import *


def capability_sid(name):
    derive = api(C.WinDLL('kernelbase', use_last_error=True), 'DeriveCapabilitySidsFromName',
                 W.BOOL, W.LPCWSTR, P, P, P, P)
    groups, caps = C.POINTER(P)(), C.POINTER(P)()
    ng, nc = D(), D()
    check(derive(name, C.byref(groups), C.byref(ng), C.byref(caps), C.byref(nc)))
    try:
        require(nc.value == 1, 'Unexpected capability SID count')
        return sid_string(caps[0])
    finally:
        for array, count in ((groups, ng.value), (caps, nc.value)):
            for i in range(count): LocalFree(array[i])
            LocalFree(array)


def main():
    expected = {capability_sid(name) for name in ('registryRead', 'lpacCom')}
    with test_directory() as folder:
        app = folder / 'pipe_hook_app.exe'
        shutil.copyfile(ROOT / 'x64/Release/pipe_hook_app.exe', app)
        os.environ['SANDY_PIPE_TEST_DIR'] = str(folder)
        original = {p: dacl(p) for p in (folder, app)}
        text = (ROOT / 'test_lpac_capabilities.toml').read_text()
        config = folder / 'caps.toml'
        config.write_text(text, encoding='utf-8')
        name = r'\\.\pipe\sandy-capability-test'
        result = run_case('lpac_explicit_capabilities', app, name, folder, config,
                          expected_capabilities=2)
        require(set(result['token']['capability_sids']) == expected, 'Wrong named capabilities')
        profile = 'caps-test-' + uuid.uuid4().hex
        created = subprocess.run([str(SANDY), '--create-profile', profile, '-c', str(config)],
                                 capture_output=True, text=True, timeout=30)
        require(created.returncode == 0, created.stdout + created.stderr)
        try:
            result = run_case('lpac_saved_capabilities', app, name, folder, profile=profile,
                              expected_capabilities=2)
            require(set(result['token']['capability_sids']) == expected, 'Profile lost capabilities')
            info = subprocess.run([str(SANDY), '--profile-info', profile], capture_output=True, text=True)
            require(re.search(r'registry_read\s*=\s*true', info.stdout) and
                    re.search(r'com\s*=\s*true', info.stdout), 'Profile output lost options')
        finally:
            deleted = subprocess.run([str(SANDY), '--delete-profile', profile], capture_output=True, text=True)
            require(deleted.returncode == 0, deleted.stdout + deleted.stderr)
        config.write_text(text.replace('= true', '= false'), encoding='utf-8')
        run_case('lpac_disabled_capabilities', app, name, folder, config)
        for mode in ("'appcontainer'", "'restricted'\nintegrity='low'"):
            config.write_text(text.replace("'lpac'", mode), encoding='utf-8')
            output = subprocess.run([str(SANDY), '--print-config', '-c', str(config)],
                                    capture_output=True, text=True)
            require(output.returncode == 128 and 'available only in lpac mode' in output.stderr,
                    'Wrong-mode capabilities accepted')
        for p, sd in original.items(): require(dacl(p) == sd, 'DACL changed after capability tests')
    print('[PASS] exact Windows-derived SIDs, profile round trip, disabled flags, wrong modes and cleanup')


if __name__ == '__main__':
    main()
