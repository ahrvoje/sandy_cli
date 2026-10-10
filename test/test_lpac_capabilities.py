"""Verify explicit LPAC capabilities, defaults, mode validation and persistence."""
import tomllib
import winreg
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
    names = ['registryRead', 'lpacCom', 'lpacCryptoServices', 'lpacIdentityServices',
             'internetClient', 'privateNetworkClientServer']
    expected = {capability_sid(name) for name in names}
    proofs = []
    with test_directory() as folder:
        app = folder / 'pipe_hook_app.exe'
        shutil.copyfile(ROOT / 'x64/Release/pipe_hook_app.exe', app)
        os.environ['SANDY_PIPE_TEST_DIR'] = str(folder)
        original = {p: dacl(p) for p in (folder, app)}
        text = (ROOT / 'test_lpac_capabilities.toml').read_text(encoding='utf-8')
        declared = repr(names + ['REGISTRYREAD'])
        require(declared in text, 'Fixture capability list changed')
        config = folder / 'caps.toml'
        config.write_text(text, encoding='utf-8')
        pipe = r'\\.\pipe\sandy-capability-test'

        def resolved():
            result = subprocess.run([str(SANDY), '--print-config', '-c', str(config)],
                                    capture_output=True, text=True, timeout=10)
            require(result.returncode == 0, result.stdout + result.stderr)
            return tomllib.loads(result.stdout), result.stdout

        parsed, rendered = resolved()
        require(parsed['capabilities']['names'] == names, 'Names not preserved/deduplicated')
        config.write_text(rendered, encoding='utf-8')
        require(resolved()[0] == parsed, 'Resolved config did not round trip')
        result = run_case('lpac_six_capabilities', app, pipe, folder, config,
                          expected_capabilities=len(expected))
        require(set(result['token']['capability_sids']) == expected, 'Wrong capability SIDs')
        proofs.append(result)
        profile = 'caps-test-' + uuid.uuid4().hex
        created = subprocess.run([str(SANDY), '--create-profile', profile, '-c', str(config)],
                                 capture_output=True, text=True, timeout=30)
        require(created.returncode == 0, created.stdout + created.stderr)
        try:
            result = run_case('lpac_saved_capabilities', app, pipe, folder, profile=profile,
                              expected_capabilities=len(expected))
            require(set(result['token']['capability_sids']) == expected, 'Profile lost capabilities')
            proofs.append(result)
            info = subprocess.run([str(SANDY), '--profile-info', profile],
                                  capture_output=True, text=True, timeout=10)
            require(info.returncode == 0 and all(repr(n) in info.stdout for n in names),
                    'Profile output lost capability names')
            # Corrupt only our own profile, restoring each value before the next case.
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                'Software\\Sandy\\Profiles\\' + profile, 0,
                                winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                for field, bad_value in (('_capability_count', 257), ('_capability_0', ''),
                                         ('_allow_loopback', 2), ('_allow_loopback', None)):
                    value, kind = winreg.QueryValueEx(key, field)
                    try:
                        if bad_value is None:
                            winreg.DeleteValue(key, field)
                        else:
                            winreg.SetValueEx(key, field, 0, kind, bad_value)
                        bad = subprocess.run([str(SANDY), '--profile-info', profile],
                                             capture_output=True, text=True, timeout=10)
                        require(bad.returncode != 0, 'Accepted corrupt profile field ' + field)
                    finally:
                        winreg.SetValueEx(key, field, 0, kind, value)
                # Missing new metadata cannot run; deletion must still revoke its grants.
                winreg.DeleteValue(key, '_capability_count')
            bad = subprocess.run([str(SANDY), '--profile-info', profile],
                                 capture_output=True, text=True, timeout=10)
            require(bad.returncode != 0, 'Accepted a profile without capability metadata')
        finally:
            deleted = subprocess.run([str(SANDY), '--delete-profile', profile],
                                     capture_output=True, text=True, timeout=30)
            require(deleted.returncode == 0, deleted.stdout + deleted.stderr)

        # A custom name proves the implementation has no fixed capability catalogue.
        custom = 'sandy.test.' + uuid.uuid4().hex
        config.write_text(text.replace(declared, repr([custom])), encoding='utf-8')
        result = run_case('lpac_custom_capability', app, pipe, folder, config, expected_capabilities=1)
        require(result['token']['capability_sids'] == [capability_sid(custom)], 'Custom SID mismatch')
        proofs.append(result)
        config.write_text(text.replace(declared, '[]'), encoding='utf-8')
        proofs.append(run_case('lpac_empty_capabilities', app, pipe, folder, config))
        config.write_text(text.replace("'lpac'", "'appcontainer'"), encoding='utf-8')
        require(resolved()[0]['capabilities']['names'] == names, 'AC rejected named capabilities')

        for mode in ('container', 'restricted'):
            template = subprocess.check_output([str(SANDY), '--print-' + mode + '-toml'], text=True)
            config.write_text(template, encoding='utf-8')
            generated, _ = resolved()
            require(('capabilities' in generated) == (mode == 'container'),
                    'Default template uses the wrong mode fields')

        invalid = {
            'scalar names': text.replace(declared, "'registryRead'"),
            'non-string name': text.replace(declared, '[true]'),
            'empty name': text.replace(declared, "['']"),
            'whitespace name': text.replace(declared, "['registry Read']"),
            'embedded NUL': text.replace(declared, '["registry\\u0000Read"]'),
            'too long': text.replace(declared, repr(['x' * 257])),
            'too many': text.replace(declared, repr(['x' + str(i) for i in range(257)])),
            'unknown key': text.replace('names =', 'unknown ='),
            'restricted mode': text.replace("'lpac'", "'restricted'\nintegrity='low'"),
            'empty capabilities in RT': "[sandbox]\ntoken='restricted'\nintegrity='low'\n\n[capabilities]\nnames=[]",
            'loopback false in RT': "[sandbox]\ntoken='restricted'\nintegrity='low'\n\n[privileges]\nloopback=false",
            'loopback without LAN': text.replace(declared, "['internetClient']").replace('loopback = false', 'loopback = true'),
            'invalid loopback': text.replace('loopback = false', 'loopback = []'),
        }
        for removed in ('network', 'lan', 'registry_read', 'com', 'localhost'):
            invalid['removed ' + removed] = text.replace('loopback = false', removed + ' = true')
        for label, value in invalid.items():
            config.write_text(value, encoding='utf-8')
            result = subprocess.run([str(SANDY), '--dry-run', '-c', str(config)],
                                    capture_output=True, text=True, timeout=10)
            require(result.returncode == 128, f'Accepted {label}: {result.stdout} {result.stderr}')
        # Dry-run must accept the separate loopback control without creating an exemption.
        config.write_text(text.replace('loopback = false', 'loopback = true'), encoding='utf-8')
        require(resolved()[0]['privileges']['loopback'] is True, 'Loopback setting lost')
        for p, sd in original.items():
            require(dacl(p) == sd, 'DACL changed after capability tests')
        status = subprocess.check_output([str(SANDY), '--status'], text=True)
        require(all(case['token']['sid'] not in status for case in proofs), 'Test sandbox remains active')
    (ROOT / 'capabilities_proof.json').write_text(
        json.dumps({'passed': True, 'cases': proofs, 'invalid_cases': list(invalid)}, indent=2),
        encoding='utf-8')
    print('[PASS] six Windows capabilities, custom SID, empty defaults, deduplication,')
    print('       config/profile round trip, AC support, rejected old keys and cleanup')


if __name__ == '__main__':
    main()
