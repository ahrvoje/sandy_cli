"""Real non-LOCAL pipe IPC under Sandy LPAC; standard-library Python only.

The native app is built by sandy.sln. Optional --app accepts the unchanged
ideas/lpac_named_pipe/build/pipe_app.exe. No debugger or test-side rewrite is used.
"""
import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parent
SANDY = ROOT.parent / 'x64' / 'Release' / 'sandy.exe'
P, D = C.c_void_p, W.DWORD
INVALID = P(-1).value
kernel = C.WinDLL('kernel32', use_last_error=True)
advapi = C.WinDLL('advapi32', use_last_error=True)
ntdll = C.WinDLL('ntdll')


def api(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, args
    return fn


OpenProcess = api(kernel, 'OpenProcess', P, D, W.BOOL, D)
CloseHandle = api(kernel, 'CloseHandle', W.BOOL, P)
Wait = api(kernel, 'WaitForSingleObject', D, P, D)
OpenToken = api(advapi, 'OpenProcessToken', W.BOOL, P, D, P)
TokenInfo = api(advapi, 'GetTokenInformation', W.BOOL, P, D, P, D, P)
SidToString = api(advapi, 'ConvertSidToStringSidW', W.BOOL, P, P)
LocalFree = api(kernel, 'LocalFree', P, P)
DuplicateToken = api(advapi, 'DuplicateToken', W.BOOL, P, D, P)
ConvertSDDL = api(advapi, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', W.BOOL, W.LPCWSTR, D, P, P)
AccessCheck = api(advapi, 'AccessCheck', W.BOOL, P, P, D, P, P, P, P, P)
GetSecurity = api(advapi, 'GetNamedSecurityInfoW', D, W.LPCWSTR, D, D, P, P, P, P, P)
SDToString = api(advapi, 'ConvertSecurityDescriptorToStringSecurityDescriptorW', W.BOOL, P, D, D, P, P)
CreateFile = api(kernel, 'CreateFileW', P, W.LPCWSTR, D, D, P, D, D, P)
ReadFile = api(kernel, 'ReadFile', W.BOOL, P, P, D, P, P)
WriteFile = api(kernel, 'WriteFile', W.BOOL, P, P, D, P, P)
ServerPid = api(kernel, 'GetNamedPipeServerProcessId', W.BOOL, P, P)
QueryObject = api(ntdll, 'NtQueryObject', C.c_long, P, D, P, D, P)


class UnicodeString(C.Structure):
    _fields_ = [('length', W.WORD), ('maximum', W.WORD), ('buffer', P)]


class Attribute(C.Structure):
    _fields_ = [('name', UnicodeString), ('type', W.WORD), ('reserved', W.WORD),
                ('flags', D), ('count', D), ('values', P)]


class Attributes(C.Structure):
    _fields_ = [('version', W.WORD), ('reserved', W.WORD), ('count', D),
                ('attributes', C.POINTER(Attribute))]


class SidAttributes(C.Structure):
    _fields_ = [('sid', P), ('attributes', D)]


class TokenGroups(C.Structure):
    _fields_ = [('count', D), ('groups', SidAttributes * 1)]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check(value):
    if not value:
        raise C.WinError(C.get_last_error())
    return value


def sid_string(sid):
    text = P()
    check(SidToString(sid, C.byref(text)))
    try:
        return C.wstring_at(text)
    finally:
        LocalFree(text)


def dacl(path):
    descriptor, text = P(), P()
    error = GetSecurity(str(path), 1, 4, None, None, None, None, C.byref(descriptor))
    require(error == 0, f'DACL query failed: {path}: {error}')
    try:
        check(SDToString(descriptor, 1, 4, C.byref(text), None))
        return C.wstring_at(text)
    finally:
        LocalFree(text)
        LocalFree(descriptor)


def token_proof(pid, expect_lpac, expected_capabilities=0):
    process = check(OpenProcess(0x1000, False, pid))
    token, duplicate = P(), P()
    try:
        check(OpenToken(process, 0xA, C.byref(token)))  # QUERY | DUPLICATE
        buffers = {}
        for kind in (12, 25, 29, 30, 31, 39):
            needed = D()
            TokenInfo(token, kind, None, 0, C.byref(needed))
            require(needed.value, f'No token data for class {kind}')
            buf = C.create_string_buffer(needed.value)
            check(TokenInfo(token, kind, buf, len(buf), C.byref(needed)))
            buffers[kind] = buf  # pointer fields reference these live buffers
        attrs = Attributes.from_buffer(buffers[39])
        lpac = 0
        for i in range(attrs.count):
            attr = attrs.attributes[i]
            if C.wstring_at(attr.name.buffer, attr.name.length // 2) == 'WIN://NOALLAPPPKG':
                require(attr.type == 2 and attr.count == 1, 'Invalid LPAC attribute')
                lpac = C.c_uint64.from_address(attr.values).value
        sid = P.from_buffer(buffers[31]).value
        proof = {
            'appcontainer': D.from_buffer(buffers[29]).value,
            'lpac': lpac,
            'sid': sid_string(sid) if sid else None,
            'integrity': sid_string(P.from_buffer(buffers[25]).value),
            'capabilities': D.from_buffer(buffers[30]).value,
            'capability_sids': [sid_string(SidAttributes.from_buffer(
                buffers[30], TokenGroups.groups.offset + i * C.sizeof(SidAttributes)).sid)
                for i in range(D.from_buffer(buffers[30]).value)],
            'session': D.from_buffer(buffers[12]).value,
        }
        require(proof['lpac'] == int(expect_lpac), f'Wrong LPAC token: {proof}')
        if expect_lpac:
            require(proof['appcontainer'] == 1 and proof['integrity'] == 'S-1-16-4096'
                    and proof['capabilities'] == expected_capabilities, f'Wrong sandbox token: {proof}')
            check(DuplicateToken(token, 2, C.byref(duplicate)))
            for label, access_sid, expected in [('all_packages', 'S-1-15-2-1', False),
                                                 ('own_package', proof['sid'], True)]:
                sd = P()
                check(ConvertSDDL(f'O:SYG:SYD:(A;;1;;;WD)(A;;1;;;{access_sid})', 1, C.byref(sd), None))
                try:
                    mapping = (D * 4)(1, 2, 4, 7)
                    privileges = C.create_string_buffer(1024)
                    size, granted, allowed = D(len(privileges)), D(), W.BOOL()
                    check(AccessCheck(sd, duplicate, 1, mapping, privileges,
                                      C.byref(size), C.byref(granted), C.byref(allowed)))
                    proof[label] = bool(allowed.value)
                    require(proof[label] == expected, f'AccessCheck failed: {label}')
                finally:
                    LocalFree(sd)
        return proof
    finally:
        if duplicate: CloseHandle(duplicate)
        if token: CloseHandle(token)
        CloseHandle(process)


def exchange(path, pid):
    pipe = CreateFile(path, 0xC0000000, 0, None, 3, 0, None)
    require(pipe != INVALID, f'Cannot open measured pipe: {path}: {C.get_last_error()}')
    try:
        observed = D()
        check(ServerPid(pipe, C.byref(observed)))
        require(observed.value == pid, 'Connected to another server')
        buf, needed = C.create_string_buffer(4096), D()
        require(QueryObject(pipe, 1, buf, len(buf), C.byref(needed)) >= 0, 'Object name query failed')
        name = UnicodeString.from_buffer(buf)
        native = C.wstring_at(name.buffer, name.length // 2)
        require(native == '\\Device\\NamedPipe\\' + path[9:], f'Unexpected kernel name: {native}')
        request = ('ping:' + uuid.uuid4().hex).encode('ascii')
        count = D()
        check(WriteFile(pipe, request, len(request), C.byref(count), None))
        require(count.value == len(request), 'Short request write')
        response = C.create_string_buffer(2048)
        check(ReadFile(pipe, response, len(response), C.byref(count), None))
        reply = response.raw[:count.value]
        require(reply == b'echo:' + request, f'Wrong response: {reply!r}')
        return {'native_pipe': native, 'server_pid': pid, 'request': request.decode(), 'reply': reply.decode()}
    finally:
        CloseHandle(pipe)


def run_case(label, app, name, folder, config=None, profile=None, blocked=False, crash=False,
             expected_capabilities=0):
    log = folder / (label + '.log')
    command = [str(app), name]
    if config or profile:
        selection = ['-p', profile] if profile else ['-c', str(config)]
        command = [str(SANDY), '-q', '-l', str(log), *selection, '-x', *command]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding='utf-8', errors='replace')
    lines, events = [], queue.Queue()

    def collect():
        for line in process.stdout:
            lines.append(line)
            events.put(line)
        events.put(None)

    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    proof = {'case': label}
    try:
        if not blocked:
            pid = None
            while True:
                line = events.get(timeout=30)
                require(line is not None, 'App did not create pipe: ' + ''.join(lines))
                match = re.search(r'PID[=:](\d+)', line)
                if match: pid = int(match[1])
                if line.strip() == 'READY' or 'CreateNamedPipeW succeeded:' in line:
                    break
            require(pid, 'App did not report its PID')
            lpac = bool(config or profile)
            proof['token'] = token_proof(pid, lpac, expected_capabilities)
            token = proof['token']
            path = (rf'\\.\pipe\Sessions\{token["session"]}\AppContainerNamedObjects\{token["sid"]}\{name[9:]}'
                    if lpac else name)
            if crash:
                child = check(OpenProcess(0x100000, False, pid))
                try:
                    process.terminate()
                    require(Wait(child, 5000) == 0, 'Killed launcher left its child alive')
                finally:
                    CloseHandle(child)
            else:
                proof.update(exchange(path, pid))
        code = process.wait(timeout=30)
        reader.join(5)
        require(not reader.is_alive(), 'Output reader did not finish')
        proof['exit_code'] = code
        proof['output'] = ''.join(lines)
        require(code == (1 if crash else 5 if blocked else 0), f'{label}: exit {code}: {proof["output"]}')
        if blocked:
            require('CREATE_ERROR:5' in proof['output'] or 'CREATE failed; GetLastError=5' in proof['output'],
                    'Control did not fail at pipe creation')
        elif not crash:
            require('IPC_OK' in proof['output'] or 'FlushFileBuffers succeeded' in proof['output'],
                    'App did not finish IPC')
        if log.exists():
            proof['sandy_log'] = log.read_text(encoding='utf-8-sig')
            proof['artifacts'] = re.findall(r'PIPEHOOK: extracted hook DLL -> (.*?) \(\d+ bytes\)', proof['sandy_log'])
            if not crash:
                for artifact in proof['artifacts']:
                    require(not Path(artifact).exists(), 'Hook DLL was not cleaned up: ' + artifact)
        print(f'[PASS] {label}: exit={code}', flush=True)
        return proof
    finally:
        if process.poll() is None:
            process.terminate()  # only our launcher; its job closes with it
            process.wait(timeout=10)
        reader.join(5)
        process.stdout.close()


@contextmanager
def test_directory():
    # Normal inherited Windows DACL, as with mkdir in the existing tests.
    # Python 3.13's mkdtemp mode=0700 instead installs a special protected DACL.
    parent = Path(tempfile.gettempdir()).resolve()
    folder = parent / ('sandy-pipe-test-' + uuid.uuid4().hex)
    folder.mkdir()
    try:
        yield folder
    finally:
        require(folder.resolve().parent == parent, 'Unexpected test cleanup target')
        shutil.rmtree(folder)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', type=Path, default=ROOT / 'x64/Release/pipe_hook_app.exe')
    args = parser.parse_args()
    require(args.app.is_file(), 'Build sandy.sln first, or supply --app')
    before = hashlib.sha256(args.app.read_bytes()).hexdigest()
    results = []
    with test_directory() as folder:
        app = folder / 'pipe_hook_app.exe'
        shutil.copyfile(args.app, app)
        os.environ['SANDY_PIPE_TEST_DIR'] = str(folder)
        original_dacls = {path: dacl(path) for path in (folder, app)}
        name = r'\\.\pipe\sandy-pipe-test-' + uuid.uuid4().hex
        config = folder / 'hook.toml'
        text = (ROOT / 'test_pipe_hook_config.toml').read_text().replace('sandy-pipe-test', name[9:])
        config.write_text(text, encoding='utf-8')
        control = ROOT / 'test_pipe_hook_control.toml'
        results.append(run_case('normal_nonlocal', app, name, folder))
        results.append(run_case('lpac_nonlocal_control', app, name, folder, control, blocked=True))
        results.append(run_case('lpac_local_rewrite', app, name, folder, config))
        results.append(run_case('lpac_unmapped_name', app, name + '-unmapped', folder, config, blocked=True))
        mismatch_log = folder / 'mismatched_architecture.log'
        mismatch = subprocess.run([str(SANDY), '-q', '-c', str(config), '-l', str(mismatch_log),
                                   '-x', str(Path(os.environ['SYSTEMROOT']) / 'SysWOW64/cmd.exe'),
                                   '/c', 'echo SANDY_PIPE_UNEXPECTED'],
                                  capture_output=True, text=True, timeout=25)
        require(mismatch.returncode == 129 and 'SANDY_PIPE_UNEXPECTED' not in mismatch.stdout,
                'Architecture mismatch did not abort before app entry')
        for artifact in re.findall(r'PIPEHOOK: extracted hook DLL -> (.*?) \(\d+ bytes\)',
                                   mismatch_log.read_text(encoding='utf-8-sig')):
            require(not Path(artifact).exists(), 'Failed injection left its payload')
        print('[PASS] mismatched architecture aborts with 129 and removes payload')
        if args.app.resolve() == (ROOT / 'x64/Release/pipe_hook_app.exe').resolve():
            for mode in ('--client-file', '--client-call'):
                client = subprocess.run([str(SANDY), '-q', '-c', str(config), '-x', str(app), name, mode],
                                        capture_output=True, text=True, timeout=25)
                require(client.returncode == 0 and 'IPC_OK' in client.stdout,
                        f'{mode}: {client.returncode}: {client.stdout} {client.stderr}')
                print('[PASS] mapped in-process client: ' + mode)
                results.append({'case': mode, 'exit_code': client.returncode, 'output': client.stdout})
        os.environ['SANDY_PIPEHOOK'] = 'stale parent value must be replaced'
        config.write_text(text + '\n[environment]\ninherit = true\n', encoding='utf-8')
        results.append(run_case('lpac_inherited_environment', app, name, folder, config))
        profile = 'pipe-test-' + uuid.uuid4().hex
        created = subprocess.run([str(SANDY), '--create-profile', profile, '-c', str(config)],
                                 capture_output=True, text=True, timeout=30)
        require(created.returncode == 0, created.stdout + created.stderr)
        try:
            results.append(run_case('lpac_saved_profile', app, name, folder, profile=profile))
            with ThreadPoolExecutor(max_workers=2) as pool:
                runs = [pool.submit(run_case, 'profile_parallel_' + str(i), app, pipe, folder, profile=profile)
                        for i, pipe in enumerate((name, name + '-peer'))]
                parallel = [run.result() for run in runs]
            require(len({path for run in parallel for path in run['artifacts']}) == 2,
                    'Concurrent runs shared a hook DLL')
            results.extend(parallel)
            crashed = run_case('profile_killed_launcher', app, name, folder, profile=profile, crash=True)
            results.append(crashed)
            results.append(run_case('profile_after_recovery', app, name, folder, profile=profile))
            require(crashed['artifacts'] and all(not Path(path).exists() for path in crashed['artifacts']),
                    'Startup did not remove the crashed run payload')
            info = subprocess.run([str(SANDY), '--profile-info', profile], capture_output=True, text=True, timeout=30)
            require(info.returncode == 0 and '[pipes]' in info.stdout and name in info.stdout,
                    'Saved profile lost its pipe map')
        finally:
            removed = subprocess.run([str(SANDY), '--delete-profile', profile], capture_output=True, text=True, timeout=30)
            require(removed.returncode == 0, removed.stdout + removed.stderr)
        require(hashlib.sha256(app.read_bytes()).hexdigest() == before, 'App binary changed')
        for path, value in original_dacls.items():
            actual = dacl(path)
            require(actual == value, f'Test DACL changed: {path}\nbefore: {value}\nafter: {actual}')
        resolved = subprocess.run([str(SANDY), '--print-config', '-c', str(config)],
                                  capture_output=True, text=True, timeout=10)
        require(resolved.returncode == 0 and '[pipes]' in resolved.stdout and name in resolved.stdout,
                'Resolved config lost its pipe map')
        for label, invalid in [
            ('nonlocal destination', text.replace('pipe\\LOCAL\\', 'pipe\\')),
            ('restricted mode', text.replace("token = 'lpac'", "token = 'restricted'\nintegrity = 'low'")),
            ('control character', text.replace("' = '", "\x1f' = '")),
            ('case duplicate', text.replace('[pipes]', '[pipes]\n' + "'" + name.upper() + "' = '" + name + "'")),
        ]:
            config.write_text(invalid, encoding='utf-8')
            rejected = subprocess.run([str(SANDY), '--dry-run', '-c', str(config)],
                                      capture_output=True, text=True, timeout=10)
            require(rejected.returncode == 128, f'Accepted {label}: {rejected.stdout} {rejected.stderr}')
            print('[PASS] reject ' + label)
    require(hashlib.sha256(args.app.read_bytes()).hexdigest() == before, 'Source app binary changed')
    help_text = subprocess.run([str(SANDY), '--help'], capture_output=True, text=True, timeout=10)
    require(help_text.returncode == 0 and '[pipes]' in help_text.stdout and 'CallNamedPipeW' in help_text.stdout,
            'Help is missing pipe configuration')
    external = args.app.resolve() != (ROOT / 'x64/Release/pipe_hook_app.exe').resolve()
    output = ROOT / ('pipe_hook_external_proof.json' if external else 'pipe_hook_proof.json')
    output.write_text(json.dumps({'passed': True, 'app': str(args.app), 'app_sha256': before, 'cases': results}, indent=2) + '\n', encoding='utf-8')
    print('[PASS] original binary and DACLs unchanged; payload files removed')
    print('Proof: ' + str(output))


if __name__ == '__main__':
    main()
