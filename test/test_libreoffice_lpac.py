"""Verify the live Writer token, exact pipe, window and file access for --scratch."""
import argparse
import re
import tomllib
from test_pipe_hook import (
    C, W, P, D, INVALID, ROOT, Path, os, json, uuid, advapi,
    api, check, require, OpenProcess, OpenToken, DuplicateToken, CloseHandle,
    CreateFile, WriteFile, ReadFile, token_proof,
)
from test_lpac_capabilities import capability_sid


def verify_writer(pid, state):
    expected = tomllib.loads(Path(__file__).with_suffix('.toml').read_text())['expected']
    base = Path(state['scratch'])
    runtime = Path(state['runtime'])
    work = Path(state['work'])
    proof = {'pid': pid, 'token': token_proof(pid, True, expected['capabilities'])}
    token = proof['token']
    require(set(token['capability_sids']) == {capability_sid('registryRead'), capability_sid('lpacCom')},
            'Unexpected capabilities in Writer token')
    prefix = f'Sessions\\{token["session"]}\\AppContainerNamedObjects\\{token["sid"]}\\OSL_PIPE_'
    proof['pipes'] = [p for p in os.listdir('\\\\.\\pipe\\')
                      if p.startswith(prefix) and '_SingleOfficeIPC_' in p]
    require(proof['pipes'] == [prefix[:-len('OSL_PIPE_')] + state['pipe_source'][9:]],
            'Expected the exact mapped LibreOffice pipe')

    user32 = C.WinDLL('user32', use_last_error=True)
    enum = api(user32, 'EnumWindows', W.BOOL, P, P)
    owner = api(user32, 'GetWindowThreadProcessId', D, P, P)
    title = api(user32, 'GetWindowTextW', C.c_int, P, P, C.c_int)
    visible = api(user32, 'IsWindowVisible', W.BOOL, P)
    proof['windows'] = []

    @C.WINFUNCTYPE(W.BOOL, P, P)
    def visit(hwnd, _):
        wp = D()
        owner(hwnd, C.byref(wp))
        if wp.value == pid and visible(hwnd):
            text = C.create_unicode_buffer(512)
            title(hwnd, text, len(text))
            proof['windows'].append(text.value)
        return True

    check(enum(visit, None))
    require(any(expected['window_title'] in t and expected['document'] in t
                for t in proof['windows']), 'Demo document is not visible in Writer')
    outside = ROOT / ('lpac-outside-' + uuid.uuid4().hex + '.txt')
    inside = work / ('lpac-write-' + uuid.uuid4().hex + '.txt')
    outside.write_text('This host file must be denied to Writer.', encoding='utf-8')
    process = check(OpenProcess(0x1000, False, pid))
    source, duplicate = P(), P()
    impersonate = api(advapi, 'SetThreadToken', W.BOOL, P, P)
    revert = api(advapi, 'RevertToSelf', W.BOOL)
    proof['file_access'] = []

    def attempt(label, path, mask, allowed, disposition=3, payload=None):
        handle = CreateFile(str(path), mask, 7, None, disposition, 0x02000000, None)
        error = C.get_last_error() if handle == INVALID else 0
        actual = handle != INVALID
        try:
            require(actual == allowed and (allowed or error == 5),
                    f'{label}: allowed={actual}, error={error}')
            if payload is not None:
                count = D()
                check(WriteFile(handle, payload, len(payload), C.byref(count), None))
                require(count.value == len(payload), 'Short sandbox write')
            elif allowed and mask == 0x80000000 and path.is_file():
                data, count = C.create_string_buffer(32), D()
                check(ReadFile(handle, data, len(data), C.byref(count), None))
                require(count.value > 0, 'Empty sandbox read')
            proof['file_access'].append({'check': label, 'allowed': actual, 'error': error})
        finally:
            if actual:
                CloseHandle(handle)

    try:
        check(OpenToken(process, 0xA, C.byref(source)))
        check(DuplicateToken(source, 2, C.byref(duplicate)))
        check(impersonate(None, duplicate))
        try:
            attempt('runtime read', runtime / 'program/soffice.bin', 0x80000000, True)
            attempt('runtime write', runtime / 'program/soffice.bin', 0x40000000, False)
            attempt('document read', work / expected['document'], 0x80000000, True)
            attempt('document create/write', inside, 0x40000000, True, 1, b'LPAC write verified\n')
            attempt('host file read', outside, 0x80000000, False)
            attempt('host file write', outside, 0x40000000, False)
            attempt('parent listing', base, 0x80000000, True)
            attempt('scratch control file write', base / 'initialized.json', 0x40000000, False)
            attempt('profile settings write', base / 'profile/user/registrymodifications.xcu', 0x40000000, True)
            attempt('work file execute', work / expected['document'], 0x20, False)
            for name in ('home', 'appdata/local', 'appdata/roaming'):
                attempt('profile directory ' + name, base / 'profile' / name, 1, True)
            attempt('temporary directory write', Path(state['temp']), 2, True)
            for path in (Path(os.environ['SystemDrive'] + '/'), Path(os.environ['USERPROFILE']).parent):
                attempt('protected ancestor listing ' + str(path), path, 1, False)
            attempt('parent file contents', Path(state['config']), 0x80000000, False)
        finally:
            check(revert())
        require(inside.read_bytes() == b'LPAC write verified\n', 'Sandbox write contents differ')
    finally:
        if duplicate: CloseHandle(duplicate)
        if source: CloseHandle(source)
        CloseHandle(process)
        outside.unlink(missing_ok=True)
        inside.unlink(missing_ok=True)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--pid', type=int, help='Default: PID from the current Sandy run log')
    args = parser.parse_args()
    state = json.loads((args.scratch / 'last-run.json').read_text(encoding='utf-8'))
    matches = re.findall(r'LAUNCH: PID (\d+),', Path(state['sandy_log']).read_text(encoding='utf-8-sig'))
    pid = args.pid or (int(matches[-1]) if matches else None)
    require(pid is not None, 'No Writer PID in the Sandy log')
    proof = verify_writer(pid, state)
    output = Path(state['logs']) / 'lpac-proof.json'
    output.write_text(json.dumps(proof, indent=2), encoding='utf-8')
    print(json.dumps(proof, indent=2))
    print('PASS: live LPAC Writer, isolated pipe, narrow file access')


if __name__ == '__main__':
    main()
