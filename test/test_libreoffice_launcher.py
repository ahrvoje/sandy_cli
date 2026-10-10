"""Fresh launcher -> visible LPAC Writer -> normal close -> repeat PDF export.

Uses only processes and scratch data created by this test. The optional screenshot
uses Pillow; all assertions and the launcher itself use the standard library.
"""
import argparse
import importlib.util
import re
import tempfile
import stat
import time
import tomllib
from test_pipe_hook import (
    C, W, P, D, ROOT, SANDY, Path, os, json, uuid, subprocess, shutil,
    api, check, require, kernel, OpenToken, TokenInfo, CloseHandle, dacl,
)
from test_libreoffice_lpac import verify_writer

LAUNCHER = ROOT.parent / 'docs/libreoffice-demo.py'
user32 = C.WinDLL('user32', use_last_error=True)
enum = api(user32, 'EnumWindows', W.BOOL, P, P)
owner = api(user32, 'GetWindowThreadProcessId', D, P, P)
title = api(user32, 'GetWindowTextW', C.c_int, P, P, C.c_int)
visible = api(user32, 'IsWindowVisible', W.BOOL, P)
post = api(user32, 'PostMessageW', W.BOOL, P, D, P, P)


def windows(pid):
    found = []

    @C.WINFUNCTYPE(W.BOOL, P, P)
    def visit(hwnd, _):
        wp = D()
        owner(hwnd, C.byref(wp))
        if wp.value == pid and visible(hwnd):
            text = C.create_unicode_buffer(512)
            title(hwnd, text, len(text))
            if 'LPAC-demo.fodt' in text.value and 'LibreOffice Writer' in text.value:
                found.append(hwnd)
        return True

    check(enum(visit, None))
    return found


def main():
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--libreoffice', type=Path, required=True)
    args = parser.parse_args()
    app = args.libreoffice.resolve()
    proof = {}
    token, size, elevation = P(), D(), D()
    check(OpenToken(P(-1), 8, C.byref(token)))
    try:
        check(TokenInfo(token, 20, C.byref(elevation), C.sizeof(elevation), C.byref(size)))
        require(elevation.value == 0, 'Run this test without elevation')
        proof['host_elevated'] = elevation.value
    finally:
        CloseHandle(token)
    parent = Path(tempfile.gettempdir()).resolve()
    scratch = parent / ('sandy-lo-launcher-' + uuid.uuid4().hex + ' space')
    scratch.mkdir()
    evidence = ROOT / 'libreoffice-work'
    evidence.mkdir(exist_ok=True)
    paths = [scratch, parent, app, Path(os.environ['USERPROFILE']),
             Path(os.environ['SystemDrive'] + '/'), Path(os.environ['USERPROFILE']).parent]
    before = {p: dacl(p) for p in paths}
    environment = dict(os.environ)
    command = [sys.executable, str(LAUNCHER), '--scratch', str(scratch), '--libreoffice', str(app)]
    process, writer = None, None
    try:
        with (evidence / 'launcher-test.out').open('w', encoding='utf-8') as out:
            process = subprocess.Popen(command, stdout=out, stderr=out,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            deadline = time.monotonic() + 100
            hwnd = None
            while process.poll() is None and time.monotonic() < deadline:
                state_path = scratch / 'last-run.json'
                if state_path.exists():
                    state = json.loads(state_path.read_text(encoding='utf-8'))
                    log = Path(state.get('sandy_log', 'missing'))
                    if log.is_file():
                        matches = re.findall(r'LAUNCH: PID (\d+),', log.read_text(encoding='utf-8-sig'))
                        if matches:
                            writer = int(matches[-1])
                            found = windows(writer)
                            if found:
                                hwnd = found[0]
                                break
                time.sleep(0.1)
            require(hwnd is not None, f'Writer did not open; see {evidence / "launcher-test.out"}')
            proof['live'] = verify_writer(writer, state)
            proof['initialization_before_lpac'] = state['initialized_now']
            require(state['initialized_now'], 'Fresh scratch skipped initialization')
            require(not state['exit_codes'], 'Sandboxed launch needed a retry after initialization')
            config = tomllib.loads(Path(state['config']).read_text(encoding='utf-8'))
            require(Path(config['sandbox']['workdir']) == scratch / 'work', 'Wrong working directory')
            require(config['pipes'] == {state['pipe_source']: state['pipe_destination']}, 'Wrong pipe map')
            require(not any(k in config for k in ('compat', 'application', 'restart', 'directories')),
                    'Generated config uses proposed, unimplemented features')
            conflict = subprocess.run(command, capture_output=True, text=True, timeout=10,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            require(conflict.returncode != 0 and 'Cannot lock scratch' in conflict.stderr,
                    'Concurrent use of one scratch/profile was not refused')
            proof['same_scratch_rejected'] = True
            # Wait only for initial window painting, not for process cleanup.
            time.sleep(2)
            if importlib.util.find_spec('PIL'):
                from PIL import ImageGrab
                ImageGrab.grab(window=hwnd).save(evidence / 'launcher-writer.png')
            check(post(hwnd, 0x112, P(0xF060), None))  # WM_SYSCOMMAND / SC_CLOSE: title-bar Close.
            require(process.wait(timeout=30) == 0, 'Launcher failed after normal Writer close')
        first = json.loads((scratch / 'last-run.json').read_text())
        require(first['exit_codes'] == [0], 'Expected one successful sandbox launch')
        require(first['temp_removed'] and not Path(first['temp']).exists(), 'Temporary data survived')
        require((scratch / 'profile/user/registrymodifications.xcu').is_file(), 'Profile was deleted')
        require(all(dacl(p) == old for p, old in before.items()), 'DACL changed after first cleanup')
        proof['first_run'] = first
        marker_before = (scratch / 'initialized.json').read_bytes()
        # Relative input and default output verify the real working directory.
        result = subprocess.run(command + ['--', '--headless', '--convert-to', 'pdf', 'LPAC-demo.fodt'],
                                capture_output=True, text=True, timeout=70,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        require(result.returncode == 0, result.stdout + result.stderr)
        second = json.loads((scratch / 'last-run.json').read_text())
        require(not second['initialized_now'], 'Repeat launch initialized outside LPAC again')
        require(second['exit_codes'] == [0], 'Repeat launch requested a restart')
        require((scratch / 'initialized.json').read_bytes() == marker_before, 'Initialization marker changed')
        pdf = scratch / 'work/LPAC-demo.pdf'
        require(pdf.read_bytes().startswith(b'%PDF-'), 'Sandboxed PDF output missing')
        require(not Path(second['temp']).exists(), 'Second temporary directory survived')
        require(all(dacl(p) == old for p, old in before.items()), 'DACL changed after repeat cleanup')
        require(dict(os.environ) == environment, 'Host environment was modified')
        for record in (first, second):
            log = Path(record['sandy_log']).read_text(encoding='utf-8-sig')
            for payload in re.findall(r'PIPEHOOK: extracted hook DLL -> (.*?) \(\d+ bytes\)', log):
                require(not Path(payload).exists(), 'Hook DLL survived Sandy cleanup')
        # Changing a prepared runtime must fail before unsandboxed reinitialization.
        marker = json.loads(marker_before)
        marker['build'] = 'different-build'
        (scratch / 'initialized.json').write_text(json.dumps(marker), encoding='utf-8')
        rejected = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        require(rejected.returncode != 0 and 'Use a new scratch' in rejected.stderr,
                'Changed runtime was not refused')
        failed = json.loads((scratch / 'last-run.json').read_text())
        require(failed['phase'] == 'failed' and failed['temp_removed']
                and not Path(failed['temp']).exists(), 'Setup failure left temporary data')
        proof['changed_runtime_rejected_and_cleaned'] = True
        status = subprocess.check_output([str(SANDY), '--status'], text=True)
        require(proof['live']['token']['sid'] not in status, 'Test sandbox remains registered')
        proof.update(second_run=second, pdf_bytes=pdf.stat().st_size, dacls_unchanged=True,
                     environment_unchanged=True, status=status)
        (evidence / 'launcher-proof.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
        print('PASS: fresh initialization, visible LPAC Writer, exact pipe, file restrictions,')
        print('      scratch lock, working directory, repeat PDF export, temp and ACL cleanup.')
    finally:
        if process and process.poll() is None:
            # Kill only this test's launcher tree, then let Sandy recover its own state.
            subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                           capture_output=True, check=False)
            process.wait(timeout=15)
            subprocess.run([str(SANDY), '--cleanup'], check=True, capture_output=True)
        require(scratch.parent == parent and scratch.name.startswith('sandy-lo-launcher-'),
                'Unexpected test cleanup path')
        def writable_remove(function, path, _):
            os.chmod(path, stat.S_IWRITE)
            function(path)
        shutil.rmtree(scratch, onexc=writable_remove)


if __name__ == '__main__':
    main()

