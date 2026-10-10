"""Launch LibreOffice in Sandy LPAC. Python 3.11+, Windows, standard library only.

Usage: py -3 docs/libreoffice-demo.py --scratch PATH --libreoffice APP_DIRECTORY
Append -- and LibreOffice arguments to replace the default Writer demo.

The first launch initializes a dedicated profile OUTSIDE the sandbox using
soffice.com and a generated document. Subsequent launches use soffice.bin inside
a fresh Sandy sandbox. The launcher owns application data; Sandy owns its token,
ACL grants, injected hook and recovery records. See libreoffice.html for details.
"""
import argparse
from contextlib import contextmanager
import csv
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
DOCUMENT = '''<?xml version="1.0" encoding="UTF-8"?>
<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
 office:mimetype="application/vnd.oasis.opendocument.text" office:version="1.3">
<office:body><office:text>
<text:h text:outline-level="1">LibreOffice in Sandy LPAC</text:h>
<text:p>This Writer process uses a Least Privileged AppContainer.</text:p>
<text:p>The selected scratch folder holds its profile, working documents,
application data, temporary files, configuration and logs.</text:p>
<text:p>Sandy intercepts the normal LibreOffice named pipe and maps it to LOCAL.</text:p>
<text:p>The application files are read-only. Network, clipboard and child
processes are disabled. Close Writer to finish sandbox and temporary-file cleanup.</text:p>
</office:text></office:body></office:document>
'''

kernel = ctypes.WinDLL('kernel32', use_last_error=True)
create_file = kernel.CreateFileW
create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
create_file.restype = wintypes.HANDLE
close_handle = kernel.CloseHandle
close_handle.argtypes = [wintypes.HANDLE]
close_handle.restype = wintypes.BOOL
INVALID_HANDLE = ctypes.c_void_p(-1).value


@contextmanager
def scratch_lock(scratch):
    """Exclusive file handle, also held by our children if the launcher dies."""
    handle = create_file(str(scratch / '.launcher.lock'), 0x80000000, 0, None, 4, 0, None)
    if handle == INVALID_HANDLE:
        raise OSError('Cannot lock scratch folder; another launch may still be using it.')
    try:
        os.set_handle_inheritable(handle, True)
        startup = subprocess.STARTUPINFO()
        startup.lpAttributeList = {'handle_list': [handle]}
        yield startup
    finally:
        close_handle(handle)


def directory_listings(paths):
    """List ancestor objects we can grant without elevation; never a drive root.

    GetLongPathNameW can inspect ancestors. LibreOffice tolerates failures on
    protected ancestors such as C:\\Users. Do not grant a whole subtree here.
    """
    candidates = {p for path in paths for p in path.parents if p != Path(p.anchor)}
    result = []
    for path in sorted(candidates):
        # READ_CONTROL | WRITE_DAC, sharing all, OPEN_EXISTING, BACKUP_SEMANTICS.
        handle = create_file(str(path), 0x60000, 7, None, 3, 0x02000000, None)
        if handle != INVALID_HANDLE:
            close_handle(handle)
            result.append(str(path))
    return result


def pipe_mapping(profile_url):
    whoami = Path(os.environ['SystemRoot']) / 'System32' / 'whoami.exe'
    row = subprocess.check_output([str(whoami), '/user', '/fo', 'csv', '/nh'],
                                  text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    sid = next(csv.reader(row.splitlines()))[1]
    if not sid.startswith('S-1-5-'):
        raise ValueError('Cannot determine the Windows user SID.')
    # LibreOffice uses UTF-16LE and formats each MD5 byte WITHOUT zero padding.
    digest = hashlib.md5(profile_url.encode('utf-16le')).digest()
    suffix = ''.join(format(byte, 'x') for byte in digest)
    source = '\\\\.\\pipe\\OSL_PIPE_' + sid + '_SingleOfficeIPC_' + suffix
    return source, source.replace('\\pipe\\', '\\pipe\\LOCAL\\', 1)


def finish_profile_setup(profile):
    """Suppress first-GUI welcome/tip dialogs after successful native warm-up."""
    path = profile / 'user/registrymodifications.xcu'
    oor = 'http://openoffice.org/2001/registry'
    ET.register_namespace('oor', oor)
    ET.register_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
    tree = ET.parse(path)
    root = tree.getroot()
    root.set('xmlns:xs', 'http://www.w3.org/2001/XMLSchema')
    for location, name in (('/org.openoffice.Setup/Product', 'WhatsNew'),
                           ('/org.openoffice.Office.Common/Misc', 'ShowTipOfTheDay')):
        matches = [prop for item in root.findall('item')
                   if item.get('{' + oor + '}path') == location
                   for prop in item.findall('prop') if prop.get('{' + oor + '}name') == name]
        if not matches:
            item = ET.SubElement(root, 'item', {'{' + oor + '}path': location})
            matches = [ET.SubElement(item, 'prop', {'{' + oor + '}name': name,
                                                   '{' + oor + '}op': 'fuse'})]
        for prop in matches:
            prop.clear()
            prop.set('{' + oor + '}name', name)
            prop.set('{' + oor + '}op', 'fuse')
            ET.SubElement(prop, 'value').text = 'false'
    tree.write(path, encoding='utf-8', xml_declaration=True)


def write_json(path, value):
    """Publish complete metadata for readers in a second terminal."""
    staging = path.with_suffix('.new')
    staging.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    staging.replace(path)


def remove_temp(path, parent):
    """Delete only our UUID directory; never follow a replaced directory junction."""
    if path.parent != parent or len(path.name) != 32 or path.resolve() != path:
        raise ValueError(f'Refusing unexpected temporary path: {path}')
    int(path.name, 16)
    # Python 3.11+ rmtree does not descend into Windows directory junctions.
    shutil.rmtree(path)


def launch(args):
    scratch = args.scratch.resolve()
    app = (args.libreoffice or scratch / 'app').resolve()
    sandy = args.sandy.resolve()
    for file in (sandy, app / 'program/soffice.bin', app / 'program/soffice.com',
                 app / 'program/version.ini'):
        if not file.is_file():
            raise ValueError(f'Required file is missing: {file}')
    if '%' in str(scratch) or '%' in str(app):
        raise ValueError('Scratch and runtime paths cannot contain literal % characters (Sandy path expansion).')
    office_args = args.office_args
    if office_args[:1] == ['--']:
        office_args = office_args[1:]
    if any(arg.lower().startswith('-env:') for arg in office_args):
        raise ValueError('The launcher owns bootstrap variables; do not pass -env: arguments.')
    scratch.mkdir(parents=True, exist_ok=True)
    with scratch_lock(scratch) as startup:
        profile, work = scratch / 'profile', scratch / 'work'
        # Writable data must never contain the executable or launcher controls.
        if any(app.is_relative_to(p) or p.is_relative_to(app) for p in (profile, work, scratch / 'temp')):
            raise ValueError('The runtime must be separate from profile, work and temp folders.')
        home = profile / 'home'
        roaming, local = profile / 'appdata/roaming', profile / 'appdata/local'
        run_id = uuid.uuid4().hex
        run = scratch / 'runs' / run_id
        temp_parent = scratch / 'temp'
        temp = temp_parent / run_id
        state = None
        temp_owned = False
        try:
            for path in (profile, work, home, roaming, local, run):
                if path.resolve() != path:
                    raise ValueError(f'Data directories must not redirect outside their expected path: {path}')
                path.mkdir(parents=True, exist_ok=True)
            if temp.resolve() != temp:
                raise ValueError(f'Temporary path redirects elsewhere: {temp}')
            temp.parent.mkdir(parents=True, exist_ok=True)
            temp.mkdir()
            temp_owned = True
            profile_url = profile.as_uri()
            env = os.environ.copy()
            env.update(TEMP=str(temp), TMP=str(temp), HOME=str(home), USERPROFILE=str(home),
                       HOMEDRIVE=home.drive, HOMEPATH=str(home)[len(home.drive):],
                       APPDATA=str(roaming), LOCALAPPDATA=str(local),
                       SAL_DISABLESKIA='1', SAL_DISABLE_OPENCL='1')
            # Host Python overrides and this OpenCL override must not affect warm-up.
            for name in ('PYTHONHOME', 'PYTHONPATH', 'SC_FORCE_CALCULATION'):
                env.pop(name, None)
            source, destination = pipe_mapping(profile_url)
            values = {'@APP@': str(app), '@WORK@': str(work),
                      '@DATA@': [str(profile), str(work), str(temp)],
                      '@ANCESTORS@': directory_listings((app, profile, work, temp)),
                      '@SOURCE@': source, '@DESTINATION@': destination}
            config = HERE.joinpath('libreoffice.toml').read_text(encoding='utf-8')
            for key, value in values.items():
                config = config.replace(key, json.dumps(value, ensure_ascii=False))
            config_path = run / 'libreoffice.toml'
            config_path.write_text(config, encoding='utf-8')
            document = work / 'LPAC-demo.fodt'
            if not document.exists():
                document.write_text(DOCUMENT, encoding='utf-8')
            state = {'scratch': str(scratch), 'runtime': str(app), 'profile_url': profile_url,
                     'work': str(work), 'temp': str(temp), 'config': str(config_path),
                     'logs': str(run), 'pipe_source': source, 'pipe_destination': destination,
                     'initialized_now': False, 'exit_codes': [], 'phase': 'preparing'}
            state_path = scratch / 'last-run.json'
            output_path = run / 'libreoffice.log'

            def report(message):
                print(message, flush=True)
                with (run / 'launcher.log').open('a', encoding='utf-8') as log:
                    log.write(message + '\n')

            def execute(command, phase, output):
                report(subprocess.list2cmdline([str(p) for p in command]))
                with output.open('ab') as log:
                    process = subprocess.Popen(command, cwd=work, env=env, stdout=log, stderr=log,
                                               startupinfo=startup, close_fds=True,
                                               creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                    try:
                        state.update(phase=phase, pid=process.pid)
                        write_json(state_path, state)
                        return process.wait()
                    except BaseException:
                        # Never remove temp while our child is still using it,
                        # including when publishing run metadata fails.
                        try:
                            if process.poll() is None:
                                process.send_signal(signal.CTRL_BREAK_EVENT)
                        finally:
                            process.wait()
                        raise

            report(f'Scratch: {scratch}\nWorking folder: {work}\nConfig: {config_path}\nLogs: {run}')
            write_json(state_path, state)
            marker = scratch / 'initialized.json'
            identity = {'runtime': str(app), 'profile_url': profile_url,
                        'build': hashlib.sha256((app / 'program/version.ini').read_bytes()).hexdigest()}
            if marker.exists():
                if json.loads(marker.read_text(encoding='utf-8')) != identity:
                    raise ValueError('Runtime or profile changed. Use a new scratch folder for initialization.')
                if not (profile / 'user/registrymodifications.xcu').is_file():
                    raise ValueError('Initialized profile is missing. Use a new scratch folder.')
                report('Reusing the initialized LibreOffice profile.')
            else:
                report('Initializing outside LPAC with LibreOffice\'s normal launcher (no user document).')
                seed = temp / 'initialize.fodt'
                seed.write_text(DOCUMENT, encoding='utf-8')
                command = [app / 'program/soffice.com', '-env:UserInstallation=' + profile_url,
                           '--headless', '--norestore', '--convert-to', 'pdf', '--outdir', temp, seed]
                code = execute(command, 'initializing', run / 'initialize.log')
                pdf = temp / 'initialize.pdf'
                if code != 0 or not pdf.is_file() or not pdf.read_bytes().startswith(b'%PDF-'):
                    raise RuntimeError(f'LibreOffice initialization failed (exit {code}); see {run / "initialize.log"}')
                finish_profile_setup(profile)
                write_json(marker, identity)
                state['initialized_now'] = True
                report('Initialization completed; starting the application in LPAC.')
            command_args = office_args or ['--writer', str(document)]
            for attempt in range(3):
                log_path = run / f'sandy-{attempt}.log'
                state['sandy_log'] = str(log_path)
                command = [sandy, '-c', config_path, '-l', log_path, '-x', app / 'program/soffice.bin',
                           '-env:UserInstallation=' + profile_url, '--norestore', *command_args]
                code = execute(command, 'sandboxed', output_path)
                state['exit_codes'].append(code)
                write_json(state_path, state)
                if code != 81:
                    break
                report('LibreOffice requested restart 81; Sandy exited after cleanup. Retrying under LPAC.')
            state.update(phase='finished', exit_code=code)
            report(f'Sandy exit: {code}')
            return code
        except BaseException:
            if state is not None:
                state['phase'] = 'failed'
            raise
        finally:
            if temp_owned:
                remove_temp(temp, temp_parent)
            if state is not None:
                state['temp_removed'] = True
                write_json(run / 'result.json', state)
                write_json(state_path, state)
                report('Temporary folder removed. Profile, working documents, configuration and logs retained.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--scratch', required=True, type=Path, help='User-owned folder for all demo data')
    parser.add_argument('--libreoffice', type=Path, help='Extracted runtime root (default: SCRATCH/app)')
    parser.add_argument('--sandy', type=Path, default=HERE.parent / 'x64/Release/sandy.exe', help='Sandy executable')
    parser.add_argument('office_args', nargs=argparse.REMAINDER, help='After --, arguments for sandboxed soffice.bin')
    args = parser.parse_args()
    try:
        return launch(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    raise SystemExit(main())

