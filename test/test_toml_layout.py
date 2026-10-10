"""Check fixture and emitted TOML layout without launching sandboxed processes."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent
SANDY = ROOT.parent / 'x64/Release/sandy.exe'
HEADER = re.compile(r'\s*\[([\w.]+)\]\s*(?:#.*)?')
PRIVILEGES = {'loopback', 'desktop', 'stdin', 'clipboard_read', 'clipboard_write',
              'child_processes'}


def check_layout(text, label):
    lines = text.splitlines()
    headers = [(i, HEADER.fullmatch(line).group(1))
               for i, line in enumerate(lines) if HEADER.fullmatch(line)]
    for n, (i, section) in enumerate(headers):
        end = headers[n + 1][0] if n + 1 < len(headers) else len(lines)
        assert any(line.strip() and not line.lstrip().startswith('#')
                   for line in lines[i + 1:end]), f'{label}: empty [{section}]'
        if n:
            previous = i - 1
            while previous >= 0 and (not lines[previous].strip()
                                    or lines[previous].lstrip().startswith('#')):
                previous -= 1
            blanks = sum(not line.strip() for line in lines[previous + 1:i])
            assert blanks == 1, f'{label}: {blanks} blank lines before [{section}]'
    return {section for _, section in headers}


def check_config(text, label):
    check_layout(text, label)
    config = tomllib.loads(text)
    assert set(config.get('privileges', {})) <= PRIVILEGES, f'{label}: obsolete privilege'
    caps = config.get('capabilities')
    if caps is not None:
        assert set(caps) == {'names'} and isinstance(caps['names'], list), label
        assert all(isinstance(name, str) for name in caps['names']), label
        assert config['sandbox']['token'] != 'restricted', label
    return config


def run(*args, env=None):
    result = subprocess.run([str(SANDY), *args], env=env, capture_output=True,
                            text=True, encoding='utf-8', timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def main():
    fixtures = sorted(ROOT.glob('*.toml')) + sorted(ROOT.parent.glob('sandy_config*.toml'))
    for path in fixtures:
        check_config(path.read_text(encoding='utf-8'), path.name)
    template = ROOT.parent / 'docs/libreoffice.toml'
    check_layout(template.read_text(encoding='utf-8'), template.name)

    with tempfile.TemporaryDirectory(prefix='sandy-toml-') as directory:
        path = Path(directory) / 'config.toml'
        for mode in ('container', 'restricted', 'lpac'):
            option = 'restricted' if mode == 'restricted' else 'container'
            text = run('--print-' + option + '-toml')
            if mode == 'lpac':
                text = text.replace("token = 'appcontainer'", "token = 'lpac'")
            check_config(text, mode + ' template')
            path.write_text(text, encoding='utf-8')
            resolved = run('--print-config', '-c', str(path))
            config = check_config(resolved, mode + ' resolved')
            assert 'allow' not in config and 'deny' not in config, 'Empty access tables emitted'
            path.write_text(resolved, encoding='utf-8')
            assert check_config(run('--print-config', '-c', str(path)), mode + ' round trip') == config

        for name in ('allow-deep', 'allow-this', 'deny-deep', 'deny-this'):
            (Path(directory) / name).mkdir()
        resolved = run('--print-config', '-c', str(ROOT / 'test_toml_layout.toml'),
                       env=dict(os.environ, SANDY_TOML_TEST_DIR=directory))
        check_config(resolved, 'all access scopes')
        assert {'allow.deep', 'allow.this', 'deny.deep', 'deny.this', 'registry'} <= check_layout(
            resolved, 'all access scopes'), 'Nonempty table omitted'
    print(f'PASS: {len(fixtures)} configs, LibreOffice template, AC/LPAC/RT output, all access scopes.')


if __name__ == '__main__':
    main()
