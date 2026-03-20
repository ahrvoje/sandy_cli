"""
test_sneaky.py — Profile round-trip fidelity and scope interaction probe.

Part 1: Reads registry values for a named profile and validates every field
         matches expected values from the original TOML config.
Part 2: Tests effective permissions from overlapping .this + .deep grants.
"""
import sys
import os
import winreg

passed = 0
failed = 0

def check(label, condition):
    global passed, failed
    if condition:
        print(f"  [PASS] {label}")
        passed += 1
    else:
        print(f"  [FAIL] {label}")
        failed += 1

def read_reg_sz(hKey, name):
    try:
        val, _ = winreg.QueryValueEx(hKey, name)
        return str(val) if val else ""
    except FileNotFoundError:
        return ""

def read_reg_dword(hKey, name, default=0):
    try:
        val, _ = winreg.QueryValueEx(hKey, name)
        return int(val)
    except FileNotFoundError:
        return default

# ===================================================================
# Part 1: Profile Round-Trip Fidelity
# ===================================================================
def test_profile_roundtrip(profile_name, expected):
    """Verify that every config field in the registry matches expected values."""
    print(f"\n--- Profile Round-Trip: {profile_name} ---")
    key_path = f"Software\\Sandy\\Profiles\\{profile_name}"
    try:
        hKey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        print(f"  [FAIL] Profile key not found: {key_path}")
        global failed
        failed += 1
        return

    # Token mode
    check(f"token_mode = {expected['token_mode']}",
          read_reg_sz(hKey, "_token_mode") == expected['token_mode'])

    # Integrity
    if 'integrity' in expected:
        check(f"integrity = {expected['integrity']}",
              read_reg_sz(hKey, "_cfg_integrity") == expected['integrity'])

    # Strict
    check(f"strict = {expected['strict']}",
          read_reg_dword(hKey, "_strict") == expected['strict'])

    # Booleans
    for reg_name, exp_val, label in expected.get('booleans', []):
        actual = read_reg_dword(hKey, reg_name, -1)
        check(f"{label} = {exp_val}", actual == exp_val)

    # Strings
    for reg_name, exp_val, label in expected.get('strings', []):
        actual = read_reg_sz(hKey, reg_name)
        check(f"{label} = '{exp_val}'", actual == exp_val)

    # Stdin mode
    if 'stdin_mode' in expected:
        actual_stdin = read_reg_sz(hKey, "_stdin_mode")
        check(f"stdin_mode = '{expected['stdin_mode']}'",
              actual_stdin == expected['stdin_mode'])

    # Allow entries: count and scope tags
    # IMPORTANT: entries are written in sorted order by access level name,
    # not in TOML declaration order. We verify that the expected tags
    # appear in the correct sorted positions.
    allow_count = read_reg_dword(hKey, "_allow_count")
    check(f"allow_count = {expected['allow_count']}", allow_count == expected['allow_count'])

    for i, (exp_tag,) in enumerate(expected.get('allow_tags', [])):
        name = f"_allow_{i}"
        actual = read_reg_sz(hKey, name)
        check(f"allow[{i}] starts with '{exp_tag}'",
              actual.startswith(f"{exp_tag}|"))

    # Deny entries round-trip
    deny_count = read_reg_dword(hKey, "_deny_count")
    check(f"deny_count = {expected['deny_count']}", deny_count == expected['deny_count'])
    for i, (exp_tag,) in enumerate(expected.get('deny_tags', [])):
        name = f"_deny_{i}"
        actual = read_reg_sz(hKey, name)
        check(f"deny[{i}] starts with '{exp_tag}'",
              actual.startswith(f"{exp_tag}|"))

    # Registry keys round-trip
    reg_read_count = read_reg_dword(hKey, "_reg_read_count")
    check(f"reg_read_count = {expected.get('reg_read_count', 0)}",
          reg_read_count == expected.get('reg_read_count', 0))
    for i, exp in enumerate(expected.get('reg_read_entries', [])):
        actual = read_reg_sz(hKey, f"_reg_read_{i}")
        check(f"reg_read[{i}] = '{exp}'", actual == exp)

    reg_write_count = read_reg_dword(hKey, "_reg_write_count")
    check(f"reg_write_count = {expected.get('reg_write_count', 0)}",
          reg_write_count == expected.get('reg_write_count', 0))
    for i, exp in enumerate(expected.get('reg_write_entries', [])):
        actual = read_reg_sz(hKey, f"_reg_write_{i}")
        check(f"reg_write[{i}] = '{exp}'", actual == exp)

    # Env pass round-trip
    env_pass_count = read_reg_dword(hKey, "_env_pass_count")
    check(f"env_pass_count = {expected.get('env_pass_count', 0)}",
          env_pass_count == expected.get('env_pass_count', 0))
    for i, exp in enumerate(expected.get('env_pass_entries', [])):
        actual = read_reg_sz(hKey, f"_env_pass_{i}")
        check(f"env_pass[{i}] = '{exp}'", actual == exp)

    # Limits
    for reg_name, exp_val, label in expected.get('limits', []):
        actual = read_reg_dword(hKey, reg_name)
        check(f"{label} = {exp_val}", actual == exp_val)

    # SID must be non-empty
    sid = read_reg_sz(hKey, "_sid")
    check("SID is non-empty", len(sid) > 5 and sid.startswith("S-"))

    # Staging marker must be absent (fully committed)
    staging = read_reg_dword(hKey, "_staging", 0)
    check("_staging marker absent (committed)", staging == 0)

    winreg.CloseKey(hKey)

# ===================================================================
# Part 2: Scope Interaction (.this + .deep overlap)
# ===================================================================
def test_scope_interaction():
    """Test that .this and .deep grants on overlapping paths produce
    correct effective permissions."""
    print("\n--- Scope Interaction Tests ---")

    test_root = os.environ.get("SNEAKY_SCOPE_ROOT", "")
    if not test_root or not os.path.isdir(test_root):
        print("  [SKIP] SNEAKY_SCOPE_ROOT not set or missing")
        return

    stat_dir = os.path.join(test_root, "stat_only")
    deep_dir = os.path.join(test_root, "deep_read")
    child_file = os.path.join(deep_dir, "child.txt")
    stat_child = os.path.join(stat_dir, "child.txt")

    # .this stat on stat_dir: should be able to stat parent
    if os.path.isdir(stat_dir):
        try:
            attrs = os.stat(stat_dir)
            check("scope: can stat .this dir", attrs is not None)
        except PermissionError:
            check("scope: can stat .this dir", False)

        # Should NOT be able to read child (no deep grant)
        try:
            with open(stat_child, 'r') as f:
                f.read()
            check("scope: cannot read child of .this stat dir", False)
        except (PermissionError, OSError):
            check("scope: cannot read child of .this stat dir", True)

    # .deep read on deep_dir: should be able to read children
    if os.path.isdir(deep_dir) and os.path.isfile(child_file):
        try:
            with open(child_file, 'r') as f:
                content = f.read()
            check("scope: can read child of .deep dir", len(content) > 0)
        except (PermissionError, OSError):
            check("scope: can read child of .deep dir", False)


# ===================================================================
# Main
# ===================================================================
if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "scope"

    if mode == "rt_roundtrip":
        # Registry entries are sorted alphabetically by tag, NOT TOML order.
        # RT profile with 10 allow entries (no deny — deny ACEs fail at profile creation)
        # Sorted order: all.deep, execute.deep, read.deep, write.deep,
        #               append.this, create.this, delete.this, run.this, stat.this, touch.this
        test_profile_roundtrip("sneaky_rt", {
            'token_mode': 'restricted',
            'integrity': 'low',
            'strict': 1,
            'stdin_mode': 'NUL',
            'booleans': [
                ('_allow_named_pipes',  0, 'named_pipes'),
                ('_allow_desktop',      1, 'desktop'),
                ('_allow_clipboard_r',  1, 'clipboard_read'),
                ('_allow_clipboard_w',  0, 'clipboard_write'),
                ('_allow_child_procs',  1, 'child_processes'),
                ('_env_inherit',        1, 'env_inherit'),
            ],
            'allow_count': 10,
            'allow_tags': [
                ('all.deep',),
                ('execute.deep',),
                ('read.deep',),
                ('write.deep',),
                ('append.this',),
                ('create.this',),
                ('delete.this',),
                ('run.this',),
                ('stat.this',),
                ('touch.this',),
            ],
            'deny_count': 0,
            'deny_tags': [],
            'reg_read_count': 1,
            'reg_read_entries': ['HKCU\\Software\\Sandy\\Test'],
            'reg_write_count': 1,
            'reg_write_entries': ['HKCU\\Software\\Sandy\\Test'],
            'env_pass_count': 3,
            'env_pass_entries': ['PATH', 'TEMP', 'USERPROFILE'],
            'limits': [
                ('_timeout', 60, 'timeout'),
                ('_memory_limit_mb', 512, 'memory'),
                ('_max_processes', 10, 'processes'),
            ],
        })
    elif mode == "ac_roundtrip":
        # AC profile with 10 allow entries (no deny, no registry)
        # Sorted: all.deep, execute.deep, read.deep, write.deep,
        #         append.this, create.this, delete.this, run.this, stat.this, touch.this
        test_profile_roundtrip("sneaky_ac", {
            'token_mode': 'appcontainer',
            'integrity': 'low',
            'strict': 0,
            'stdin_mode': 'NUL',
            'booleans': [
                ('_allow_network',      0, 'network'),
                ('_allow_clipboard_r',  0, 'clipboard_read'),
                ('_allow_clipboard_w',  1, 'clipboard_write'),
                ('_allow_child_procs',  0, 'child_processes'),
                ('_env_inherit',        0, 'env_inherit'),
            ],
            'strings': [
                ('_lan_mode',           'off', 'lan_mode'),
            ],
            'allow_count': 10,
            'allow_tags': [
                ('all.deep',),
                ('execute.deep',),
                ('read.deep',),
                ('write.deep',),
                ('append.this',),
                ('create.this',),
                ('delete.this',),
                ('run.this',),
                ('stat.this',),
                ('touch.this',),
            ],
            'deny_count': 0,
            'deny_tags': [],
            'reg_read_count': 0,
            'reg_read_entries': [],
            'reg_write_count': 0,
            'reg_write_entries': [],
            'env_pass_count': 1,
            'env_pass_entries': ['TEMP'],
            'limits': [
                ('_timeout', 30, 'timeout'),
                ('_memory_limit_mb', 256, 'memory'),
                ('_max_processes', 5, 'processes'),
            ],
        })
    elif mode == "scope":
        test_scope_interaction()
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)

    print(f"\n  Totals: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
