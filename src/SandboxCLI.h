// =========================================================================
// SandboxCLI.h — Help text and argument utilities
//
// Contains all CLI help/usage text and argument quoting/collecting helpers.
// Extracted from sandy.cpp for readability.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

// -----------------------------------------------------------------------
// Print usage help (full reference including TOML config example)
// -----------------------------------------------------------------------
inline void PrintUsage(const char* version)
{
    printf(
        "Sandy - Windows Sandbox Runner  v%s\n"
        "\n"
        "Usage:\n"
        "  sandy.exe -c <config.toml> [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-L] [-q] -x <executable> [args...]\n"
        "  sandy.exe -s \"<toml>\"      [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-L] [-q] -x <executable> [args...]\n"
        "  sandy.exe -p <profile>     [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-q] -x <executable> [args...]\n"
        "  sandy.exe -t <report>       -x <executable> [args...]\n"
        "  sandy.exe --create-profile <name> -c <config.toml>  (create persistent sandbox profile)\n"
        "  sandy.exe --delete-profile <name>                   (delete profile + revoke ACLs)\n"
        "  sandy.exe --profile-info <name>                     (show profile details)\n"
        "  sandy.exe --print-container-toml          (print default appcontainer config)\n"
        "  sandy.exe --print-restricted-toml         (print default restricted config)\n"
        "  sandy.exe --cleanup                       (restore stale state from crashed runs)\n"
        "  sandy.exe --status [--json]                (show active instances, stale state, and summary counts)\n"
        "  sandy.exe --explain <code>                 (decode exit code: Sandy, NTSTATUS, Win32)\n"
        "  sandy.exe --dry-run -c <config.toml> [-x <exec>]  (validate + show plan, no changes)\n"
        "  sandy.exe --print-config -c <config.toml>  (print resolved config)\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Path to TOML config file\n"
        "  -s, --string <toml>   Inline TOML config string (alternative to -c)\n"
        "  -l, --log <path>      Session log (config, output, exit code)\n"
        "  -a, --audit <path>    Audit log of denied resource access (requires Procmon + admin)\n"
        "  -d, --dump <path>     Crash dump output path (independent of -a)\n"
        "  -L, --log-stamp       Prepend YYYYMMDD_HHMMSS_uid_ to log/audit/dump filenames\n"
        "  -x, --exec <path>     Executable to run sandboxed (consumes remaining args)\n"
        "  -t, --trace <path>    Trace unsandboxed run for sandbox feasibility (requires Procmon + admin)\n"
        "  -p, --profile <name>  Run with a saved profile (mutually exclusive with -c/-s)\n"
        "  --create-profile <n>  Create a persistent sandbox profile from TOML config\n"
        "  --delete-profile <n>  Delete a saved profile and revoke its persistent ACLs\n"
        "  --profile-info <n>    Show saved profile details (type, SID, config, grants)\n"
        "  -q, --quiet           Suppress the config banner on stderr\n"
        "  --dry-run, --check    Validate config + show plan (no system changes)\n"
        "  --print-config        Print resolved config to stdout\n"
        "  --json                JSON output (with --status, includes summary counts)\n"
        "  --explain <code>      Decode exit code (Sandy, NTSTATUS, Win32)\n"
        "  -v, --version         Print version\n"
        "  -h, --help            Print this help text\n"
        "\n"
        "All flags must come before -x. Arguments after -x are forwarded to the child.\n"
        "\n"
        "Config reference:\n"
        "  Only [sandbox] token is always mandatory. All other sections/keys are optional\n"
        "  with safe defaults (deny-all / disabled / unlimited). Omitting a field never\n"
        "  grants more access.\n"
        "\n"
        "  [sandbox]                              (required)\n"
        "  token = 'appcontainer'                 # required: 'appcontainer' or 'restricted'\n"
        "  # integrity = 'low'                    # required (restricted only): 'low' or 'medium'\n"
        "  # workdir = 'inherit'                  # optional (default: 'inherit' = exe folder)\n"
        "\n"
        "  [allow]                                (optional, defaults to no grants)\n"
        "  peek    = []                           # list dir + stat only (NON-recursive, single dir)\n"
        "  read    = ['C:\\\\path']                 # read files, list dirs (recursive)\n"
        "  write   = []                           # create/modify files, no read (recursive)\n"
        "  execute = []                           # read + execute (recursive)\n"
        "  append  = []                           # append only, no overwrite, no read (recursive)\n"
        "  delete  = []                           # delete only (recursive)\n"
        "  all     = []                           # full access: read+write+exec+delete (recursive)\n"
        "  All keys optional (default: []).  Absolute paths only, must exist on disk.\n"
        "  Grants (except peek) are recursive: a directory grant applies to ALL descendants.\n"
        "\n"
        "  [deny]                                 (optional, defaults to no denies)\n"
        "  Same 6 keys as [allow] (no peek). Block access within a broader grant.\n"
        "  Pipeline sorts by path depth — most specific (deepest) path wins.\n"
        "\n"
        "  [privileges]                           (optional)\n"
        "  system_dirs     = true                 # default: true  (appcontainer only)\n"
        "  network         = false                # default: false (appcontainer only)\n"
        "  localhost       = false                # default: false (appcontainer only, admin)\n"
        "  lan             = false                # default: false (appcontainer only)\n"
        "  named_pipes     = false                # default: false (restricted only)\n"
        "  stdin           = false                # default: false (NUL). true=inherit, path=file\n"
        "  clipboard_read  = false                # default: false\n"
        "  clipboard_write = false                # default: false\n"
        "  child_processes = true                 # default: true\n"
        "\n"
        "  [registry]                             (restricted only, default: [])\n"
        "  read  = []                             # default: []\n"
        "  write = []                             # default: []\n"
        "\n"
        "  [environment]                          (optional)\n"
        "  inherit = false                        # default: false (filtered environment)\n"
        "  pass = []                              # default: [] (pass no variables)\n"
        "\n"
        "  [limit]                                (default: 0)\n"
        "  timeout   = 0                          # default: 0 (no timeout)\n"
        "  memory    = 0                          # default: 0 (no memory cap)\n"
        "  processes = 0                          # default: 0 (no process cap)\n"
        "\n"
        "  Minimal appcontainer config:\n"
        "    [sandbox]\n"
        "    token = 'appcontainer'\n"
        "    [allow]\n"
        "    all = ['C:\\\\path\\\\to\\\\folder']\n"
        "\n"
        "  Minimal restricted config:\n"
        "    [sandbox]\n"
        "    token = 'restricted'\n"
        "    integrity = 'low'\n"
        "    [allow]\n"
        "    read = ['C:\\\\path\\\\to\\\\folder']\n"
        "\n"
        "Wrong-mode flags are rejected (e.g. named_pipes in appcontainer, network in restricted).\n"
        "\n"
        "Logging (-l):\n"
        "  Logger starts early (before config parsing) — config warnings go to log.\n"
        "  Console passthrough: child inherits real console (TTY). Sandy does NOT\n"
        "  interpose on stdout/stderr. Use shell redirection for output capture:\n"
        "    sandy ... -x myapp > output.log 2>&1\n"
        "  Log file captures Sandy operational events (grants, timing, config, cleanup).\n"
        "  Log file uses unbuffered I/O with fsync — every write is on disk immediately.\n"
        "  If file exists and --log-stamp is not used, POSIX rotation applies (.1, .2, ...).\n"
        "  Use -L to prepend YYYYMMDD_HHMMSS_uid_ prefix for unique filenames.\n"
        "  Timestamps are local time with ISO 8601 UTC offset.\n"
        "  ACL failures include exact Win32 error code + message: FAILED (0x00000005: Access is denied).\n"
        "\n"
        "Audit (-a):\n"
        "  Captures resource denial events via Procmon (headless). Requires Procmon + admin.\n"
        "  Records file, registry, network, DLL, and process denials during child lifetime.\n"
        "  Outputs deduplicated post-mortem log with summary counts.\n"
        "\n"
        "Trace mode (-t):\n"
        "  Runs the process UNSANDBOXED under Procmon, analyzes resource usage,\n"
        "  and writes a feasibility report with a suggested TOML config.\n"
        "  Requires: Procmon on PATH + admin privileges.\n"
        "  Report includes: sandboxability verdict, mode recommendations,\n"
        "  required read/write paths, network/pipe/registry usage.\n"
        "\n"
        "Crash resilience:\n"
        "  Per-instance scheduled tasks (SandyCleanup_<uuid>) restore stale state at next logon.\n"
        "  Use --cleanup to manually restore stale state from crashed runs.\n"
        "  Ctrl+C/Break/close triggers cleanup before exit.\n"
        "  SEH handler catches fatal errors in sandy itself.\n"
        "\n"
        "Cleanup guarantees (on clean exit):\n"
        "  Guaranteed: file/registry ACE removal, AppContainer profile deletion,\n"
        "    loopback exemption removal, instance registry subkey deletion.\n"
        "  Permanent: parent registry keys (Software\\Sandy, Grants, WER) are never deleted.\n"
        "  Best-effort: stale scheduled task cleanup, desktop/WinSta ACL cleanup (may fail in\n"
        "    service/headless contexts — logged but not fatal).\n"
        "  Malformed persisted records are skipped and logged (never cause cleanup failures).\n"
        "  Desktop/WinSta cleanup removes only our SID's ACEs — never restores full snapshots.\n"
        "  --status summarizes active/stale Sandy state, but is not yet a full requested-vs-effective\n"
        "    policy report. Check logs for cleanup parse diagnostics and best-effort failures.\n"
        "\n"
        "Config hardening:\n"
        "  Max config file size: 1 MB. Max path length: 32768 chars. Max rules per section: 256.\n"
        "  Pre-launch token integrity validation (restricted mode): aborts if token IL\n"
        "    does not match configured value. Logged as TOKEN_VALIDATE: OK or FAILED.\n"
        "\n"
        "Mode trust boundaries:\n"
        "  AppContainer: strongest isolation (kernel namespace + SID). DENY ACEs have no effect\n"
        "    on AC SIDs (by OS design) — Sandy uses allow-mask reduction instead.\n"
        "  Restricted (low): shared namespace, low integrity + restricting SIDs. Real DENY ACEs.\n"
        "    Requires desktop/WinSta grants for interactive use. Named pipes configurable.\n"
        "  Restricted (medium): weakest isolation — medium integrity allows HKCU writes, UIPI\n"
        "    bypass, and scheduled task creation. Suitable only for trusted code.\n"
        "\n"
        "Multi-instance:\n"
        "  Each instance uses a unique per-instance SID (AppContainer: S-1-15-2-*,\n"
        "  Restricted Token: S-1-9-*), so concurrent instances do not interfere with\n"
        "  each other's file grants. Registry state is keyed by UUID. On exit, each\n"
        "  instance removes only its own ACEs. Use --status to see active instances.\n"
        "  Use --cleanup to clear stale state.\n"
        "\n"
        "Exit codes (POSIX convention — child codes 0-124 pass through unchanged):\n"
        "  0       Success (child exited 0, or info command succeeded)\n"
        "  1-124   Child's exit code (passed through with zero ambiguity)\n"
        "  125     Sandy internal/general error\n"
        "  126     Cannot execute (CreateProcess failed, permission denied)\n"
        "  127     Command not found (executable does not exist)\n"
        "  128     Configuration error (invalid TOML, wrong-mode keys)\n"
        "  129     Sandbox setup failed (token, SID, ACL, or stdin setup)\n"
        "  130     Timeout (child killed by watchdog)\n"
        "  131     Child crashed (NTSTATUS crash code detected)\n",
        version
    );
}

// -----------------------------------------------------------------------
// Print default TOML configs to stdout
// -----------------------------------------------------------------------
inline void PrintContainerToml()
{
    printf(
        "# Sandy AppContainer config — only [sandbox] token is required.\n"
        "# All other sections/keys are optional (defaults shown in comments).\n"
        "\n"
        "[sandbox]\n"
        "token = 'appcontainer'\n"
        "# workdir = 'inherit'            # default: 'inherit'\n"
        "\n"
        "[allow]                           # default: no grants (all keys default to [])\n"
        "# peek    = []\n"
        "# read    = []\n"
        "# write   = []\n"
        "# execute = []\n"
        "# append  = []\n"
        "# delete  = []\n"
        "# all     = []\n"
        "\n"
        "# [deny]                          # default: no denies\n"
        "\n"
        "# [privileges]                    # defaults shown\n"
        "# system_dirs     = true\n"
        "# network         = false\n"
        "# localhost       = false\n"
        "# lan             = false\n"
        "# stdin           = false\n"
        "# clipboard_read  = false\n"
        "# clipboard_write = false\n"
        "# child_processes = true\n"
        "\n"
        "# [environment]                   # defaults shown\n"
        "# inherit = false\n"
        "# pass    = []\n"
        "\n"
        "# [limit]                         # defaults shown\n"
        "# timeout   = 0\n"
        "# memory    = 0\n"
        "# processes = 0\n"
    );
}

inline void PrintRestrictedToml()
{
    printf(
        "# Sandy Restricted Token config — token + integrity are required.\n"
        "# All other sections/keys are optional (defaults shown in comments).\n"
        "\n"
        "[sandbox]\n"
        "token     = 'restricted'\n"
        "integrity = 'low'\n"
        "# workdir   = 'inherit'           # default: 'inherit'\n"
        "\n"
        "[allow]                           # default: no grants (all keys default to [])\n"
        "# peek    = []\n"
        "# read    = []\n"
        "# write   = []\n"
        "# execute = []\n"
        "# append  = []\n"
        "# delete  = []\n"
        "# all     = []\n"
        "\n"
        "# [deny]                          # default: no denies\n"
        "\n"
        "# [privileges]                    # defaults shown\n"
        "# named_pipes     = false\n"
        "# stdin           = false\n"
        "# clipboard_read  = false\n"
        "# clipboard_write = false\n"
        "# child_processes = true\n"
        "\n"
        "# [registry]                      # defaults shown\n"
        "# read  = []\n"
        "# write = []\n"
        "\n"
        "# [environment]                   # defaults shown\n"
        "# inherit = false\n"
        "# pass    = []\n"
        "\n"
        "# [limit]                         # defaults shown\n"
        "# timeout   = 0\n"
        "# memory    = 0\n"
        "# processes = 0\n"
    );
}

// -----------------------------------------------------------------------
// Argument quoting and collection
// -----------------------------------------------------------------------

// Quote a single argument per MSDN CommandLineToArgvW convention.
// Handles backslashes-before-quotes (2N+1 rule), empty args, and
// arguments containing spaces, tabs, or embedded double-quotes.
inline std::wstring QuoteArg(const std::wstring& arg)
{
    if (arg.empty())
        return L"\"\"";

    // Check if quoting is needed
    bool needsQuote = false;
    for (wchar_t c : arg) {
        if (c == L' ' || c == L'\t' || c == L'"') {
            needsQuote = true;
            break;
        }
    }
    if (!needsQuote)
        return arg;

    // MSDN-compliant quoting (CommandLineToArgvW parsing rules)
    std::wstring out = L"\"";
    for (size_t i = 0; i < arg.size(); ) {
        size_t numBS = 0;
        while (i < arg.size() && arg[i] == L'\\') { i++; numBS++; }

        if (i == arg.size()) {
            // Trailing backslashes: double them (closing quote follows)
            out.append(numBS * 2, L'\\');
            break;
        } else if (arg[i] == L'"') {
            // Backslashes before quote: double them + escape the quote
            out.append(numBS * 2 + 1, L'\\');
            out += L'"';
            i++;
        } else {
            // Regular character: output backslashes as-is
            out.append(numBS, L'\\');
            out += arg[i];
            i++;
        }
    }
    out += L'"';
    return out;
}

// Collect all remaining argv[start..argc-1] as forwarded args
inline std::wstring CollectArgs(int start, int argc, wchar_t* argv[])
{
    std::wstring args;
    for (int j = start; j < argc; j++) {
        if (!args.empty()) args += L" ";
        args += QuoteArg(argv[j]);
    }
    return args;
}

} // namespace Sandbox
