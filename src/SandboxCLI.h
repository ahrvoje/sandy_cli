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
        "  sandy.exe -p <report>       -x <executable> [args...]\n"
        "  sandy.exe --print-container-toml          (print default appcontainer config)\n"
        "  sandy.exe --print-restricted-toml         (print default restricted config)\n"
        "  sandy.exe --cleanup                       (restore stale state from crashed runs)\n"
        "  sandy.exe --status [--json]                (show active instances and stale state)\n"
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
        "  -p, --profile <path>  Profile unsandboxed run for sandbox feasibility (requires Procmon + admin)\n"
        "  -q, --quiet           Suppress the config banner on stderr\n"
        "  --dry-run, --check    Validate config + show plan (no system changes)\n"
        "  --print-config        Print resolved config to stdout\n"
        "  --json                JSON output (with --status)\n"
        "  --explain <code>      Decode exit code (Sandy, NTSTATUS, Win32)\n"
        "  -v, --version         Print version\n"
        "  -h, --help            Print this help text\n"
        "\n"
        "All flags must come before -x. Arguments after -x are forwarded to the child.\n"
        "\n"
        "Config reference (all configs must include [sandbox]):\n"
        "\n"
        "  [sandbox]                              (required)\n"
        "  token = 'appcontainer'                 # required: 'appcontainer' or 'restricted'\n"
        "  # integrity = 'low'                    # required (restricted only): 'low' or 'medium'\n"
        "  workdir = 'inherit'                    # required: absolute path or 'inherit' (exe folder)\n"
        "\n"
        "  [allow]                                (required, both modes)\n"
        "  read    = ['C:\\\\path']                 # read files, list dirs\n"
        "  write   = []                           # create/modify files (no read)\n"
        "  execute = []                           # read + execute\n"
        "  append  = []                           # append only (no overwrite, no read)\n"
        "  delete  = []                           # delete only\n"
        "  all     = []                           # full access (read+write+exec+delete)\n"
        "  All 6 keys required. Use [] for no grants. Absolute paths only.\n"
        "  Grants are recursive: a directory grant applies to ALL descendants.\n"
        "\n"
        "  [deny]                                 (required, both modes)\n"
        "  Same 6 keys as [allow]. Use to block specific paths within a broader grant.\n"
        "  Deny ALWAYS overrides allow: if a path is in both, deny wins.\n"
        "  Deny is recursive: applies to the path and all its descendants.\n"
        "  Note: deny.write does NOT block delete (DELETE is a separate permission).\n"
        "  All 6 keys required. Use [] for no denials.\n"
        "\n"
        "  [privileges]                           (required, all keys mandatory per mode)\n"
        "  system_dirs     = true                 # required (appcontainer)\n"
        "  network         = true                 # required (appcontainer)\n"
        "  localhost       = true                 # required (appcontainer, admin)\n"
        "  lan             = true                 # required (appcontainer)\n"
        "  named_pipes     = true                 # required (restricted)\n"
        "  stdin           = true                 # required (both)\n"
        "  clipboard_read  = true                 # required (both)\n"
        "  clipboard_write = true                 # required (both)\n"
        "  child_processes = true                 # required (both)\n"
        "\n"
        "  [registry]                             (required, restricted only)\n"
        "  read  = ['HKCU\\\\Software\\\\MyApp']\n"
        "  write = []\n"
        "  Both keys required. Use [] for no grants.\n"
        "\n"
        "  [environment]                          (required)\n"
        "  inherit = true                         # required: true or false\n"
        "  pass = ['PATH', 'USERPROFILE']         # required: [] or list of var names\n"
        "\n"
        "  [limit]                                (required, both modes)\n"
        "  timeout   = 0                          # 0 = no timeout, positive = seconds\n"
        "  memory    = 0                          # 0 = no cap, positive = MB\n"
        "  processes = 0                          # 0 = no cap, positive = max processes\n"
        "  All 3 keys required. Use 0 for unlimited.\n"
        "\n"
        "Mode comparison:          AppContainer          Restricted Low        Restricted Medium\n"
        "  Integrity level         Low (fixed)           Low (fixed)           Medium (fixed)\n"
        "  Object namespace        isolated (fixed)      shared (fixed)        shared (fixed)\n"
        "  Elevation               blocked               blocked               blocked\n"
        "  Privilege stripping     all stripped (fixed)  all except SeChange   all except SeChange\n"
        "  Isolation layers        2: SID+namespace      2: SIDs+integrity     1: SIDs only\n"
        "  Named pipes             blocked               configurable          configurable\n"
        "  Network                 configurable          allowed               allowed\n"
        "  System dir reads        configurable          allowed               allowed\n"
        "  System dir writes       blocked               blocked               blocked\n"
        "  User profile reads      configurable          allowed               allowed\n"
        "  User profile writes     configurable          configurable          allowed\n"
        "  Registry reads          private hive          allowed               allowed\n"
        "  Registry HKCU writes    blocked               blocked               allowed\n"
        "  Registry HKLM writes    blocked               blocked               blocked\n"
        "  DLL/API set resolve     allowed               may break apps        allowed\n"
        "  COM/RPC servers         blocked               allowed               allowed\n"
        "  Scheduled tasks         blocked               blocked               allowed\n"
        "  Window messages (UIPI)  blocked               blocked               allowed\n"
        "  Clipboard               configurable          configurable          configurable\n"
        "  Child processes         configurable          configurable          configurable\n"
        "  Stdin                   configurable          configurable          configurable\n"
        "  Environment             configurable          configurable          configurable\n"
        "  File/folder grants      configurable          configurable          configurable\n"
        "  Resource limits         configurable          configurable          configurable\n"
        "\n"
        "Use appcontainer for network isolation. Use restricted for named pipes/COM.\n"
        "Wrong-mode flags are rejected (e.g. named_pipes in appcontainer, network in restricted).\n"
        "\n"
        "Logging (-l):\n"
        "  Session log captures config, child output, exit code, and cleanup events.\n"
        "  Log file uses unbuffered I/O with fsync — every write is on disk immediately.\n"
        "  If file exists and --log-stamp is not used, POSIX rotation applies (.1, .2, ...).\n"
        "  Use -L to prepend YYYYMMDD_HHMMSS_uid_ prefix for unique filenames.\n"
        "  Timestamps are local time with ISO 8601 UTC offset.\n"
        "\n"
        "Audit (-a):\n"
        "  Captures resource denial events via Procmon (headless). Requires Procmon + admin.\n"
        "  Records file, registry, network, DLL, and process denials during child lifetime.\n"
        "  Outputs deduplicated post-mortem log with summary counts.\n"
        "\n"
        "Profile mode (-p):\n"
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
        "  129     Sandbox setup failed (token, SID, ACL, or pipe creation)\n"
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
        "[sandbox]\n"
        "token = 'appcontainer'\n"
        "workdir = 'inherit'\n"
        "\n"
        "[allow]\n"
        "read    = []\n"
        "write   = []\n"
        "execute = []\n"
        "append  = []\n"
        "delete  = []\n"
        "all     = []\n"
        "\n"
        "[deny]\n"
        "read    = []\n"
        "write   = []\n"
        "execute = []\n"
        "append  = []\n"
        "delete  = []\n"
        "all     = []\n"
        "\n"
        "[privileges]\n"
        "system_dirs     = true\n"
        "network         = false\n"
        "localhost       = false\n"
        "lan             = false\n"
        "stdin           = false\n"
        "clipboard_read  = false\n"
        "clipboard_write = false\n"
        "child_processes = true\n"
        "\n"
        "[environment]\n"
        "inherit = true\n"
        "pass    = []\n"
        "\n"
        "[limit]\n"
        "timeout   = 0\n"
        "memory    = 0\n"
        "processes = 0\n"
    );
}

inline void PrintRestrictedToml()
{
    printf(
        "[sandbox]\n"
        "token     = 'restricted'\n"
        "integrity = 'low'\n"
        "workdir   = 'inherit'\n"
        "\n"
        "[allow]\n"
        "read    = []\n"
        "write   = []\n"
        "execute = []\n"
        "append  = []\n"
        "delete  = []\n"
        "all     = []\n"
        "\n"
        "[deny]\n"
        "read    = []\n"
        "write   = []\n"
        "execute = []\n"
        "append  = []\n"
        "delete  = []\n"
        "all     = []\n"
        "\n"
        "[privileges]\n"
        "named_pipes     = false\n"
        "stdin           = false\n"
        "clipboard_read  = false\n"
        "clipboard_write = false\n"
        "child_processes = true\n"
        "\n"
        "[registry]\n"
        "read  = []\n"
        "write = []\n"
        "\n"
        "[environment]\n"
        "inherit = true\n"
        "pass    = []\n"
        "\n"
        "[limit]\n"
        "timeout   = 0\n"
        "memory    = 0\n"
        "processes = 0\n"
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
