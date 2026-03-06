// sandy.cpp — Sandboxed Executable Runner (CLI)
// Launches any executable inside a Windows sandbox (AppContainer or Restricted Token).
// Usage: sandy.exe -c <config.toml> -x <executable> [args...]
//        sandy.exe -s "<toml string>" -x <executable> [args...]

#include "framework.h"
#include "Sandbox.h"

constexpr const char* kVersion = "0.97";
using namespace Sandbox;

// -----------------------------------------------------------------------
// Print usage help (full reference including TOML config example)
// -----------------------------------------------------------------------
static void PrintUsage()
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
        kVersion
    );
}

// -----------------------------------------------------------------------
// Print default TOML configs to stdout
// -----------------------------------------------------------------------
static void PrintContainerToml()
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

static void PrintRestrictedToml()
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

// Helper: quote a single argument per MSDN CommandLineToArgvW convention.
// Handles backslashes-before-quotes (2N+1 rule), empty args, and
// arguments containing spaces, tabs, or embedded double-quotes.
static std::wstring QuoteArg(const std::wstring& arg)
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

// Helper: collect all remaining argv[start..argc-1] as forwarded args
static std::wstring CollectArgs(int start, int argc, wchar_t* argv[])
{
    std::wstring args;
    for (int j = start; j < argc; j++) {
        if (!args.empty()) args += L" ";
        args += QuoteArg(argv[j]);
    }
    return args;
}

// -----------------------------------------------------------------------
// Console control handler — cleanup on Ctrl+C, Ctrl+Break, window close
// -----------------------------------------------------------------------
static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    const wchar_t* name = ctrlType == CTRL_C_EVENT ? L"CTRL_C" :
                           ctrlType == CTRL_CLOSE_EVENT ? L"CTRL_CLOSE" :
                           ctrlType == CTRL_BREAK_EVENT ? L"CTRL_BREAK" :
                           ctrlType == CTRL_LOGOFF_EVENT ? L"CTRL_LOGOFF" :
                           ctrlType == CTRL_SHUTDOWN_EVENT ? L"CTRL_SHUTDOWN" : L"UNKNOWN";
    wchar_t msg[128]; swprintf(msg, 128, L"SIGNAL: %s (code=%lu)", name, ctrlType);
    Sandbox::g_logger.Log(msg);
    Sandbox::CleanupSandbox();
    return FALSE;  // let default handler terminate the process
}

// -----------------------------------------------------------------------
// Enumerate Sandy AppContainer profiles from Windows Mappings registry.
// Returns a vector of Sandy_ moniker names.
// -----------------------------------------------------------------------
static std::vector<std::wstring> EnumSandyProfiles()
{
    std::vector<std::wstring> profiles;
    HKEY hMap = nullptr;
    const wchar_t* mapKey = L"Software\\Classes\\Local Settings\\Software\\"
        L"Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings";
    if (RegOpenKeyExW(HKEY_CURRENT_USER, mapKey, 0,
            KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hMap) != ERROR_SUCCESS)
        return profiles;

    DWORD subCount = 0;
    RegQueryInfoKeyW(hMap, nullptr, nullptr, nullptr, &subCount,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    for (DWORD i = 0; i < subCount; i++) {
        wchar_t sid[256];
        DWORD sidLen = 256;
        if (RegEnumKeyExW(hMap, i, sid, &sidLen,
                nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            continue;
        HKEY hSub = nullptr;
        if (RegOpenKeyExW(hMap, sid, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
            continue;
        wchar_t moniker[256] = {};
        DWORD mSize = sizeof(moniker);
        if (RegQueryValueExW(hSub, L"Moniker", nullptr, nullptr,
                reinterpret_cast<BYTE*>(moniker), &mSize) == ERROR_SUCCESS) {
            if (_wcsnicmp(moniker, L"Sandy_", 6) == 0)
                profiles.push_back(moniker);
        }
        RegCloseKey(hSub);
    }
    RegCloseKey(hMap);
    return profiles;
}

// -----------------------------------------------------------------------
// Show active instances and stale state (--status [--json])
// -----------------------------------------------------------------------
static int HandleStatus(bool json = false)
{
    // --- Collect data ---
    struct Inst { std::wstring uuid; DWORD pid; bool alive; };
    struct Wer  { DWORD pid; std::wstring exe; bool alive; };
    std::vector<Inst> insts;
    std::vector<Wer>  wers;
    std::vector<std::wstring> tasks;
    std::vector<std::wstring> profiles;

    // Grants registry
    HKEY hGrants = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, Sandbox::kGrantsParentKey, 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hGrants) == ERROR_SUCCESS) {
        DWORD n = 0;
        RegQueryInfoKeyW(hGrants, 0, 0, 0, &n, 0, 0, 0, 0, 0, 0, 0);
        for (DWORD i = 0; i < n; i++) {
            wchar_t nm[128]; DWORD nl = 128;
            if (RegEnumKeyExW(hGrants, i, nm, &nl, 0, 0, 0, 0) != ERROR_SUCCESS) continue;
            std::wstring fk = std::wstring(Sandbox::kGrantsParentKey) + L"\\" + nm;
            HKEY hS = nullptr; DWORD pid = 0; ULONGLONG ct = 0;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fk.c_str(), 0, KEY_READ, &hS) == ERROR_SUCCESS) {
                Sandbox::ReadPidAndCtime(hS, pid, ct); RegCloseKey(hS);
            }
            insts.push_back({ nm, pid, Sandbox::IsProcessAlive(pid, ct) });
        }
        RegCloseKey(hGrants);
    }

    // WER registry
    HKEY hWER = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, Sandbox::kWERParentKey, 0,
                      KEY_READ, &hWER) == ERROR_SUCCESS) {
        DWORD vc = 0;
        RegQueryInfoKeyW(hWER, 0, 0, 0, 0, 0, 0, &vc, 0, 0, 0, 0);
        for (DWORD i = 0; i < vc; i++) {
            wchar_t nm[64]; DWORD nl = 64, ds = 0;
            if (RegEnumValueW(hWER, i, nm, &nl, 0, 0, 0, &ds) != ERROR_SUCCESS) continue;
            DWORD pid = (DWORD)_wtoi(nm);
            std::wstring exe(ds / sizeof(wchar_t), L'\0');
            nl = 64;
            RegEnumValueW(hWER, i, nm, &nl, 0, 0, (BYTE*)&exe[0], &ds);
            while (!exe.empty() && exe.back() == L'\0') exe.pop_back();
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            bool alive = (h != nullptr); if (h) CloseHandle(h);
            wers.push_back({ pid, exe, alive });
        }
        RegCloseKey(hWER);
    }

    // Scheduled tasks
    {
        std::wstring cmd = L"schtasks.exe /Query /FO CSV /NH";
        HANDLE hR = 0, hW = 0;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), 0, TRUE };
        if (CreatePipe(&hR, &hW, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.hStdOutput = hW; si.hStdError = hW;
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            if (CreateProcessW(0, (LPWSTR)cmd.c_str(), 0, 0, TRUE,
                               CREATE_NO_WINDOW, 0, 0, &si, &pi)) {
                CloseHandle(hW);
                std::string out; char buf[4096]; DWORD br;
                while (ReadFile(hR, buf, sizeof(buf), &br, 0) && br > 0) out.append(buf, br);
                CloseHandle(hR);
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                std::istringstream ss(out); std::string line;
                while (std::getline(ss, line)) {
                    std::wstring wl(line.begin(), line.end());
                    if (wl.find(Sandbox::kCleanupTaskPrefix) == std::wstring::npos) continue;
                    auto q1 = wl.find(L'"'), q2 = wl.find(L'"', q1 + 1);
                    if (q1 != std::wstring::npos && q2 != std::wstring::npos) {
                        auto tp = wl.substr(q1 + 1, q2 - q1 - 1);
                        auto bs = tp.find_last_of(L'\\');
                        tasks.push_back(bs != std::wstring::npos ? tp.substr(bs + 1) : tp);
                    }
                }
            } else { CloseHandle(hR); CloseHandle(hW); }
        }
    }

    profiles = EnumSandyProfiles();

    // --- Output ---
    if (json) {
        auto esc = [](const std::wstring& s) {
            std::string r; for (wchar_t c : s) {
                if (c == L'"') r += "\\\""; else if (c == L'\\') r += "\\\\";
                else if (c < 128) r += (char)c;
                else { char b[8]; snprintf(b, 8, "\\u%04X", (unsigned)c); r += b; }
            } return r;
        };
        printf("{\"instances\":[");
        for (size_t i = 0; i < insts.size(); i++)
            printf("%s{\"uuid\":\"%s\",\"pid\":%lu,\"status\":\"%s\"}",
                   i ? "," : "", esc(insts[i].uuid).c_str(),
                   insts[i].pid, insts[i].alive ? "active" : "stale");
        printf("],\"wer\":[");
        for (size_t i = 0; i < wers.size(); i++)
            printf("%s{\"pid\":%lu,\"exe\":\"%s\",\"status\":\"%s\"}",
                   i ? "," : "", wers[i].pid,
                   esc(wers[i].exe).c_str(), wers[i].alive ? "active" : "stale");
        printf("],\"tasks\":[");
        for (size_t i = 0; i < tasks.size(); i++)
            printf("%s\"%s\"", i ? "," : "", esc(tasks[i]).c_str());
        printf("],\"profiles\":[");
        for (size_t i = 0; i < profiles.size(); i++)
            printf("%s\"%s\"", i ? "," : "", esc(profiles[i]).c_str());
        printf("]}\n");
    } else {
        bool found = false;
        for (auto& x : insts) {
            printf("  [%s]  PID %-6lu  %ls%s\n",
                   x.alive ? "ACTIVE" : "STALE ", x.pid, x.uuid.c_str(),
                   x.alive ? "" : " (dead process)");
            found = true;
        }
        for (auto& w : wers) {
            printf("  [%s]  PID %-6lu  WER key for %ls%s\n",
                   w.alive ? "ACTIVE" : "STALE ", w.pid, w.exe.c_str(),
                   w.alive ? "" : " (dead process)");
            found = true;
        }
        for (auto& t : tasks) { printf("  [TASK]    %ls scheduled task exists\n", t.c_str()); found = true; }
        for (auto& p : profiles) { printf("  [PROFILE] %ls\n", p.c_str()); found = true; }
        if (!found) printf("Sandy - no active instances or stale state.\n");
    }
    return 0;
}



// -----------------------------------------------------------------------
// Restore stale state from crashed runs (--cleanup)
// -----------------------------------------------------------------------
static int HandleCleanup()
{
    Sandbox::ForceDisableLoopback();
    Sandbox::RestoreStaleGrants();   // restores DACLs + deletes stale container profiles
    Sandbox::RestoreStaleWER();
    Sandbox::DeleteStaleCleanupTasks();

    // Clean orphaned Sandy AppContainer profiles from Windows Mappings
    auto orphans = EnumSandyProfiles();
    if (!orphans.empty())
        printf("  Cleaning %zu orphaned AppContainer profile(s)...\n",
                orphans.size());
    for (const auto& m : orphans) {
        HRESULT hr = DeleteAppContainerProfile(m.c_str());
        if (SUCCEEDED(hr))
            printf("  [PROFILE] %ls -> deleted\n", m.c_str());
        else
            fprintf(stderr, "  [PROFILE] %ls -> FAILED\n", m.c_str());
    }
    printf("Sandy - cleanup complete.\n");
    return 0;
}

// -----------------------------------------------------------------------
// Explain an exit code (--explain <code>)
// -----------------------------------------------------------------------
static int HandleExplain(const wchar_t* codeStr)
{
    // Parse code (decimal, hex, or negative)
    wchar_t* end = nullptr;
    long long code = wcstoll(codeStr, &end, 0);
    if (end == codeStr || *end != L'\0') {
        fprintf(stderr, "Error: '%ls' is not a valid number.\n", codeStr);
        return SandyExit::InternalError;
    }
    DWORD dw = static_cast<DWORD>(code);

    printf("Code: %lld (0x%08X)\n\n", code, dw);

    // Sandy exit codes
    struct { int code; const char* name; const char* desc; } sandyCodes[] = {
        { 0,   "Success",       "Child exited cleanly, or info command succeeded" },
        { 125, "InternalError", "Sandy internal / general error" },
        { 126, "CannotExec",    "CreateProcess failed (permission denied, bad format)" },
        { 127, "NotFound",      "Executable not found on disk" },
        { 128, "ConfigError",   "Configuration error (invalid TOML, wrong-mode keys)" },
        { 129, "SetupError",    "Sandbox setup failed (token, SID, ACL, pipes)" },
        { 130, "Timeout",       "Child killed by Sandy's timeout watchdog" },
        { 131, "ChildCrash",    "Child crashed (NTSTATUS crash code detected)" },
    };
    for (auto& s : sandyCodes) {
        if (s.code == static_cast<int>(code)) {
            printf("Sandy exit code: %s\n  %s\n", s.name, s.desc);
            return 0;
        }
    }

    // Known NTSTATUS crash codes
    struct { DWORD code; const char* name; } crashCodes[] = {
        { 0xC0000005, "STATUS_ACCESS_VIOLATION (SIGSEGV equivalent)" },
        { 0xC00000FD, "STATUS_STACK_OVERFLOW" },
        { 0xC0000409, "STATUS_STACK_BUFFER_OVERRUN (/GS security check failure)" },
        { 0x80000003, "STATUS_BREAKPOINT (INT 3 / debugger break)" },
        { 0xC0000374, "STATUS_HEAP_CORRUPTION" },
        { 0xC0000096, "STATUS_PRIVILEGED_INSTRUCTION" },
        { 0xC000001D, "STATUS_ILLEGAL_INSTRUCTION" },
        { 0xC0000094, "STATUS_INTEGER_DIVIDE_BY_ZERO" },
        { 0xC000008C, "STATUS_ARRAY_BOUNDS_EXCEEDED" },
        { 0xC0000135, "STATUS_DLL_NOT_FOUND" },
        { 0xC0000142, "STATUS_DLL_INIT_FAILED" },
        { 0x40010004, "STATUS_DEBUGGER_INACTIVE (WerFault)" },
    };
    for (auto& c : crashCodes) {
        if (c.code == dw) {
            printf("NTSTATUS: %s\n", c.name);
            return 0;
        }
    }

    // Try FormatMessage for Win32 or NTSTATUS
    wchar_t* msgBuf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, dw, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                               reinterpret_cast<LPWSTR>(&msgBuf), 0, nullptr);
    if (len > 0 && msgBuf) {
        // Strip trailing newline
        while (len > 0 && (msgBuf[len-1] == L'\n' || msgBuf[len-1] == L'\r')) msgBuf[--len] = 0;
        printf("System message: %ls\n", msgBuf);
        LocalFree(msgBuf);
    } else {
        // Try NTSTATUS via ntdll
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            len = FormatMessageW(flags | FORMAT_MESSAGE_FROM_HMODULE, hNtdll, dw,
                                 MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                                 reinterpret_cast<LPWSTR>(&msgBuf), 0, nullptr);
            if (len > 0 && msgBuf) {
                while (len > 0 && (msgBuf[len-1] == L'\n' || msgBuf[len-1] == L'\r')) msgBuf[--len] = 0;
                printf("NTSTATUS message: %ls\n", msgBuf);
                LocalFree(msgBuf);
            } else {
                printf("Unknown code.\n");
            }
        } else {
            printf("Unknown code.\n");
        }
    }

    // Additional context for NTSTATUS range
    if (dw >= 0x80000000)
        printf("  (NTSTATUS range: 0x8* = warning, 0xC* = error/crash)\n");
    else if (code >= 1 && code <= 124)
        printf("  (In Sandy: this would be the child process's own exit code)\n");

    return 0;
}

// -----------------------------------------------------------------------
// Dry-run mode (--dry-run / --check) — validate config + show plan
// -----------------------------------------------------------------------
static const char* AccessLevelName(Sandbox::AccessLevel a) {
    switch (a) {
        case Sandbox::AccessLevel::Read:    return "read";
        case Sandbox::AccessLevel::Write:   return "write";
        case Sandbox::AccessLevel::Execute: return "execute";
        case Sandbox::AccessLevel::Append:  return "append";
        case Sandbox::AccessLevel::Delete:  return "delete";
        case Sandbox::AccessLevel::All:     return "all";
    }
    return "?";
}

static void PrintFolderEntries(const char* section,
                               const std::vector<Sandbox::FolderEntry>& entries)
{
    printf("[%s]\n", section);
    if (entries.empty()) { printf("  (none)\n"); return; }
    // Group by access level
    for (int a = 0; a <= 5; a++) {
        auto lvl = static_cast<Sandbox::AccessLevel>(a);
        bool first = true;
        for (auto& e : entries) {
            if (e.access != lvl) continue;
            if (first) { printf("  %s:\n", AccessLevelName(lvl)); first = false; }
            printf("    %ls\n", e.path.c_str());
        }
    }
}

static int HandleDryRun(const Sandbox::SandboxConfig& config,
                        const std::wstring& exePath,
                        const std::wstring& exeArgs)
{
    bool isRestricted = (config.tokenMode == Sandbox::TokenMode::Restricted);
    printf("=== Sandy Dry Run ===\n\n");

    printf("Mode: %s\n", isRestricted ? "restricted" : "appcontainer");
    if (isRestricted)
        printf("Integrity: %s\n",
               config.integrity == Sandbox::IntegrityLevel::Low ? "low" : "medium");
    if (!exePath.empty()) printf("Executable: %ls\n", exePath.c_str());
    if (!exeArgs.empty()) printf("Arguments: %ls\n", exeArgs.c_str());
    printf("Working dir: %s\n\n",
           config.workdir.empty() ? "(sandy.exe folder)" : "custom");

    PrintFolderEntries("allow", config.folders);
    printf("\n");
    PrintFolderEntries("deny", config.denyFolders);

    printf("\n[privileges]\n");
    if (!isRestricted) {
        printf("  system_dirs:     %s\n", config.allowSystemDirs ? "true" : "false");
        printf("  network:         %s\n", config.allowNetwork ? "true" : "false");
        printf("  localhost:       %s\n", config.allowLocalhost ? "true" : "false");
        printf("  lan:             %s\n", config.allowLan ? "true" : "false");
    } else {
        printf("  named_pipes:     %s\n", config.allowNamedPipes ? "true" : "false");
    }
    printf("  stdin:           %ls\n", config.stdinMode.c_str());
    printf("  clipboard_read:  %s\n", config.allowClipboardRead ? "true" : "false");
    printf("  clipboard_write: %s\n", config.allowClipboardWrite ? "true" : "false");
    printf("  child_processes: %s\n", config.allowChildProcesses ? "true" : "false");

    if (isRestricted) {
        printf("\n[registry]\n");
        if (!config.registryRead.empty()) {
            printf("  read:\n");
            for (auto& k : config.registryRead) printf("    %ls\n", k.c_str());
        }
        if (!config.registryWrite.empty()) {
            printf("  write:\n");
            for (auto& k : config.registryWrite) printf("    %ls\n", k.c_str());
        }
        if (config.registryRead.empty() && config.registryWrite.empty())
            printf("  (none)\n");
    }

    printf("\n[limit]\n");
    printf("  timeout:   %lu%s\n", config.timeoutSeconds,
           config.timeoutSeconds == 0 ? " (unlimited)" : "s");
    printf("  memory:    %zuMB%s\n", config.memoryLimitMB,
           config.memoryLimitMB == 0 ? " (unlimited)" : "");
    printf("  processes: %lu%s\n", config.maxProcesses,
           config.maxProcesses == 0 ? " (unlimited)" : "");

    printf("\n[environment]\n");
    printf("  inherit: %s\n", config.envInherit ? "true" : "false");
    if (!config.envPass.empty()) {
        printf("  pass:");
        for (auto& v : config.envPass) printf(" %ls", v.c_str());
        printf("\n");
    }

    printf("\n=== Config valid. No system state modified. ===\n");
    return 0;
}

// -----------------------------------------------------------------------
// Print resolved config (--print-config)
// -----------------------------------------------------------------------
static void PrintFolderToml(const char* section,
                            const std::vector<Sandbox::FolderEntry>& entries)
{
    printf("[%s]\n", section);
    for (int a = 0; a <= 5; a++) {
        auto lvl = static_cast<Sandbox::AccessLevel>(a);
        std::string paths;
        for (auto& e : entries) {
            if (e.access != lvl) continue;
            if (!paths.empty()) paths += ", ";
            // Convert wstring path to narrow for printf
            paths += "'";
            for (wchar_t c : e.path) paths += (c < 128) ? (char)c : '?';
            paths += "'";
        }
        if (!paths.empty())
            printf("%s = [%s]\n", AccessLevelName(lvl), paths.c_str());
    }
}

static int HandlePrintConfig(const Sandbox::SandboxConfig& config)
{
    bool isRT = (config.tokenMode == Sandbox::TokenMode::Restricted);

    printf("[sandbox]\n");
    printf("token = '%s'\n", isRT ? "restricted" : "appcontainer");
    if (isRT)
        printf("integrity = '%s'\n",
               config.integrity == Sandbox::IntegrityLevel::Low ? "low" : "medium");
    printf("workdir = '%ls'\n\n",
           config.workdir.empty() ? L"inherit" : config.workdir.c_str());

    PrintFolderToml("allow", config.folders);
    printf("\n");
    PrintFolderToml("deny", config.denyFolders);

    printf("\n[privileges]\n");
    if (!isRT) {
        printf("system_dirs     = %s\n", config.allowSystemDirs ? "true" : "false");
        printf("network         = %s\n", config.allowNetwork ? "true" : "false");
        printf("localhost       = %s\n", config.allowLocalhost ? "true" : "false");
        printf("lan             = %s\n", config.allowLan ? "true" : "false");
    } else {
        printf("named_pipes     = %s\n", config.allowNamedPipes ? "true" : "false");
    }
    printf("stdin           = %ls\n", config.stdinMode.c_str());
    printf("clipboard_read  = %s\n", config.allowClipboardRead ? "true" : "false");
    printf("clipboard_write = %s\n", config.allowClipboardWrite ? "true" : "false");
    printf("child_processes = %s\n", config.allowChildProcesses ? "true" : "false");

    if (isRT) {
        printf("\n[registry]\n");
        auto printKeys = [](const char* k, const std::vector<std::wstring>& v) {
            printf("%s = [", k);
            for (size_t i = 0; i < v.size(); i++) {
                if (i) printf(", ");
                printf("'%ls'", v[i].c_str());
            }
            printf("]\n");
        };
        printKeys("read",  config.registryRead);
        printKeys("write", config.registryWrite);
    }

    printf("\n[environment]\n");
    printf("inherit = %s\n", config.envInherit ? "true" : "false");
    printf("pass = [");
    for (size_t i = 0; i < config.envPass.size(); i++) {
        if (i) printf(", ");
        printf("'%ls'", config.envPass[i].c_str());
    }
    printf("]\n");

    printf("\n[limit]\n");
    printf("timeout   = %lu\n", config.timeoutSeconds);
    printf("memory    = %zu\n", config.memoryLimitMB);
    printf("processes = %lu\n", config.maxProcesses);

    return 0;
}

// -----------------------------------------------------------------------
// Sandboxed execution (separated for SEH wrapping)
// -----------------------------------------------------------------------
static int RunMain(int argc, wchar_t* argv[])
{
    std::wstring configPath;
    std::wstring configString;
    std::wstring logPath;
    std::wstring auditLogPath;
    std::wstring profilePath;
    std::wstring dumpPath;
    std::wstring exePath;
    std::wstring exeArgs;
    bool quiet = false;
    bool logStamp = false;
    bool dryRun = false;
    bool printConfig = false;
    bool jsonOutput = false;

    // --- Pre-scan for isolated flags ---
    // These flags must appear alone (or with a minimal companion like --json).
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        bool isIsolated = (arg == L"-v" || arg == L"--version" ||
                           arg == L"-h" || arg == L"--help" ||
                           arg == L"--cleanup" ||
                           arg == L"--print-container-toml" ||
                           arg == L"--print-restricted-toml");
        if (isIsolated) {
            if (argc > 2) {
                fprintf(stderr, "Error: %ls must be used alone, without other options.\n",
                        arg.c_str());
                return SandyExit::InternalError;
            }
            if (arg == L"-v" || arg == L"--version") {
                printf("sandy v%s\n", kVersion);
                return 0;
            }
            if (arg == L"-h" || arg == L"--help") {
                PrintUsage();
                return 0;
            }
            if (arg == L"--print-container-toml") {
                PrintContainerToml();
                return 0;
            }
            if (arg == L"--print-restricted-toml") {
                PrintRestrictedToml();
                return 0;
            }
            if (arg == L"--cleanup") {
                return HandleCleanup();
            }
        }

        // --status [--json] — up to 2 args
        if (arg == L"--status") {
            bool json = (argc > 2 && std::wstring(argv[i == 1 ? 2 : 1]) == L"--json");
            if (argc > (json ? 3 : 2)) {
                fprintf(stderr, "Error: --status only accepts --json as companion.\n");
                return SandyExit::InternalError;
            }
            return HandleStatus(json);
        }

        // --explain <code> — exactly 2 args
        if (arg == L"--explain") {
            if (argc != 3 || i + 1 >= argc) {
                fprintf(stderr, "Error: --explain requires exactly one argument.\n");
                return SandyExit::InternalError;
            }
            return HandleExplain(argv[i + 1]);
        }
    }

    // --- Parse command-line arguments ---
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-q" || arg == L"--quiet") {
            quiet = true;
        }
        else if (arg == L"-L" || arg == L"--log-stamp") {
            logStamp = true;
        }
        else if (arg == L"--dry-run" || arg == L"--check") {
            dryRun = true;
        }
        else if (arg == L"--print-config") {
            printConfig = true;
        }
        else if ((arg == L"-c" || arg == L"--config") && i + 1 < argc) {
            configPath = argv[++i];
        }
        else if ((arg == L"-s" || arg == L"--string") && i + 1 < argc) {
            configString = argv[++i];
        }
        else if ((arg == L"-l" || arg == L"--log") && i + 1 < argc) {
            logPath = argv[++i];
        }
        else if ((arg == L"-a" || arg == L"--audit") && i + 1 < argc) {
            auditLogPath = argv[++i];
        }
        else if ((arg == L"-p" || arg == L"--profile") && i + 1 < argc) {
            profilePath = argv[++i];
        }
        else if ((arg == L"-d" || arg == L"--dump") && i + 1 < argc) {
            dumpPath = argv[++i];
        }
        else if ((arg == L"-x" || arg == L"--exec") && i + 1 < argc) {
            exePath = argv[++i];
            exeArgs = CollectArgs(i + 1, argc, argv);
            break; // -x/--exec consumes all remaining args
        }
        else if (arg == L"--") {
            // End of options: next arg is exe, rest are its arguments
            if (i + 1 < argc) {
                exePath = argv[++i];
                exeArgs = CollectArgs(i + 1, argc, argv);
            }
            break;
        }
        else {
            fprintf(stderr, "Unknown option: %ls\n\n", arg.c_str());
            PrintUsage();
            return SandyExit::InternalError;
        }
    }

    // --- Profile mode (no config needed) ---
    if (!profilePath.empty()) {
        if (exePath.empty()) {
            fprintf(stderr, "Error: -p requires -x <executable>.\n\n");
            PrintUsage();
            return SandyExit::InternalError;
        }
        int rc = Sandbox::RunProfile(exePath, exeArgs, profilePath);
        return rc;
    }

    // --- No config/exec provided ---
    if (configPath.empty() && configString.empty()) {
        PrintUsage();
        return SandyExit::InternalError;
    }
    if (exePath.empty() && !dryRun && !printConfig) {
        fprintf(stderr, "Error: -x <executable> required (or use --dry-run / --print-config).\n\n");
        PrintUsage();
        return SandyExit::InternalError;
    }

    if (!configPath.empty() && !configString.empty()) {
        fprintf(stderr, "Error: -c and -s are mutually exclusive.\n\n");
        PrintUsage();
        return SandyExit::InternalError;
    }

    // --- Load configuration ---
    Sandbox::SandboxConfig config;
    if (!configString.empty()) {
        config = Sandbox::ParseConfig(configString);
    } else {
        DWORD attrs = GetFileAttributesW(configPath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "Error: Config file not found: %ls\n", configPath.c_str());
            return SandyExit::ConfigError;
        }
        config = Sandbox::LoadConfig(configPath);
    }
    if (config.parseError) {
        fprintf(stderr, "Error: Config contains unknown sections or keys. Aborting.\n");
        return SandyExit::ConfigError;
    }

    // --- Config-only modes (no -x needed) ---
    if (printConfig)
        return HandlePrintConfig(config);
    if (dryRun)
        return HandleDryRun(config, exePath, exeArgs);

    // --- Apply timestamp + UID prefix to log filenames if --log-stamp ---
    if (logStamp) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        DWORD uid = (GetTickCount() ^ GetCurrentProcessId()) & 0xFFFF;
        wchar_t prefix[32];
        swprintf(prefix, 32, L"%04d%02d%02d_%02d%02d%02d_%04x_",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, uid);
        auto stampPath = [&](const std::wstring& path) -> std::wstring {
            if (path.empty()) return path;
            auto slash = path.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
                return path.substr(0, slash + 1) + prefix + path.substr(slash + 1);
            return std::wstring(prefix) + path;
        };
        logPath = stampPath(logPath);
        auditLogPath = stampPath(auditLogPath);
        dumpPath = stampPath(dumpPath);
    }

    config.logPath = logPath;
    config.quiet = quiet;
    config.configSource = !configPath.empty() ? configPath : L"<inline>";

    // --- Run sandboxed ---
    // cleanup() inside RunSandboxed handles ACL restore, loopback, AppContainer.
    // CleanupSandbox() remains as safety net for CTRL+C / SEH crash paths only.
    int exitCode = Sandbox::RunSandboxed(config, exePath, exeArgs, auditLogPath, dumpPath);

    return exitCode;
}

// -----------------------------------------------------------------------
// Entry point — SEH wrapper for crash resilience
// -----------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    __try {
        return RunMain(argc, argv);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        g_logger.LogFmt(L"FATAL_EXCEPTION: 0x%08X", code);
        CleanupSandbox();
        return SandyExit::InternalError;
    }
}
