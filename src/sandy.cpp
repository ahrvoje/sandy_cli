// sandy.cpp — Sandboxed Executable Runner (CLI)
// Launches any executable inside a Windows sandbox (AppContainer or Restricted Token).
// Usage: sandy.exe -c <config.toml> -x <executable> [args...]
//        sandy.exe -s "<toml string>" -x <executable> [args...]

#include "framework.h"
#include "Sandbox.h"

constexpr const char* kVersion = "0.91";

// -----------------------------------------------------------------------
// Print usage help (full reference including TOML config example)
// -----------------------------------------------------------------------
static void PrintUsage()
{
    printf(
        "Sandy - Windows Sandbox Runner  v%s\n"
        "\n"
        "Usage:\n"
        "  sandy.exe -c <config.toml> [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-q] -x <executable> [args...]\n"
        "  sandy.exe -s \"<toml>\"      [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-q] -x <executable> [args...]\n"
        "  sandy.exe -p <report>       -x <executable> [args...]\n"
        "  sandy.exe --print-container-toml          (print default appcontainer config)\n"
        "  sandy.exe --print-restricted-toml         (print default restricted config)\n"
        "  sandy.exe --cleanup                       (restore stale state from crashed runs)\n"
        "  sandy.exe --status                        (show active instances and stale state)\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Path to TOML config file\n"
        "  -s, --string <toml>   Inline TOML config string (alternative to -c)\n"
        "  -l, --log <path>      Session log (config, output, exit code)\n"
        "  -a, --audit <path>    Audit log of denied resource access (requires Procmon + admin)\n"
        "  -d, --dump <path>     Crash dump output path (independent of -a)\n"
        "  -x, --exec <path>     Executable to run sandboxed (consumes remaining args)\n"
        "  -p, --profile <path>  Profile unsandboxed run for sandbox feasibility (requires Procmon + admin)\n"
        "  -q, --quiet           Suppress the config banner on stderr\n"
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
        "  [access]                               (required, both modes)\n"
        "  read    = ['C:\\\\path']                 # read files, list dirs (no execute)\n"
        "  write   = []                           # create/modify files (no read)\n"
        "  execute = []                           # execute only (no read)\n"
        "  append  = []                           # append only (no overwrite)\n"
        "  delete  = []                           # delete only\n"
        "  all     = []                           # full access\n"
        "  All 6 keys required. Use [] for no grants. Absolute paths only.\n"
        "\n"
        "  [allow]                                (required, all keys mandatory per mode)\n"
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
        "Profile mode (-p):\n"
        "  Runs the process UNSANDBOXED under Procmon, analyzes resource usage,\n"
        "  and writes a feasibility report with a suggested TOML config.\n"
        "  Requires: Procmon on PATH + admin privileges.\n"
        "  Report includes: sandboxability verdict, mode recommendations,\n"
        "  required read/write paths, network/pipe/registry usage.\n"
        "\n"
        "Crash resilience:\n"
        "  A scheduled task (SandyCleanup) restores stale state at next logon.\n"
        "  Use --cleanup to manually restore stale state from crashed runs.\n"
        "  Ctrl+C/Break/close triggers cleanup before exit.\n"
        "  SEH handler catches fatal errors in sandy itself.\n"
        "\n"
        "Multi-instance:\n"
        "  Each instance creates its own AppContainer profile (Sandy_<UUID>) with a\n"
        "  unique SID, so concurrent instances do not interfere with each other's\n"
        "  file grants. Registry state is keyed by UUID. On exit, an instance only\n"
        "  revokes its own ACEs; paths still needed by other instances are preserved.\n"
        "  Use --status to see active instances. Use --cleanup to clear stale state.\n",
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
        "[access]\n"
        "read    = []\n"
        "write   = []\n"
        "execute = []\n"
        "append  = []\n"
        "delete  = []\n"
        "all     = []\n"
        "\n"
        "[allow]\n"
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
        "[access]\n"
        "read    = []\n"
        "write   = []\n"
        "execute = []\n"
        "append  = []\n"
        "delete  = []\n"
        "all     = []\n"
        "\n"
        "[allow]\n"
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

// Helper: collect all remaining argv[start..argc-1] as forwarded args
static std::wstring CollectArgs(int start, int argc, wchar_t* argv[])
{
    std::wstring args;
    for (int j = start; j < argc; j++) {
        if (!args.empty()) args += L" ";
        std::wstring a = argv[j];
        bool needsQuoting = a.find(L' ') != std::wstring::npos && a.front() != L'"';
        if (needsQuoting) {
            // Escape embedded double-quotes before wrapping
            std::wstring escaped;
            escaped.reserve(a.size());
            for (wchar_t c : a) {
                if (c == L'"') escaped += L'\\';
                escaped += c;
            }
            args += L"\"" + escaped + L"\"";
        } else {
            args += a;
        }
    }
    return args;
}

// -----------------------------------------------------------------------
// Console control handler — cleanup on Ctrl+C, Ctrl+Break, window close
// -----------------------------------------------------------------------
static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    (void)ctrlType;
    fprintf(stderr, "\n[Sandy] Signal received, cleaning up...\n");
    Sandbox::CleanupSandbox();
    return FALSE;  // let default handler terminate the process
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

    // --- Parse command-line arguments ---
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

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
        if (arg == L"--status") {
            bool found = false;

            // Check Grants registry
            HKEY hGrants = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, Sandbox::kGrantsParentKey, 0,
                              KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hGrants) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hGrants, nullptr, nullptr, nullptr, &subKeyCount,
                                 nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                for (DWORD i = 0; i < subKeyCount; i++) {
                    wchar_t name[128];
                    DWORD nameLen = 128;
                    if (RegEnumKeyExW(hGrants, i, name, &nameLen,
                            nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                        // Read _pid from subkey
                        std::wstring fullKey = std::wstring(Sandbox::kGrantsParentKey) + L"\\" + name;
                        HKEY hSub = nullptr;
                        DWORD pid = 0;
                        if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey.c_str(), 0,
                                          KEY_READ, &hSub) == ERROR_SUCCESS) {
                            DWORD size = sizeof(DWORD);
                            RegQueryValueExW(hSub, L"_pid", nullptr, nullptr,
                                             reinterpret_cast<BYTE*>(&pid), &size);
                            RegCloseKey(hSub);
                        }
                        HANDLE h = pid ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) : nullptr;
                        if (h) {
                            CloseHandle(h);
                            fprintf(stderr, "  [ACTIVE]  PID %-6lu  %ls\n", pid, name);
                        } else {
                            fprintf(stderr, "  [STALE]   PID %-6lu  %ls (dead process)\n", pid, name);
                        }
                        found = true;
                    }
                }
                RegCloseKey(hGrants);
            }

            // Check WER registry
            HKEY hWER = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, Sandbox::kWERParentKey, 0,
                              KEY_READ, &hWER) == ERROR_SUCCESS) {
                DWORD valueCount = 0;
                RegQueryInfoKeyW(hWER, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                 &valueCount, nullptr, nullptr, nullptr, nullptr);
                for (DWORD i = 0; i < valueCount; i++) {
                    wchar_t name[64];
                    DWORD nameLen = 64;
                    DWORD dataSize = 0;
                    if (RegEnumValueW(hWER, i, name, &nameLen, nullptr, nullptr,
                                      nullptr, &dataSize) == ERROR_SUCCESS) {
                        DWORD pid = static_cast<DWORD>(_wtoi(name));
                        // Read the exe name
                        std::wstring exeName(dataSize / sizeof(wchar_t), L'\0');
                        nameLen = 64;
                        RegEnumValueW(hWER, i, name, &nameLen, nullptr, nullptr,
                                      reinterpret_cast<BYTE*>(&exeName[0]), &dataSize);
                        while (!exeName.empty() && exeName.back() == L'\0') exeName.pop_back();

                        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                        if (h) {
                            CloseHandle(h);
                            fprintf(stderr, "  [ACTIVE]  PID %-6lu  WER key for %ls\n", pid, exeName.c_str());
                        } else {
                            fprintf(stderr, "  [STALE]   PID %-6lu  WER key for %ls (dead process)\n", pid, exeName.c_str());
                        }
                        found = true;
                    }
                }
                RegCloseKey(hWER);
            }

            // Check scheduled task
            bool taskExists = false;
            {
                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi = {};
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                wchar_t cmd[] = L"schtasks.exe /Query /TN \"SandyCleanup\"";
                if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, 5000);
                    DWORD exitCode = 1;
                    GetExitCodeProcess(pi.hProcess, &exitCode);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    taskExists = (exitCode == 0);
                }
            }
            if (taskExists) {
                fprintf(stderr, "  [TASK]    SandyCleanup scheduled task exists\n");
                found = true;
            }

            if (!found) {
                fprintf(stderr, "Sandy - no active instances or stale state.\n");
            }
            return 0;
        }
        if (arg == L"--cleanup") {
            Sandbox::ForceDisableLoopback();
            Sandbox::RestoreStaleGrants();   // restores DACLs + deletes stale container profiles
            Sandbox::RestoreStaleWER();
            Sandbox::DeleteCleanupTask();
            fprintf(stderr, "Sandy - cleanup complete.\n");
            return 0;
        }
        if (arg == L"-q" || arg == L"--quiet") {
            quiet = true;
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
            return 1;
        }
    }

    // --- Profile mode (no config needed) ---
    if (!profilePath.empty()) {
        if (exePath.empty()) {
            fprintf(stderr, "Error: -p requires -x <executable>.\n\n");
            PrintUsage();
            return 1;
        }
        int rc = Sandbox::RunProfile(exePath, exeArgs, profilePath);
        return rc;
    }

    // --- No config/exec provided ---
    if ((configPath.empty() && configString.empty()) || exePath.empty()) {
        PrintUsage();
        return 1;
    }

    if (!configPath.empty() && !configString.empty()) {
        fprintf(stderr, "Error: -c and -s are mutually exclusive.\n\n");
        PrintUsage();
        return 1;
    }

    // --- Load configuration ---
    Sandbox::SandboxConfig config;
    if (!configString.empty()) {
        config = Sandbox::ParseConfig(configString);
    } else {
        DWORD attrs = GetFileAttributesW(configPath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "Error: Config file not found: %ls\n", configPath.c_str());
            return 1;
        }
        config = Sandbox::LoadConfig(configPath);
    }
    if (config.parseError) {
        fprintf(stderr, "Error: Config contains unknown sections or keys. Aborting.\n");
        return 1;
    }
    config.logPath = logPath;
    config.quiet = quiet;

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
        fprintf(stderr, "[Sandy] Fatal exception 0x%08X, cleaning up...\n", code);
        Sandbox::CleanupSandbox();
        return 1;
    }
}
