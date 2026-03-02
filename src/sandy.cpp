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
        "  sandy.exe -c <config.toml> [-l <logfile>] [-a <auditlog>] [-q] -x <executable> [args...]\n"
        "  sandy.exe -s \"<toml>\"      [-l <logfile>] [-a <auditlog>] [-q] -x <executable> [args...]\n"
        "  sandy.exe -p <report>       -x <executable> [args...]\n"
        "  sandy.exe                   (cleanup stale state from crashed runs)\n"
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
        "  -v, --version         Print version and exit\n"
        "  -h, --help            Print this help text and exit\n"
        "\n"
        "All flags must come before -x. Arguments after -x are forwarded to the child.\n"
        "\n"
        "Config reference (all configs must include [sandbox]):\n"
        "\n"
        "  [sandbox]                              (required)\n"
        "  token = 'appcontainer'                 # required: 'appcontainer' or 'restricted'\n"
        "  # integrity = 'low'                    # required (restricted only): 'low' or 'medium'\n"
        "  # workdir = 'C:\\\\projects\\\\myapp'      # optional: child working dir\n"
        "\n"
        "  [access]                               (optional, both modes)\n"
        "  read    = ['C:\\\\path']                 # read files, list dirs (no execute)\n"
        "  write   = ['C:\\\\path']                 # create/modify files (no read)\n"
        "  execute = ['C:\\\\path']                 # execute only (no read)\n"
        "  append  = ['C:\\\\path']                 # append only (no overwrite)\n"
        "  delete  = ['C:\\\\path']                 # delete only\n"
        "  all     = ['C:\\\\path']                 # full access\n"
        "  Permissions are independent: read!=execute, write!=read. Use absolute paths.\n"
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
        "  [registry]                             (optional, restricted only)\n"
        "  read  = ['HKCU\\\\Software\\\\MyApp']\n"
        "  write = ['HKCU\\\\Software\\\\MyApp\\\\Settings']\n"
        "\n"
        "  [environment]                          (required)\n"
        "  inherit = true                         # required: true or false\n"
        "  pass = ['PATH', 'USERPROFILE']         # optional: extends clean env\n"
        "\n"
        "  [limit]                                (optional, both modes)\n"
        "  timeout = 300                          # kill after N seconds (exit code 1)\n"
        "  memory = 4096                          # job-wide memory cap in MB (all combined)\n"
        "  processes = 10                         # max active processes incl. main\n"
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
        "  User profile reads      blocked               allowed               allowed\n"
        "  User profile writes     blocked               blocked               allowed\n"
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
        "  Startup cleans stale state from previous crashed runs.\n"
        "  Running sandy with no arguments performs cleanup only.\n"
        "  Ctrl+C/Break/close triggers cleanup before exit.\n"
        "  SEH handler catches fatal errors in sandy itself.\n",
        kVersion
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

    // --- Cleanup-only mode (no arguments) ---
    if (configPath.empty() && configString.empty() && exePath.empty()) {
        if (argc > 1 && !quiet) {
            fprintf(stderr, "Error: -x is required, and one of -c or -s must be provided.\n\n");
            PrintUsage();
            return 1;
        }
        Sandbox::ForceDisableLoopback();
        DeleteAppContainerProfile(Sandbox::kContainerName);
        Sandbox::RestoreStaleGrants();
        Sandbox::DeleteCleanupTask();
        if (!quiet)
            fprintf(stderr, "Sandy - cleanup complete.\n");
        return 0;
    }

    // --- Validate required options ---
    if ((configPath.empty() && configString.empty()) || exePath.empty()) {
        fprintf(stderr, "Error: -x is required, and one of -c or -s must be provided.\n\n");
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
