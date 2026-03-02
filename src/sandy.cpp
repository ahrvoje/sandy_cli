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
        "  token = 'appcontainer'                 # or 'restricted'\n"
        "  # integrity = 'low'                    # restricted only: 'low' or 'medium'\n"
        "  # workdir = 'C:\\\\projects\\\\myapp'      # child working dir (default: sandy.exe folder)\n"
        "\n"
        "  [access]                               (both modes, recursive for dirs)\n"
        "  read    = ['C:\\\\path']                 # read files, list dirs (no execute)\n"
        "  write   = ['C:\\\\path']                 # create/modify files (no read)\n"
        "  execute = ['C:\\\\path']                 # execute only (no read)\n"
        "  append  = ['C:\\\\path']                 # append only (no overwrite)\n"
        "  delete  = ['C:\\\\path']                 # delete only\n"
        "  all     = ['C:\\\\path']                 # full access\n"
        "  Permissions are independent: read!=execute, write!=read. Use absolute paths.\n"
        "\n"
        "  [allow]                                (mode-specific)\n"
        "  system_dirs     = true                 # appcontainer only\n"
        "  network         = true                 # appcontainer only\n"
        "  localhost       = true                 # appcontainer only (admin)\n"
        "  lan             = true                 # appcontainer only\n"
        "  named_pipes     = true                 # restricted only\n"
        "  stdin           = false                # both modes (false = NUL, or path)\n"
        "  clipboard_read  = false                # both modes (default: true)\n"
        "  clipboard_write = false                # both modes (default: true)\n"
        "  child_processes = false                # both modes (default: true)\n"
        "\n"
        "  [registry]                             (restricted only)\n"
        "  read  = ['HKCU\\\\Software\\\\MyApp']\n"
        "  write = ['HKCU\\\\Software\\\\MyApp\\\\Settings']\n"
        "\n"
        "  [environment]                          (both modes)\n"
        "  inherit = false                        # don't inherit parent env\n"
        "  pass = ['PATH', 'USERPROFILE']         # only effective when inherit = false\n"
        "\n"
        "  [limit]                                (both modes)\n"
        "  timeout = 300                          # kill after N seconds (exit code 1)\n"
        "  memory = 4096                          # job-wide memory cap in MB (all combined)\n"
        "  processes = 10                         # max active processes incl. main\n"
        "\n"
        "Mode comparison:          AppContainer          Restricted Low        Restricted Medium\n"
        "  Integrity level         Low (fixed)           Low                   Medium\n"
        "  Named pipes             blocked (kernel)      configurable          configurable\n"
        "  Network                 configurable          unrestricted          unrestricted\n"
        "  Object namespace        isolated              shared                shared\n"
        "  System dir reads        configurable          always readable       always readable\n"
        "  System dir writes       blocked               blocked               blocked\n"
        "  User profile reads      blocked               allowed               allowed\n"
        "  User profile writes     blocked               blocked (IL)          allowed\n"
        "  Registry reads          private hive          most keys             most keys\n"
        "  Registry HKCU writes    blocked               blocked (IL)          allowed\n"
        "  Registry HKLM writes    blocked               blocked               blocked\n"
        "  DLL/API set resolve     works                 breaks some apps      works\n"
        "  COM/RPC servers         mostly blocked        accessible            accessible\n"
        "  Scheduled tasks         blocked (COM)         blocked (IL)          allowed\n"
        "  Window messages (UIPI)  blocked               blocked (IL)          allowed\n"
        "  Clipboard               configurable          configurable          configurable\n"
        "  Child processes         configurable          configurable          configurable\n"
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
        "  Report includes: sandboxability verdict, mode recommendations,\n"
        "  required read/write paths, network/pipe/registry usage.\n"
        "\n"
        "Crash resilience:\n"
        "  Startup cleans stale state from previous crashed runs.\n"
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
        if (a.find(L' ') != std::wstring::npos && a.front() != L'"')
            args += L"\"" + a + L"\"";
        else
            args += a;
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

    // --- Validate required options ---
    if ((configPath.empty() && configString.empty()) || exePath.empty()) {
        if (argc > 1)
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
    int exitCode = Sandbox::RunSandboxed(config, exePath, exeArgs, auditLogPath, dumpPath);

    Sandbox::CleanupSandbox();

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
