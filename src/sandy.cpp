// sandy.cpp — Sandboxed Executable Runner (CLI)
// Launches any executable inside a Windows sandbox (AppContainer or Restricted Token).
// Usage: sandy.exe -c <config.toml> -x <executable> [args...]
//        sandy.exe -s "<toml string>" -x <executable> [args...]

#include "framework.h"
#include "Sandbox.h"

constexpr const char* kVersion = "0.7";

// -----------------------------------------------------------------------
// Print usage help (full reference including TOML config example)
// -----------------------------------------------------------------------
static void PrintUsage()
{
    printf(
        "Sandy - Windows Sandbox Runner  v%s\n"
        "\n"
        "Usage:\n"
        "  sandy.exe -c <config.toml> [-l <logfile>] [-q] -x <executable> [args...]\n"
        "  sandy.exe -s \"<toml>\"      [-l <logfile>] [-q] -x <executable> [args...]\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>   Path to TOML config file\n"
        "  -s, --string <toml>   Inline TOML config string (alternative to -c)\n"
        "  -l, --log <path>      Log file for session output, config, and exit code\n"
        "  -x, --exec <path>     Executable to run sandboxed (consumes remaining args)\n"
        "  -q, --quiet           Suppress the config banner on stderr\n"
        "  -v, --version         Print version and exit\n"
        "  -h, --help            Print this help text and exit\n"
        "  --                    End of options (all following args passed to executable)\n"
        "\n"
        "Arguments after -x <executable> (or after --) are forwarded to it.\n"
        "\n"
        "Config reference (all configs must include [sandbox]):\n"
        "\n"
        "  [sandbox]                                    (required)\n"
        "  token = \"appcontainer\"                     # or \"restricted\"\n"
        "  # integrity = \"low\"                        # restricted only: \"low\" or \"medium\"\n"
        "\n"
        "  [access]                                     (both modes)\n"
        "  read    = ['C:\\\\path']                        # read files, list dirs\n"
        "  write   = ['C:\\\\path']                        # create/modify files\n"
        "  execute = ['C:\\\\path']                        # execute only (no read)\n"
        "  append  = ['C:\\\\path']                        # append only (no overwrite)\n"
        "  delete  = ['C:\\\\path']                        # delete only\n"
        "  all     = ['C:\\\\path']                        # full access\n"
        "\n"
        "  [allow]                                      (mode-specific)\n"
        "  system_dirs = true                           # appcontainer only\n"
        "  network     = true                           # appcontainer only\n"
        "  localhost    = true                          # appcontainer only (admin)\n"
        "  lan          = true                          # appcontainer only\n"
        "  pipes        = true                          # restricted only\n"
        "  stdin        = false                         # both modes\n"
        "\n"
        "  [registry]                                   (restricted only)\n"
        "  read  = ['HKCU\\\\Software\\\\MyApp']\n"
        "  write = ['HKCU\\\\Software\\\\MyApp\\\\Settings']\n"
        "\n"
        "  [environment]                                (both modes)\n"
        "  inherit = false                              # don't inherit parent env\n"
        "  pass = ['PATH', 'USERPROFILE']               # specific vars to pass\n"
        "\n"
        "  [limit]                                      (both modes)\n"
        "  timeout = 300                                # kill after N seconds\n"
        "  memory = 4096                                # max memory in MB\n"
        "  processes = 10                               # max child processes\n"
        "\n"
        "Mode comparison:\n"
        "                          AppContainer          Restricted Token\n"
        "  Integrity level         Low (fixed)           configurable (low/medium)\n"
        "  Named pipe creation     blocked (kernel)      configurable\n"
        "  Network isolation       configurable          unrestricted\n"
        "  Object namespace        isolated              shared\n"
        "  System dir access       configurable          always readable\n"
        "  User profile access     blocked               blocked (low) / open (medium)\n"
        "  Registry access         private hive          configurable\n"
        "  COM/RPC servers         mostly blocked        accessible\n"
        "  File/folder grants      configurable          configurable\n"
        "  Resource limits         yes                   yes\n"
        "\n"
        "Use appcontainer for network isolation. Use restricted for named pipes/COM.\n"
        "Wrong-mode flags are rejected (e.g. pipes in appcontainer, network in restricted).\n",
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
// Entry point
// -----------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    std::wstring configPath;
    std::wstring configString;
    std::wstring logPath;
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
    int exitCode = Sandbox::RunSandboxed(config, exePath, exeArgs);

    Sandbox::CleanupSandbox();

    return exitCode;
}
