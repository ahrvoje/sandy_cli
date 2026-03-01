// sandy.cpp — Sandboxed Executable Runner (CLI)
// Launches any executable inside a Windows AppContainer sandbox.
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
        "Sandy - AppContainer Sandbox Runner  v%s\n"
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
        "Config file reference:\n"
        "\n"
        "  [sandbox]\n"
        "  # token = \"restricted\"  # use restricted token instead of AppContainer\n"
        "  #                        # allows named pipe creation (Flutter, Chromium)\n"
        "\n"
        "  [access]\n"
        "  read = [\n"
        "      'C:\\data\\config.json',             # single file\n"
        "      'C:\\Python314',                     # entire folder (recursive)\n"
        "  ]\n"
        "  write = [\n"
        "      'C:\\logs\\agent.log',                # single log file\n"
        "      'C:\\temp\\output',                   # output folder\n"
        "  ]\n"
        "  execute = ['C:\\tools\\bin']               # execute-only (no read)\n"
        "  append = ['C:\\logs\\audit.log']            # append-only (no overwrite)\n"
        "  delete = ['C:\\temp\\scratch']              # delete-only\n"
        "  all = ['C:\\workspace']                    # full access\n"
        "\n"
        "  [allow]\n"
        "  system_dirs = true   # read C:\\Windows, Program Files\n"
        "  # network = true     # outbound internet access\n"
        "  # localhost = true   # loopback connections (admin required)\n"
        "  # lan = true         # local network access\n"
        "  # pipes = true       # allow named pipe creation (restricted mode only)\n"
        "  # stdin = false      # block stdin (redirect to NUL)\n"
        "\n"
        "  [registry]            # restricted mode only\n"
        "  # read = ['HKCU\\\\Software\\\\MyApp']\n"
        "  # write = ['HKCU\\\\Software\\\\MyApp\\\\Settings']\n"
        "\n"
        "  [environment]\n"
        "  # inherit = false    # don't inherit parent env vars\n"
        "  # pass = ['PATH', 'USERPROFILE']  # specific vars to pass\n"
        "  # Always passed when inherit=false:\n"
        "  #   SYSTEMROOT SYSTEMDRIVE WINDIR TEMP TMP COMSPEC PATHEXT\n"
        "  #   LOCALAPPDATA APPDATA USERPROFILE HOMEDRIVE HOMEPATH\n"
        "  #   PROCESSOR_ARCHITECTURE NUMBER_OF_PROCESSORS OS\n"
        "\n"
        "  [limit]\n"
        "  # timeout = 300      # kill process after N seconds\n"
        "  # memory = 4096      # maximum memory in MB\n"
        "  # processes = 10     # maximum concurrent child processes\n"
        "\n"
        "AppContainer limitations (kernel-enforced, cannot be overridden):\n"
        "  - Process runs at Low integrity (0x1000) with a unique AppContainer SID.\n"
        "    Windows integrity levels:  High (0x3000) = admin/elevated processes\n"
        "                               Medium (0x2000) = normal user apps (Explorer, cmd)\n"
        "                               Low (0x1000) = AppContainer, Protected Mode IE\n"
        "    Low cannot write to Medium+ objects unless explicitly granted via [access].\n"
        "    User profile, HKCU, temp — all blocked by default but grantable per-folder.\n"
        "  - Cannot elevate privileges\n"
        "  - Registry: private container hive is read/write, most system keys are\n"
        "    readable, writes to HKLM and HKCU are blocked by mandatory integrity\n"
        "  - Named pipes: CreateNamedPipeW always fails from an AppContainer — the\n"
        "    kernel blocks pipe creation at Low integrity. Connecting to existing\n"
        "    pipes requires the pipe creator to set ALL_APPLICATION_PACKAGES or the\n"
        "    specific AppContainer SID in the pipe's security descriptor (most apps,\n"
        "    e.g. Chromium/Mojo, use nullptr = default DACL, which excludes AppContainers)\n"
        "\n"
        "  Use token = \"restricted\" in [sandbox] to enable named pipe creation.\n"
        "  Restricted mode uses restricting SIDs + Low integrity instead of AppContainer.\n"
        "\n"
        "Mode comparison:\n"
        "                          AppContainer (default)   Restricted Token\n"
        "  Named pipe creation     blocked                  configurable\n"
        "  Network isolation       configurable             unrestricted\n"
        "  Object namespace        isolated                 shared\n"
        "  System dir blocking     configurable             always readable\n"
        "  Registry access         fixed private hive       configurable\n"
        "  Low integrity           yes                      configurable\n"
        "  File/folder grants      configurable             configurable\n"
        "  Resource limits         yes                      yes\n",
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

