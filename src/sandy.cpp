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
        "  sandy.exe -c <config.toml> [-l <logfile>] -x <executable> [args...]\n"
        "  sandy.exe -s \"<toml>\"      [-l <logfile>] -x <executable> [args...]\n"
        "\n"
        "Options:\n"
        "  -c <path>      Path to TOML config file (access, permissions, limits)\n"
        "  -s <toml>      Inline TOML config string (alternative to -c)\n"
        "  -l <path>      Log file for session output, config, and exit code\n"
        "  -x <path>      Path to executable to run sandboxed (.exe, .bat, etc.)\n"
        "  -v, --version  Print version and exit\n"
        "  -h, --help     Print this help text and exit\n"
        "\n"
        "Any arguments after the executable path are forwarded to it.\n"
        "\n"
        "Config file reference:\n"
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
        "  readwrite = [\n"
        "      'C:\\workspace',                     # project folder\n"
        "      'C:\\data\\state.db',                 # database file\n"
        "  ]\n"
        "\n"
        "  [allow]\n"
        "  system_dirs = true   # read C:\\Windows, Program Files (required for most exes)\n"
        "  # network = true     # outbound internet access\n"
        "  # localhost = true   # loopback/localhost connections (admin required)\n"
        "  # lan = true         # local network access\n"
        "\n"
        "  [limit]\n"
        "  # timeout = 300      # kill process after N seconds\n"
        "  # memory = 4096      # maximum memory in MB\n"
        "  # processes = 10     # maximum concurrent child processes\n",
        kVersion
    );
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
        if (arg == L"-c" && i + 1 < argc) {
            configPath = argv[++i];
        }
        else if (arg == L"-s" && i + 1 < argc) {
            configString = argv[++i];
        }
        else if (arg == L"-l" && i + 1 < argc) {
            logPath = argv[++i];
        }
        else if (arg == L"-x" && i + 1 < argc) {
            exePath = argv[++i];
            // Everything after -x <exe> is forwarded as arguments
            for (int j = i + 1; j < argc; j++) {
                if (!exeArgs.empty()) exeArgs += L" ";
                // Quote arguments that contain spaces
                std::wstring a = argv[j];
                if (a.find(L' ') != std::wstring::npos && a.front() != L'"') {
                    exeArgs += L"\"" + a + L"\"";
                } else {
                    exeArgs += a;
                }
            }
            break; // -x consumes all remaining args
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
    config.logPath = logPath;

    // --- Run sandboxed ---
    int exitCode = Sandbox::RunSandboxed(config, exePath, exeArgs);

    Sandbox::CleanupSandbox();

    return exitCode;
}

