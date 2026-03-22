#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

// -----------------------------------------------------------------------
// TomlQuotedValue -- emit a string as TOML, using double-quotes with
// escaping when the value contains an apostrophe.
// -----------------------------------------------------------------------
inline void TomlQuotedValue(const std::wstring& val)
{
    if (val.find(L'\'') != std::wstring::npos) {
        // Escape backslashes and double-quotes for a TOML basic string
        std::wstring escaped;
        for (auto ch : val) {
            if (ch == L'\\') escaped += L"\\\\";
            else if (ch == L'"') escaped += L"\\\"";
            else escaped += ch;
        }
        printf("\"%ls\"", escaped.c_str());
    } else {
        printf("'%ls'", val.c_str());
    }
}

// -----------------------------------------------------------------------
// PrintFolderToml -- print grouped folder entries as resolved TOML.
// Shared by --print-config and --profile-info so persisted config and
// runtime config display never drift.
// -----------------------------------------------------------------------
inline void PrintFolderToml(const wchar_t* section,
                            const std::vector<FolderEntry>& entries,
                            GrantScope scope)
{
    printf("[%ls]\n", section);
    for (int a = 0; a <= static_cast<int>(AccessLevel::Create); a++) {
        auto lvl = static_cast<AccessLevel>(a);
        bool first = true;
        for (const auto& e : entries) {
            if (e.access != lvl || e.scope != scope) continue;
            if (first) {
                printf("%ls = [", AccessLevelName(lvl));
                first = false;
            } else {
                printf(", ");
            }
            TomlQuotedValue(e.path);
        }
        if (!first) printf("]\n");
    }
}

// -----------------------------------------------------------------------
// PrintResolvedConfig -- print a fully resolved config in TOML form.
// -----------------------------------------------------------------------
inline void PrintResolvedConfig(const SandboxConfig& config)
{
    bool isRT = IsRestrictedTokenMode(config.tokenMode);

    printf("[sandbox]\n");
    printf("token = '%ls'\n", TokenModeName(config.tokenMode));
    if (isRT)
        printf("integrity = '%ls'\n",
               config.integrity == IntegrityLevel::Low ? L"low" : L"medium");
    if (isRT && config.strict)
        printf("strict = true\n");
    printf("workdir = ");
    TomlQuotedValue(config.workdir.empty() ? L"inherit" : config.workdir);
    printf("\n\n");

    PrintFolderToml(L"allow.deep", config.folders, GrantScope::Deep);
    PrintFolderToml(L"allow.this", config.folders, GrantScope::This);
    printf("\n");
    PrintFolderToml(L"deny.deep", config.denyFolders, GrantScope::Deep);
    PrintFolderToml(L"deny.this", config.denyFolders, GrantScope::This);

    printf("\n[privileges]\n");
    if (!isRT) {
        printf("network         = %ls\n", config.allowNetwork ? L"true" : L"false");
        printf("lan             = %ls\n", LanModeTomlDisplayValue(config.lanMode));
    } else {
        printf("named_pipes     = %ls\n", config.allowNamedPipes ? L"true" : L"false");
        printf("desktop         = %ls\n", config.allowDesktop ? L"true" : L"false");
    }
    if (config.stdinMode == L"NUL")
        printf("stdin           = false\n");
    else if (config.stdinMode.empty())
        printf("stdin           = true\n");
    else {
        printf("stdin           = ");
        TomlQuotedValue(config.stdinMode);
        printf("\n");
    }
    printf("clipboard_read  = %ls\n", config.allowClipboardRead ? L"true" : L"false");
    printf("clipboard_write = %ls\n", config.allowClipboardWrite ? L"true" : L"false");
    printf("child_processes = %ls\n", config.allowChildProcesses ? L"true" : L"false");

    if (isRT) {
        bool hasRegKeys = !config.registryRead.empty() || !config.registryWrite.empty();
        if (hasRegKeys) {
            printf("\n[registry]\n");
            auto printKeys = [](const wchar_t* key, const std::vector<std::wstring>& values) {
                if (values.empty()) return;
                printf("%ls = [", key);
                for (size_t i = 0; i < values.size(); i++) {
                    if (i) printf(", ");
                    TomlQuotedValue(values[i]);
                }
                printf("]\n");
            };
            printKeys(L"read", config.registryRead);
            printKeys(L"write", config.registryWrite);
        }
    }

    printf("\n[environment]\n");
    printf("inherit = %ls\n", config.envInherit ? L"true" : L"false");
    if (!config.envPass.empty()) {
        printf("pass = [");
        for (size_t i = 0; i < config.envPass.size(); i++) {
            if (i) printf(", ");
            TomlQuotedValue(config.envPass[i]);
        }
        printf("]\n");
    }

    printf("\n[limit]\n");
    printf("timeout   = %lu\n", config.timeoutSeconds);
    printf("memory    = %zu\n", config.memoryLimitMB);
    printf("processes = %lu\n", config.maxProcesses);
}

} // namespace Sandbox
