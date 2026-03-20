// =========================================================================
// TomlAdapter.h — TOML parsing via toml11 (spec-compliant)
//
// Wraps toml11 v4.4.0 and exposes the same Toml:: types that Sandy's config
// mapper (SandboxConfig.h) consumes.  Replaces the former hand-rolled subset
// parser with a full TOML 1.0 implementation.
//
// Design:
//   - Same output types: TomlValue, TomlSection, TomlDocument, ParseResult
//   - Nested tables produced by toml11 for dotted headers like [allow.deep]
//     are flattened back into dotted string keys (e.g. section "allow.deep")
//   - ConvertLiteralNewlines() is preserved for -s CLI mode
//   - All parse errors are collected in ParseResult::errors
// =========================================================================
#pragma once

#include <string>
#include <vector>
#include <map>

// Suppress toml11 warnings for MSVC
#pragma warning(push)
#pragma warning(disable: 4244 4267 4996)
#include <toml.hpp>
#pragma warning(pop)

namespace Toml {

// -----------------------------------------------------------------------
// Data types — the public interface consumed by the application
// (identical to the former TomlParser.h types)
// -----------------------------------------------------------------------

struct TomlValue {
    std::wstring str;                    // scalar string value
    std::vector<std::wstring> arr;       // array of strings
    bool isArray = false;
};

// Section name → { key → value }
using TomlSection = std::map<std::wstring, TomlValue>;

// Top-level document: section name → section contents
// Keys outside any section go into section "" (empty string).
using TomlDocument = std::map<std::wstring, TomlSection>;

// -----------------------------------------------------------------------
// Parse errors — collected during parsing
// -----------------------------------------------------------------------

struct ParseResult {
    TomlDocument doc;
    std::vector<std::wstring> errors;
    bool ok() const { return errors.empty(); }
};

// -----------------------------------------------------------------------
// UTF-8 ↔ wstring helpers
// -----------------------------------------------------------------------
inline std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                    static_cast<int>(utf8.size()), nullptr, 0);
    if (wlen == 0) return {};
    std::wstring result(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                         static_cast<int>(utf8.size()), &result[0], wlen);
    return result;
}

inline std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                                   static_cast<int>(wide.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (len == 0) return {};
    std::string result(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                         static_cast<int>(wide.size()),
                         &result[0], len, nullptr, nullptr);
    return result;
}

// -----------------------------------------------------------------------
// Convert literal \n sequences to real newlines (for CLI -s usage)
// Preserved from the former parser — this is non-standard TOML behavior
// needed for inline config strings passed via -s flag.
// -----------------------------------------------------------------------
inline std::wstring ConvertLiteralNewlines(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    bool inSQ = false, inDQ = false;
    for (size_t i = 0; i < s.size(); i++) {
        if (!inDQ && s[i] == L'\'')  { inSQ = !inSQ; out += s[i]; }
        else if (!inSQ && s[i] == L'"') {
            // Count consecutive backslashes before this quote.
            // Odd count = escaped quote (\"); even count = real quote (\\")
            size_t bsCount = 0;
            size_t j = i;
            while (j > 0 && s[j - 1] == L'\\') { bsCount++; j--; }
            if (bsCount % 2 == 0) inDQ = !inDQ;
            out += s[i];
        }
        else if (!inSQ && !inDQ &&
                 s[i] == L'\\' && i + 1 < s.size() && s[i + 1] == L'n') {
            out += L'\n';
            i++;
        } else {
            out += s[i];
        }
    }
    return out;
}

// -----------------------------------------------------------------------
// Walk toml11 value tree and populate TomlDocument.
// Dotted section headers like [allow.deep] produce nested tables in toml11;
// we flatten them back into dotted names for the config mapper.
// -----------------------------------------------------------------------
namespace detail {

    // Recursively flatten a toml::value table into TomlDocument sections.
    // `prefix` is the dotted section path accumulated so far.
    //
    // Only creates a section in TomlDocument if the table has at least one
    // non-table child.  Pure passthrough parents (tables containing only
    // sub-tables, like `allow` when only `[allow.deep]` exists) are skipped
    // to avoid creating spurious empty sections the config mapper would reject.
    inline void FlattenTable(const toml::value& table,
                              const std::wstring& prefix,
                              TomlDocument& doc,
                              std::vector<std::wstring>& errors) {
        if (!table.is_table()) return;

        // First pass: check if this table has any non-table leaf children
        bool hasLeafChildren = false;
        for (const auto& [key, val] : table.as_table()) {
            if (!val.is_table()) { hasLeafChildren = true; break; }
        }

        // Only create the section if it has leaf children (or is the root)
        if (hasLeafChildren && !prefix.empty()) {
            doc[prefix];  // ensure section exists even before populating
        }

        for (const auto& [key, val] : table.as_table()) {
            std::wstring wkey = Utf8ToWide(key);

            if (val.is_table()) {
                // This is a sub-table — recurse with dotted prefix
                std::wstring childPrefix = prefix.empty()
                    ? wkey
                    : prefix + L"." + wkey;
                FlattenTable(val, childPrefix, doc, errors);
            }
            else if (val.is_array()) {
                // Check if this is an array of tables (not supported by Sandy config)
                // or an array of strings (the normal case for path lists)
                const auto& arr = val.as_array();
                TomlValue tv;
                tv.isArray = true;

                bool allStrings = true;
                for (const auto& elem : arr) {
                    if (elem.is_string()) {
                        tv.arr.push_back(Utf8ToWide(elem.as_string()));
                    } else {
                        allStrings = false;
                        break;
                    }
                }

                if (!allStrings) {
                    wchar_t buf[256];
                    swprintf(buf, 256,
                             L"Array for key '%ls' in [%ls] contains non-string elements",
                             wkey.c_str(), prefix.c_str());
                    errors.push_back(buf);
                    continue;
                }

                doc[prefix][wkey] = tv;
            }
            else if (val.is_string()) {
                TomlValue tv;
                tv.str = Utf8ToWide(val.as_string());
                doc[prefix][wkey] = tv;
            }
            else if (val.is_boolean()) {
                TomlValue tv;
                tv.str = val.as_boolean() ? L"true" : L"false";
                doc[prefix][wkey] = tv;
            }
            else if (val.is_integer()) {
                TomlValue tv;
                tv.str = std::to_wstring(val.as_integer());
                doc[prefix][wkey] = tv;
            }
            else if (val.is_floating()) {
                // Sandy doesn't use floats, but convert gracefully
                TomlValue tv;
                wchar_t buf[64];
                swprintf(buf, 64, L"%g", val.as_floating());
                tv.str = buf;
                doc[prefix][wkey] = tv;
            }
            else {
                // Unsupported TOML type (datetime, etc.)
                wchar_t buf[256];
                swprintf(buf, 256,
                         L"Unsupported TOML value type for key '%ls' in [%ls]",
                         wkey.c_str(), prefix.c_str());
                errors.push_back(buf);
            }
        }
    }

} // namespace detail

// -----------------------------------------------------------------------
// Parse a UTF-8 string into a TomlDocument (primary parse entry point).
// -----------------------------------------------------------------------
inline ParseResult ParseUtf8(const std::string& utf8Content) {
    ParseResult result;

    try {
        auto parsed = toml::parse_str(utf8Content);

        // Walk the top-level table and flatten into TomlDocument
        detail::FlattenTable(parsed, L"", result.doc, result.errors);

        // Detect bare top-level keys (keys in the root "" section).
        // Sandy requires all keys to be under an explicit [section] header.
        // toml11 puts bare keys into the root table alongside sub-tables.
        // We need to flag non-table root entries the same way the old parser did.
        for (const auto& [key, val] : parsed.as_table()) {
            if (!val.is_table()) {
                std::wstring wkey = Utf8ToWide(key);
                wchar_t buf[256];
                swprintf(buf, 256,
                         L"Key '%ls' appears before any [section] header — it will be ignored. Place it under the appropriate section.",
                         wkey.c_str());
                result.errors.push_back(buf);
            }
        }

    } catch (const toml::syntax_error& e) {
        // Convert toml11 parse error to our error format
        result.errors.push_back(Utf8ToWide(e.what()));
    } catch (const std::exception& e) {
        result.errors.push_back(Utf8ToWide(e.what()));
    }

    return result;
}

// -----------------------------------------------------------------------
// Parse a wide string into a TomlDocument.
// Used by ParseConfig(wstring) for -s mode and profile text.
// Applies ConvertLiteralNewlines before parsing.
// -----------------------------------------------------------------------
inline ParseResult Parse(const std::wstring& contentRaw) {
    std::wstring content = ConvertLiteralNewlines(contentRaw);
    std::string utf8 = WideToUtf8(content);
    return ParseUtf8(utf8);
}

} // namespace Toml
