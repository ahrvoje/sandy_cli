// =========================================================================
// TomlParser.h — Lightweight TOML parser (subset)
//
// Parses TOML into a generic TomlDocument structure.
// Supports: sections, scalar key=value, string arrays, single/double quotes,
//           escape sequences in double-quoted strings, inline/full-line comments,
//           multi-line arrays, literal \n (for CLI -s usage).
//
// This module has no Sandy-specific knowledge and can be replaced with
// a full TOML library (e.g. toml++, toml11) by providing the same types.
// =========================================================================
#pragma once

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <cstdio>

namespace Toml {

// -----------------------------------------------------------------------
// Data types — the public interface consumed by the application
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
// Unescape TOML double-quoted string (\\, \n, \t, \r, \")
// -----------------------------------------------------------------------
inline std::wstring UnescapeDQ(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == L'\\' && i + 1 < s.size()) {
            switch (s[i + 1]) {
                case L'\\': out += L'\\'; i++; break;
                case L'n':  out += L'\n'; i++; break;
                case L't':  out += L'\t'; i++; break;
                case L'r':  out += L'\r'; i++; break;
                case L'"':  out += L'"';  i++; break;
                default:    out += s[i]; break;
            }
        } else {
            out += s[i];
        }
    }
    return out;
}

// -----------------------------------------------------------------------
// Strip a quoted string value, applying escape processing for DQ strings.
// Returns the unquoted value. Sets `error` if unterminated.
// -----------------------------------------------------------------------
inline std::wstring StripQuotes(const std::wstring& val, bool& error) {
    error = false;
    if (val.size() < 2) {
        if (!val.empty() && (val.front() == L'"' || val.front() == L'\'')) {
            error = true;
        }
        return val;
    }
    if ((val.front() == L'"'  && val.back() == L'"') ||
        (val.front() == L'\'' && val.back() == L'\''))
    {
        bool isDQ = (val.front() == L'"');
        std::wstring inner = val.substr(1, val.size() - 2);
        return isDQ ? UnescapeDQ(inner) : inner;
    }
    if (val.front() == L'"' || val.front() == L'\'') {
        error = true;
    }
    return val;
}

// -----------------------------------------------------------------------
// Extract all quoted strings from text (for array parsing).
// Handles both 'literal' and "basic" TOML strings.
// -----------------------------------------------------------------------
inline std::vector<std::wstring> ExtractQuotedStrings(const std::wstring& text) {
    std::vector<std::wstring> result;
    size_t pos = 0;
    while (pos < text.size()) {
        auto sq = text.find(L'\'', pos);
        auto dq = text.find(L'"', pos);
        if (sq == std::wstring::npos && dq == std::wstring::npos) break;

        bool isSingle = (sq != std::wstring::npos && (dq == std::wstring::npos || sq < dq));
        wchar_t quote = isSingle ? L'\'' : L'"';
        size_t qstart = isSingle ? sq : dq;
        auto qend = text.find(quote, qstart + 1);
        if (qend == std::wstring::npos) break;

        std::wstring s = text.substr(qstart + 1, qend - qstart - 1);
        if (!isSingle) s = UnescapeDQ(s);
        if (!s.empty()) result.push_back(s);
        pos = qend + 1;
    }
    return result;
}

// -----------------------------------------------------------------------
// Trim whitespace from both ends
// -----------------------------------------------------------------------
inline std::wstring Trim(const std::wstring& s) {
    auto start = s.find_first_not_of(L" \t");
    if (start == std::wstring::npos) return {};
    auto end = s.find_last_not_of(L" \t");
    return s.substr(start, end - start + 1);
}

// -----------------------------------------------------------------------
// Strip inline comment (respecting quoted strings)
// -----------------------------------------------------------------------
inline std::wstring StripInlineComment(const std::wstring& line) {
    if (line.front() == L'"' || line.front() == L'\'') return line;
    bool inQuote = false;
    wchar_t quoteChar = 0;
    for (size_t i = 0; i < line.size(); i++) {
        if (!inQuote && (line[i] == L'\'' || line[i] == L'"')) {
            inQuote = true;
            quoteChar = line[i];
        } else if (inQuote && line[i] == quoteChar) {
            inQuote = false;
        } else if (!inQuote && line[i] == L'#') {
            return Trim(line.substr(0, i));
        }
    }
    return line;
}

// -----------------------------------------------------------------------
// Convert literal \n sequences to real newlines (for CLI -s usage)
// -----------------------------------------------------------------------
inline std::wstring ConvertLiteralNewlines(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == L'\\' && i + 1 < s.size() && s[i + 1] == L'n') {
            out += L'\n';
            i++;
        } else {
            out += s[i];
        }
    }
    return out;
}

// -----------------------------------------------------------------------
// Parse a TOML string into a TomlDocument.
// -----------------------------------------------------------------------
inline ParseResult Parse(const std::wstring& contentRaw) {
    ParseResult result;
    std::wstring content = ConvertLiteralNewlines(contentRaw);

    std::wstring currentSection;
    std::wstringstream ss(content);
    std::wstring line;

    while (std::getline(ss, line)) {
        // Trim \r
        if (!line.empty() && line.back() == L'\r')
            line.pop_back();

        line = Trim(line);
        if (line.empty() || line[0] == L'#')
            continue;

        // Strip inline comments
        line = StripInlineComment(line);
        if (line.empty()) continue;

        // Section header
        if (line.front() == L'[' && line.back() == L']') {
            currentSection = line.substr(1, line.size() - 2);
            // Ensure section exists in document even if empty
            result.doc[currentSection];
            continue;
        }

        // Key = value
        auto eq = line.find(L'=');
        if (eq == std::wstring::npos) {
            // Bare continuation line inside an array — skip silently
            // (arrays are handled by looking back at the last key)
            continue;
        }

        std::wstring key = Trim(line.substr(0, eq));
        std::wstring rawVal = Trim(line.substr(eq + 1));

        // Detect array: value starts with '['
        if (!rawVal.empty() && rawVal.front() == L'[') {
            TomlValue tv;
            tv.isArray = true;

            // Collect all lines of the array
            std::wstring arrayText = rawVal;
            bool closed = (rawVal.find(L']') != std::wstring::npos);

            while (!closed) {
                std::wstring contLine;
                if (!std::getline(ss, contLine)) break;
                if (!contLine.empty() && contLine.back() == L'\r') contLine.pop_back();
                contLine = Trim(contLine);
                if (contLine.empty() || contLine[0] == L'#') continue;
                arrayText += L' ' + contLine;
                if (contLine.find(L']') != std::wstring::npos) closed = true;
            }

            tv.arr = ExtractQuotedStrings(arrayText);
            result.doc[currentSection][key] = tv;
        }
        else {
            // Scalar value
            TomlValue tv;
            bool quoteErr = false;
            tv.str = StripQuotes(rawVal, quoteErr);
            if (quoteErr) {
                wchar_t buf[256];
                swprintf(buf, 256, L"Unterminated quote in value for key '%ls'", key.c_str());
                result.errors.push_back(buf);
            }
            result.doc[currentSection][key] = tv;
        }
    }

    return result;
}

} // namespace Toml
