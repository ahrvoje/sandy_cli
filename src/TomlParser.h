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
    if (val.front() == L'"' || val.front() == L'\'') {
        bool isDQ = (val.front() == L'"');
        // Find real closing quote (respecting escape sequences in DQ strings)
        size_t closePos = std::wstring::npos;
        if (isDQ) {
            for (size_t i = 1; i < val.size(); i++) {
                if (val[i] == L'\\') { i++; continue; }
                if (val[i] == L'"') { closePos = i; break; }
            }
        } else {
            closePos = val.find(L'\'', 1);
        }
        if (closePos == std::wstring::npos) {
            error = true;
            return val;
        }
        // P2: Reject trailing garbage after closing quote
        for (size_t i = closePos + 1; i < val.size(); i++) {
            if (val[i] != L' ' && val[i] != L'\t') {
                error = true;
                return val;
            }
        }
        std::wstring inner = val.substr(1, closePos - 1);
        return isDQ ? UnescapeDQ(inner) : inner;
    }
    return val;
}

// -----------------------------------------------------------------------
// Extract all quoted strings from text (for array parsing).
// Handles both 'literal' and "basic" TOML strings.
// P1: Validates comma separators between elements — adjacent quoted
// strings without a comma (e.g. ['a' 'b']) are rejected.
// -----------------------------------------------------------------------
inline std::vector<std::wstring> ExtractQuotedStrings(const std::wstring& text,
                                                      bool* unterminated = nullptr,
                                                      bool* missingComma = nullptr) {
    std::vector<std::wstring> result;
    if (unterminated) *unterminated = false;
    if (missingComma) *missingComma = false;
    size_t pos = 0;
    size_t prevQend = std::wstring::npos;  // end of previous quoted string
    while (pos < text.size()) {
        auto sq = text.find(L'\'', pos);
        auto dq = text.find(L'"', pos);
        if (sq == std::wstring::npos && dq == std::wstring::npos) break;

        bool isSingle = (sq != std::wstring::npos && (dq == std::wstring::npos || sq < dq));
        size_t qstart = isSingle ? sq : dq;

        // P1: Validate comma between previous element and this one
        if (prevQend != std::wstring::npos) {
            bool foundComma = false;
            for (size_t i = prevQend + 1; i < qstart; i++) {
                if (text[i] == L',') { foundComma = true; break; }
            }
            if (!foundComma) {
                if (missingComma) *missingComma = true;
                break;
            }
        }

        // Find closing quote — for DQ strings, skip escaped quotes (\")
        size_t qend = std::wstring::npos;
        if (!isSingle) {
            for (size_t i = qstart + 1; i < text.size(); i++) {
                if (text[i] == L'\\') { i++; continue; }
                if (text[i] == L'"') { qend = i; break; }
            }
        } else {
            qend = text.find(L'\'', qstart + 1);
        }
        if (qend == std::wstring::npos) {
            // Unterminated string element — flag the error
            if (unterminated) *unterminated = true;
            break;
        }

        std::wstring s = text.substr(qstart + 1, qend - qstart - 1);
        if (!isSingle) s = UnescapeDQ(s);
        result.push_back(s);
        prevQend = qend;
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
    if (line.empty()) return line;
    // P2: removed early-return for quote-leading lines — the quote-tracking
    // loop below already handles them correctly and the early-return caused
    // multi-line array continuation lines ('path', # comment) to keep the
    // # comment text, which later aborted parsing.
    bool inQuote = false;
    wchar_t quoteChar = 0;
    for (size_t i = 0; i < line.size(); i++) {
        if (!inQuote && (line[i] == L'\'' || line[i] == L'"')) {
            inQuote = true;
            quoteChar = line[i];
        } else if (inQuote && quoteChar == L'"' && line[i] == L'\\') {
            // P2: skip escaped character in DQ strings so \" doesn't toggle state
            i++;
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
    bool inSQ = false, inDQ = false;
    for (size_t i = 0; i < s.size(); i++) {
        if (!inDQ && s[i] == L'\'')  { inSQ = !inSQ; out += s[i]; }
        else if (!inSQ && s[i] == L'"') {
            // Count consecutive backslashes before this quote.
            // Odd count = escaped quote (\"); even count = real quote (\\").
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
                contLine = StripInlineComment(contLine);
                if (contLine.empty()) continue;
                arrayText += L' ' + contLine;
                if (contLine.find(L']') != std::wstring::npos) closed = true;
            }

            if (!closed) {
                wchar_t buf[256];
                swprintf(buf, 256, L"Unterminated array for key '%ls' (missing ']')", key.c_str());
                result.errors.push_back(buf);
            }

            bool unterminatedStr = false;
            bool missingComma = false;
            tv.arr = ExtractQuotedStrings(arrayText, &unterminatedStr, &missingComma);
            if (unterminatedStr) {
                wchar_t buf[256];
                swprintf(buf, 256, L"Unterminated string in array for key '%ls' (missing closing quote)", key.c_str());
                result.errors.push_back(buf);
            }
            if (missingComma) {
                wchar_t buf[256];
                swprintf(buf, 256, L"Missing comma between array elements for key '%ls'", key.c_str());
                result.errors.push_back(buf);
            }

            // P2: Validate array syntax — reject unquoted stray tokens
            {
                size_t vp = 0;
                while (vp < arrayText.size()) {
                    wchar_t ch = arrayText[vp];
                    if (ch == L'\'' || ch == L'"') {
                        // Skip quoted string
                        size_t qend = std::wstring::npos;
                        if (ch == L'"') {
                            for (size_t j = vp + 1; j < arrayText.size(); j++) {
                                if (arrayText[j] == L'\\') { j++; continue; }
                                if (arrayText[j] == L'"') { qend = j; break; }
                            }
                        } else {
                            qend = arrayText.find(L'\'', vp + 1);
                        }
                        if (qend == std::wstring::npos) break; // unterminated already reported
                        vp = qend + 1;
                    } else if (ch == L'[' || ch == L']' || ch == L',' ||
                               ch == L' ' || ch == L'\t' || ch == L'\n' || ch == L'\r') {
                        vp++;
                    } else {
                        wchar_t buf[256];
                        swprintf(buf, 256, L"Unexpected unquoted token in array for key '%ls'", key.c_str());
                        result.errors.push_back(buf);
                        break;
                    }
                }
            }

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
