// =============================================================================
//  Threat Analyzer - static file, log and live-system threat analysis (C++17)
//  Single-file build: declarations, core, scanner, log analyzer, Windows system
//  audit, reporting and the command-line interface.
// =============================================================================
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <wintrust.h>
#else
#include <unistd.h>
#endif
#include "threat_analyzer.hpp"

// =============================================================================
//  core
// =============================================================================
// Threat Analyzer - core utilities: severities, rule database, SHA-256, entropy, helpers.

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>


namespace ta {

// ======================================================================= severity
const char* severityName(Severity s) {
    switch (s) {
        case Severity::Info: return "INFO";
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

int severityWeight(Severity s) {
    switch (s) {
        case Severity::Info: return 0;
        case Severity::Low: return 2;
        case Severity::Medium: return 6;
        case Severity::High: return 15;
        case Severity::Critical: return 40;
    }
    return 0;
}

bool parseSeverity(const std::string& text, Severity& out) {
    const std::string t = toLower(trim(text));
    if (t == "info") out = Severity::Info;
    else if (t == "low") out = Severity::Low;
    else if (t == "medium" || t == "med") out = Severity::Medium;
    else if (t == "high") out = Severity::High;
    else if (t == "critical" || t == "crit") out = Severity::Critical;
    else return false;
    return true;
}

// ======================================================================= helpers
std::string toLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n\v\f";
    const size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return {};
    const size_t e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

std::string printable(const std::string& s, size_t maxLen) {
    std::string out;
    out.reserve(std::min(s.size(), maxLen) + 3);
    for (unsigned char c : s) {
        if (out.size() >= maxLen) {
            out += "...";
            break;
        }
        if (c >= 0x20 && c < 0x7f) out += static_cast<char>(c);
        else if (c == '\t' || c == '\r' || c == '\n') out += ' ';
        else out += '.';
    }
    return out;
}

std::string pathToUtf8(const fs::path& p) {
    const auto u = p.u8string();  // std::string in C++17, std::u8string in C++20
    return std::string(u.begin(), u.end());
}

fs::path utf8ToPath(const std::string& s) {
#if defined(__cpp_char8_t)
    return fs::path(std::u8string(s.begin(), s.end()));
#else
    return fs::u8path(s);
#endif
}

std::string formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        ++u;
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), u == 0 ? "%.0f %s" : "%.2f %s", v, units[u]);
    return buf;
}

std::string wideToUtf8(const std::wstring& w) {
#ifdef _WIN32
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
#else
    std::string s;
    for (wchar_t c : w) s += (c < 0x80) ? static_cast<char>(c) : '?';
    return s;
#endif
}

static bool validIPv4(const std::string& tok) {
    int parts = 0;
    size_t i = 0;
    while (i <= tok.size()) {
        size_t j = tok.find('.', i);
        if (j == std::string::npos) j = tok.size();
        const size_t len = j - i;
        if (len == 0 || len > 3) return false;
        int v = 0;
        for (size_t k = i; k < j; ++k) {
            if (!std::isdigit(static_cast<unsigned char>(tok[k]))) return false;
            v = v * 10 + (tok[k] - '0');
        }
        if (v > 255) return false;
        ++parts;
        i = j + 1;
        if (j == tok.size()) break;
    }
    return parts == 4;
}

std::vector<std::string> extractIPv4(const std::string& text) {
    std::vector<std::string> ips;
    const size_t n = text.size();
    size_t i = 0;
    while (i < n) {
        if (!std::isdigit(static_cast<unsigned char>(text[i]))) {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < n && (std::isdigit(static_cast<unsigned char>(text[j])) || text[j] == '.')) ++j;
        std::string tok = text.substr(i, j - i);
        while (!tok.empty() && tok.back() == '.') tok.pop_back();
        const bool glued = i > 0 && std::isalpha(static_cast<unsigned char>(text[i - 1]));
        if (!glued && validIPv4(tok)) ips.push_back(tok);
        i = j;
    }
    return ips;
}

bool isPrivateIPv4(const std::string& ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    return a == 10 || a == 127 || a == 0 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) ||
           (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127) || a >= 224;
}

// ======================================================================= rule database
static bool decodeHex(const std::string& text, std::vector<uint8_t>& out) {
    std::string h;
    for (char c : text)
        if (!std::isspace(static_cast<unsigned char>(c))) h += c;
    if (h.empty() || h.size() % 2 != 0) return false;
    out.clear();
    for (size_t i = 0; i < h.size(); i += 2) {
        if (!std::isxdigit(static_cast<unsigned char>(h[i])) || !std::isxdigit(static_cast<unsigned char>(h[i + 1])))
            return false;
        out.push_back(static_cast<uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    }
    return true;
}

bool RuleSet::load(const fs::path& file, std::string& error) {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        error = "cannot open rule file: " + pathToUtf8(file);
        return false;
    }
    hashRules.clear();
    stringRules.clear();
    hexRules.clear();
    logRules.clear();
    source = file;

    std::string raw;
    size_t lineNo = 0;
    while (std::getline(in, raw)) {
        ++lineNo;
        if (lineNo == 1 && raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF &&
            static_cast<unsigned char>(raw[1]) == 0xBB && static_cast<unsigned char>(raw[2]) == 0xBF)
            raw.erase(0, 3);  // UTF-8 BOM
        const std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;

        const std::string where = pathToUtf8(file.filename()) + ":" + std::to_string(lineNo) + ": ";
        const size_t p1 = line.find('|');
        const size_t p2 = p1 == std::string::npos ? p1 : line.find('|', p1 + 1);
        const size_t p3 = p2 == std::string::npos ? p2 : line.find('|', p2 + 1);
        if (p3 == std::string::npos) {
            error = where + "expected TYPE|NAME|SEVERITY|VALUE";
            return false;
        }
        Rule r;
        const std::string type = toLower(trim(line.substr(0, p1)));
        r.name = trim(line.substr(p1 + 1, p2 - p1 - 1));
        const std::string sev = line.substr(p2 + 1, p3 - p2 - 1);
        r.value = trim(line.substr(p3 + 1));
        if (r.name.empty() || r.value.empty()) {
            error = where + "rule name and value must not be empty";
            return false;
        }
        if (!parseSeverity(sev, r.severity)) {
            error = where + "unknown severity '" + trim(sev) + "'";
            return false;
        }

        if (type == "hash") {
            r.type = Rule::Type::Hash;
            r.value = toLower(r.value);
            const bool hex = std::all_of(r.value.begin(), r.value.end(),
                                         [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; });
            if (r.value.size() != 64 || !hex) {
                error = where + "HASH value must be a 64 character SHA-256 hex string";
                return false;
            }
            hashRules.push_back(std::move(r));
        } else if (type == "string") {
            r.type = Rule::Type::String;
            r.value = toLower(r.value);
            stringRules.push_back(std::move(r));
        } else if (type == "hex") {
            r.type = Rule::Type::Hex;
            if (!decodeHex(r.value, r.bytes)) {
                error = where + "HEX value must be an even number of hex digits";
                return false;
            }
            hexRules.push_back(std::move(r));
        } else if (type == "log") {
            r.type = Rule::Type::Regex;
            try {
                r.re = std::regex(r.value, std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
            } catch (const std::regex_error& e) {
                error = where + "invalid regular expression (" + e.what() + ")";
                return false;
            }
            logRules.push_back(std::move(r));
        } else {
            error = where + "unknown rule type '" + type + "' (use HASH, STRING, HEX or LOG)";
            return false;
        }
    }
    return true;
}

size_t RuleSet::total() const {
    return hashRules.size() + stringRules.size() + hexRules.size() + logRules.size();
}

// ======================================================================= SHA-256 (FIPS 180-4)
namespace {
constexpr uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
}  // namespace

Sha256::Sha256() {
    const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(state_, init, sizeof(init));
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::transform(const uint8_t* b) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(b[4 * i]) << 24) | (uint32_t(b[4 * i + 1]) << 16) | (uint32_t(b[4 * i + 2]) << 8) |
               uint32_t(b[4 * i + 3]);
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state_[0], bb = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = h + S1 + ch + kSha256K[i] + w[i];
        const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & bb) ^ (a & c) ^ (bb & c);
        const uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = bb;
        bb = a;
        a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += bb;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const uint8_t* data, size_t len) {
    totalLen_ += len;
    while (len > 0) {
        const size_t take = std::min(len, sizeof(buffer_) - bufferLen_);
        std::memcpy(buffer_ + bufferLen_, data, take);
        bufferLen_ += take;
        data += take;
        len -= take;
        if (bufferLen_ == sizeof(buffer_)) {
            transform(buffer_);
            bufferLen_ = 0;
        }
    }
}

std::string Sha256::hexDigest() {
    const uint64_t bits = totalLen_ * 8;
    buffer_[bufferLen_++] = 0x80;
    if (bufferLen_ > 56) {
        std::memset(buffer_ + bufferLen_, 0, 64 - bufferLen_);
        transform(buffer_);
        bufferLen_ = 0;
    }
    std::memset(buffer_ + bufferLen_, 0, 56 - bufferLen_);
    for (int i = 0; i < 8; ++i) buffer_[56 + i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
    transform(buffer_);
    bufferLen_ = 0;

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint32_t v : state_)
        for (int shift = 28; shift >= 0; shift -= 4) out += hex[(v >> shift) & 0xF];
    return out;
}

std::string sha256Hex(const uint8_t* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.hexDigest();
}

bool sha256File(const fs::path& file, std::string& hexOut) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    Sha256 h;
    std::vector<char> buf(1 << 16);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) h.update(reinterpret_cast<const uint8_t*>(buf.data()), static_cast<size_t>(got));
    }
    if (in.bad()) return false;
    hexOut = h.hexDigest();
    return true;
}

double shannonEntropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i) ++counts[data[i]];
    double e = 0.0;
    const double n = static_cast<double>(len);
    for (size_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        e -= p * std::log2(p);
    }
    return e;
}

}  // namespace ta

// =============================================================================
//  scanner
// =============================================================================
// Threat Analyzer - static file scanner: signatures, PE structure checks and heuristics.

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>

namespace ta {

namespace {

const std::set<std::string> kExecExt = {".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js",
                                        ".jse", ".wsf", ".ps1", ".hta", ".pif", ".msi", ".jar", ".lnk",
                                        ".cpl", ".dll"};

const std::set<std::string> kLureExt = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                                        ".txt", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3",
                                        ".mp4", ".avi", ".zip", ".rar", ".rtf", ".csv", ".odt"};

const std::set<std::string> kCompressedExt = {
    ".zip", ".gz",   ".tgz",  ".7z",   ".rar",  ".xz",   ".bz2", ".zst",  ".cab",   ".jar",  ".apk",
    ".docx", ".xlsx", ".pptx", ".odt",  ".ods",  ".jpg",  ".jpeg", ".png", ".gif",   ".webp", ".heic",
    ".mp3",  ".mp4",  ".mkv",  ".avi",  ".mov",  ".webm", ".flac", ".ogg", ".aac",   ".m4a",  ".pdf",
    ".woff", ".woff2", ".msi", ".pack", ".idx",  ".whl",  ".nupkg", ".iso", ".dmg",  ".gpg",  ".pgp",
    ".crx",  ".vsix", ".pak",  ".pyc",  ".jxl",  ".avif", ".epub", ".msix", ".appx", ".lzma", ".br"};

const std::set<std::string> kEncodedTextExt = {".pem", ".crt", ".cer", ".key", ".asc", ".eml",
                                               ".mbox", ".p7b", ".sig", ".pub", ".msg"};

const char* kPackerSections[][2] = {
    {"upx0", "UPX"},       {"upx1", "UPX"},          {"upx2", "UPX"},          {".aspack", "ASPack"},
    {".adata", "ASPack"},  {"mpress1", "MPRESS"},    {"mpress2", "MPRESS"},    {".petite", "Petite"},
    {".nsp0", "NsPack"},   {".nsp1", "NsPack"},      {".themida", "Themida"},  {".vmp0", "VMProtect"},
    {".vmp1", "VMProtect"}, {".enigma1", "Enigma"},  {".perplex", "Perplex"},  {"pec2", "PECompact"},
    {".mew", "MEW"},       {".packed", "generic packer"}};

const char* kInjectionApis[] = {"virtualallocex",      "writeprocessmemory", "createremotethread",
                                "ntunmapviewofsection", "queueuserapc",       "setthreadcontext",
                                "ntwritevirtualmemory", "rtlcreateuserthread"};

inline uint16_t rd16(const std::vector<uint8_t>& d, size_t o) {
    return static_cast<uint16_t>(d[o] | (d[o + 1] << 8));
}
inline uint32_t rd32(const std::vector<uint8_t>& d, size_t o) {
    return uint32_t(d[o]) | (uint32_t(d[o + 1]) << 8) | (uint32_t(d[o + 2]) << 16) | (uint32_t(d[o + 3]) << 24);
}

std::string fmtEntropy(double e) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2f", e);
    return buf;
}

bool startsWith(const std::vector<uint8_t>& d, const char* magic, size_t len, size_t offset = 0) {
    if (d.size() < offset + len) return false;
    return std::equal(magic, magic + len, d.begin() + static_cast<std::ptrdiff_t>(offset),
                      [](char a, uint8_t b) { return static_cast<uint8_t>(a) == b; });
}

bool isCompressedFormat(const std::string& ext, const std::vector<uint8_t>& d) {
    if (kCompressedExt.count(ext)) return true;
    return startsWith(d, "PK\x03\x04", 4) || startsWith(d, "\x1f\x8b", 2) || startsWith(d, "7z\xBC\xAF", 4) ||
           startsWith(d, "Rar!", 4) || startsWith(d, "\x89PNG", 4) || startsWith(d, "\xFF\xD8\xFF", 3) ||
           startsWith(d, "GIF8", 4) || startsWith(d, "%PDF", 4) || startsWith(d, "MSCF", 4) ||
           startsWith(d, "ID3", 3) || startsWith(d, "ftyp", 4, 4) || startsWith(d, "OggS", 4) ||
           startsWith(d, "fLaC", 4) || startsWith(d, "RIFF", 4) || startsWith(d, "wOFF", 4) ||
           startsWith(d, "wOF2", 4) || startsWith(d, "BZh", 3) || startsWith(d, "\xFD" "7zXZ", 5) ||
           startsWith(d, "\x28\xB5\x2F\xFD", 4) || startsWith(d, "\x1A\x45\xDF\xA3", 4);
}

Finding make(const char* category, std::string title, std::string detail, const std::string& target,
             Severity sev) {
    Finding f;
    f.category = category;
    f.title = std::move(title);
    f.detail = std::move(detail);
    f.target = target;
    f.severity = sev;
    return f;
}

// Parses the PE headers. Returns true when the buffer is a valid PE image.
bool analyzePE(const std::string& name, const std::vector<uint8_t>& d, const std::string& ext,
               double entropyThreshold, std::vector<Finding>& out) {
    const size_t size = d.size();
    if (size < 0x40 || d[0] != 'M' || d[1] != 'Z') return false;
    const uint32_t lfanew = rd32(d, 0x3C);
    if (size < 24 || lfanew > size - 24) return false;
    if (!(d[lfanew] == 'P' && d[lfanew + 1] == 'E' && d[lfanew + 2] == 0 && d[lfanew + 3] == 0)) return false;

    const size_t coff = lfanew + 4;
    const uint16_t numSections = rd16(d, coff + 2);
    const uint16_t optSize = rd16(d, coff + 16);
    const uint16_t characteristics = rd16(d, coff + 18);
    const size_t opt = coff + 20;
    const uint32_t entryPoint = (opt + 20 <= size) ? rd32(d, opt + 16) : 0;
    const bool isDll = (characteristics & 0x2000) != 0;

    if (kLureExt.count(ext)) {
        out.push_back(make("PE", "Executable disguised as " + ext + " file",
                           std::string("File has a Windows ") + (isDll ? "DLL" : "executable") +
                               " header but a document/media extension",
                           name, Severity::High));
    }
    if (numSections == 0 || numSections > 32) {
        out.push_back(make("PE", "Abnormal section count",
                           std::to_string(numSections) + " sections (normal images have 3-12)", name,
                           Severity::Low));
    }

    const size_t secTable = opt + optSize;
    bool entryInSection = (entryPoint == 0);
    std::set<std::string> packersSeen;
    for (size_t i = 0; i < std::min<size_t>(numSections, 96); ++i) {
        const size_t s = secTable + 40 * i;
        if (s + 40 > size) break;
        std::string secName;
        for (size_t k = 0; k < 8 && d[s + k] != 0; ++k) secName += static_cast<char>(d[s + k]);
        const std::string secLower = toLower(secName);
        const uint32_t vsize = rd32(d, s + 8);
        const uint32_t vaddr = rd32(d, s + 12);
        const uint32_t rawSize = rd32(d, s + 16);
        const uint32_t rawPtr = rd32(d, s + 20);
        const uint32_t chars = rd32(d, s + 36);
        const bool exec = (chars & 0x20000000u) != 0;
        const bool write = (chars & 0x80000000u) != 0;

        const uint32_t span = std::max(vsize, rawSize);
        if (entryPoint >= vaddr && entryPoint < vaddr + span) entryInSection = true;

        for (const auto& p : kPackerSections) {
            if (secLower == p[0] && packersSeen.insert(p[1]).second) {
                out.push_back(make("PE", std::string("Packed with ") + p[1],
                                   "Section '" + printable(secName, 8) + "' is characteristic of the " + p[1] +
                                       " packer/protector (hides real code from static analysis)",
                                   name, Severity::Medium));
            }
        }
        if (exec && write) {
            out.push_back(make("PE", "Writable + executable section",
                               "Section '" + printable(secName, 8) +
                                   "' is both writable and executable (self-modifying or unpacking code)",
                               name, Severity::Medium));
        }
        if (exec && rawSize >= 1024 && rawPtr < size && rawSize <= size - rawPtr) {
            const double e = shannonEntropy(d.data() + rawPtr, rawSize);
            if (e >= entropyThreshold) {
                out.push_back(make("PE", "High-entropy code section",
                                   "Executable section '" + printable(secName, 8) + "' has entropy " +
                                       fmtEntropy(e) + " bits/byte (packed or encrypted code)",
                                   name, Severity::Medium));
            }
        }
    }
    if (!entryInSection && numSections > 0) {
        out.push_back(make("PE", "Entry point outside all sections",
                           "AddressOfEntryPoint does not fall inside any section (common in packed malware)",
                           name, Severity::Medium));
    }
    return true;
}

}  // namespace

FileScanner::FileScanner(const RuleSet& rules, ScanOptions options) : rules_(rules), opt_(std::move(options)) {}

std::vector<Finding> FileScanner::scanPath(const fs::path& target, ScanStats& stats) const {
    std::vector<Finding> all;
    std::error_code ec;
    if (fs::is_regular_file(target, ec)) return scanFile(target, stats);
    if (!fs::is_directory(target, ec)) return all;

    // Iterative per-directory walk: an unreadable directory only skips that directory instead of
    // aborting the whole scan. Symlinks/junctions are not followed and depth is capped to avoid loops.
    struct Pending {
        fs::path dir;
        int depth;
    };
    std::vector<Pending> stack{{target, 0}};
    while (!stack.empty()) {
        const Pending cur = stack.back();
        stack.pop_back();
        fs::directory_iterator it(cur.dir, fs::directory_options::skip_permission_denied, ec), end;
        if (ec) {
            ++stats.dirsFailed;
            ec.clear();
            continue;
        }
        std::vector<fs::path> subdirs;
        while (it != end) {
            const fs::directory_entry& entry = *it;
            std::error_code fec;
            const fs::file_status st = entry.symlink_status(fec);
            if (!fec && !fs::is_symlink(st)) {
                if (fs::is_directory(st)) {
                    subdirs.push_back(entry.path());
                } else if (fs::is_regular_file(st)) {
                    auto found = scanFile(entry.path(), stats);
                    all.insert(all.end(), std::make_move_iterator(found.begin()),
                               std::make_move_iterator(found.end()));
                }
            }
            it.increment(ec);
            if (ec) {
                ++stats.dirsFailed;
                ec.clear();
                break;
            }
        }
        if (opt_.recursive && cur.depth < 64)
            for (auto d = subdirs.rbegin(); d != subdirs.rend(); ++d) stack.push_back({*d, cur.depth + 1});
    }
    return all;
}

std::vector<Finding> FileScanner::scanFile(const fs::path& file, ScanStats& stats) const {
    std::vector<Finding> out;
    std::error_code ec;
    if (!opt_.excluded.empty()) {
        const fs::path canon = fs::weakly_canonical(file, ec);
        if (!ec && opt_.excluded.count(canon)) return out;
        ec.clear();
    }

    const std::string name = pathToUtf8(file);
    const std::string ext = toLower(pathToUtf8(file.extension()));
    const std::string fileName = pathToUtf8(file.filename());

    // ---- filename tricks
    if (kExecExt.count(ext)) {
        const std::string inner = toLower(pathToUtf8(file.stem().extension()));
        if (kLureExt.count(inner)) {
            out.push_back(make("Heuristic", "Double file extension",
                               "'" + printable(fileName, 80) + "' pretends to be a " + inner + " but is a " + ext,
                               name, Severity::High));
        }
    }
    if (fileName.find("\xE2\x80\xAE") != std::string::npos) {
        out.push_back(make("Heuristic", "Right-to-left override in filename",
                           "Filename contains U+202E which visually reverses the extension", name,
                           Severity::High));
    }

    const uint64_t size = fs::file_size(file, ec);
    if (ec) {
        ++stats.filesFailed;
        return out;
    }

    // ---- large files: hash only
    if (size > opt_.maxFileSize) {
        std::string hash;
        if (!sha256File(file, hash)) {
            ++stats.filesFailed;
            return out;
        }
        ++stats.filesHashOnly;
        for (const auto& r : rules_.hashRules)
            if (r.value == hash)
                out.push_back(make("Signature", r.name, "SHA-256 matches known malicious hash " + hash, name,
                                   r.severity));
        return out;
    }

    std::vector<uint8_t> data(static_cast<size_t>(size));
    {
        std::ifstream in(file, std::ios::binary);
        if (!in) {
            ++stats.filesFailed;
            return out;
        }
        if (size > 0) in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
        if (static_cast<uint64_t>(in.gcount()) != size && size > 0) {
            ++stats.filesFailed;
            return out;
        }
    }
    ++stats.filesScanned;
    stats.bytesScanned += size;
    analyzeContent(name, data, ext, out, stats);
    return out;
}

void FileScanner::analyzeContent(const std::string& name, const std::vector<uint8_t>& data, const std::string& ext,
                                 std::vector<Finding>& out, ScanStats& stats) const {
    // ---- 1. hash signatures
    const std::string hash = sha256Hex(data.data(), data.size());
    for (const auto& r : rules_.hashRules)
        if (r.value == hash)
            out.push_back(make("Signature", r.name, "SHA-256 matches known malicious hash " + hash, name, r.severity));

    // ---- 2. string signatures (case-insensitive)
    std::string lower(data.begin(), data.end());
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    for (const auto& r : rules_.stringRules) {
        const size_t pos = lower.find(r.value);
        if (pos == std::string::npos) continue;
        const size_t from = pos >= 24 ? pos - 24 : 0;
        const std::string context(data.begin() + static_cast<std::ptrdiff_t>(from),
                                  data.begin() + static_cast<std::ptrdiff_t>(std::min(data.size(), pos + r.value.size() + 40)));
        out.push_back(make("Signature", r.name,
                           "Matched \"" + printable(r.value, 60) + "\" at offset " + std::to_string(pos) +
                               "  context: " + printable(context, 120),
                           name, r.severity));
    }

    // ---- 3. byte-pattern signatures
    for (const auto& r : rules_.hexRules) {
        auto it = std::search(data.begin(), data.end(), r.bytes.begin(), r.bytes.end());
        if (it == data.end()) continue;
        out.push_back(make("Signature", r.name,
                           "Byte pattern " + r.value + " found at offset " + std::to_string(it - data.begin()), name,
                           r.severity));
    }

    // ---- 4. PE structure
    const bool isPE = analyzePE(name, data, ext, opt_.entropyThreshold, out);
    if (isPE) ++stats.peFiles;

    // ---- 5. process-injection API combination
    std::vector<std::string> apis;
    for (const char* api : kInjectionApis)
        if (lower.find(api) != std::string::npos) apis.emplace_back(api);
    if (apis.size() >= 3) {
        std::string list;
        for (const auto& a : apis) list += (list.empty() ? "" : ", ") + a;
        // Scripts that reference these APIs (e.g. PowerShell Add-Type loaders) are far more suspicious than
        // compiled programs, where debuggers, browsers and security tools import them legitimately.
        out.push_back(make("Heuristic", "Process-injection API combination",
                           std::to_string(apis.size()) + " injection-related APIs referenced: " + list, name,
                           isPE ? Severity::Medium : Severity::High));
    }

    // ---- 6. text-only heuristics
    const size_t probe = std::min<size_t>(data.size(), 8192);
    const bool isText = !data.empty() && std::find(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(probe), 0) ==
                                             data.begin() + static_cast<std::ptrdiff_t>(probe);
    if (isText && !kEncodedTextExt.count(ext)) {
        size_t run = 0;
        for (size_t i = 0; i <= data.size(); ++i) {
            const bool b64 = i < data.size() && (std::isalnum(data[i]) || data[i] == '+' || data[i] == '/' || data[i] == '=');
            if (b64) {
                ++run;
                continue;
            }
            if (run >= 400) {
                const size_t start = i - run;
                const size_t ctxFrom = start >= 48 ? start - 48 : 0;
                const std::string before = lower.substr(ctxFrom, start - ctxFrom);
                const bool dataUri = before.find("data:image") != std::string::npos ||
                                     before.find("data:font") != std::string::npos ||
                                     before.find("data:application/font") != std::string::npos ||
                                     before.find("data:application/x-font") != std::string::npos;
                if (!dataUri) {
                    out.push_back(make("Heuristic", "Large encoded payload in text file",
                                       "Base64-like blob of " + std::to_string(run) + " characters at offset " +
                                           std::to_string(start) + " (often an embedded, hidden payload)",
                                       name, Severity::Medium));
                    break;
                }
            }
            run = 0;
        }

        size_t charCalls = 0;
        for (const char* tok : {"chr(", "char(", "fromcharcode", "[char]"}) {
            size_t p = 0;
            while ((p = lower.find(tok, p)) != std::string::npos) {
                ++charCalls;
                p += 4;
            }
        }
        if (charCalls >= 50) {
            out.push_back(make("Heuristic", "Character-code string obfuscation",
                               std::to_string(charCalls) + " chr()/fromCharCode calls - strings are being assembled to evade signatures",
                               name, Severity::Medium));
        }
    }

    // ---- 7. entropy of non-PE, non-compressed data
    if (!isPE && data.size() >= 4096 && !isCompressedFormat(ext, data)) {
        const double e = shannonEntropy(data.data(), data.size());
        if (e >= opt_.entropyThreshold) {
            out.push_back(make("Heuristic", "High-entropy content",
                               "Entropy " + fmtEntropy(e) + " bits/byte - data looks encrypted or packed "
                               "(ransomware output, encrypted payload or unknown archive)",
                               name, Severity::Low));
        }
    }
}

}  // namespace ta

// =============================================================================
//  log_analyzer
// =============================================================================
// Threat Analyzer - log analysis: signature rules, brute force, web enumeration and port scans.

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>

namespace ta {

namespace {

struct RuleHit {
    size_t count = 0;
    size_t firstLine = 0;
    std::string sample;
    std::set<std::string> ips;
};

struct LoginStats {
    size_t failures = 0;
    size_t firstLine = 0;
    size_t lastLine = 0;
    std::set<std::string> accounts;
    size_t successAfterBrute = 0;  // line number of a success after threshold failures
};

struct WebStats {
    size_t requests = 0;
    size_t notFound = 0;
    size_t loginPosts = 0;
    size_t firstLine = 0;
};

struct FwStats {
    std::set<int> ports;
    size_t events = 0;
    size_t firstLine = 0;
};

// Decode a UTF-16LE buffer (Windows PowerShell 5 "Out-File" default) to UTF-8.
std::string utf16leToUtf8(const std::string& raw) {
    std::string out;
    out.reserve(raw.size() / 2);
    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
        uint32_t cp = static_cast<uint8_t>(raw[i]) | (static_cast<uint8_t>(raw[i + 1]) << 8);
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < raw.size()) {
            const uint32_t lo = static_cast<uint8_t>(raw[i + 2]) | (static_cast<uint8_t>(raw[i + 3]) << 8);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        if (cp < 0x80) out += static_cast<char>(cp);
        else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

std::string joinLimited(const std::set<std::string>& items, size_t limit) {
    std::string s;
    size_t n = 0;
    for (const auto& i : items) {
        if (n == limit) {
            s += " (+" + std::to_string(items.size() - limit) + " more)";
            break;
        }
        s += (n ? ", " : "") + i;
        ++n;
    }
    return s;
}

bool looksLikeDate(const std::string& t) {
    return t.size() == 10 && t[4] == '-' && t[7] == '-' && std::isdigit(static_cast<unsigned char>(t[0]));
}

}  // namespace

std::vector<Finding> analyzeLog(const fs::path& file, const RuleSet& rules, const LogOptions& opt, LogStats& stats,
                                std::string& error) {
    std::vector<Finding> out;
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        error = "cannot open log file: " + pathToUtf8(file);
        return out;
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    if (content.size() >= 2 && static_cast<uint8_t>(content[0]) == 0xFF && static_cast<uint8_t>(content[1]) == 0xFE) {
        content = utf16leToUtf8(content.substr(2));
    } else if (content.size() >= 3 && static_cast<uint8_t>(content[0]) == 0xEF &&
               static_cast<uint8_t>(content[1]) == 0xBB && static_cast<uint8_t>(content[2]) == 0xBF) {
        content.erase(0, 3);
    } else if (content.find('\0') < std::min<size_t>(content.size(), 4096)) {
        error = "binary file - export binary logs (.evtx) to text first, see README 'Windows event logs'";
        return out;
    }

    static const std::regex failRe(
        R"(failed password|authentication failure|login failed|failed login|invalid user|logon failure|failed logon|eventid[=: "]*4625|an account failed to log on)",
        std::regex::icase | std::regex::optimize);
    static const std::regex successRe(
        R"(accepted password|accepted publickey|login successful|successful login|logged in successfully|eventid[=: "]*4624)",
        std::regex::icase | std::regex::optimize);
    static const std::regex userRe(R"(for (?:invalid user )?([A-Za-z0-9._$@\\-]+) from)", std::regex::icase);
    static const std::regex accountRe(R"(account name:\s*([A-Za-z0-9._$@\\-]+)\s+account domain)", std::regex::icase);
    static const std::regex webRe(R"rx(^(\S+) \S+ \S+ \[[^\]]*\] "([A-Z]+) (\S+)[^"]*" (\d{3}))rx",
                                  std::regex::optimize);
    static const std::regex loginPathRe(R"(login|signin|wp-login|logon|auth|admin)", std::regex::icase);
    static const std::regex iptablesRe(R"(SRC=(\d{1,3}(?:\.\d{1,3}){3}).*?DPT=(\d+))", std::regex::optimize);

    std::vector<RuleHit> hits(rules.logRules.size());
    std::map<std::string, LoginStats> logins;
    std::map<std::string, WebStats> web;
    std::map<std::string, FwStats> fw;
    std::set<std::string> allIps;

    std::istringstream lines(content);
    std::string line;
    size_t lineNo = 0;
    while (std::getline(lines, line)) {
        ++lineNo;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line.size() > 8192) line.resize(8192);
        ++stats.lines;

        const std::vector<std::string> ips = extractIPv4(line);
        for (const auto& ip : ips) allIps.insert(ip);

        // ---- signature rules
        for (size_t i = 0; i < rules.logRules.size(); ++i) {
            if (!std::regex_search(line, rules.logRules[i].re)) continue;
            RuleHit& h = hits[i];
            if (h.count++ == 0) {
                h.firstLine = lineNo;
                h.sample = printable(line, 180);
            }
            for (const auto& ip : ips)
                if (h.ips.size() < 64) h.ips.insert(ip);
        }

        // ---- authentication
        if (std::regex_search(line, failRe)) {
            ++stats.failedLogins;
            if (!ips.empty()) {
                LoginStats& ls = logins[ips.front()];
                if (ls.failures++ == 0) ls.firstLine = lineNo;
                ls.lastLine = lineNo;
                std::smatch m;
                if (std::regex_search(line, m, userRe) || std::regex_search(line, m, accountRe))
                    if (ls.accounts.size() < 256) ls.accounts.insert(m[1].str());
            }
        } else if (!ips.empty() && std::regex_search(line, successRe)) {
            auto it = logins.find(ips.front());
            if (it != logins.end() && it->second.failures >= static_cast<size_t>(opt.bruteForceThreshold) &&
                it->second.successAfterBrute == 0)
                it->second.successAfterBrute = lineNo;
        }

        // ---- web access log (Common / Combined Log Format)
        std::smatch wm;
        if (std::regex_search(line, wm, webRe)) {
            ++stats.httpRequests;
            WebStats& ws = web[wm[1].str()];
            if (ws.requests++ == 0) ws.firstLine = lineNo;
            const int status = std::stoi(wm[4].str());
            if (status == 404) ++ws.notFound;
            if (wm[2].str() == "POST" && std::regex_search(wm[3].str(), loginPathRe) &&
                (status == 200 || status == 401 || status == 403))
                ++ws.loginPosts;
            continue;
        }

        // ---- firewall: iptables / ufw
        std::smatch fm;
        if (std::regex_search(line, fm, iptablesRe)) {
            ++stats.firewallEvents;
            FwStats& f = fw[fm[1].str()];
            if (f.events++ == 0) f.firstLine = lineNo;
            f.ports.insert(std::stoi(fm[2].str()));
            continue;
        }

        // ---- firewall: Windows pfirewall.log  (date time action protocol src dst sport dport ...)
        std::istringstream tok(line);
        std::vector<std::string> t;
        std::string w;
        while (t.size() < 8 && tok >> w) t.push_back(w);
        if (t.size() == 8 && looksLikeDate(t[0]) && (t[2] == "DROP" || t[2] == "ALLOW")) {
            ++stats.firewallEvents;
            if (t[2] == "DROP" && !extractIPv4(t[4]).empty()) {
                FwStats& f = fw[t[4]];
                if (f.events++ == 0) f.firstLine = lineNo;
                try {
                    f.ports.insert(std::stoi(t[7]));
                } catch (...) {
                }
            }
        }
    }
    stats.uniqueIps = allIps.size();
    const std::string fname = pathToUtf8(file.filename());

    // ---- emit signature findings (one per rule)
    for (size_t i = 0; i < hits.size(); ++i) {
        const RuleHit& h = hits[i];
        if (h.count == 0) continue;
        Finding f;
        f.category = "Log";
        f.title = rules.logRules[i].name;
        f.severity = rules.logRules[i].severity;
        f.target = fname + ":" + std::to_string(h.firstLine);
        f.detail = std::to_string(h.count) + " matching line(s)";
        if (!h.ips.empty()) f.detail += " from " + joinLimited(h.ips, 5);
        f.detail += ". First: " + h.sample;
        out.push_back(std::move(f));
    }

    // ---- brute force
    for (const auto& kv : logins) {
        const LoginStats& ls = kv.second;
        if (ls.failures < static_cast<size_t>(opt.bruteForceThreshold)) continue;
        Finding f;
        f.category = "Log";
        f.target = kv.first;
        const bool spray = ls.accounts.size() >= 5;
        f.title = spray ? "Password spraying / brute-force login attempts" : "Brute-force login attempts";
        f.severity = Severity::High;
        f.detail = std::to_string(ls.failures) + " failed logins (lines " + std::to_string(ls.firstLine) + "-" +
                   std::to_string(ls.lastLine) + ")";
        if (!ls.accounts.empty())
            f.detail += " against " + std::to_string(ls.accounts.size()) + " account(s): " + joinLimited(ls.accounts, 6);
        out.push_back(f);
        if (ls.successAfterBrute) {
            Finding s;
            s.category = "Log";
            s.target = kv.first;
            s.title = "Successful login after brute force";
            s.severity = Severity::Critical;
            s.detail = "Login succeeded at line " + std::to_string(ls.successAfterBrute) + " after " +
                       std::to_string(ls.failures) + "+ failures - account is likely compromised";
            out.push_back(s);
        }
    }

    // ---- web enumeration / login brute force
    for (const auto& kv : web) {
        const WebStats& ws = kv.second;
        if (ws.notFound >= static_cast<size_t>(opt.notFoundThreshold)) {
            Finding f;
            f.category = "Log";
            f.target = kv.first;
            f.title = "Web content enumeration (forced browsing)";
            f.severity = Severity::Medium;
            f.detail = std::to_string(ws.notFound) + " HTTP 404 responses out of " + std::to_string(ws.requests) +
                       " requests, starting line " + std::to_string(ws.firstLine);
            out.push_back(f);
        }
        if (ws.loginPosts >= static_cast<size_t>(opt.bruteForceThreshold)) {
            Finding f;
            f.category = "Log";
            f.target = kv.first;
            f.title = "Web login brute force";
            f.severity = Severity::High;
            f.detail = std::to_string(ws.loginPosts) + " POST requests to login/admin endpoints";
            out.push_back(f);
        }
    }

    // ---- port scans
    for (const auto& kv : fw) {
        const FwStats& f = kv.second;
        if (f.ports.size() < static_cast<size_t>(opt.portScanThreshold)) continue;
        std::set<std::string> sample;
        for (int p : f.ports) {
            if (sample.size() == 8) break;
            sample.insert(std::to_string(p));
        }
        Finding x;
        x.category = "Log";
        x.target = kv.first;
        x.title = "Port scan";
        x.severity = Severity::High;
        x.detail = std::to_string(f.ports.size()) + " distinct destination ports probed in " + std::to_string(f.events) +
                   " blocked packets (first line " + std::to_string(f.firstLine) + "), e.g. ports " +
                   joinLimited(sample, 8);
        out.push_back(x);
    }
    return out;
}

}  // namespace ta

// =============================================================================
//  system_monitor
// =============================================================================
// Threat Analyzer - live Windows system audit: processes, TCP connections and autorun persistence.


#include <algorithm>
#include <cstdio>
#include <map>

namespace ta {

#ifndef _WIN32

bool systemAuditSupported() { return false; }

std::vector<Finding> analyzeSystem(const RuleSet&, const SystemOptions&, SystemStats&, std::string& error) {
    error = "the live system audit is only available in Windows builds";
    return {};
}

#else

namespace {

struct ProcInfo {
    DWORD pid = 0;
    DWORD ppid = 0;
    std::string name;
    std::string nameLower;
    std::string path;
    std::string pathLower;
};

std::string windowsDirLower() {
    wchar_t buf[MAX_PATH] = {0};
    const UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
    std::string s = toLower(wideToUtf8(std::wstring(buf, n)));
    if (s.empty()) s = "c:\\windows";
    if (s.back() == '\\') s.pop_back();
    return s;
}

std::string envVar(const wchar_t* name) {
    wchar_t buf[32768];
    const DWORD n = GetEnvironmentVariableW(name, buf, 32768);
    if (n == 0 || n >= 32768) return {};
    return wideToUtf8(std::wstring(buf, n));
}

bool isElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != 0;
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// True when the file carries a valid embedded Authenticode signature chaining to a trusted root.
bool hasValidSignature(const fs::path& file) {
    const std::wstring path = file.wstring();
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return status == ERROR_SUCCESS;
}

const char* suspiciousLocation(const std::string& lowerPath) {
    static const char* places[][2] = {
        {"\\appdata\\local\\temp\\", "user Temp folder"},
        {"\\windows\\temp\\", "Windows Temp folder"},
        {"\\users\\public\\", "Public user folder"},
        {"\\$recycle.bin\\", "Recycle Bin"},
        {"\\downloads\\", "Downloads folder"},
        {"\\perflogs\\", "PerfLogs folder"},
        {"\\windows\\tasks\\", "Windows Tasks folder"},
        {"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\", "Startup folder"}};
    for (const auto& p : places)
        if (lowerPath.find(p[0]) != std::string::npos) return p[1];
    return nullptr;
}

std::map<DWORD, ProcInfo> listProcesses() {
    std::map<DWORD, ProcInfo> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return procs;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo p;
            p.pid = pe.th32ProcessID;
            p.ppid = pe.th32ParentProcessID;
            p.name = wideToUtf8(pe.szExeFile);
            p.nameLower = toLower(p.name);
            if (p.pid > 4) {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
                if (h) {
                    wchar_t buf[32768];
                    DWORD len = 32768;
                    if (QueryFullProcessImageNameW(h, 0, buf, &len)) {
                        p.path = wideToUtf8(std::wstring(buf, len));
                        p.pathLower = toLower(p.path);
                    }
                    CloseHandle(h);
                }
            }
            procs[p.pid] = std::move(p);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return procs;
}

std::string procLabel(const ProcInfo& p) { return p.name + " (PID " + std::to_string(p.pid) + ")"; }

// ------------------------------------------------------------------ processes
void auditProcesses(const std::map<DWORD, ProcInfo>& procs, std::vector<Finding>& out) {
    const std::string win = windowsDirLower();
    const std::string sys32 = win + "\\system32\\";
    const std::string wow64 = win + "\\syswow64\\";

    static const std::set<std::string> systemNames = {
        "svchost.exe", "lsass.exe",   "csrss.exe",   "winlogon.exe", "services.exe", "smss.exe",
        "wininit.exe", "spoolsv.exe", "taskhostw.exe", "lsaiso.exe", "dwm.exe",      "conhost.exe",
        "dllhost.exe", "sihost.exe",  "fontdrvhost.exe", "ctfmon.exe", "wmiprvse.exe", "searchindexer.exe",
        "taskmgr.exe", "cmd.exe",     "rundll32.exe", "regsvr32.exe"};
    static const std::map<std::string, std::string> typosquats = {
        {"scvhost.exe", "svchost.exe"}, {"svch0st.exe", "svchost.exe"}, {"svhost.exe", "svchost.exe"},
        {"svchosts.exe", "svchost.exe"}, {"lsas.exe", "lsass.exe"},     {"lssass.exe", "lsass.exe"},
        {"isass.exe", "lsass.exe"},     {"csrsss.exe", "csrss.exe"},    {"csrrs.exe", "csrss.exe"},
        {"explore.exe", "explorer.exe"}, {"explorer32.exe", "explorer.exe"}, {"winlogin.exe", "winlogon.exe"},
        {"iexplorer.exe", "iexplore.exe"}, {"smss32.exe", "smss.exe"},   {"servics.exe", "services.exe"}};
    static const std::map<std::string, std::string> hackTools = {
        {"mimikatz.exe", "credential dumping tool"},   {"psexec.exe", "remote execution tool (dual-use)"},
        {"psexesvc.exe", "PsExec service - remote command execution in progress"},
        {"nc.exe", "netcat - raw shells / data exfiltration"}, {"nc64.exe", "netcat - raw shells"},
        {"ncat.exe", "netcat variant"},                {"procdump.exe", "memory dumper (used to dump LSASS)"},
        {"procdump64.exe", "memory dumper (used to dump LSASS)"}, {"lazagne.exe", "password recovery/stealer"},
        {"rubeus.exe", "Kerberos attack tool"},        {"sharphound.exe", "Active Directory recon (BloodHound)"},
        {"xmrig.exe", "cryptocurrency miner"},         {"plink.exe", "SSH tunnelling tool"},
        {"chisel.exe", "TCP tunnelling tool"},         {"ngrok.exe", "public tunnel exposing local services"},
        {"pwdump.exe", "password hash dumper"},        {"wce.exe", "Windows Credential Editor"},
        {"gsecdump.exe", "credential dumper"},         {"advanced_ip_scanner.exe", "network scanner (ransomware recon)"},
        {"anydesk.exe", "remote access tool (verify it is authorised)"}};
    static const std::set<std::string> officeApps = {"winword.exe", "excel.exe",  "powerpnt.exe", "outlook.exe",
                                                     "msaccess.exe", "mspub.exe", "onenote.exe",  "visio.exe"};
    static const std::set<std::string> shells = {"cmd.exe",     "powershell.exe", "pwsh.exe",   "wscript.exe",
                                                 "cscript.exe", "mshta.exe",      "rundll32.exe", "regsvr32.exe",
                                                 "certutil.exe", "bitsadmin.exe"};

    size_t lsassCount = 0;
    for (const auto& kv : procs) {
        const ProcInfo& p = kv.second;
        if (p.pid <= 4) continue;
        if (p.nameLower == "lsass.exe") ++lsassCount;

        if (systemNames.count(p.nameLower) && !p.pathLower.empty()) {
            const bool ok = p.pathLower.rfind(sys32, 0) == 0 || p.pathLower.rfind(wow64, 0) == 0;
            if (!ok)
                out.push_back(make("Process", "System process masquerading",
                                   p.name + " normally runs only from " + sys32 + " but this one runs from " + p.path,
                                   procLabel(p), Severity::Critical));
        }
        if (p.nameLower == "explorer.exe" && !p.pathLower.empty() && p.pathLower != win + "\\explorer.exe" &&
            p.pathLower != win + "\\syswow64\\explorer.exe") {
            out.push_back(make("Process", "explorer.exe masquerading",
                               "explorer.exe should run from " + win + "\\explorer.exe, found " + p.path, procLabel(p),
                               Severity::Critical));
        }
        auto ty = typosquats.find(p.nameLower);
        if (ty != typosquats.end())
            out.push_back(make("Process", "Typosquatted process name",
                               "'" + p.name + "' imitates the Windows process '" + ty->second + "'" +
                                   (p.path.empty() ? "" : " - path: " + p.path),
                               procLabel(p), Severity::High));
        auto ht = hackTools.find(p.nameLower);
        if (ht != hackTools.end())
            out.push_back(make("Process", "Known attack / dual-use tool running",
                               p.name + ": " + ht->second + (p.path.empty() ? "" : " - path: " + p.path), procLabel(p),
                               Severity::High));
        if (const char* where = suspiciousLocation(p.pathLower))
            out.push_back(make("Process", "Process running from suspicious location",
                               std::string("Executable lives in the ") + where + ": " + p.path, procLabel(p),
                               Severity::Medium));

        auto parent = procs.find(p.ppid);
        if (parent != procs.end() && parent->second.pid > 4) {
            const ProcInfo& pp = parent->second;
            if (officeApps.count(pp.nameLower) && shells.count(p.nameLower))
                out.push_back(make("Process", "Office application spawned a shell",
                                   pp.name + " (PID " + std::to_string(pp.pid) + ") started " + p.name +
                                       " - typical of a malicious macro document",
                                   procLabel(p), Severity::High));
            if (p.nameLower == "svchost.exe" && pp.nameLower != "services.exe" && pp.nameLower != "svchost.exe")
                out.push_back(make("Process", "svchost.exe with unexpected parent",
                                   "Parent is " + pp.name + " (PID " + std::to_string(pp.pid) +
                                       "); genuine svchost.exe is started by services.exe",
                                   procLabel(p), Severity::Medium));
        }
    }
    if (lsassCount > 1)
        out.push_back(make("Process", "Multiple lsass.exe instances",
                           std::to_string(lsassCount) + " processes named lsass.exe - only one may exist", "lsass.exe",
                           Severity::Critical));
}

// ------------------------------------------------------------------ network
std::string ipv4(DWORD addr) {
    const auto* b = reinterpret_cast<const unsigned char*>(&addr);
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}
unsigned port(DWORD p) { return ((p & 0xFF) << 8) | ((p >> 8) & 0xFF); }

void auditNetwork(const std::map<DWORD, ProcInfo>& procs, SystemStats& stats, std::vector<Finding>& out) {
    struct PortInfo {
        Severity sev;
        const char* why;
    };
    static const std::map<unsigned, PortInfo> badPorts = {
        {4444, {Severity::High, "Metasploit default handler"}},
        {1337, {Severity::Medium, "common backdoor port"}},
        {31337, {Severity::High, "Back Orifice / 'elite' backdoor"}},
        {12345, {Severity::High, "NetBus trojan"}},
        {27374, {Severity::High, "SubSeven trojan"}},
        {6666, {Severity::Medium, "IRC - legacy botnet C2"}},
        {6667, {Severity::Medium, "IRC - legacy botnet C2"}},
        {6697, {Severity::Medium, "IRC over TLS - botnet C2"}},
        {5555, {Severity::Medium, "ADB / common RAT port"}},
        {9001, {Severity::Medium, "Tor relay"}},
        {9050, {Severity::Medium, "Tor SOCKS proxy"}},
        {9150, {Severity::Medium, "Tor Browser SOCKS proxy"}},
        {3333, {Severity::High, "Stratum crypto-mining pool"}},
        {14444, {Severity::High, "Monero mining pool"}},
        {45700, {Severity::High, "Monero mining pool"}},
        {50050, {Severity::High, "Cobalt Strike team server"}},
        {1080, {Severity::Low, "SOCKS proxy"}}};
    static const std::set<std::string> scriptHosts = {"powershell.exe", "pwsh.exe",     "wscript.exe",
                                                      "cscript.exe",    "mshta.exe",    "rundll32.exe",
                                                      "regsvr32.exe",   "certutil.exe", "bitsadmin.exe"};

    std::vector<unsigned char> buf;
    DWORD size = 0;
    DWORD rc = ERROR_INSUFFICIENT_BUFFER;
    for (int attempt = 0; attempt < 5 && rc == ERROR_INSUFFICIENT_BUFFER; ++attempt) {
        buf.resize(size + 4096);
        size = static_cast<DWORD>(buf.size());
        rc = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    if (rc != NO_ERROR) {
        out.push_back(make("Network", "TCP table unavailable",
                           "GetExtendedTcpTable failed with error " + std::to_string(rc), "system", Severity::Info));
        return;
    }
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID& r = table->table[i];
        auto pi = procs.find(r.dwOwningPid);
        const std::string owner = pi != procs.end() ? procLabel(pi->second) : "PID " + std::to_string(r.dwOwningPid);
        const std::string lname = pi != procs.end() ? pi->second.nameLower : "";
        const std::string lpath = pi != procs.end() ? pi->second.pathLower : "";
        const unsigned lport = port(r.dwLocalPort);
        const unsigned rport = port(r.dwRemotePort);
        const std::string local = ipv4(r.dwLocalAddr) + ":" + std::to_string(lport);
        const std::string remoteIp = ipv4(r.dwRemoteAddr);
        const std::string remote = remoteIp + ":" + std::to_string(rport);

        if (r.dwState == 2) {  // LISTEN
            ++stats.listeners;
            auto bp = badPorts.find(lport);
            if (bp != badPorts.end() && bp->second.sev >= Severity::Medium)
                out.push_back(make("Network", "Listener on backdoor-associated port",
                                   "Listening on " + local + " (" + bp->second.why + ")", owner,
                                   bp->second.sev == Severity::High ? Severity::High : Severity::Medium));
        } else if (r.dwState == 5) {  // ESTABLISHED
            ++stats.tcpConnections;
            auto bp = badPorts.find(rport);
            if (bp != badPorts.end() && remoteIp != "127.0.0.1")
                out.push_back(make("Network", "Connection to suspicious remote port",
                                   local + " -> " + remote + " (" + bp->second.why + ")", owner, bp->second.sev));
            if (const char* where = suspiciousLocation(lpath))
                out.push_back(make("Network", "Network activity from suspicious location",
                                   std::string("Process in the ") + where + " is connected to " + remote, owner,
                                   Severity::High));
            if (scriptHosts.count(lname) && !isPrivateIPv4(remoteIp))
                out.push_back(make("Network", "Script host with outbound internet connection",
                                   lname + " is connected to " + remote + " (download cradle / C2 beacon?)", owner,
                                   Severity::Medium));
        }
    }
}

// ------------------------------------------------------------------ autoruns
void checkAutorunCommand(const std::string& location, const std::string& command, const RuleSet& rules,
                         std::vector<Finding>& out) {
    const std::string lc = toLower(command);
    const std::string shown = printable(command, 220);
    if (const char* where = suspiciousLocation(lc))
        out.push_back(make("Persistence", "Autorun points to suspicious location",
                           std::string("Starts from the ") + where + ": " + shown, location, Severity::High));
    if (lc.find("powershell") != std::string::npos || lc.find("pwsh") != std::string::npos) {
        for (const char* flag : {" -enc", " -e ", "-encodedcommand", "-w hidden", "-windowstyle hidden", "iex",
                                 "downloadstring", "frombase64string", "invoke-expression"}) {
            if (lc.find(flag) != std::string::npos) {
                out.push_back(make("Persistence", "Autorun launches hidden/encoded PowerShell", shown, location,
                                   Severity::High));
                break;
            }
        }
    }
    for (const char* lol : {"mshta", "wscript", "cscript", "regsvr32 /s /n /u /i:", "certutil", "bitsadmin",
                            "rundll32 javascript", "rundll32.exe javascript"}) {
        if (lc.find(lol) != std::string::npos) {
            out.push_back(make("Persistence", "Autorun uses a script host / LOLBin",
                               std::string("Uses '") + lol + "': " + shown, location, Severity::Medium));
            break;
        }
    }
    for (const auto& r : rules.stringRules)
        if (lc.find(r.value) != std::string::npos)
            out.push_back(make("Persistence", r.name, "Autorun command matches signature: " + shown, location,
                               r.severity));
}

void auditRunKeys(const RuleSet& rules, SystemStats& stats, std::vector<Finding>& out) {
    struct Key {
        HKEY root;
        const char* rootName;
        const wchar_t* path;
        const char* pathName;
        REGSAM view;
    };
    const Key keys[] = {
        {HKEY_CURRENT_USER, "HKCU", L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0},
        {HKEY_CURRENT_USER, "HKCU", L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
         "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0},
        {HKEY_LOCAL_MACHINE, "HKLM", L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE, "HKLM", L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
         "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE, "HKLM", L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_32KEY},
        {HKEY_CURRENT_USER, "HKCU", L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
         "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0}};

    for (const Key& k : keys) {
        HKEY h = nullptr;
        if (RegOpenKeyExW(k.root, k.path, 0, KEY_READ | k.view, &h) != ERROR_SUCCESS) continue;
        DWORD valueCount = 0, maxName = 0, maxData = 0;
        if (RegQueryInfoKeyW(h, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxName, &maxData,
                             nullptr, nullptr) != ERROR_SUCCESS) {
            RegCloseKey(h);
            continue;
        }
        const bool windowsKey = std::string(k.pathName).find("Windows NT") != std::string::npos;
        std::vector<wchar_t> name(maxName + 2);
        std::vector<BYTE> data(maxData + 4);
        for (DWORD i = 0; i < valueCount; ++i) {
            DWORD nameLen = static_cast<DWORD>(name.size());
            DWORD dataLen = static_cast<DWORD>(data.size() - 4);
            DWORD type = 0;
            if (RegEnumValueW(h, i, name.data(), &nameLen, nullptr, &type, data.data(), &dataLen) != ERROR_SUCCESS)
                continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
            const std::string valueName = wideToUtf8(std::wstring(name.data(), nameLen));
            // In ...\Windows only the "Load" and "Run" values are persistence points.
            if (windowsKey && toLower(valueName) != "load" && toLower(valueName) != "run") continue;
            std::wstring w(reinterpret_cast<const wchar_t*>(data.data()), dataLen / sizeof(wchar_t));
            while (!w.empty() && w.back() == L'\0') w.pop_back();
            if (w.empty()) continue;
            ++stats.autoruns;
            const std::string location = std::string(k.rootName) + "\\" + k.pathName + "\\" + valueName;
            checkAutorunCommand(location, wideToUtf8(w), rules, out);
        }
        RegCloseKey(h);
    }
}

void auditStartupFolders(const RuleSet& rules, const SystemOptions& opt, SystemStats& stats,
                         std::vector<Finding>& out) {
    std::vector<fs::path> folders;
    const std::string appdata = envVar(L"APPDATA");
    const std::string programdata = envVar(L"ProgramData");
    if (!appdata.empty())
        folders.push_back(utf8ToPath(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup");
    if (!programdata.empty())
        folders.push_back(utf8ToPath(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp");

    static const std::set<std::string> scriptExt = {".vbs", ".vbe", ".js",  ".jse", ".wsf", ".bat",
                                                    ".cmd", ".ps1", ".hta", ".scr", ".pif"};
    FileScanner scanner(rules, opt.scan);
    for (const auto& folder : folders) {
        std::error_code ec;
        if (!fs::is_directory(folder, ec)) continue;
        for (fs::directory_iterator it(folder, fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; it.increment(ec)) {
            std::error_code fec;
            if (!it->is_regular_file(fec)) continue;
            const std::string fname = toLower(pathToUtf8(it->path().filename()));
            if (fname == "desktop.ini") continue;
            ++stats.autoruns;
            const std::string ext = toLower(pathToUtf8(it->path().extension()));
            const std::string full = pathToUtf8(it->path());
            if (scriptExt.count(ext))
                out.push_back(make("Persistence", "Script in Startup folder",
                                   "Runs at every logon: " + full, full, Severity::Medium));
            else if (ext == ".exe")
                out.push_back(make("Persistence", "Executable in Startup folder",
                                   "Runs at every logon (verify it is expected): " + full, full, Severity::Low));
            if (ext != ".lnk") {
                ScanStats ss;
                auto found = scanner.scanFile(it->path(), ss);
                out.insert(out.end(), found.begin(), found.end());
            }
        }
    }
}

}  // namespace

bool systemAuditSupported() { return true; }

std::vector<Finding> analyzeSystem(const RuleSet& rules, const SystemOptions& opt, SystemStats& stats,
                                   std::string& error) {
    std::vector<Finding> out;
    stats.elevated = isElevated();
    const auto procs = listProcesses();
    if (procs.empty()) {
        error = "could not enumerate processes (CreateToolhelp32Snapshot failed)";
        return out;
    }
    stats.processes = procs.size();

    auditProcesses(procs, out);
    auditNetwork(procs, stats, out);
    auditRunKeys(rules, stats, out);
    auditStartupFolders(rules, opt, stats, out);

    if (opt.deep) {
        FileScanner scanner(rules, opt.scan);
        std::map<std::string, const ProcInfo*> images;
        const DWORD self = GetCurrentProcessId();  // our own image contains every rule string
        for (const auto& kv : procs)
            if (!kv.second.path.empty() && kv.first != self) images.emplace(kv.second.pathLower, &kv.second);
        for (const auto& img : images) {
            ScanStats ss;
            const fs::path imagePath = utf8ToPath(img.second->path);
            auto found = scanner.scanFile(imagePath, ss);
            ++stats.imagesScanned;
            if (found.empty()) continue;
            const bool signedOk = hasValidSignature(imagePath);
            if (signedOk) ++stats.imagesSigned;
            for (auto& f : found) {
                // Heuristics on a validly signed binary are almost always benign: keep them as INFO.
                if (signedOk && f.category != "Signature") {
                    f.severity = Severity::Info;
                    f.detail += " [image has a valid Authenticode signature]";
                }
                f.category = "Process image";
                f.target = procLabel(*img.second) + " " + f.target;
                out.push_back(std::move(f));
            }
        }
    }
    return out;
}

#endif  // _WIN32

}  // namespace ta

// =============================================================================
//  report
// =============================================================================
// Threat Analyzer - risk scoring, console report and JSON export.

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>

namespace ta {

// The score is the risk of the *worst* target (file, IP, process, ...): severity weights are summed
// per target and capped at 100. Scanning a big folder with a few weak heuristic hits spread over many
// files therefore stays low, while one file with several strong indicators scores high.
int riskScore(const std::vector<Finding>& findings) {
    std::map<std::string, long> perTarget;
    long worst = 0;
    for (const auto& f : findings) {
        long& s = perTarget[f.target];
        s += severityWeight(f.severity);
        worst = std::max(worst, s);
    }
    return static_cast<int>(std::min<long>(worst, 100));
}

std::string verdict(int score) {
    if (score == 0) return "CLEAN";
    if (score < 15) return "LOW RISK";
    if (score < 40) return "SUSPICIOUS";
    return "HIGH RISK";
}

void sortFindings(std::vector<Finding>& findings) {
    std::stable_sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        if (a.category != b.category) return a.category < b.category;
        return a.target < b.target;
    });
}

namespace {

struct Palette {
    bool on;
    const char* c(const char* code) const { return on ? code : ""; }
    const char* reset() const { return c("\x1b[0m"); }
    const char* bold() const { return c("\x1b[1m"); }
    const char* dim() const { return c("\x1b[90m"); }
    const char* sev(Severity s) const {
        switch (s) {
            case Severity::Critical: return c("\x1b[1;97;41m");
            case Severity::High: return c("\x1b[1;91m");
            case Severity::Medium: return c("\x1b[1;33m");
            case Severity::Low: return c("\x1b[36m");
            case Severity::Info: return c("\x1b[90m");
        }
        return "";
    }
    const char* verdictColor(int score) const {
        if (score == 0) return c("\x1b[1;92m");
        if (score < 15) return c("\x1b[1;36m");
        if (score < 40) return c("\x1b[1;33m");
        return c("\x1b[1;91m");
    }
};

const std::string kRule(72, '=');
const std::string kThin(72, '-');

// Wraps long text onto continuation lines aligned under the value column.
void printField(const char* label, const std::string& value, const Palette& p) {
    const size_t width = 58;
    const std::string indent(14, ' ');
    std::cout << "    " << p.dim() << label << p.reset();
    size_t pos = 0;
    bool first = true;
    while (pos < value.size()) {
        size_t len = std::min(width, value.size() - pos);
        if (pos + len < value.size()) {
            const size_t space = value.rfind(' ', pos + len);
            if (space != std::string::npos && space > pos + width / 2) len = space - pos + 1;
        }
        std::cout << (first ? "" : indent) << value.substr(pos, len) << "\n";
        pos += len;
        first = false;
    }
    if (value.empty()) std::cout << "\n";
}

std::string jsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

std::string isoTimeUtc() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_MSC_VER)
    gmtime_s(&tm, &t);
#elif defined(_WIN32)
    tm = *std::gmtime(&t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

}  // namespace

void printReport(const Report& r, bool color, Severity minSeverity) {
    const Palette p{color};
    std::cout << "\n" << p.bold() << kRule << "\n"
              << "  THREAT ANALYZER v" << TA_VERSION << "   |   " << r.mode << "\n"
              << kRule << p.reset() << "\n";
    printField("Target    : ", r.target, p);
    if (!r.rulesFile.empty()) printField("Rules     : ", r.rulesFile, p);
    for (const auto& s : r.stats) {
        std::string label = s.first;
        label.resize(10, ' ');
        printField((label + ": ").c_str(), s.second, p);
    }

    size_t counts[5] = {0, 0, 0, 0, 0};
    size_t shown = 0;
    for (const auto& f : r.findings) {
        ++counts[static_cast<int>(f.severity)];
        if (f.severity >= minSeverity) ++shown;
    }

    std::cout << kThin << "\n" << p.bold() << "  FINDINGS" << p.reset() << "  (" << shown << " shown";
    if (shown != r.findings.size())
        std::cout << ", " << (r.findings.size() - shown) << " below " << severityName(minSeverity) << " hidden";
    std::cout << ")\n\n";

    if (shown == 0) std::cout << "    No threats detected.\n\n";
    size_t index = 0;
    for (const auto& f : r.findings) {
        if (f.severity < minSeverity) continue;
        ++index;
        char tag[16];
        std::snprintf(tag, sizeof(tag), "%-8s", severityName(f.severity));
        std::cout << "  " << p.dim() << "#" << index << p.reset() << " " << p.sev(f.severity) << "[" << tag << "]"
                  << p.reset() << " " << p.bold() << f.title << p.reset() << "\n";
        printField("Category  : ", f.category, p);
        printField("Target    : ", f.target, p);
        printField("Detail    : ", f.detail, p);
        std::cout << "\n";
    }

    const int score = riskScore(r.findings);
    char timing[32];
    std::snprintf(timing, sizeof(timing), "%.2f s", r.seconds);
    std::cout << kThin << "\n"
              << "  Summary   : " << p.sev(Severity::Critical) << "Critical " << counts[4] << p.reset() << "  "
              << p.sev(Severity::High) << "High " << counts[3] << p.reset() << "  " << p.sev(Severity::Medium)
              << "Medium " << counts[2] << p.reset() << "  " << p.sev(Severity::Low) << "Low " << counts[1]
              << p.reset() << "  Info " << counts[0] << "\n"
              << "  Risk      : " << p.verdictColor(score) << score << "/100  ->  " << verdict(score) << p.reset()
              << "\n"
              << "  Duration  : " << timing << "\n"
              << p.bold() << kRule << p.reset() << "\n\n";
}

bool writeJson(const Report& r, const fs::path& file, std::string& error) {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot write JSON report: " + pathToUtf8(file);
        return false;
    }
    size_t counts[5] = {0, 0, 0, 0, 0};
    for (const auto& f : r.findings) ++counts[static_cast<int>(f.severity)];
    const int score = riskScore(r.findings);
    char secs[32];
    std::snprintf(secs, sizeof(secs), "%.3f", r.seconds);

    out << "{\n"
        << "  \"tool\": \"Threat Analyzer\",\n"
        << "  \"version\": \"" << TA_VERSION << "\",\n"
        << "  \"generated\": \"" << isoTimeUtc() << "\",\n"
        << "  \"mode\": \"" << jsonEscape(r.mode) << "\",\n"
        << "  \"target\": \"" << jsonEscape(r.target) << "\",\n"
        << "  \"rules\": \"" << jsonEscape(r.rulesFile) << "\",\n"
        << "  \"durationSeconds\": " << secs << ",\n"
        << "  \"riskScore\": " << score << ",\n"
        << "  \"verdict\": \"" << verdict(score) << "\",\n"
        << "  \"summary\": {\"critical\": " << counts[4] << ", \"high\": " << counts[3] << ", \"medium\": " << counts[2]
        << ", \"low\": " << counts[1] << ", \"info\": " << counts[0] << "},\n"
        << "  \"stats\": {";
    for (size_t i = 0; i < r.stats.size(); ++i)
        out << (i ? ", " : "") << "\"" << jsonEscape(r.stats[i].first) << "\": \"" << jsonEscape(r.stats[i].second)
            << "\"";
    out << "},\n  \"findings\": [";
    for (size_t i = 0; i < r.findings.size(); ++i) {
        const Finding& f = r.findings[i];
        out << (i ? ",\n" : "\n") << "    {\"severity\": \"" << severityName(f.severity) << "\", \"category\": \""
            << jsonEscape(f.category) << "\", \"title\": \"" << jsonEscape(f.title) << "\", \"target\": \""
            << jsonEscape(f.target) << "\", \"detail\": \"" << jsonEscape(f.detail) << "\"}";
    }
    out << (r.findings.empty() ? "]\n" : "\n  ]\n") << "}\n";
    out.flush();
    if (!out) {
        error = "error while writing JSON report: " + pathToUtf8(file);
        return false;
    }
    return true;
}

}  // namespace ta

// =============================================================================
//  main
// =============================================================================
// Threat Analyzer - command line front end.


#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>

using namespace ta;

namespace {

constexpr int kExitClean = 0;
constexpr int kExitFindings = 1;
constexpr int kExitError = 2;

struct Options {
    std::string command;
    std::string target;
    std::string rules;
    std::string json;
    Severity minSeverity = Severity::Low;
    double maxSizeMb = 64;
    double entropy = 7.2;
    bool recursive = true;
    bool deep = false;
    bool color = true;
    int threshold = 5;
    int portscan = 10;
    int notfound = 20;
    // serve (web dashboard)
    int port = 18080;
    std::string web;
    bool openBrowser = true;
    bool strictPort = false;
};

void usage() {
    std::cout <<
        "Threat Analyzer " TA_VERSION " - static file, log and live-system threat analysis\n"
        "\n"
        "Usage:\n"
        "  threat_analyzer scan   <file|folder> [options]  Scan files: signatures, PE checks, heuristics\n"
        "  threat_analyzer logs   <logfile>     [options]  Detect attacks in auth / web / firewall logs\n"
        "  threat_analyzer system               [options]  Audit processes, TCP connections, autoruns (Windows)\n"
        "  threat_analyzer hash   <file>                   Print SHA-256, size and entropy of a file\n"
        "  threat_analyzer rules                           List the loaded detection rules\n"
        "  threat_analyzer selftest                        Verify the internal algorithms\n"
        "  threat_analyzer serve                [options]  Start the web dashboard on http://localhost:18080\n"
        "  threat_analyzer help | --version\n"
        "\n"
        "Options:\n"
        "  --rules <file>     Rule database (default: rules/signatures.txt next to the executable)\n"
        "  --json <file>      Also write the report as JSON\n"
        "  --min <level>      Show findings at or above info|low|medium|high|critical (default: low)\n"
        "  --max-size <MB>    Content-scan limit per file; larger files are hash-checked only (default 64)\n"
        "  --entropy <bits>   Entropy alarm threshold 0-8 (default 7.2)\n"
        "  --no-recursive     scan: do not descend into sub-folders\n"
        "  --threshold <n>    logs: failed logins per IP that count as brute force (default 5)\n"
        "  --portscan <n>     logs: distinct blocked ports per IP that count as a port scan (default 10)\n"
        "  --notfound <n>     logs: HTTP 404s per IP that count as enumeration (default 20)\n"
        "  --deep             system: also scan the executable of every running process\n"
        "  --no-color         Disable coloured output\n"
        "  --port <n>         serve: HTTP port (default 18080; the next free port is used if busy)\n"
        "  --strict-port      serve: exit with an error instead of trying the next port\n"
        "  --web <dir>        serve: front-end folder (default: web/ next to the executable or project)\n"
        "  --no-browser       serve: do not open the dashboard in the default browser\n"
        "\n"
        "Exit codes: 0 = clean, 1 = findings reported, 2 = error\n";
}

std::vector<std::string> utf8Args(int argc, char** argv) {
    std::vector<std::string> args;
#ifdef _WIN32
    int n = 0;
    LPWSTR* w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (w) {
        for (int i = 0; i < n; ++i) args.push_back(wideToUtf8(w[i]));
        LocalFree(w);
        return args;
    }
#endif
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
    return args;
}

bool setupConsole() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode)) return false;  // redirected to a file/pipe
    return SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

fs::path executableDir(const std::string& argv0) {
#ifdef _WIN32
    std::wstring buf(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, &buf[0], static_cast<DWORD>(buf.size()));
    if (n > 0) return fs::path(buf.substr(0, n)).parent_path();
#else
    std::error_code ec;
    const fs::path self = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) return self.parent_path();
#endif
    std::error_code ec2;
    return fs::absolute(utf8ToPath(argv0), ec2).parent_path();
}

fs::path locateRules(const std::string& explicitPath, const fs::path& exeDir) {
    if (!explicitPath.empty()) return utf8ToPath(explicitPath);
    const fs::path candidates[] = {exeDir / "rules" / "signatures.txt", fs::current_path() / "rules" / "signatures.txt",
                                   exeDir.parent_path() / "rules" / "signatures.txt",
                                   exeDir.parent_path().parent_path() / "rules" / "signatures.txt"};
    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::is_regular_file(c, ec)) return c;
    }
    return candidates[0];
}

bool parseNumber(const std::string& opt, const std::string& text, double lo, double hi, double& out) {
    try {
        size_t used = 0;
        const double v = std::stod(text, &used);
        if (used != text.size() || v < lo || v > hi) throw std::out_of_range("range");
        out = v;
        return true;
    } catch (...) {
        std::cerr << "error: " << opt << " expects a number between " << lo << " and " << hi << ", got '" << text
                  << "'\n";
        return false;
    }
}

bool parseArgs(const std::vector<std::string>& args, Options& o) {
    if (args.size() < 2) return false;
    o.command = toLower(args[1]);
    for (size_t i = 2; i < args.size(); ++i) {
        const std::string& a = args[i];
        auto value = [&](std::string& dst) {
            if (i + 1 >= args.size()) {
                std::cerr << "error: " << a << " needs a value\n";
                return false;
            }
            dst = args[++i];
            return true;
        };
        double num = 0;
        std::string v;
        if (a == "--rules") {
            if (!value(o.rules)) return false;
        } else if (a == "--json") {
            if (!value(o.json)) return false;
        } else if (a == "--min") {
            if (!value(v)) return false;
            if (!parseSeverity(v, o.minSeverity)) {
                std::cerr << "error: unknown severity '" << v << "'\n";
                return false;
            }
        } else if (a == "--max-size") {
            if (!value(v) || !parseNumber(a, v, 0.001, 4096, o.maxSizeMb)) return false;
        } else if (a == "--entropy") {
            if (!value(v) || !parseNumber(a, v, 0, 8, o.entropy)) return false;
        } else if (a == "--threshold" || a == "--portscan" || a == "--notfound") {
            if (!value(v) || !parseNumber(a, v, 1, 1000000, num)) return false;
            (a == "--threshold" ? o.threshold : a == "--portscan" ? o.portscan : o.notfound) = static_cast<int>(num);
        } else if (a == "--port") {
            if (!value(v) || !parseNumber(a, v, 1, 65535, num)) return false;
            o.port = static_cast<int>(num);
        } else if (a == "--web") {
            if (!value(o.web)) return false;
        } else if (a == "--no-browser") {
            o.openBrowser = false;
        } else if (a == "--strict-port") {
            o.strictPort = true;
        } else if (a == "--no-recursive") {
            o.recursive = false;
        } else if (a == "--deep") {
            o.deep = true;
        } else if (a == "--no-color" || a == "--no-colour") {
            o.color = false;
        } else if (!a.empty() && a[0] == '-' && a.size() > 1) {
            std::cerr << "error: unknown option '" << a << "'\n";
            return false;
        } else if (o.target.empty()) {
            o.target = a;
        } else {
            std::cerr << "error: unexpected argument '" << a << "'\n";
            return false;
        }
    }
    return true;
}

bool loadRules(const Options& o, const fs::path& exeDir, RuleSet& rules, fs::path& rulesPath) {
    rulesPath = locateRules(o.rules, exeDir);
    std::string err;
    if (!rules.load(rulesPath, err)) {
        std::cerr << "error: " << err << "\n"
                  << "       Use --rules <file> or keep the 'rules' folder next to threat_analyzer.exe.\n";
        return false;
    }
    return true;
}

}  // namespace

std::vector<SelfTestCheck> ta::runSelfTestChecks() {
    std::vector<SelfTestCheck> results;
    struct Vec {
        std::string input;
        const char* expected;
    };
    const Vec vectors[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"}};
    auto check = [&](const std::string& name, bool ok) { results.push_back({name, ok}); };
    for (const auto& v : vectors) {
        const std::string got = sha256Hex(reinterpret_cast<const uint8_t*>(v.input.data()), v.input.size());
        check("SHA-256 of " + std::to_string(v.input.size()) + "-byte vector", got == v.expected);
    }
    {
        Sha256 h;  // streaming in odd-sized chunks must equal one-shot hashing
        const std::string data(100003, 'x');
        for (size_t i = 0; i < data.size(); i += 777)
            h.update(reinterpret_cast<const uint8_t*>(data.data()) + i, std::min<size_t>(777, data.size() - i));
        check("SHA-256 streaming == one-shot",
              h.hexDigest() == sha256Hex(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
    }
    std::vector<uint8_t> all(256);
    for (int i = 0; i < 256; ++i) all[i] = static_cast<uint8_t>(i);
    check("Entropy of 256 distinct bytes == 8.0", std::abs(shannonEntropy(all.data(), all.size()) - 8.0) < 1e-9);
    const std::vector<uint8_t> zeros(4096, 0);
    check("Entropy of constant data == 0.0", shannonEntropy(zeros.data(), zeros.size()) == 0.0);
    const auto ips = extractIPv4("Failed password for root from 203.0.113.7 port 22 v1.2.3.4 999.1.1.1 10.0.0.1.");
    check("IPv4 extraction", ips.size() == 2 && ips[0] == "203.0.113.7" && ips[1] == "10.0.0.1");
    check("Private IPv4 detection", isPrivateIPv4("192.168.1.5") && !isPrivateIPv4("8.8.8.8"));
    Severity s;
    check("Severity parsing", parseSeverity(" High ", s) && s == Severity::High && !parseSeverity("bogus", s));
    return results;
}

namespace {

int selfTest() {
    int failures = 0;
    std::cout << "Threat Analyzer self-test\n";
    for (const auto& c : runSelfTestChecks()) {
        std::cout << "  [" << (c.passed ? "PASS" : "FAIL") << "] " << c.name << "\n";
        if (!c.passed) ++failures;
    }
    std::cout << (failures == 0 ? "All self-tests passed.\n" : "Self-test FAILED.\n");
    return failures == 0 ? kExitClean : kExitError;
}

int finish(Report& report, const Options& o, bool color, std::chrono::steady_clock::time_point start) {
    sortFindings(report.findings);
    report.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    printReport(report, color, o.minSeverity);
    if (!o.json.empty()) {
        std::string err;
        if (!writeJson(report, utf8ToPath(o.json), err)) {
            std::cerr << "error: " << err << "\n";
            return kExitError;
        }
        std::cout << "JSON report written to " << o.json << "\n";
    }
    return riskScore(report.findings) > 0 ? kExitFindings : kExitClean;
}

}  // namespace

int main(int argc, char** argv) {
    const bool consoleColor = setupConsole();
    const std::vector<std::string> args = utf8Args(argc, argv);
    Options o;
    if (!parseArgs(args, o)) {
        if (args.size() < 2) usage();
        return kExitError;
    }
    const bool color = consoleColor && o.color;
    const fs::path exeDir = executableDir(args.empty() ? "" : args[0]);
    const auto start = std::chrono::steady_clock::now();

    try {
        if (o.command == "help" || o.command == "--help" || o.command == "-h" || o.command == "/?") {
            usage();
            return kExitClean;
        }
        if (o.command == "--version" || o.command == "version" || o.command == "-v") {
            std::cout << "Threat Analyzer " << TA_VERSION << "\n";
            return kExitClean;
        }
        if (o.command == "selftest") return selfTest();

        if (o.command == "hash") {
            if (o.target.empty()) {
                std::cerr << "error: hash needs a file\n";
                return kExitError;
            }
            const fs::path p = utf8ToPath(o.target);
            std::error_code ec;
            if (!fs::is_regular_file(p, ec)) {
                std::cerr << "error: not a file: " << o.target << "\n";
                return kExitError;
            }
            std::string hash;
            if (!sha256File(p, hash)) {
                std::cerr << "error: cannot read " << o.target << "\n";
                return kExitError;
            }
            const uint64_t size = fs::file_size(p, ec);
            std::cout << "File    : " << pathToUtf8(fs::absolute(p, ec)) << "\n"
                      << "Size    : " << size << " bytes (" << formatBytes(size) << ")\n"
                      << "SHA-256 : " << hash << "\n";
            if (size <= 256ull * 1024 * 1024) {
                std::vector<uint8_t> data;
                std::ifstream in(p, std::ios::binary);
                data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
                char e[32];
                std::snprintf(e, sizeof(e), "%.4f", shannonEntropy(data.data(), data.size()));
                std::cout << "Entropy : " << e << " bits/byte\n";
            }
            std::cout << "Rule    : HASH|<name>|HIGH|" << hash << "\n";
            return kExitClean;
        }

        RuleSet rules;
        fs::path rulesPath;
        if (!loadRules(o, exeDir, rules, rulesPath)) return kExitError;
        std::error_code ec;
        const std::string rulesShown = pathToUtf8(fs::weakly_canonical(rulesPath, ec));

        if (o.command == "rules") {
            std::cout << "Rule file: " << rulesShown << "\n"
                      << "  HASH   " << rules.hashRules.size() << "\n  STRING " << rules.stringRules.size()
                      << "\n  HEX    " << rules.hexRules.size() << "\n  LOG    " << rules.logRules.size()
                      << "\n  total  " << rules.total() << "\n\n";
            auto list = [](const char* type, const std::vector<Rule>& v) {
                for (const auto& r : v) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "%-7s%-9s", type, severityName(r.severity));
                    std::cout << "  " << buf << r.name << "\n";
                }
            };
            list("HASH", rules.hashRules);
            list("STRING", rules.stringRules);
            list("HEX", rules.hexRules);
            list("LOG", rules.logRules);
            return kExitClean;
        }

        if (o.command == "serve" || o.command == "web") {
            WebOptions wo;
            wo.port = static_cast<uint16_t>(o.port);
            wo.strictPort = o.strictPort;
            wo.openBrowser = o.openBrowser;
            wo.rulesPath = fs::weakly_canonical(rulesPath, ec);
            if (!o.web.empty()) {
                wo.webRoot = fs::absolute(utf8ToPath(o.web), ec);
            } else {
                for (const fs::path& c : {exeDir / "web", exeDir.parent_path() / "web", fs::current_path() / "web",
                                          exeDir.parent_path().parent_path() / "web"}) {
                    if (fs::is_regular_file(c / "index.html", ec)) {
                        wo.webRoot = c;
                        break;
                    }
                }
            }
            if (wo.webRoot.empty() || !fs::is_regular_file(wo.webRoot / "index.html", ec)) {
                std::cerr << "error: web front-end (web/index.html) not found. Use --web <dir>.\n";
                return kExitError;
            }
            wo.webRoot = fs::weakly_canonical(wo.webRoot, ec);
            wo.projectDir = wo.webRoot.parent_path();
            return runWebServer(rules, wo);
        }

        Report report;
        report.rulesFile = rulesShown + "  (" + std::to_string(rules.total()) + " rules)";

        if (o.command == "scan") {
            if (o.target.empty()) {
                std::cerr << "error: scan needs a file or folder\n";
                return kExitError;
            }
            const fs::path target = fs::absolute(utf8ToPath(o.target), ec);
            if (!fs::exists(target, ec)) {
                std::cerr << "error: path not found: " << o.target << "\n";
                return kExitError;
            }
            ScanOptions so;
            so.maxFileSize = static_cast<uint64_t>(o.maxSizeMb * 1024 * 1024);
            so.recursive = o.recursive;
            so.entropyThreshold = o.entropy;
            so.excluded.insert(fs::weakly_canonical(rulesPath, ec));
            if (!o.json.empty()) so.excluded.insert(fs::weakly_canonical(utf8ToPath(o.json), ec));
            FileScanner scanner(rules, so);
            ScanStats st;
            report.findings = scanner.scanPath(target, st);
            report.mode = "FILE SCAN";
            report.target = pathToUtf8(fs::weakly_canonical(target, ec));
            report.stats = {{"Scanned", std::to_string(st.filesScanned) + " file(s), " + formatBytes(st.bytesScanned)},
                            {"PE files", std::to_string(st.peFiles)},
                            {"Hash only", std::to_string(st.filesHashOnly) + " (larger than " +
                                              formatBytes(so.maxFileSize) + ")"},
                            {"Unreadable", std::to_string(st.filesFailed) + " file(s), " +
                                               std::to_string(st.dirsFailed) + " folder(s)"}};
            return finish(report, o, color, start);
        }

        if (o.command == "logs" || o.command == "log") {
            if (o.target.empty()) {
                std::cerr << "error: logs needs a log file\n";
                return kExitError;
            }
            const fs::path target = utf8ToPath(o.target);
            if (!fs::is_regular_file(target, ec)) {
                std::cerr << "error: log file not found: " << o.target << "\n";
                return kExitError;
            }
            LogOptions lo;
            lo.bruteForceThreshold = o.threshold;
            lo.portScanThreshold = o.portscan;
            lo.notFoundThreshold = o.notfound;
            LogStats st;
            std::string err;
            report.findings = analyzeLog(target, rules, lo, st, err);
            if (!err.empty()) {
                std::cerr << "error: " << err << "\n";
                return kExitError;
            }
            report.mode = "LOG ANALYSIS";
            report.target = pathToUtf8(fs::weakly_canonical(target, ec));
            report.stats = {{"Lines", std::to_string(st.lines)},
                            {"Unique IPs", std::to_string(st.uniqueIps)},
                            {"Failed auth", std::to_string(st.failedLogins)},
                            {"HTTP reqs", std::to_string(st.httpRequests)},
                            {"FW events", std::to_string(st.firewallEvents)}};
            return finish(report, o, color, start);
        }

        if (o.command == "system") {
            if (!systemAuditSupported()) {
                std::cerr << "error: the live system audit is only available in Windows builds\n";
                return kExitError;
            }
            SystemOptions so;
            so.deep = o.deep;
            so.scan.maxFileSize = static_cast<uint64_t>(o.maxSizeMb * 1024 * 1024);
            so.scan.entropyThreshold = o.entropy;
            SystemStats st;
            std::string err;
            report.findings = analyzeSystem(rules, so, st, err);
            if (!err.empty()) {
                std::cerr << "error: " << err << "\n";
                return kExitError;
            }
            report.mode = o.deep ? "LIVE SYSTEM AUDIT (DEEP)" : "LIVE SYSTEM AUDIT";
            report.target = "local machine";
            report.stats = {{"Elevated", st.elevated ? "yes" : "no (run as Administrator for full visibility)"},
                            {"Processes", std::to_string(st.processes)},
                            {"TCP estab.", std::to_string(st.tcpConnections)},
                            {"Listeners", std::to_string(st.listeners)},
                            {"Autoruns", std::to_string(st.autoruns)}};
            if (o.deep)
                report.stats.emplace_back("Images", std::to_string(st.imagesScanned) + " scanned, " +
                                                        std::to_string(st.imagesSigned) +
                                                        " flagged image(s) validly signed -> downgraded to INFO");
            return finish(report, o, color, start);
        }

        std::cerr << "error: unknown command '" << o.command << "'\n\n";
        usage();
        return kExitError;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return kExitError;
    }
}
