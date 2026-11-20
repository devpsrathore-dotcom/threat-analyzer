#pragma once
// Threat Analyzer - shared declarations for every module.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <regex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifndef TA_VERSION
#define TA_VERSION "1.0.0"
#endif

namespace ta {

namespace fs = std::filesystem;

// ---------------------------------------------------------------- severity
enum class Severity { Info = 0, Low, Medium, High, Critical };

const char* severityName(Severity s);
int severityWeight(Severity s);
bool parseSeverity(const std::string& text, Severity& out);

// ---------------------------------------------------------------- findings
struct Finding {
    std::string category;  // Signature, Heuristic, PE, Log, Process, Network, Persistence
    std::string title;     // short name of what was detected
    std::string detail;    // human readable evidence
    std::string target;    // file path / IP address / process
    Severity severity = Severity::Info;
};

// ---------------------------------------------------------------- rules
struct Rule {
    enum class Type { Hash, String, Hex, Regex };
    Type type = Type::String;
    std::string name;
    Severity severity = Severity::Medium;
    std::string value;           // original text (lower-cased for String rules)
    std::vector<uint8_t> bytes;  // decoded bytes for Hex rules
    std::regex re;               // compiled pattern for Regex (LOG) rules
};

class RuleSet {
public:
    bool load(const fs::path& file, std::string& error);
    size_t total() const;

    std::vector<Rule> hashRules;    // HASH   - SHA-256 of known bad files
    std::vector<Rule> stringRules;  // STRING - case-insensitive text inside files
    std::vector<Rule> hexRules;     // HEX    - raw byte sequences inside files
    std::vector<Rule> logRules;     // LOG    - regular expressions for log lines
    fs::path source;
};

// ---------------------------------------------------------------- utilities
std::string toLower(std::string s);
std::string trim(const std::string& s);
std::string printable(const std::string& s, size_t maxLen = 160);
std::string pathToUtf8(const fs::path& p);
fs::path utf8ToPath(const std::string& s);
std::string formatBytes(uint64_t bytes);
std::string wideToUtf8(const std::wstring& w);
std::vector<std::string> extractIPv4(const std::string& text);
bool isPrivateIPv4(const std::string& ip);

// ---------------------------------------------------------------- hashing / entropy
class Sha256 {
public:
    Sha256();
    void update(const uint8_t* data, size_t len);
    std::string hexDigest();  // finalises the hash

private:
    void transform(const uint8_t* block);
    uint32_t state_[8];
    uint8_t buffer_[64];
    size_t bufferLen_ = 0;
    uint64_t totalLen_ = 0;
};

std::string sha256Hex(const uint8_t* data, size_t len);
bool sha256File(const fs::path& file, std::string& hexOut);
double shannonEntropy(const uint8_t* data, size_t len);

// ---------------------------------------------------------------- file scanner
struct ScanOptions {
    uint64_t maxFileSize = 64ull * 1024 * 1024;  // content analysis limit
    bool recursive = true;
    double entropyThreshold = 7.2;
    std::set<fs::path> excluded;  // canonical paths never scanned (rules file, reports)
};

struct ScanStats {
    size_t filesScanned = 0;
    size_t filesHashOnly = 0;
    size_t filesFailed = 0;
    size_t dirsFailed = 0;
    size_t peFiles = 0;
    uint64_t bytesScanned = 0;
};

class FileScanner {
public:
    FileScanner(const RuleSet& rules, ScanOptions options);
    std::vector<Finding> scanPath(const fs::path& target, ScanStats& stats) const;
    std::vector<Finding> scanFile(const fs::path& file, ScanStats& stats) const;

private:
    void analyzeContent(const std::string& name, const std::vector<uint8_t>& data,
                        const std::string& ext, std::vector<Finding>& out, ScanStats& stats) const;
    const RuleSet& rules_;
    ScanOptions opt_;
};

// ---------------------------------------------------------------- log analyzer
struct LogOptions {
    int bruteForceThreshold = 5;  // failed logins from one IP
    int portScanThreshold = 10;   // distinct destination ports from one IP
    int notFoundThreshold = 20;   // HTTP 404 responses for one IP
};

struct LogStats {
    size_t lines = 0;
    size_t uniqueIps = 0;
    size_t failedLogins = 0;
    size_t httpRequests = 0;
    size_t firewallEvents = 0;
};

std::vector<Finding> analyzeLog(const fs::path& file, const RuleSet& rules, const LogOptions& opt,
                                LogStats& stats, std::string& error);

// ---------------------------------------------------------------- live system audit
struct SystemOptions {
    bool deep = false;  // also scan every running executable with the file scanner
    ScanOptions scan;
};

struct SystemStats {
    size_t processes = 0;
    size_t tcpConnections = 0;
    size_t listeners = 0;
    size_t autoruns = 0;
    size_t imagesScanned = 0;
    size_t imagesSigned = 0;  // flagged images that turned out to be validly signed
    bool elevated = false;
};

bool systemAuditSupported();
std::vector<Finding> analyzeSystem(const RuleSet& rules, const SystemOptions& opt,
                                   SystemStats& stats, std::string& error);

// ---------------------------------------------------------------- reporting
struct Report {
    std::string mode;
    std::string target;
    std::string rulesFile;
    std::vector<std::pair<std::string, std::string>> stats;
    std::vector<Finding> findings;
    double seconds = 0.0;
};

int riskScore(const std::vector<Finding>& findings);
std::string verdict(int score);
void sortFindings(std::vector<Finding>& findings);
void printReport(const Report& report, bool color, Severity minSeverity);
bool writeJson(const Report& report, const fs::path& file, std::string& error);

// ---------------------------------------------------------------- self-test
struct SelfTestCheck {
    std::string name;
    bool passed = false;
};
std::vector<SelfTestCheck> runSelfTestChecks();  // shared by the CLI and the web dashboard

// ---------------------------------------------------------------- web dashboard (web_server.cpp)
struct WebOptions {
    uint16_t port = 18080;      // http://localhost:18080
    bool strictPort = false;    // fail instead of trying the next port when busy
    bool openBrowser = true;    // open the dashboard once the server is ready
    fs::path webRoot;           // folder with index.html, styles.css, app.js
    fs::path rulesPath;         // rule file that was loaded
    fs::path projectDir;        // used to offer the bundled samples/ folder
};
int runWebServer(const RuleSet& rules, const WebOptions& options);

}  // namespace ta
