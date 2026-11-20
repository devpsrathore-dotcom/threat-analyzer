// Threat Analyzer - web server for the dashboard (uses Crow)
// runs on 127.0.0.1 only, serves the web folder and the /api/ routes
// requests from other hosts/origins are rejected
#include <crow.h>

#include "threat_analyzer.hpp"

#ifdef _WIN32
#include <shellapi.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <deque>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

namespace ta {

namespace {

using Method = crow::HTTPMethod;

// helpers
std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string nowIsoUtc() {
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

void replaceAll(std::string& s, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    for (size_t pos = 0; (pos = s.find(from, pos)) != std::string::npos; pos += to.size()) s.replace(pos, from.size(), to);
}

void securityHeaders(crow::response& r) {
    r.set_header("X-Content-Type-Options", "nosniff");
    r.set_header("X-Frame-Options", "DENY");
    r.set_header("Referrer-Policy", "no-referrer");
    r.set_header("Content-Security-Policy",
                 "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                 "connect-src 'self'; frame-ancestors 'none'");
}

crow::response json(const crow::json::wvalue& j, int code = 200) {
    crow::response r(code);
    r.set_header("Content-Type", "application/json; charset=utf-8");
    r.set_header("Cache-Control", "no-store");
    securityHeaders(r);
    r.body = j.dump();
    return r;
}

crow::response error(int code, const std::string& message) {
    crow::json::wvalue j;
    j["error"] = message;
    return json(j, code);
}

// bad input -> 400 error
struct BadRequest : std::runtime_error {
    using std::runtime_error::runtime_error;
};

template <typename F>
crow::response guarded(F&& f) {
    try {
        return f();
    } catch (const BadRequest& e) {
        return error(400, e.what());
    } catch (const std::exception& e) {
        return error(500, std::string("Internal error: ") + e.what());
    }
}

crow::json::rvalue parseJsonBody(const crow::request& req) {
    if (req.body.empty()) return crow::json::load("{}");
    auto body = crow::json::load(req.body);
    if (!body || body.t() != crow::json::type::Object) throw BadRequest("Request body must be a JSON object");
    return body;
}

std::string optString(const crow::json::rvalue& b, const char* key, size_t maxLen) {
    if (!b.has(key)) return "";
    if (b[key].t() != crow::json::type::String) throw BadRequest(std::string("'") + key + "' must be a string");
    std::string v = b[key].s();
    if (v.size() > maxLen) throw BadRequest(std::string("'") + key + "' is too long");
    return v;
}

bool optBool(const crow::json::rvalue& b, const char* key, bool def) {
    if (!b.has(key)) return def;
    const auto t = b[key].t();
    if (t == crow::json::type::True) return true;
    if (t == crow::json::type::False) return false;
    throw BadRequest(std::string("'") + key + "' must be true or false");
}

double optNumber(const crow::json::rvalue& b, const char* key, double def, double lo, double hi) {
    if (!b.has(key)) return def;
    if (b[key].t() != crow::json::type::Number) throw BadRequest(std::string("'") + key + "' must be a number");
    const double v = b[key].d();
    if (v < lo || v > hi)
        throw BadRequest(std::string("'") + key + "' must be between " + std::to_string(lo) + " and " +
                         std::to_string(hi));
    return v;
}

std::string stripQuotes(std::string s) {
    s = trim(s);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') s = s.substr(1, s.size() - 2);
    return s;
}

// clean up uploaded file name (keep extension)
std::string safeFileName(std::string name) {
    const size_t slash = name.find_last_of("/\\");
    if (slash != std::string::npos) name = name.substr(slash + 1);
    for (char& c : name) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || std::string("<>:\"/\\|?*").find(c) != std::string::npos) c = '_';
    }
    while (!name.empty() && (name.back() == '.' || name.back() == ' ')) name.pop_back();
    if (name.size() > 120) name = name.substr(name.size() - 120);
    return name.empty() ? "upload.bin" : name;
}

// reports
struct StoredReport {
    int id = 0;
    std::string generated;
    Report report;
};

crow::json::wvalue severityCounts(const std::vector<Finding>& findings) {
    int64_t c[5] = {0, 0, 0, 0, 0};
    for (const auto& f : findings) ++c[static_cast<int>(f.severity)];
    crow::json::wvalue s;
    s["critical"] = c[4];
    s["high"] = c[3];
    s["medium"] = c[2];
    s["low"] = c[1];
    s["info"] = c[0];
    return s;
}

// same as --json output + id and time
crow::json::wvalue reportJson(const StoredReport& sr, bool withFindings) {
    const Report& r = sr.report;
    const int score = riskScore(r.findings);
    crow::json::wvalue j;
    j["id"] = sr.id;
    j["tool"] = "Threat Analyzer";
    j["version"] = TA_VERSION;
    j["generated"] = sr.generated;
    j["mode"] = r.mode;
    j["target"] = r.target;
    j["rules"] = r.rulesFile;
    j["durationSeconds"] = r.seconds;
    j["riskScore"] = score;
    j["verdict"] = verdict(score);
    j["summary"] = severityCounts(r.findings);
    j["findingCount"] = static_cast<int64_t>(r.findings.size());
    std::vector<crow::json::wvalue> stats;
    for (const auto& s : r.stats) {
        crow::json::wvalue e;
        e["label"] = s.first;
        e["value"] = s.second;
        stats.push_back(std::move(e));
    }
    j["stats"] = std::move(stats);
    if (withFindings) {
        std::vector<crow::json::wvalue> list;
        list.reserve(r.findings.size());
        for (const auto& f : r.findings) {
            crow::json::wvalue e;
            e["severity"] = severityName(f.severity);
            e["category"] = f.category;
            e["title"] = f.title;
            e["target"] = f.target;
            e["detail"] = f.detail;
            list.push_back(std::move(e));
        }
        j["findings"] = std::move(list);
    }
    return j;
}

class History {
public:
    const StoredReport& add(Report r) {
        std::lock_guard<std::mutex> lock(m_);
        StoredReport sr;
        sr.id = ++nextId_;
        sr.generated = nowIsoUtc();
        sr.report = std::move(r);
        items_.push_front(std::move(sr));
        if (items_.size() > kMax) items_.pop_back();
        return items_.front();
    }
    crow::json::wvalue list() {
        std::lock_guard<std::mutex> lock(m_);
        std::vector<crow::json::wvalue> arr;
        int64_t totals[5] = {0, 0, 0, 0, 0};
        int worst = 0;
        for (const auto& sr : items_) {
            arr.push_back(reportJson(sr, false));
            for (const auto& f : sr.report.findings) ++totals[static_cast<int>(f.severity)];
            worst = std::max(worst, riskScore(sr.report.findings));
        }
        crow::json::wvalue j;
        j["count"] = static_cast<int64_t>(items_.size());
        j["items"] = std::move(arr);
        crow::json::wvalue t;
        t["critical"] = totals[4];
        t["high"] = totals[3];
        t["medium"] = totals[2];
        t["low"] = totals[1];
        t["info"] = totals[0];
        j["totals"] = std::move(t);
        j["worstScore"] = worst;
        j["worstVerdict"] = verdict(worst);
        return j;
    }
    bool get(int id, crow::json::wvalue& out) {
        std::lock_guard<std::mutex> lock(m_);
        for (const auto& sr : items_)
            if (sr.id == id) {
                out = reportJson(sr, true);
                return true;
            }
        return false;
    }

private:
    static constexpr size_t kMax = 50;
    std::mutex m_;
    std::deque<StoredReport> items_;
    int nextId_ = 0;
};

// request guard
bool isLocalHostHeader(const std::string& raw) {
    std::string host = lower(trim(raw));
    if (host.rfind("[::1]", 0) == 0) host = host.substr(5);
    else if (host.rfind("127.0.0.1", 0) == 0) host = host.substr(9);
    else if (host.rfind("localhost", 0) == 0) host = host.substr(9);
    else return false;
    if (host.empty()) return true;
    if (host[0] != ':' || host.size() < 2 || host.size() > 6) return false;
    return std::all_of(host.begin() + 1, host.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}

struct LocalOnlyGuard {
    struct context {};
    void before_handle(crow::request& req, crow::response& res, context&) {
        auto reject = [&](const std::string& why) {
            std::cerr << "  [web] blocked request: " << why << "\n";
            res = error(403, why);
            res.end();
        };
        const std::string& peer = req.remote_ip_address;
        const bool loopback =
            peer.rfind("127.", 0) == 0 || peer == "::1" || peer.rfind("::ffff:127.", 0) == 0;
        if (!peer.empty() && !loopback) return reject("Requests are accepted from this computer only.");
        if (!isLocalHostHeader(req.get_header_value("Host")))
            return reject("Host header must be localhost or 127.0.0.1 (DNS-rebinding protection).");
        if (req.method == Method::Post || req.method == Method::Put || req.method == Method::Delete) {
            const std::string origin = lower(req.get_header_value("Origin"));
            if (!origin.empty() && !(origin.rfind("http://", 0) == 0 && isLocalHostHeader(origin.substr(7))))
                return reject("Cross-origin request refused (CSRF protection).");
        }
    }
    void after_handle(crow::request&, crow::response&, context&) {}
};

using WebApp = crow::App<LocalOnlyGuard>;

// static files
std::string mimeFor(const std::string& ext) {
    static const std::map<std::string, std::string> types{
        {".html", "text/html; charset=utf-8"},      {".css", "text/css; charset=utf-8"},
        {".js", "application/javascript; charset=utf-8"}, {".json", "application/json"},
        {".svg", "image/svg+xml"},                   {".png", "image/png"},
        {".ico", "image/x-icon"},                    {".woff2", "font/woff2"}};
    auto it = types.find(lower(ext));
    return it == types.end() ? "application/octet-stream" : it->second;
}

crow::response serveStatic(const fs::path& root, const std::string& rel) {
    if (rel.empty() || rel.find("..") != std::string::npos || rel.find('\\') != std::string::npos ||
        rel.find(':') != std::string::npos || rel[0] == '/')
        return crow::response(404, "Not found");
    const fs::path file = root / utf8ToPath(rel);
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) return crow::response(404, "Not found");
    std::ifstream in(file, std::ios::binary);
    std::ostringstream buf;
    buf << in.rdbuf();
    crow::response r(200);
    r.set_header("Content-Type", mimeFor(file.extension().string()));
    r.set_header("Cache-Control", "no-cache");
    securityHeaders(r);
    r.body = buf.str();
    return r;
}

// OS helpers
bool portAvailable(uint16_t port) {
    try {
        asio::io_context io;
        asio::ip::tcp::acceptor acceptor(io);
        const asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), port);
        acceptor.open(ep.protocol());
        acceptor.bind(ep);
        return true;
    } catch (...) {
        return false;
    }
}

bool serverReachable(uint16_t port) {
    try {
        asio::io_context io;
        asio::ip::tcp::socket s(io);
        s.connect({asio::ip::make_address("127.0.0.1"), port});
        return true;
    } catch (...) {
        return false;
    }
}

void openInBrowser(const std::string& url) {
#ifdef _WIN32
    ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#elif defined(__APPLE__)
    std::system(("open '" + url + "' >/dev/null 2>&1 &").c_str());
#else
    std::system(("xdg-open '" + url + "' >/dev/null 2>&1 &").c_str());
#endif
}

fs::path tempWorkDir() {
    std::error_code ec;
    fs::path dir = fs::temp_directory_path(ec) / "threat_analyzer_web";
    fs::create_directories(dir, ec);
    return dir;
}

std::string uniqueStamp() {
    static std::atomic<unsigned> counter{0};
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" +
           std::to_string(++counter);
}

// deletes temp file when done
struct TempGuard {
    fs::path path;
    ~TempGuard() {
        std::error_code ec;
        if (!path.empty()) fs::remove_all(path, ec);
    }
};

}  // namespace

int runWebServer(const RuleSet& rules, const WebOptions& opt) {
    std::cout << std::unitbuf;  // flush every line so redirected logs are complete
    uint16_t port = opt.port;
    while (!portAvailable(port)) {
        if (opt.strictPort) {
            std::cerr << "  [error] Port " << port << " is already in use by another program.\n"
                      << "          Close it (or run stop.bat if Threat Analyzer is already running) and try again.\n";
            return 2;
        }
        if (port - opt.port >= 20 || port == 65535) {
            std::cerr << "  [error] No free port found from " << opt.port << " to " << port << "\n";
            return 2;
        }
        std::cout << "  [web] Port " << port << " is in use, trying " << port + 1 << "\n";
        ++port;
    }

    const fs::path webRoot = opt.webRoot;
    const fs::path samplesDir = opt.projectDir / "samples";
    const std::string rulesShown = pathToUtf8(opt.rulesPath);
    const std::string rulesLabel = rulesShown + "  (" + std::to_string(rules.total()) + " rules)";
    const auto started = std::chrono::steady_clock::now();
    const RuleSet* rs = &rules;

    History history;
    History* hist = &history;
    std::mutex jobMutex;  // one analysis at a time; health and static files stay responsive
    std::mutex* job = &jobMutex;

    auto finish = [hist](Report& report, std::chrono::steady_clock::time_point t0) {
        sortFindings(report.findings);
        report.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        const StoredReport& sr = hist->add(report);
        return json(reportJson(sr, true));
    };

    auto makeScanOptions = [rs, &opt](const crow::json::rvalue& b) {
        ScanOptions so;
        so.maxFileSize = static_cast<uint64_t>(optNumber(b, "maxSizeMb", 64, 0.001, 4096) * 1024 * 1024);
        so.entropyThreshold = optNumber(b, "entropy", 7.2, 0, 8);
        so.recursive = optBool(b, "recursive", true);
        so.excluded.insert(opt.rulesPath);
        (void)rs;
        return so;
    };

    WebApp app;
    app.loglevel(crow::LogLevel::Warning);

    // front-end
    CROW_ROUTE(app, "/")([webRoot] { return serveStatic(webRoot, "index.html"); });

    // system
    CROW_ROUTE(app, "/api/health").methods(Method::Get)([rs, rulesShown, port, started, samplesDir] {
        crow::json::wvalue j;
        j["status"] = "ok";
        j["product"] = "THREAT ANALYZER";
        j["version"] = TA_VERSION;
        j["engine"] = "C++17 / Crow";
        j["port"] = port;
        j["url"] = "http://localhost:" + std::to_string(port);
        j["uptimeSeconds"] =
            static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started).count());
        j["systemAuditSupported"] = systemAuditSupported();
        crow::json::wvalue r;
        r["file"] = rulesShown;
        r["total"] = static_cast<int64_t>(rs->total());
        r["hash"] = static_cast<int64_t>(rs->hashRules.size());
        r["string"] = static_cast<int64_t>(rs->stringRules.size());
        r["hex"] = static_cast<int64_t>(rs->hexRules.size());
        r["log"] = static_cast<int64_t>(rs->logRules.size());
        j["rules"] = std::move(r);
        std::error_code ec;
        j["samplesDir"] = fs::is_directory(samplesDir, ec) ? pathToUtf8(samplesDir) : "";
        return json(j);
    });

    CROW_ROUTE(app, "/api/rules").methods(Method::Get)([rs, rulesShown] {
        std::vector<crow::json::wvalue> list;
        auto add = [&list](const char* type, const std::vector<Rule>& v) {
            for (const auto& r : v) {
                crow::json::wvalue e;
                e["type"] = type;
                e["name"] = r.name;
                e["severity"] = severityName(r.severity);
                e["value"] = printable(r.value, 200);
                list.push_back(std::move(e));
            }
        };
        add("HASH", rs->hashRules);
        add("STRING", rs->stringRules);
        add("HEX", rs->hexRules);
        add("LOG", rs->logRules);
        crow::json::wvalue j;
        j["file"] = rulesShown;
        j["total"] = static_cast<int64_t>(rs->total());
        j["rules"] = std::move(list);
        return json(j);
    });

    CROW_ROUTE(app, "/api/samples").methods(Method::Get)([samplesDir] {
        std::vector<crow::json::wvalue> files;
        std::error_code ec;
        if (fs::is_directory(samplesDir, ec)) {
            for (const auto& e : fs::directory_iterator(samplesDir, ec)) {
                if (!e.is_regular_file(ec)) continue;
                crow::json::wvalue f;
                const std::string ext = lower(e.path().extension().string());
                f["name"] = pathToUtf8(e.path().filename());
                f["path"] = pathToUtf8(e.path());
                f["size"] = static_cast<int64_t>(e.file_size(ec));
                f["kind"] = ext == ".log" ? "log" : "file";
                files.push_back(std::move(f));
            }
        }
        crow::json::wvalue j;
        j["dir"] = pathToUtf8(samplesDir);
        j["files"] = std::move(files);
        return json(j);
    });

    CROW_ROUTE(app, "/api/selftest").methods(Method::Get)([] {
        const auto checks = runSelfTestChecks();
        std::vector<crow::json::wvalue> list;
        int passed = 0;
        for (const auto& c : checks) {
            crow::json::wvalue e;
            e["name"] = c.name;
            e["passed"] = c.passed;
            passed += c.passed ? 1 : 0;
            list.push_back(std::move(e));
        }
        crow::json::wvalue j;
        j["passed"] = passed;
        j["total"] = static_cast<int64_t>(checks.size());
        j["checks"] = std::move(list);
        return json(j);
    });

    CROW_ROUTE(app, "/api/history").methods(Method::Get)([hist] { return json(hist->list()); });

    CROW_ROUTE(app, "/api/history/<int>").methods(Method::Get)([hist](int id) {
        crow::json::wvalue j;
        if (!hist->get(id, j)) return error(404, "Report not found (reports are kept in memory until the server stops)");
        return json(j);
    });

    // analysis
    CROW_ROUTE(app, "/api/scan").methods(Method::Post)([rs, rulesLabel, job, finish, makeScanOptions](const crow::request& req) {
        return guarded([&] {
            const auto b = parseJsonBody(req);
            const std::string path = stripQuotes(optString(b, "path", 4096));
            if (path.empty()) throw BadRequest("Enter a file or folder path to scan");
            std::error_code ec;
            const fs::path target = fs::absolute(utf8ToPath(path), ec);
            if (ec || !fs::exists(target, ec)) throw BadRequest("Path not found: " + path);
            ScanOptions so = makeScanOptions(b);
            std::lock_guard<std::mutex> lock(*job);
            const auto t0 = std::chrono::steady_clock::now();
            FileScanner scanner(*rs, so);
            ScanStats st;
            Report report;
            report.findings = scanner.scanPath(target, st);
            report.mode = "FILE SCAN";
            report.target = pathToUtf8(fs::weakly_canonical(target, ec));
            report.rulesFile = rulesLabel;
            report.stats = {{"Scanned", std::to_string(st.filesScanned) + " file(s), " + formatBytes(st.bytesScanned)},
                            {"PE files", std::to_string(st.peFiles)},
                            {"Hash only", std::to_string(st.filesHashOnly) + " (larger than " +
                                              formatBytes(so.maxFileSize) + ")"},
                            {"Unreadable", std::to_string(st.filesFailed) + " file(s), " +
                                               std::to_string(st.dirsFailed) + " folder(s)"}};
            return finish(report, t0);
        });
    });

    // POST /api/scan/upload?name=filename  (body = file)
    CROW_ROUTE(app, "/api/scan/upload").methods(Method::Post)([rs, rulesLabel, job, finish, &opt](const crow::request& req) {
        return guarded([&] {
            constexpr size_t kMaxUpload = 128ull * 1024 * 1024;
            if (req.body.size() > kMaxUpload) return error(413, "File too large for upload (limit 128 MB). Scan it by path instead.");
            const char* rawName = req.url_params.get("name");
            const std::string name = safeFileName(rawName ? rawName : "");
            TempGuard tmp{tempWorkDir() / ("upload-" + uniqueStamp())};
            std::error_code ec;
            fs::create_directories(tmp.path, ec);
            const fs::path file = tmp.path / utf8ToPath(name);
            {
                std::ofstream out(file, std::ios::binary | std::ios::trunc);
                if (!out) throw std::runtime_error("cannot write temporary file");
                out.write(req.body.data(), static_cast<std::streamsize>(req.body.size()));
            }
            ScanOptions so;
            so.excluded.insert(opt.rulesPath);
            std::lock_guard<std::mutex> lock(*job);
            const auto t0 = std::chrono::steady_clock::now();
            FileScanner scanner(*rs, so);
            ScanStats st;
            Report report;
            report.findings = scanner.scanFile(file, st);
            const std::string tmpShown = pathToUtf8(file);
            for (auto& f : report.findings) {
                replaceAll(f.target, tmpShown, name);
                replaceAll(f.detail, tmpShown, name);
            }
            report.mode = "FILE SCAN (UPLOAD)";
            report.target = name + "  (uploaded, " + formatBytes(req.body.size()) + ")";
            report.rulesFile = rulesLabel;
            report.stats = {{"Scanned", std::to_string(st.filesScanned) + " file(s), " + formatBytes(st.bytesScanned)},
                            {"PE files", std::to_string(st.peFiles)}};
            return finish(report, t0);
        });
    });

    // log analysis: send a path or pasted content
    CROW_ROUTE(app, "/api/logs").methods(Method::Post)([rs, rulesLabel, job, finish](const crow::request& req) {
        return guarded([&] {
            const auto b = parseJsonBody(req);
            const std::string path = stripQuotes(optString(b, "path", 4096));
            const std::string content = optString(b, "content", 64ull * 1024 * 1024);
            if (path.empty() && content.empty()) throw BadRequest("Enter a log file path or paste log lines");
            LogOptions lo;
            lo.bruteForceThreshold = static_cast<int>(optNumber(b, "threshold", 5, 1, 1000000));
            lo.portScanThreshold = static_cast<int>(optNumber(b, "portscan", 10, 1, 1000000));
            lo.notFoundThreshold = static_cast<int>(optNumber(b, "notfound", 20, 1, 1000000));

            TempGuard tmp;
            fs::path target;
            std::string shown;
            std::error_code ec;
            if (!path.empty()) {
                target = utf8ToPath(path);
                if (!fs::is_regular_file(target, ec)) throw BadRequest("Log file not found: " + path);
                shown = pathToUtf8(fs::weakly_canonical(target, ec));
            } else {
                std::string name = safeFileName(optString(b, "name", 200));
                if (name == "upload.bin") name = "pasted.log";
                tmp.path = tempWorkDir() / ("paste-" + uniqueStamp());
                fs::create_directories(tmp.path, ec);
                target = tmp.path / utf8ToPath(name);
                std::ofstream out(target, std::ios::binary | std::ios::trunc);
                if (!out) throw std::runtime_error("cannot write temporary file");
                out << content;
                out.close();
                shown = name + "  (pasted text, " + formatBytes(content.size()) + ")";
            }
            std::lock_guard<std::mutex> lock(*job);
            const auto t0 = std::chrono::steady_clock::now();
            LogStats st;
            std::string err;
            Report report;
            report.findings = analyzeLog(target, *rs, lo, st, err);
            if (!err.empty()) throw BadRequest(err);
            if (!tmp.path.empty()) {
                const std::string tmpShown = pathToUtf8(target);
                for (auto& f : report.findings) {
                    replaceAll(f.target, tmpShown, "pasted log");
                    replaceAll(f.detail, tmpShown, "pasted log");
                }
            }
            report.mode = "LOG ANALYSIS";
            report.target = shown;
            report.rulesFile = rulesLabel;
            report.stats = {{"Lines", std::to_string(st.lines)},
                            {"Unique IPs", std::to_string(st.uniqueIps)},
                            {"Failed auth", std::to_string(st.failedLogins)},
                            {"HTTP reqs", std::to_string(st.httpRequests)},
                            {"FW events", std::to_string(st.firewallEvents)}};
            return finish(report, t0);
        });
    });

    CROW_ROUTE(app, "/api/system").methods(Method::Post)([rs, rulesLabel, job, finish](const crow::request& req) {
        return guarded([&] {
            if (!systemAuditSupported()) throw BadRequest("The live system audit is only available in Windows builds");
            const auto b = parseJsonBody(req);
            SystemOptions so;
            so.deep = optBool(b, "deep", false);
            std::lock_guard<std::mutex> lock(*job);
            const auto t0 = std::chrono::steady_clock::now();
            SystemStats st;
            std::string err;
            Report report;
            report.findings = analyzeSystem(*rs, so, st, err);
            if (!err.empty()) throw std::runtime_error(err);
            report.mode = so.deep ? "LIVE SYSTEM AUDIT (DEEP)" : "LIVE SYSTEM AUDIT";
            report.target = "local machine";
            report.rulesFile = rulesLabel;
            report.stats = {{"Elevated", st.elevated ? "yes" : "no (run start.bat as Administrator for full visibility)"},
                            {"Processes", std::to_string(st.processes)},
                            {"TCP estab.", std::to_string(st.tcpConnections)},
                            {"Listeners", std::to_string(st.listeners)},
                            {"Autoruns", std::to_string(st.autoruns)}};
            if (so.deep)
                report.stats.emplace_back("Images", std::to_string(st.imagesScanned) + " scanned, " +
                                                        std::to_string(st.imagesSigned) +
                                                        " flagged image(s) validly signed -> downgraded to INFO");
            return finish(report, t0);
        });
    });

    CROW_ROUTE(app, "/api/hash").methods(Method::Post)([](const crow::request& req) {
        return guarded([&] {
            const auto b = parseJsonBody(req);
            const std::string path = stripQuotes(optString(b, "path", 4096));
            if (path.empty()) throw BadRequest("Enter a file path");
            const fs::path p = utf8ToPath(path);
            std::error_code ec;
            if (!fs::is_regular_file(p, ec)) throw BadRequest("Not a file: " + path);
            std::string hash;
            if (!sha256File(p, hash)) throw BadRequest("Cannot read " + path);
            const uint64_t size = fs::file_size(p, ec);
            crow::json::wvalue j;
            j["file"] = pathToUtf8(fs::absolute(p, ec));
            j["size"] = static_cast<int64_t>(size);
            j["sizeText"] = formatBytes(size);
            j["sha256"] = hash;
            j["rule"] = "HASH|<name>|HIGH|" + hash;
            if (size <= 256ull * 1024 * 1024) {
                std::ifstream in(p, std::ios::binary);
                std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                j["entropy"] = shannonEntropy(data.data(), data.size());
            }
            return json(j);
        });
    });

    // shutdown route for stop.bat (needs custom header)
    CROW_ROUTE(app, "/api/shutdown").methods(Method::Post)([&app](const crow::request& req) {
        if (req.get_header_value("X-Threat-Analyzer") != "shutdown")
            return error(400, "Missing header X-Threat-Analyzer: shutdown");
        std::cout << "  [web] Shutdown requested - stopping server\n";
        WebApp* a = &app;
        std::thread([a] {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            a->stop();
        }).detach();
        crow::json::wvalue j;
        j["status"] = "stopping";
        return json(j);
    });

    // remaining static files
    CROW_ROUTE(app, "/<path>")([webRoot](const std::string& path) {
        if (path.rfind("api/", 0) == 0) return error(404, "Unknown API endpoint");
        return serveStatic(webRoot, path);
    });

    const std::string url = "http://localhost:" + std::to_string(port);
    std::cout << "\n  THREAT ANALYZER v" << TA_VERSION << "  -  web dashboard\n\n"
              << "  [web] Front-end : " << pathToUtf8(webRoot) << "\n"
              << "  [web] Rules     : " << rulesLabel << "\n"
              << "  [web] Listening : 127.0.0.1:" << port << "  (this computer only; Ctrl+C or stop.bat to stop)\n\n"
              << "  ==========================================================\n"
              << "    Open THREAT ANALYZER in your browser:  " << url << "\n"
              << "  ==========================================================\n\n"
              << std::flush;

    if (opt.openBrowser) {
        std::thread([url, port] {
            for (int i = 0; i < 75; ++i) {  // up to ~15 s
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                if (serverReachable(port)) {
                    std::cout << "  [web] Server ready - opening " << url << " in the default browser\n" << std::flush;
                    openInBrowser(url);
                    return;
                }
            }
            std::cout << "  [web] Server did not become ready; open " << url << " manually\n" << std::flush;
        }).detach();
    }

    try {
        app.bindaddr("127.0.0.1").port(port).multithreaded().run();
    } catch (const std::exception& e) {
        std::cerr << "  [fatal] " << e.what() << "\n";
        return 2;
    }
    std::cout << "  [web] Server stopped.\n";
    return 0;
}

}  // namespace ta
