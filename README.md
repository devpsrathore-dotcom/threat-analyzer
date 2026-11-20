# Threat Analyzer

A C++17 threat analysis tool for Windows, with a command-line interface and a browser dashboard.
The analysis engine has no third-party dependencies. The dashboard's web server uses Crow and Asio,
which are header-only and included in `third_party/`, so the build works offline.
It also builds on Linux, but the `system` command is Windows-only.

**Quick start:** double-click **`start.bat`**. The dashboard opens at **http://localhost:18080**.
See [Web dashboard: build and launch](#web-dashboard-build-and-launch).

- **`scan`**: checks files and folders for known-bad SHA-256 hashes, text and byte signatures,
  suspicious PE headers (packers, writable+executable sections, high-entropy code),
  double extensions, process-injection APIs, hidden base64 payloads and encrypted-looking data.
- **`logs`**: reads auth, Apache/Nginx, iptables and Windows Firewall logs, plus exported event logs.
  It detects SQL injection, XSS, path traversal, Log4Shell, scanners, brute force, a successful
  login after brute force, port scans, new admin accounts and log clearing.
- **`system`**: audits the running Windows machine for fake system processes, attack tools,
  programs running from Temp, Office apps starting shells, connections to backdoor or
  crypto-mining ports, and Run-key or Startup-folder persistence. `--deep` also scans every
  running program and checks its digital signature.
- **`hash`**, **`rules`**, **`selftest`**: helper commands.
- **`serve`**: starts the **web dashboard** at **http://localhost:18080** (C++/Crow server).
  Every command above is also available in the browser.

```
start.bat                   double-click: build if needed, start server, open the dashboard
stop.bat                    stop the web server cleanly
build.bat                   build with g++ only (no CMake needed)
CMakeLists.txt              optional CMake build
src/threat_analyzer.hpp     shared declarations
src/threat_analyzer.cpp     engine + command-line interface
src/web_server.cpp          Crow web server: REST API + static front-end
web/index.html              dashboard page
web/styles.css              dashboard styles
web/app.js                  dashboard logic (talks to /api/... on the same server)
rules/signatures.txt        detection rules, editable
samples/                    harmless test data
third_party/                Crow 1.2.0 and Asio 1.30.2 (header-only, with licences)
```

## Web dashboard: build and launch

**Address: <http://localhost:18080>**

1. Install the compiler once: [MSYS2](https://www.msys2.org), then in the **MSYS2 UCRT64** shell run
   `pacman -S --needed mingw-w64-ucrt-x86_64-gcc`. You need `C:\msys64\ucrt64\bin\g++.exe`.
2. **Double-click `start.bat`** in this folder.
3. Your default browser opens THREAT ANALYZER at **http://localhost:18080**.
   Keep the console window open while you use it.
4. To stop it, **double-click `stop.bat`**, press `Ctrl+C` in the console window, or close that window.

What `start.bat` does:

| Step | Action |
|---|---|
| 1 | If THREAT ANALYZER is already running on port 18080, it opens the browser and exits. |
| 2 | If `build\threat_analyzer.exe` is missing or older than any file in `src\`, it runs `build.bat`. That compiles, links and runs the self-test (about 30 seconds). If the build fails, the window stays open and shows the error. |
| 3 | It runs `build\threat_analyzer.exe serve --port 18080 --strict-port --web web --rules rules\signatures.txt`. The Crow server serves `web\index.html`, `web\styles.css` and `web\app.js` plus the JSON API under `/api/`, all from the same address. |
| 4 | As soon as the server accepts connections, it opens **http://localhost:18080** in the default browser. The console also shows the URL. |

`stop.bat` sends `POST /api/shutdown` to the server on port 18080 and waits for it to exit. If it is still
running after 10 seconds, it ends only the process that owns port 18080.

Manual equivalent (Command Prompt, in this folder):

```bat
build.bat
build\threat_analyzer.exe serve
```

Then open http://localhost:18080. Options for `serve`: `--port <n>` (default 18080), `--strict-port`,
`--web <dir>`, `--no-browser`, `--rules <file>`.

If port 18080 is used by another program, `start.bat` stops with
*"Port 18080 is already in use by another program"*. Close that program, or run
`build\threat_analyzer.exe serve --port 18090` and open http://localhost:18090.

### What the dashboard offers

| Page | What it does |
|---|---|
| Dashboard | Session risk, severity totals, rule counts, quick buttons for the bundled samples, recent reports |
| File Scan | Scan a file or folder by path (sub-folders, size limit and entropy threshold are configurable), or drag and drop a file to upload and scan it. Uploaded files go to a temporary folder and are deleted afterwards. |
| Log Analysis | Analyze a log file by path, or paste log lines. The brute-force, port-scan and 404 thresholds are configurable. |
| System Audit | The `system` audit, with an optional deep mode. Run `start.bat` as Administrator for full visibility. |
| Hash a File | SHA-256, size, entropy and a ready-made `HASH` rule line |
| Detection Rules | Every loaded rule, with filters |
| Self-test | The same checks as `threat_analyzer selftest` |
| Reports | Every report from this session (kept in memory, up to 50). Each report can be filtered by severity and exported as JSON in the same format as `--json`. |

### REST API (used by the dashboard)

| Method | Path | Body / purpose |
|---|---|---|
| GET | `/api/health` | Version, port, rule counts |
| GET | `/api/rules`, `/api/samples`, `/api/selftest` | Rule list, bundled sample files, self-test results |
| POST | `/api/scan` | `{"path": "...", "recursive": true, "maxSizeMb": 64, "entropy": 7.2}` |
| POST | `/api/scan/upload?name=<file name>` | Raw file bytes (`application/octet-stream`) |
| POST | `/api/logs` | `{"path": "..."}` or `{"content": "...", "name": "x.log"}`, plus optional `threshold`, `portscan`, `notfound` |
| POST | `/api/system` | `{"deep": false}` |
| POST | `/api/hash` | `{"path": "..."}` |
| GET | `/api/history`, `/api/history/{id}` | Session reports |
| POST | `/api/shutdown` | Used by `stop.bat`. Requires the header `X-Threat-Analyzer: shutdown` |

The server listens on `127.0.0.1` only. It refuses requests from other computers, requests whose `Host`
header is not `localhost`/`127.0.0.1` (DNS-rebinding protection), and `POST` requests from other
web sites (CSRF protection).

## Build (MinGW / MSYS2)

1. Install [MSYS2](https://www.msys2.org). Then, in the **MSYS2 UCRT64** shell, run:
   ```bash
   pacman -Syu
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-gdb
   ```
2. Add `C:\msys64\ucrt64\bin` to your Windows PATH. Then open a **new** terminal.
3. Build and test:
   ```powershell
   cmake -S . -B build -G Ninja
   cmake --build build
   cd build; ctest --output-on-failure; cd ..
   ```

**Without CMake**, run `build.bat`. It produces `build\threat_analyzer.exe` and runs the self-test.
Or compile with one command:
```powershell
g++ -std=c++17 -O2 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0601 -DASIO_STANDALONE -DCROW_DISABLE_STATIC_DIR -Isrc -Ithird_party/crow/include -Ithird_party/asio/include src/threat_analyzer.cpp src/web_server.cpp -o build/threat_analyzer.exe -static -pthread -liphlpapi -ladvapi32 -lshell32 -lwintrust -lws2_32 -lmswsock
```

**VS Code:**
1. Install the *C/C++* and *CMake Tools* extensions.
2. Open the folder and pick the kit **GCC … ucrt64**.
3. Press **F7** to build. Press **Shift+F5** to run, or **F5** to debug with gdb.

## Run

```powershell
$ta = ".\build\threat_analyzer.exe"
& $ta selftest
& $ta scan samples
& $ta scan "$env:USERPROFILE\Downloads" --json report.json
& $ta logs samples\auth.log
& $ta logs samples\access.log --min medium
& $ta system            # run as Administrator for full visibility
& $ta system --deep
& $ta hash file.exe     # prints a HASH rule line you can add to the rules
```

| Option | Meaning |
|---|---|
| `--rules <file>` | Rule file to use. The default is `rules\signatures.txt` next to the exe or in the current folder. |
| `--json <file>` | Also save the report as JSON. |
| `--min <level>` | Hide findings below this level: `info`, `low`, `medium`, `high` or `critical`. The default is `low`. |
| `--max-size <MB>` | Size limit for content scanning (default 64). Bigger files are only hash-checked. |
| `--entropy <bits>` | Entropy alarm threshold (default 7.2). |
| `--no-recursive` | Don't scan subfolders. |
| `--threshold` / `--portscan` / `--notfound <n>` | Log thresholds: failed logins (default 5), probed ports (10), HTTP 404s (20). |
| `--deep` | `system` only: also scan every running program. |
| `--no-color` | Turn off colours. |

**Exit codes:** `0` = clean, `1` = findings, `2` = error.

**Windows event logs** have to be exported to text first (run as admin):
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4732,1102} -MaxEvents 20000 |
  % { "EventID=$($_.Id) " + ($_.Message -replace '\s+',' ') } | Out-File events.log -Encoding utf8
```

## Rules

Each line in `rules/signatures.txt` is one rule in the form `TYPE|NAME|SEVERITY|VALUE`.

- `HASH` is a SHA-256 hash.
- `STRING` is text, matched without regard to case.
- `HEX` is a byte sequence, like `55 50 58 21`.
- `LOG` is a regular expression, matched without regard to case. It can contain `|`.

Severity is `INFO`, `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`. Lines starting with `#` are comments.

## Scoring

The weights are Low = 2, Medium = 6, High = 15 and Critical = 40. Weights are added up for each
target (a file, IP or process). The score is the total of the worst target, capped at 100.

| Score | Verdict |
|---|---|
| 0 | CLEAN |
| under 15 | LOW RISK |
| under 40 | SUSPICIOUS |
| 40 or more | HIGH RISK |

## Notes

- If you scan this project's own folder, it flags its own source code and README. Those
  files contain the attack strings the rules look for.
- This is a triage tool, not a replacement for antivirus. It uses heuristics, so it can produce
  false positives. Use it only on systems you are authorised to analyse.
