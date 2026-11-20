// Threat Analyzer - frontend
'use strict';

// helpers
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const api = {
  async request(method, path, body, headers = {}) {
    const opts = { method, headers: { ...headers } };
    if (body !== undefined) {
      if (body instanceof Blob || body instanceof ArrayBuffer) {
        opts.body = body;
        opts.headers['Content-Type'] = 'application/octet-stream';
      } else {
        opts.body = JSON.stringify(body);
        opts.headers['Content-Type'] = 'application/json';
      }
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      setOnline(false);
      throw new Error('The Threat Analyzer engine is not responding. Is start.bat still running?');
    }
    setOnline(true);
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON */ }
    if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
    return data;
  },
  get: p => api.request('GET', p),
  post: (p, b, h) => api.request('POST', p, b, h),
};

function toast(msg, isError = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (isError ? ' err' : '');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.className = 'toast'; }, 3800);
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

function verdictClass(v) { return 'v-' + String(v || '').split(' ')[0]; }
function scoreColor(score) {
  if (score === 0) return 'var(--ok)';
  if (score < 15) return 'var(--low)';
  if (score < 40) return 'var(--med)';
  return 'var(--crit)';
}

async function withBusy(btn, fn) {
  const label = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Working…';
  try { return await fn(); }
  catch (e) { toast(e.message, true); }
  finally { btn.disabled = false; btn.innerHTML = label; }
}

// engine status
const state = { health: null, online: null, samples: null };

function setOnline(on) {
  if (state.online === on) return;
  state.online = on;
  const el = $('#engine-status');
  el.className = 'engine-status ' + (on ? 'online' : 'offline');
  if (!on) {
    $('.engine-text', el).textContent = 'Engine offline';
    $('#banner').innerHTML = `<div class="banner error"><b>Backend unavailable.</b> The THREAT ANALYZER engine is not responding at <span class="mono">${esc(location.origin)}</span>. Start it with <b>start.bat</b>; this page retries automatically.</div>`;
  } else {
    $('#banner').innerHTML = '';
    if (state.health) $('.engine-text', el).textContent = `Engine online · v${state.health.version} · :${state.health.port}`;
  }
}

async function loadHealth() {
  try {
    state.health = await api.get('/api/health');
    $('.engine-text', $('#engine-status')).textContent = `Engine online · v${state.health.version} · :${state.health.port}`;
  } catch (_) { /* banner already shown */ }
  return state.health;
}

async function loadSamples() {
  if (!state.samples) {
    try { state.samples = await api.get('/api/samples'); } catch (_) { state.samples = { files: [] }; }
  }
  return state.samples;
}

async function refreshHistoryCount() {
  try {
    const h = await api.get('/api/history');
    $('#nav-history-count').textContent = h.count ? h.count : '';
  } catch (_) { /* offline */ }
}

setInterval(async () => {
  try { await fetch('/api/health').then(r => { if (!r.ok) throw 0; }); setOnline(true); if (!state.health) loadHealth(); }
  catch (_) { setOnline(false); }
}, 5000);

// report rendering
function renderReport(r) {
  const s = r.summary || {};
  const total = SEVS.reduce((n, k) => n + (s[k.toLowerCase()] || 0), 0);
  const bar = total ? SEVS.map(k => {
    const n = s[k.toLowerCase()] || 0;
    return n ? `<span class="${k}" style="width:${(n / total) * 100}%" title="${k} ${n}"></span>` : '';
  }).join('') : '';
  const stats = (r.stats || []).map(x => `<dt>${esc(x.label)}</dt><dd>${esc(x.value)}</dd>`).join('');

  const html = `
    <div class="card stack" id="report-${r.id}">
      <div class="result-head">
        <div class="gauge" style="--v:${r.riskScore};--c:${scoreColor(r.riskScore)}"><div><div><b>${r.riskScore}</b><small>/ 100 risk</small></div></div></div>
        <div>
          <div class="row" style="align-items:center">
            <span class="verdict ${verdictClass(r.verdict)}">${esc(r.verdict)}</span>
            <span class="page-sub">${esc(r.mode)} · report #${r.id} · ${esc(fmtTime(r.generated))} · ${Number(r.durationSeconds).toFixed(2)} s</span>
          </div>
          <dl class="meta">
            <dt>Target</dt><dd class="mono">${esc(r.target)}</dd>
            <dt>Rules</dt><dd class="mono">${esc(r.rules)}</dd>
            ${stats}
          </dl>
        </div>
      </div>
      <div>
        <div class="sevbar">${bar}</div>
        <div class="counts">${SEVS.map(k => `<span><span class="sev ${k}">${k}</span><b>${s[k.toLowerCase()] || 0}</b></span>`).join('')}</div>
      </div>
      <div>
        <div class="toolbar">
          <strong>Findings (${r.findings.length})</strong>
          <span class="spacer"></span>
          <select class="f-min" aria-label="Minimum severity">
            <option value="0">All severities</option>
            <option value="1" selected>Low and above</option>
            <option value="2">Medium and above</option>
            <option value="3">High and above</option>
            <option value="4">Critical only</option>
          </select>
          <input type="text" class="f-q" placeholder="Filter findings…" aria-label="Filter findings">
          <button class="btn sm f-export">Export JSON</button>
        </div>
        <ul class="findings"></ul>
      </div>
    </div>`;
  return html;
}

function bindReport(container, r) {
  const list = $('.findings', container);
  const min = $('.f-min', container);
  const q = $('.f-q', container);
  const draw = () => {
    const m = Number(min.value);
    const needle = q.value.trim().toLowerCase();
    const items = r.findings.filter(f => SEV_RANK[f.severity] >= m &&
      (!needle || `${f.title} ${f.target} ${f.detail} ${f.category}`.toLowerCase().includes(needle)));
    const hidden = r.findings.length - items.length;
    list.innerHTML = items.length ? items.map(f => `
      <li class="finding ${f.severity}">
        <div class="f-head"><span class="sev ${f.severity}">${f.severity}</span><span class="f-title">${esc(f.title)}</span><span class="f-cat">${esc(f.category)}</span></div>
        <div class="f-target">${esc(f.target)}</div>
        <div class="f-detail">${esc(f.detail)}</div>
      </li>`).join('') + (hidden ? `<li class="empty">${hidden} finding(s) hidden by the filter</li>` : '')
      : `<li class="empty">${r.findings.length ? 'No findings match the filter.' : 'No threats detected.'}</li>`;
  };
  min.addEventListener('change', draw);
  q.addEventListener('input', draw);
  $('.f-export', container).addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `threat-analyzer-report-${r.id}.json`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  });
  draw();
}

function showReport(target, r, scroll = true) {
  target.innerHTML = renderReport(r);
  bindReport(target, r);
  if (scroll) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  refreshHistoryCount();
}

// views
const views = {};

views.dashboard = {
  title: 'Dashboard', sub: 'Overview of this session’s analyses',
  async render(v) {
    v.innerHTML = '<div class="loading"><span class="spinner"></span> Loading…</div>';
    const [health, hist, samples] = await Promise.all([loadHealth(), api.get('/api/history'), loadSamples()]);
    const t = hist.totals;
    const r = health ? health.rules : {};
    const hasSamples = samples.files && samples.files.length;
    v.innerHTML = `
      <div class="stack">
        <div class="grid kpis">
          <div class="card kpi"><div class="label">Session risk</div><div class="value" style="color:${scoreColor(hist.worstScore)}">${hist.worstScore}<span class="page-sub"> /100</span></div><div class="hint">${esc(hist.count ? hist.worstVerdict : 'No analyses yet')}</div></div>
          <div class="card kpi"><div class="label">Reports</div><div class="value">${hist.count}</div><div class="hint">this session (kept in memory)</div></div>
          <div class="card kpi"><div class="label">Critical / High</div><div class="value"><span style="color:var(--crit)">${t.critical}</span> / <span style="color:var(--high)">${t.high}</span></div><div class="hint">${t.medium} medium · ${t.low} low · ${t.info} info</div></div>
          <div class="card kpi"><div class="label">Detection rules</div><div class="value">${r.total ?? '–'}</div><div class="hint">${r.hash ?? 0} hash · ${r.string ?? 0} string · ${r.hex ?? 0} hex · ${r.log ?? 0} log</div></div>
        </div>

        <div class="grid two">
          <div class="card">
            <h2>Quick start</h2>
            <p class="sub">Run the engine against the bundled, harmless sample data or this computer.</p>
            <div class="chips">
              ${hasSamples ? '<button class="btn primary" id="q-scan">Scan samples folder</button>' : ''}
              ${(samples.files || []).filter(f => f.kind === 'log').map(f => `<button class="btn q-log" data-path="${esc(f.path)}">Analyze ${esc(f.name)}</button>`).join('')}
              ${health && health.systemAuditSupported ? '<a class="btn" href="#/system">Audit this computer</a>' : ''}
            </div>
            <div id="q-result-note" class="page-sub" style="margin-top:12px"></div>
          </div>
          <div class="card">
            <h2>Engine</h2>
            <p class="sub">C++17 engine served by Crow on this computer only.</p>
            <dl class="kv">
              <dt>Status</dt><dd>${health ? '<span class="pass">ONLINE</span>' : '<span class="fail">OFFLINE</span>'}</dd>
              <dt>Version</dt><dd>${esc(health?.version)}</dd>
              <dt>Address</dt><dd class="mono">${esc(location.origin)}</dd>
              <dt>Rule file</dt><dd class="mono">${esc(r.file)}</dd>
              <dt>Uptime</dt><dd>${health ? Math.round(health.uptimeSeconds / 60) + ' min' : '–'}</dd>
            </dl>
          </div>
        </div>

        <div class="card">
          <h2>Recent reports</h2>
          <p class="sub">Click a report to open it.</p>
          ${historyTable(hist.items.slice(0, 8))}
        </div>
      </div>`;
    bindHistoryRows(v);
    const qs = $('#q-scan', v);
    if (qs) qs.addEventListener('click', () => withBusy(qs, async () => {
      const rep = await api.post('/api/scan', { path: samples.dir });
      location.hash = `#/report/${rep.id}`;
    }));
    $$('.q-log', v).forEach(b => b.addEventListener('click', () => withBusy(b, async () => {
      const rep = await api.post('/api/logs', { path: b.dataset.path });
      location.hash = `#/report/${rep.id}`;
    })));
  },
};

function historyTable(items) {
  if (!items.length) return '<div class="empty">No reports yet. Run a file scan, log analysis or system audit.</div>';
  return `<div class="table-wrap"><table>
    <thead><tr><th>#</th><th>Time</th><th>Mode</th><th>Target</th><th>Verdict</th><th class="num">Risk</th><th class="num">Crit</th><th class="num">High</th><th class="num">Med</th><th class="num">Low</th></tr></thead>
    <tbody>${items.map(r => `
      <tr class="clickable" data-id="${r.id}">
        <td>${r.id}</td><td>${esc(fmtTime(r.generated))}</td><td>${esc(r.mode)}</td><td class="wrap mono">${esc(r.target)}</td>
        <td><span class="verdict ${verdictClass(r.verdict)}">${esc(r.verdict)}</span></td>
        <td class="num">${r.riskScore}</td><td class="num">${r.summary.critical}</td><td class="num">${r.summary.high}</td><td class="num">${r.summary.medium}</td><td class="num">${r.summary.low}</td>
      </tr>`).join('')}</tbody></table></div>`;
}
function bindHistoryRows(root) {
  $$('tr.clickable', root).forEach(tr => tr.addEventListener('click', () => { location.hash = `#/report/${tr.dataset.id}`; }));
}

views.history = {
  title: 'Reports', sub: 'Every analysis run in this session (newest first, up to 50)',
  async render(v) {
    const hist = await api.get('/api/history');
    v.innerHTML = `<div class="card">${historyTable(hist.items)}</div>`;
    bindHistoryRows(v);
  },
};

views.report = {
  title: 'Report', sub: '',
  async render(v, id) {
    const r = await api.get(`/api/history/${encodeURIComponent(id)}`);
    $('#page-sub').textContent = `${r.mode} · ${r.target}`;
    v.innerHTML = '<div id="rep"></div>';
    showReport($('#rep', v), r, false);
  },
};

views.scan = {
  title: 'File Scan', sub: 'SHA-256 hashes, text and byte signatures, PE header checks and heuristics',
  async render(v) {
    const samples = await loadSamples();
    v.innerHTML = `
      <div class="stack">
        <div class="grid two">
          <div class="card">
            <h2>Scan a file or folder on this computer</h2>
            <p class="sub">Enter a full path, e.g. <span class="mono">C:\\Users\\you\\Downloads</span></p>
            <form id="scan-form">
              <label class="field"><span>Path</span><input type="text" id="scan-path" placeholder="C:\\path\\to\\file-or-folder" autocomplete="off" spellcheck="false"></label>
              <div class="options">
                <label class="check"><input type="checkbox" id="scan-rec" checked> Include sub-folders</label>
                <label class="field"><span>Content limit (MB)</span><input type="number" id="scan-max" value="64" min="1" max="4096"></label>
                <label class="field"><span>Entropy alarm (bits)</span><input type="number" id="scan-ent" value="7.2" min="0" max="8" step="0.1"></label>
              </div>
              <div class="row">
                <button class="btn primary" type="submit" id="scan-go">Scan</button>
                ${samples.dir ? `<button class="btn" type="button" id="scan-samples">Use samples folder</button>` : ''}
              </div>
            </form>
          </div>
          <div class="card">
            <h2>Upload a file</h2>
            <p class="sub">The file is written to a temporary folder, scanned and deleted (limit 128 MB).</p>
            <label class="dropzone" id="drop">
              <input type="file" id="file-input">
              <div><b>Drop a file here</b> or click to choose</div>
            </label>
          </div>
        </div>
        <div id="scan-result"></div>
      </div>`;
    const out = $('#scan-result', v);
    const go = $('#scan-go', v);
    $('#scan-form', v).addEventListener('submit', e => {
      e.preventDefault();
      withBusy(go, async () => {
        const r = await api.post('/api/scan', {
          path: $('#scan-path', v).value,
          recursive: $('#scan-rec', v).checked,
          maxSizeMb: Number($('#scan-max', v).value) || 64,
          entropy: Number($('#scan-ent', v).value),
        });
        showReport(out, r);
      });
    });
    const sb = $('#scan-samples', v);
    if (sb) sb.addEventListener('click', () => { $('#scan-path', v).value = samples.dir; go.click(); });

    const drop = $('#drop', v);
    const input = $('#file-input', v);
    const prompt = $('div', drop);
    const upload = async file => {
      if (!file) return;
      if (file.size > 128 * 1024 * 1024) return toast('File too large for upload (limit 128 MB). Scan it by path.', true);
      prompt.innerHTML = `<span class="spinner"></span> Scanning ${esc(file.name)}…`;
      try {
        const r = await api.post(`/api/scan/upload?name=${encodeURIComponent(file.name)}`, file);
        showReport(out, r);
      } catch (e) { toast(e.message, true); }
      finally { prompt.innerHTML = '<b>Drop a file here</b> or click to choose'; input.value = ''; }
    };
    input.addEventListener('change', () => upload(input.files[0]));
    ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('drag'); }));
    drop.addEventListener('drop', e => upload(e.dataTransfer.files[0]));
  },
};

views.logs = {
  title: 'Log Analysis', sub: 'Auth, Apache/Nginx, iptables, Windows Firewall and exported event logs',
  async render(v) {
    const samples = await loadSamples();
    const logSamples = (samples.files || []).filter(f => f.kind === 'log');
    v.innerHTML = `
      <div class="stack">
        <div class="card">
          <h2>Analyze a log</h2>
          <p class="sub">Give a log file path <b>or</b> paste log lines. Detects SQL injection, XSS, path traversal, Log4Shell, scanners, brute force, login after brute force, port scans, new admin accounts and log clearing.</p>
          <form id="log-form">
            <label class="field"><span>Log file path</span><input type="text" id="log-path" placeholder="C:\\path\\to\\access.log" autocomplete="off" spellcheck="false"></label>
            <label class="field"><span>…or paste log lines</span><textarea id="log-text" placeholder="Nov 20 03:12:01 server sshd[812]: Failed password for root from 203.0.113.7 port 22 ssh2"></textarea></label>
            <div class="options">
              <label class="field"><span>Brute-force threshold</span><input type="number" id="log-th" value="5" min="1"></label>
              <label class="field"><span>Port-scan threshold</span><input type="number" id="log-ps" value="10" min="1"></label>
              <label class="field"><span>HTTP 404 threshold</span><input type="number" id="log-nf" value="20" min="1"></label>
            </div>
            <div class="row">
              <button class="btn primary" type="submit" id="log-go">Analyze</button>
              ${logSamples.map(f => `<button class="btn log-sample" type="button" data-path="${esc(f.path)}">${esc(f.name)}</button>`).join('')}
            </div>
          </form>
        </div>
        <div id="log-result"></div>
      </div>`;
    const out = $('#log-result', v);
    const go = $('#log-go', v);
    const run = () => withBusy(go, async () => {
      const path = $('#log-path', v).value.trim();
      const content = $('#log-text', v).value;
      const body = {
        threshold: Number($('#log-th', v).value) || 5,
        portscan: Number($('#log-ps', v).value) || 10,
        notfound: Number($('#log-nf', v).value) || 20,
      };
      if (path) body.path = path; else body.content = content;
      showReport(out, await api.post('/api/logs', body));
    });
    $('#log-form', v).addEventListener('submit', e => { e.preventDefault(); run(); });
    $$('.log-sample', v).forEach(b => b.addEventListener('click', () => {
      $('#log-path', v).value = b.dataset.path;
      $('#log-text', v).value = '';
      run();
    }));
  },
};

views.system = {
  title: 'System Audit', sub: 'Processes, TCP connections and autorun persistence on this Windows computer',
  async render(v) {
    const health = await loadHealth();
    v.innerHTML = `
      <div class="stack">
        <div class="card">
          <h2>Audit this computer</h2>
          <p class="sub">Looks for fake system processes, attack tools, programs running from Temp, Office apps starting shells, connections to backdoor or crypto-mining ports, and Run-key / Startup-folder persistence. Run <b>start.bat</b> as Administrator for full visibility.</p>
          ${health && !health.systemAuditSupported ? '<div class="banner warn">The live system audit is only available in Windows builds.</div>' : ''}
          <div class="row">
            <label class="check"><input type="checkbox" id="sys-deep"> Deep audit: also scan every running program and check its digital signature (slower)</label>
          </div>
          <div class="row" style="margin-top:12px"><button class="btn primary" id="sys-go">Run system audit</button></div>
        </div>
        <div id="sys-result"></div>
      </div>`;
    const go = $('#sys-go', v);
    go.addEventListener('click', () => withBusy(go, async () => {
      showReport($('#sys-result', v), await api.post('/api/system', { deep: $('#sys-deep', v).checked }));
    }));
  },
};

views.hash = {
  title: 'Hash a File', sub: 'SHA-256, size and entropy – and a ready-made HASH rule line',
  async render(v) {
    v.innerHTML = `
      <div class="stack">
        <div class="card">
          <form id="hash-form" class="row">
            <label class="field grow" style="margin:0"><span>File path</span><input type="text" id="hash-path" placeholder="C:\\path\\to\\file.exe" autocomplete="off" spellcheck="false"></label>
            <button class="btn primary" id="hash-go" type="submit">Hash</button>
          </form>
        </div>
        <div id="hash-result"></div>
      </div>`;
    const go = $('#hash-go', v);
    $('#hash-form', v).addEventListener('submit', e => {
      e.preventDefault();
      withBusy(go, async () => {
        const h = await api.post('/api/hash', { path: $('#hash-path', v).value });
        $('#hash-result', v).innerHTML = `
          <div class="card">
            <dl class="kv">
              <dt>File</dt><dd class="mono">${esc(h.file)}</dd>
              <dt>Size</dt><dd>${h.size} bytes (${esc(h.sizeText)})</dd>
              <dt>SHA-256</dt><dd class="mono">${esc(h.sha256)}</dd>
              <dt>Entropy</dt><dd>${h.entropy !== undefined ? Number(h.entropy).toFixed(4) + ' bits/byte' : 'not computed (file larger than 256 MB)'}</dd>
              <dt>Rule line</dt><dd class="mono">${esc(h.rule)}</dd>
            </dl>
            <div class="row" style="margin-top:14px"><button class="btn sm" id="copy-rule">Copy rule line</button></div>
          </div>`;
        $('#copy-rule', v).addEventListener('click', () => navigator.clipboard.writeText(h.rule).then(() => toast('Rule line copied'), () => toast('Copy failed', true)));
      });
    });
  },
};

views.rules = {
  title: 'Detection Rules', sub: 'Loaded from rules/signatures.txt (edit the file and restart to change them)',
  async render(v) {
    const d = await api.get('/api/rules');
    v.innerHTML = `
      <div class="card">
        <div class="toolbar">
          <span class="page-sub mono">${esc(d.file)} · ${d.total} rules</span>
          <span class="spacer"></span>
          <select id="r-type"><option value="">All types</option><option>HASH</option><option>STRING</option><option>HEX</option><option>LOG</option></select>
          <input type="text" id="r-q" placeholder="Search rules…">
        </div>
        <div class="table-wrap"><table><thead><tr><th>Type</th><th>Severity</th><th>Name</th><th>Value</th></tr></thead><tbody id="r-body"></tbody></table></div>
      </div>`;
    const draw = () => {
      const t = $('#r-type', v).value;
      const q = $('#r-q', v).value.trim().toLowerCase();
      const rows = d.rules.filter(r => (!t || r.type === t) && (!q || `${r.name} ${r.value}`.toLowerCase().includes(q)));
      $('#r-body', v).innerHTML = rows.map(r => `<tr><td>${r.type}</td><td><span class="sev ${r.severity}">${r.severity}</span></td><td>${esc(r.name)}</td><td class="mono wrap">${esc(r.value)}</td></tr>`).join('')
        || '<tr><td colspan="4" class="empty">No rules match.</td></tr>';
    };
    $('#r-type', v).addEventListener('change', draw);
    $('#r-q', v).addEventListener('input', draw);
    draw();
  },
};

views.selftest = {
  title: 'Self-test', sub: 'Verifies the engine’s internal algorithms (SHA-256, entropy, IPv4 parsing, severities)',
  async render(v) {
    v.innerHTML = '<div class="loading"><span class="spinner"></span> Running self-test in the C++ engine…</div>';
    const d = await api.get('/api/selftest');
    v.innerHTML = `
      <div class="card">
        <h2>${d.passed === d.total ? '<span class="pass">All checks passed</span>' : '<span class="fail">Self-test failed</span>'} · ${d.passed}/${d.total}</h2>
        <div class="table-wrap"><table><thead><tr><th>Result</th><th>Check</th></tr></thead><tbody>
          ${d.checks.map(c => `<tr><td class="${c.passed ? 'pass' : 'fail'}">${c.passed ? 'PASS' : 'FAIL'}</td><td>${esc(c.name)}</td></tr>`).join('')}
        </tbody></table></div>
        <div class="row" style="margin-top:14px"><button class="btn" id="st-again">Run again</button></div>
      </div>`;
    $('#st-again', v).addEventListener('click', () => views.selftest.render(v));
  },
};

// router
async function navigate() {
  const raw = location.hash.replace(/^#\/?/, '') || 'dashboard';
  const [name, arg] = raw.split('/');
  const view = views[name] || views.dashboard;
  const route = views[name] ? name : 'dashboard';
  $$('#nav a').forEach(a => a.classList.toggle('active', a.dataset.route === (route === 'report' ? 'history' : route)));
  $('#page-title').textContent = view.title;
  $('#page-sub').textContent = view.sub;
  $('#sidebar').classList.remove('open');
  const v = $('#view');
  try {
    await view.render(v, arg);
  } catch (e) {
    v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div><div class="row" style="justify-content:center"><button class="btn" id="retry">Retry</button></div></div>`;
    $('#retry', v).addEventListener('click', navigate);
  }
}

window.addEventListener('hashchange', navigate);
$('#menu-btn').addEventListener('click', () => $('#sidebar').classList.toggle('open'));

(async function init() {
  await loadHealth();
  refreshHistoryCount();
  if (!location.hash) location.hash = '#/dashboard'; else navigate();
})();
