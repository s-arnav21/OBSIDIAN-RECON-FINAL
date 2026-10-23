'use strict';

const $ = (id) => document.getElementById(id);
const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];

let renderedFindings = 0;
let liveSev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
let livePinned = true;
let scanName = null;
let pollHandoffTimer = null;
let handoffJobId = null;

const phaseLabels = {
  recon: 'Discovery',
  network: 'Network',
  web: 'Web surface',
  scanner: 'Scanners',
  exploit: 'Exploit probes',
  post: 'Post-processing',
  report: 'Reporting',
  chain: 'Validation and finalize',
};

const iconPaths = {
  done: ['M5.5 12.5 9.5 16.5 18.5 7.5'],
  failed: ['M7 7l10 10', 'M17 7 7 17'],
  running: ['M12 4.5a7.5 7.5 0 1 1-7.5 7.5', 'M4.5 7.5v4h4'],
  skipped: ['M6 12h12'],
  cancelled: ['M8 8l8 8', 'M16 8l-8 8'],
  pending: ['M12 7v5l3 2', 'M12 3.5a8.5 8.5 0 1 1-8.5 8.5A8.5 8.5 0 0 1 12 3.5Z'],
};

function iconNode(name, label) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon icon-sm');
  svg.setAttribute('aria-hidden', 'true');
  (iconPaths[name] || iconPaths.pending).forEach((d) => {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    svg.appendChild(path);
  });
  if (label) svg.setAttribute('data-label', label);
  return svg;
}

/* ---------- formatting ---------- */
function fmtDur(ms) {
  if (ms == null) return '-';
  const s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  return m + 'm ' + (s % 60) + 's';
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function sevClass(sev) {
  const s = String(sev || 'info').toLowerCase();
  return sevOrder.includes(s) ? s : 'info';
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

/* ---------- dots & buttons ---------- */
function setDot(state) {
  $('statusDot').setAttribute('data-state', state);
  const labels = { idle: 'Ready', working: 'Scanning', scanning: 'Scanning', ok: 'Complete', err: 'Attention' };
  if ($('sessionState')) $('sessionState').textContent = labels[state] || 'Ready';
}
function setBusy(busy) {
  $('runBtn').disabled = busy;
  $('targetInput').disabled = busy;
  $('scanNameInput').disabled = busy;
  $('authCheck').disabled = busy;
  if ($('autoHandoffCheck')) $('autoHandoffCheck').disabled = busy || $('devScopedCheck').checked;
  $('devScopedCheck').disabled = busy;
  document.body.classList.toggle('is-scanning', busy);
}
function statusLine(msg, cls) {
  const s = $('statusLine');
  s.className = 'statusline' + (cls ? ' ' + cls : '');
  s.textContent = msg;
}

/* ---------- theme and shell context ---------- */
function setTheme(theme, persist) {
  const root = document.documentElement;
  root.classList.add('theme-transitioning');
  root.dataset.theme = theme;
  if (persist) localStorage.setItem('obsidian-theme', theme);
  const toggle = $('themeToggle');
  if (toggle) {
    const dark = theme === 'dark';
    toggle.setAttribute('aria-pressed', String(dark));
    toggle.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    toggle.title = dark ? 'Use dark theme' : 'Use light theme';
  }
  window.setTimeout(() => root.classList.remove('theme-transitioning'), 320);
}

function updateAuthorizationState() {
  const authorized = $('authCheck').checked;
  const tag = $('authTag');
  tag.dataset.authorized = String(authorized);
  tag.querySelector('#authTagText').textContent = authorized ? 'Authorized' : 'Authorization required';
}

function updateTargetContext() {
  const value = $('targetInput').value.trim();
  $('targetContext').textContent = value || 'Not configured';
}

/* ---------- findings narrative ---------- */
// Human-readable headings for canonical vulnerability types (mirrors the
// normalize-layer KB). Generic slugs like "reconnaissance"/"misconfiguration"
// render as proper titles instead of raw snake/kebab-case headers.
const VULN_LABELS = {
  'reconnaissance': 'Reconnaissance / enumeration result',
  'misconfiguration': 'Security misconfiguration',
  'information-disclosure': 'Information disclosure',
  'open-service-exposure': 'Open service exposure',
  'weak-tls-cipher': 'Weak TLS cipher or protocol',
  'expired-tls': 'Expired TLS certificate',
  'missing-security-header': 'Missing security header',
  'clickjacking': 'Clickjacking (frameable page)',
  'cookie-missing-secure': 'Cookie without Secure flag',
  'cookie-missing-httponly': 'Cookie without HttpOnly flag',
  'mime-sniffing': 'MIME sniffing allowed',
  'waf-presence': 'WAF/CDN detected',
  'waf-origin': 'WAF origin IP exposed',
  'sensitive-backup-file': 'Sensitive backup or archive exposed',
  'debug-mode-exposed': 'Debug interface exposed',
  'exposure': 'Sensitive content exposed',
  'env-exposed': 'Environment / .env file exposed',
  'git-exposed': '.git directory exposed',
  'discovered-path': 'Sensitive path discovered',
  'frontpage-extensions': 'FrontPage Server Extensions enabled',
  'exposed-admin-panel': 'Admin panel exposed',
  'user-enumeration': 'Username enumeration',
  'subdomain-takeover': 'Subdomain takeover',
  'sql-injection': 'SQL injection',
  'lfi': 'Local file inclusion / path traversal',
  'xss': 'Cross-site scripting (XSS)',
  'xxe': 'XML external entity (XXE)',
  'ssrf': 'Server-side request forgery (SSRF)',
  'ssti': 'Server-side template injection',
  'csrf': 'Cross-site request forgery (CSRF)',
  'idor': 'Insecure direct object reference (IDOR)',
  'command-execution': 'Command / RCE injection',
  'file-upload': 'Unrestricted file upload',
  'host-header-injection': 'Host header injection',
  'open-redirect': 'Open redirect',
  'default-credentials': 'Default credentials in use',
  'weak-credentials': 'Brute-forceable / weak credentials',
  'weak-hashing': 'Weak cryptographic hashing',
  'cve': 'Known-vulnerable component (CVE)',
  'osint-cert-expired': 'Domain certificate expired',
  'osint-domain-expiring': 'Domain expiring soon',
  'osint-internal-san': 'Internal hostname in certificate SANs',
  'osint-ip-in-cert-san': 'IP literal in certificate SANs',
  'osint-historical-sensitive-path': 'Historical sensitive path archived',
  'osint-shared-hosting-detected': 'Shared hosting detected',
  'unknown': 'Unclassified finding',
};

function vulnLabel(type) {
  return (type && VULN_LABELS[type]) || null;
}

function findingDesc(f) {
  const parts = [];
  if (f.vulnerability_type) parts.push('[' + (vulnLabel(f.vulnerability_type) || f.vulnerability_type) + ']');

  // Canonical findings carry an evidence dict.
  if (typeof f.evidence === 'object' && f.evidence) {
    const t = f.evidence.title || f.evidence.reason || f.evidence.description;
    if (f.evidence.url && t) { parts.push(t + ' @ ' + f.evidence.url); return parts.join(' '); }
    if (f.evidence.url) { parts.push(f.evidence.url); return parts.join(' '); }
    if (t) { parts.push(t); return parts.join(' '); }
  }

  // Raw scanner findings carry description / extraction / raw detail.
  if (f.description) parts.push(f.description);
  if (f.extraction != null) {
    const ex = f.extraction;
    if (typeof ex === 'string' && ex) parts.push(ex.length > 200 ? ex.slice(0, 200) + '…' : ex);
    else if (typeof ex === 'object') {
      const s = JSON.stringify(ex);
      if (s && s.length > 4) parts.push(s.length > 300 ? s.slice(0, 300) + '…' : s);
    }
  } else if (typeof f.raw === 'object' && f.raw) {
    const s = JSON.stringify(f.raw);
    if (s && s.length > 4) parts.push(s.length > 300 ? s.slice(0, 300) + '…' : s);
  }

  const url = f.url || (f.matched_at ? 'observed: ' + f.matched_at : '');
  if (url && parts.length < 3) parts.push(url);
  return parts.join(' ').trim() || '[no description]';
}

/* ---------- results view ---------- */
let summaryReady = false;

function setResultsMode(mode) {
  const liveBtn = $('viewLiveBtn');
  const sumBtn = $('viewSummaryBtn');
  if (mode === 'summary' && !summaryReady) return;
  const toggle = $('resultsToggle');
  toggle.hidden = false;
  liveBtn.classList.toggle('active', mode === 'live');
  sumBtn.classList.toggle('active', mode === 'summary');
  liveBtn.setAttribute('aria-pressed', String(mode === 'live'));
  sumBtn.setAttribute('aria-pressed', String(mode === 'summary'));
  sumBtn.disabled = !summaryReady;
  $('liveView').hidden = (mode !== 'live');
  $('resultView').hidden = (mode !== 'summary');
}

function showEmpty(title, sub) {
  $('resultView').hidden = true;
  $('liveView').hidden = true;
  $('resultsToggle').hidden = true;
  $('cancelledBanner').hidden = true;
  const es = $('emptyState');
  es.hidden = false;
  es.style.display = '';
  if (title) {
    es.querySelector('.empty-title').textContent = title;
    es.querySelector('.empty-sub').textContent = sub || '';
  }
}

function showLive() {
  $('emptyState').hidden = true;
  $('emptyState').style.display = 'none';
  setResultsMode('live');
}

function showError(msg) {
  clearError();
  const err = document.createElement('div');
  err.className = 'error-card';
  err.textContent = 'scan failed: ' + (typeof msg === 'string' ? msg : 'unknown error');
  $('results').insertBefore(err, !$('liveView').hidden ? $('liveView') : $('resultView'));
}

function clearError() {
  document.querySelectorAll('.error-card').forEach((e) => e.remove());
}

/* ---------- reset state for a new scan ---------- */
function resetForScan() {
  clearError();
  summaryReady = false;
  showLive();
  $('cancelledBanner').hidden = true;
  renderedFindings = 0;
  liveSev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  $('liveFindings').innerHTML = '';
  $('liveFindings').appendChild(el('div', 'lf-empty', 'scanning — findings will appear here as they are discovered…'));
  renderLiveSev();
  updateCountPill(0);
  setProgress(0, 0, 'running');
  $('journalFoot').textContent = 'starting…';
  $('resultView').hidden = true;
  $('groups').innerHTML = '';
  $('pills').innerHTML = '';
  $('sevBar').innerHTML = '';
  $('triageNote').textContent = '';
  $('toExploitCard').hidden = true;
  const hc = $('handoffCard');
  if (hc) hc.hidden = true;
  handoffJobId = null;
  if (pollHandoffTimer) { clearTimeout(pollHandoffTimer); pollHandoffTimer = null; }
  if (window.__handoffTimer) { clearTimeout(window.__handoffTimer); window.__handoffTimer = null; }
}

/* ---------- progress bar ---------- */
function setProgress(done, total, state) {
  const bar = $('progressBar');
  bar.className = 'progress-fill' + (state === 'running' ? ' live' : ' ' + state);
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : (state === 'running' ? 0 : 100);
  bar.style.transform = 'scaleX(' + (pct / 100) + ')';
  $('progressLabel').textContent = (state === 'running')
    ? done + ' / ' + total + ' · ' + pct + '%'
    : pct + '%';
}

/* ---------- live journal ---------- */
function renderJournal(steps) {
  const list = $('tickList');
  const box = list.parentElement;
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;

  // Steps carry a monotonically increasing run-sequence number stamped when
  // they go live; pending/skipped leftovers stay unnumbered and fall to the
  // end in manifest order. Sorting on it makes the journal read exactly in
  // the order the pipeline executed (recon -> network -> web -> scanners),
  // never in alphabetical manifest order.
  const ordered = (steps || []).slice().sort(sortBySeq);

  list.innerHTML = '';
  let activePhase = null;
  ordered.forEach((s) => {
    const phase = s.phase || 'pipeline';
    if (phase !== activePhase) {
      activePhase = phase;
      list.appendChild(el('div', 'tick-divider', phaseLabels[phase] || phase.replace(/[-_]/g, ' ')));
    }
    const tick = el('div', 'tick ' + (s.status || 'pending'));
    tick.setAttribute('role', 'listitem');
    const mark = el('span', 'mark', '');
    mark.appendChild(iconNode(tickIconName(s.status)));
    tick.appendChild(mark);
    let label = s.label;
    const fc = s.findings_count != null ? s.findings_count : (s.findings || 0);
    if (fc) label += ' · ' + fc + ' finding' + (fc === 1 ? '' : 's');
    if (s.error) label += ' — ' + s.error;
    const spokenState = (s.status || 'pending').replace(/[-_]/g, ' ');
    tick.setAttribute('aria-label', label + ', ' + spokenState);
    tick.appendChild(el('span', 'tlabel', label));
    if (s.duration_ms != null) tick.appendChild(el('span', 'ttime', (s.duration_ms / 1000).toFixed(1) + 's'));
    list.appendChild(tick);
  });
  const running = ordered.filter((s) => s.status === 'running');
  const current = running[running.length - 1];
  const finished = ordered.filter((s) => ['done', 'failed', 'skipped', 'cancelled'].includes(s.status)).length;
  const hasFailed = ordered.some((s) => s.status === 'failed');
  const hasCancelled = ordered.some((s) => s.status === 'cancelled');
  const fullyResolved = ordered.length > 0 && finished === ordered.length;
  $('currentOperation').textContent = current
    ? current.label
    : (fullyResolved
      ? (hasCancelled ? 'Pipeline cancelled' : (hasFailed ? 'Completed with issues' : 'Pipeline complete'))
      : (ordered.length ? 'Pipeline queued' : 'Waiting for a scan'));
  $('journalFoot').textContent = ordered.length
    ? finished + ' of ' + ordered.length + ' operations resolved'
    : 'Idle · no active job';
  if (nearBottom) box.scrollTop = box.scrollHeight;
}

function sortBySeq(a, b) {
  const as = a.seq == null ? 1e9 : Number(a.seq);
  const bs = b.seq == null ? 1e9 : Number(b.seq);
  return as - bs;
}

function tickIconName(status) {
  return iconPaths[status] ? status : 'pending';
}

/* ---------- live findings ---------- */
function renderLiveSev() {
  const wrap = $('liveSev');
  wrap.innerHTML = '';
  sevOrder.forEach((sev) => {
    const n = liveSev[sev] || 0;
    const item = el('div', 'sev-item');
    item.appendChild(el('span', 'sev-chip ' + sev + (n === 0 ? ' zero' : ''), String(n)));
    item.appendChild(el('span', '', sev));
    wrap.appendChild(item);
  });
}

function updateCountPill(n) {
  const pill = $('liveCount');
  pill.textContent = String(n);
  pill.classList.add('bump');
  setTimeout(() => pill.classList.remove('bump'), 200);
}

function setLivePinned(v) {
  livePinned = v;
  const p = $('livePinned');
  if (p) {
    p.classList.toggle('paused', !v);
    const label = p.querySelector('span:last-child');
    if (label) label.textContent = v ? 'Following newest' : 'Following paused';
    p.setAttribute('aria-pressed', String(!v));
  }
}

function scrollLiveToBottom() {
  window.scrollTo({ top: document.documentElement.scrollHeight, behavior: 'auto' });
}

function lfSeverityGroup(feed, sev) {
  let g = feed.querySelector('.lf-group[data-sev="' + sev + '"]');
  if (g) return g;
  g = el('div', 'lf-group');
  g.setAttribute('data-sev', sev);
  const head = el('div', 'lf-group-head ' + sev, '');
  head.appendChild(el('span', 'lf-group-label', sev + ' findings'));
  head.appendChild(el('span', 'lf-group-count', '0'));
  g.appendChild(head);
  g.appendChild(el('div', 'lf-group-body', ''));
  const idx = sevOrder.indexOf(sev);
  const next = Array.prototype.find.call(
    feed.querySelectorAll('.lf-group'),
    (gl) => sevOrder.indexOf(gl.getAttribute('data-sev')) > idx,
  );
  if (next) feed.insertBefore(g, next);
  else feed.appendChild(g);
  return g;
}

function appendLiveFindings(rows) {
  const feed = $('liveFindings');
  if (!rows || !rows.length) return;
  feed.querySelectorAll('.lf-empty').forEach((e) => e.remove());
  rows.forEach((f) => {
    const sev = sevClass(f.severity);
    liveSev[sev] = (liveSev[sev] || 0) + 1;
    const card = el('div', 'lf-card border-' + sev + ' lf-fresh');
    card.appendChild(el('span', 'sev-chip ' + sev, sev));
    const body = el('div', 'lf-body', '');
    body.appendChild(el('div', 'lf-desc', findingDesc(f)));
    const meta = el('div', 'lf-meta', '');
    meta.appendChild(el('span', 'host', String(f.host || f.target || '') + ' '));
    if (f.port != null) meta.appendChild(el('span', '', ':' + String(f.port) + (f.service ? '/' + String(f.service) : '') + ' '));
    if (f.source) meta.appendChild(el('span', '', '· ' + f.source));
    if (f.url || f.endpoint) meta.appendChild(el('span', '', '· ' + String(f.url || f.endpoint)));
    body.appendChild(meta);
    if (f.evidence && Object.keys(f.evidence).length) {
      body.appendChild(el('div', 'lf-raw', JSON.stringify(f.evidence).slice(0, 500)));
    }
    card.appendChild(body);
    const group = lfSeverityGroup(feed, sev);
    const gbody = group.querySelector('.lf-group-body');
    gbody.appendChild(card);
    group.querySelector('.lf-group-count').textContent = String(gbody.children.length);
  });
  renderedFindings += rows.length;
  renderLiveSev();
  updateCountPill(renderedFindings);
  if (livePinned) scrollLiveToBottom();
}

/* ---------- run the scan (async job) ---------- */
let activeJobId = null;
let seenLiveKeys = new Set();

function updateDevScopedState() {
  const checked = $('devScopedCheck').checked;
  $('devScopedWarning').hidden = !checked;
  if (checked) {
    $('autoHandoffCheck').checked = false;
    $('authCheck').checked = false;
    updateAuthorizationState();
  }
  $('autoHandoffCheck').disabled = checked;
}

async function loadDevScopedSettings() {
  try {
    const settings = await postJSON('/api/scans/dev-scoped-settings', null, 'GET');
    $('devScopedControl').hidden = !settings.enabled;
    if (!settings.enabled) $('devScopedCheck').checked = false;
  } catch (_) {
    $('devScopedControl').hidden = true;
    $('devScopedCheck').checked = false;
  }
  updateDevScopedState();
}

function scanPayload() {
  const url = $('targetInput').value.trim();
  if (!url) { statusLine('target URL is required', 'err'); return null; }
  scanName = $('scanNameInput').value.trim();
  if (!scanName) {
    statusLine('scan name is required', 'err');
    $('scanNameInput').focus();
    return null;
  }
  return {
    target_url: url,
    authorized: $('authCheck').checked,
    name: scanName,
    auto_handoff: $('devScopedCheck').checked ? false : $('autoHandoffCheck').checked,
  };
}

async function postJSON(path, body, method) {
  const res = await fetch(path, {
    method: method || 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body == null ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = data && (data.detail || data.error);
    const msg = typeof detail === 'string' ? detail : ('HTTP ' + res.status);
    throw new Error(msg);
  }
  return data;
}

function findingKey(f) {
  if (f.finding_id) return 'id:' + f.finding_id;
  return [
    'raw', f.scanner || '', f.url || f.path || f.target || '',
    String(f.port ?? ''), f.vulnerability_type || '',
  ].join('|');
}

async function startScan() {
  const payload = scanPayload();
  if (!payload) return;
  setBusy(true);
  setDot('working');
  resetForScan();
  seenLiveKeys = new Set();
  activeJobId = null;
  statusLine('creating scan job…');

  $('stopBtn').disabled = false;
  $('stopBtn').hidden = false;

  let job;
  try {
    job = await postJSON('/api/scans/jobs', payload);
  } catch (err) {
    setDot('err');
    setProgress(0, 0, 'failed');
    showError(err.message);
    statusLine(err.message, 'err');
  }

  activeJobId = job.id;
  renderJournal(job.steps || []);
  setProgress(job.done || 0, job.total || 0, 'running');
  appendLiveFindings(job.findings || []);
  statusLine('scan job ' + job.id + ' running…');
  pollJob(job.id);
}

async function pollJob(jobId) {
  const started = Date.now();
  const tick = async () => {
    let job;
    try {
      job = await postJSON('/api/scans/jobs/' + jobId, null, 'GET');
    } catch (err) {
      if (activeJobId === jobId) {
        setDot('err');
        showError(err.message);
        statusLine(err.message, 'err');
        finishBusyState();
      }
      return;
    }

    if (activeJobId !== jobId) return;

    const fresh = (job.findings || []).filter((f) => {
      const k = findingKey(f);
      if (seenLiveKeys.has(k)) return false;
      seenLiveKeys.add(k);
      return true;
    });
    appendLiveFindings(fresh);
    renderJournal(job.steps || []);

    const terminal = job.status === 'done' || job.status === 'failed' || job.status === 'cancelled';
    if (terminal) {
      renderJournal(job.steps || []);
      finalizeJob(job);
      return;
    }

    setProgress(job.done || 0, job.total || 0, 'running');
    const running = (job.steps || []).filter((s) => s.status === 'running');
    const last = running[running.length - 1];
    statusLine(last ? 'running: ' + last.label : 'scan running… ' + Math.round((Date.now() - started) / 1000) + 's');
    setTimeout(tick, 800);
  };
  tick();
}

function finalizeJob(job) {
  finishBusyState();
  const elapsed = job.elapsed_ms;
  if (job.status === 'failed') {
    setDot('err');
    setProgress(job.done || 0, job.total || 0, 'failed');
    showError(job.error || 'scan failed');
    statusLine('scan failed: ' + (typeof job.error === 'string' ? job.error : 'unknown'), 'err');
    return;
  }
  if (job.status === 'cancelled') {
    $('cancelledBanner').hidden = false;
    setDot('idle');
    setProgress(job.done || 0, job.total || 0, 'cancelled');
    statusLine('scan cancelled by request', 'warn');
    if (job.result) renderResults(job.result, elapsed);
    return;
  }
  setDot('ok');
  setProgress(100, 100, 'done');
  statusLine('scan complete');
  renderResults(job.result || {}, elapsed, job.handoff || null, job.id);
  setTimeout(() => setDot('idle'), 4000);
}

function finishBusyState() {
  activeJobId = null;
  const stop = $('stopBtn');
  if (stop) { stop.disabled = true; stop.hidden = true; }
  setBusy(false);
}

async function cancelScan() {
  if (!activeJobId) return;
  try {
    statusLine('stopping scan…', 'warn');
    await postJSON('/api/scans/jobs/' + activeJobId + '/cancel', {});
  } catch (err) {
    statusLine('stop failed: ' + (typeof err.message === 'string' ? err.message : 'unknown'), 'err');
  }
}

/* ---------- completed results ---------- */
function storeScanSession(data) {
  const findings = data.findings || [];
  const devScoped = data.mode === 'scoped_development_test';
  sessionStorage.setItem('obsidian_scan', JSON.stringify({
    scan_id: data.scan_id,
    scan_name: scanName || data.scan_id,
    target_url: data.target_url || '',
    mode: data.mode,
    findings: findings.map(f => ({
      finding_id: f.finding_id,
      severity: f.severity,
      vulnerability_type: f.vulnerability_type,
      host: f.host,
      port: f.port,
      url: f.url,
      endpoint: f.endpoint,
      source: f.source,
      description: f.description,
      raw: f.raw,
    })),
    services: devScoped ? [] : (data.services || []).map(s => ({
      port: s.port,
      protocol: s.protocol,
      service_name: s.service_name,
      product: s.product,
      version: s.version,
    })),
    skill_runs: data.skill_runs || [],
    triage: data.triage || {},
    validation: data.validation || {},
    groups: data.groups || [],
  }));
}

function renderResults(data, elapsedMs, handoff, jobId) {
  const findings = data.findings || [];
  const devScoped = data.mode === 'scoped_development_test';
  const eligible = devScoped ? [] : findings.filter((f) => ['confirmed', 'manual_review'].includes(f.validation_status));

  setLivePinned(false);

  $('metaScanName').textContent = scanName || data.scan_id || '—';
  $('metaTarget').textContent = data.target_url || '—';
  $('metaCanonical').textContent = data.target_url || '—';
  $('metaDuration').textContent = fmtDur(elapsedMs);
  $('metaFindings').textContent = devScoped
    ? findings.length + ' scoped observation' + (findings.length === 1 ? '' : 's')
    : findings.length + ' (' + eligible.length + ' eligible for exploitation)';

  renderServices(devScoped ? data.services : []);
  renderSevBar(findings);
  renderPills(data.skill_runs || []);
  renderGroups(findings);

  summaryReady = true;
  setResultsMode('summary');
  document.getElementById('results').scrollIntoView({ block: 'start' });

  $('toExploitCard').hidden = devScoped || !findings.length;
  if (findings.length && !devScoped) {
    $('toExploitCard').hidden = false;
    const eligibleN = eligible.length;
    const strong = eligibleN ? eligibleN + ' finding' + (eligibleN === 1 ? '' : 's') + ' ready for exploitation.' : 'Scan complete — findings are ready to analyze.';
    $('toExploitCard').querySelector('strong').textContent = strong;
    $('toExploitBtn').textContent = eligibleN ? 'Review in exploitation' : 'Open exploitation';
    $('toExploitCard').querySelector('.confirm-copy').textContent = eligibleN
      ? eligibleN + ' eligible target' + (eligibleN === 1 ? '' : 's') + ' passed forward to phase 2'
      : 'Open the exploit console to analyze the full recon picture';
  }
  $('toExploitBtn').addEventListener('click', () => {
    storeScanSession(data);
    window.location.href = '/exploit';
  });

  renderHandoff(data, handoff, jobId);
}

/* ---------- automatic recon to exploit handoff ---------- */
function renderHandoff(data, handoff, jobId) {
  const card = $('handoffCard');
  if (!card) return;
  if (!handoff || !handoff.status || !data.scan_id) {
    card.hidden = true;
    return;
  }
  card.hidden = false;
  if (window.__handoffTimer) { clearTimeout(window.__handoffTimer); window.__handoffTimer = null; }

  const title = $('handoffTitle');
  const copy = $('handoffCopy');
  const btn = $('handoffBtn');

  btn.href = '/exploit';
  storeScanSession(data);

  if (handoff.status === 'running') {
    title.textContent = 'Automatic handoff in progress…';
    copy.textContent = 'Creating the attack session and starting the LLM agent on eligible findings. This can take several minutes.';
    btn.textContent = 'Open exploitation';
    // The scan result is in, but the handoff thread keeps running — keep
    // polling the job until it reaches a terminal handoff state.
    handoffJobId = jobId || handoffJobId;
    if (handoffJobId) {
      if (pollHandoffTimer) clearTimeout(pollHandoffTimer);
      pollHandoffTimer = setTimeout(pollHandoffAfterScan, 2000);
    }
    return;
  }

  if (handoff.status === 'completed') {
    title.textContent = 'Automatic handoff complete';
    copy.textContent = 'Attack session ready — LLM agent finished (' + (handoff.agent_status || 'done') + ', ' + (handoff.steps_used || 0) + ' steps). Redirecting to the exploit console…';
    btn.textContent = 'Open attack session';
    window.__handoffTimer = setTimeout(() => { window.location.href = '/exploit'; }, 1800);
    return;
  }

  if (handoff.status === 'skipped') {
    title.textContent = 'Automatic handoff skipped';
    copy.textContent = handoff.reason || handoff.message || 'No automatic handoff was performed.';
    btn.textContent = 'Open exploitation';
    // The scan itself finished, so carry it to the exploit console regardless of
    // whether an auto session could be created.
    window.__handoffTimer = setTimeout(() => { window.location.href = '/exploit'; }, 1800);
    return;
  }

  title.textContent = 'Automatic handoff failed';
  copy.textContent = handoff.error || handoff.message || 'The automatic handoff errored.';
  btn.textContent = 'Open exploitation';
  window.__handoffTimer = setTimeout(() => { window.location.href = '/exploit'; }, 1800);
}

async function pollHandoffAfterScan() {
  if (!handoffJobId) return;
  try {
    const job = await postJSON('/api/scans/jobs/' + handoffJobId, null, 'GET');
    const h = job && job.handoff;
    if (h && h.status && h.status !== 'running') {
      renderHandoff(job.result || {}, h, handoffJobId);
      return;
    }
    // Still running — update the card and try again shortly.
    const copy = $('handoffCopy');
    if (copy) copy.textContent = 'Still running — the LLM agent is executing validated steps. Check back shortly.';
    pollHandoffTimer = setTimeout(pollHandoffAfterScan, 3000);
  } catch (_) {
    // Job may have been pruned; leave the card in its in-progress state.
  }
}

function renderServices(services) {
  const section = $('serviceObservations');
  section.innerHTML = '';
  const byPort = new Map();
  if (Array.isArray(services)) {
    services.forEach((service) => {
      if (!service || !Number.isInteger(service.port)) return;
      const key = String(service.port) + '/' + String(service.protocol || '');
      const existing = byPort.get(key);
      if (!existing || (existing.source !== 'nmap' && service.source === 'nmap')) byPort.set(key, service);
    });
  }
  section.hidden = byPort.size === 0;
  if (!byPort.size) return;

  section.appendChild(el('h3', '', 'Observed network services'));
  section.appendChild(el('p', 'triage-note', 'Open services are observations, not confirmed vulnerabilities.'));
  const list = el('div', 'service-list');
  [...byPort.values()].sort((a, b) => a.port - b.port).forEach((service) => {
    const details = [service.service_name, service.product, service.version].filter(Boolean).join(' · ');
    const label = String(service.port) + (service.protocol ? '/' + service.protocol : '');
    list.appendChild(el('div', 'service-item mono', label + (details ? ' — ' + details : '')));
  });
  section.appendChild(list);
}

function renderSevBar(findings) {
  const bar = $('sevBar');
  bar.innerHTML = '';
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => { counts[sevClass(f.severity)] += 1; });
  sevOrder.forEach((sev) => {
    const item = el('div', 'sev-item');
    item.appendChild(el('span', 'sev-chip ' + sev + (counts[sev] === 0 ? ' zero' : ''), counts[sev].toString()));
    item.appendChild(el('span', '', sev));
    bar.appendChild(item);
  });

  const note = $('triageNote');
  if (findings.length) {
    note.innerHTML = '<strong>' + esc(findings.length) + '</strong> findings reported. ' +
      '<strong>' + esc(findings.filter((f) => ['confirmed', 'manual_review'].includes(f.validation_status)).length) +
      '</strong> are eligible for phase 2 exploitation.';
  } else {
    note.textContent = 'No issues beyond information-level reconnaissance were detected on the scanned surface.';
  }
}

function renderPills(skillRuns) {
  const wrap = $('pills');
  wrap.innerHTML = '';
  (skillRuns || []).forEach((s) => {
    const pill = el('div', 'pill ' + (s.success ? 'ran' : 'failed'));
    pill.appendChild(el('span', 'pname', s.skill));
    if (s.success && s.findings != null) pill.appendChild(el('span', 'pcount', String(s.findings)));
    if (!s.success) {
      const failedMark = el('span', 'pill-mark', '');
      failedMark.appendChild(iconNode('failed'));
      pill.appendChild(failedMark);
    }
    pill.title = s.error || (s.success ? 'ok' : 'failed');
    wrap.appendChild(pill);
  });
}

function renderGroups(findings) {
  const wrap = $('groups');
  wrap.innerHTML = '';
  if (!findings.length) {
    const card = el('div', 'card', '');
    card.appendChild(el('div', 'card-title', 'Findings'));
    card.appendChild(el('div', '', 'Scan completed with no findings to report.'));
    wrap.appendChild(card);
    return;
  }

  const bucket = { critical: [], high: [], medium: [], low: [], info: [] };
  findings.forEach((f) => (bucket[sevClass(f.severity)] || bucket.info).push(f));
  sevOrder.forEach((sev) => {
    if (!bucket[sev].length) return;
    const sec = el('div', '', '');
    const h = el('div', 'severity-heading', sev + ' findings');
    sec.appendChild(h);
    bucket[sev].forEach((f) => sec.appendChild(findingEl(f)));
    wrap.appendChild(sec);
  });
}

function findingEl(f) {
  const det = document.createElement('details');
  det.className = 'fgroup border-' + sevClass(f.severity);
  if (sevClass(f.severity) === 'critical' || sevClass(f.severity) === 'high') det.open = true;

  const summary = document.createElement('summary');
  summary.appendChild(el('span', 'chev', ''));
  summary.appendChild(el('span', 'sev-chip ' + sevClass(f.severity), sevClass(f.severity)));
  summary.appendChild(el('span', 'gdesc', findingDesc(f)));
  summary.appendChild(el('span', 'scanner-tag', f.source || f.validator_id || ''));
  det.appendChild(summary);

  const wrap = el('div', '', '');
  const finding = el('div', 'finding', '');
  finding.appendChild(el('div', 'fdesc', findingDesc(f)));

  const metaRow = el('div', 'fmeta', '');
  if (f.vulnerability_type) metaRow.appendChild(el('span', '', vulnLabel(f.vulnerability_type) || f.vulnerability_type));
  const vtag = f.validator_id ? 'validator · ' + f.validator_id : (f.validation_status || '');
  if (vtag) metaRow.appendChild(el('span', '', vtag));
  if (f.host) metaRow.appendChild(el('span', 'host', '· ' + f.host));
  const copyBtn = el('button', 'copy-btn', 'copy');
  copyBtn.type = 'button';
  metaRow.appendChild(copyBtn);
  finding.appendChild(metaRow);

  if (f.endpoint) {
    finding.appendChild(el('div', 'fmeta', 'url: ' + f.endpoint));
  }
  if (f.evidence && Object.keys(f.evidence).length) {
    finding.appendChild(el('div', 'fraw', JSON.stringify(f.evidence, null, 2)));
  }
  if (f.cwe || f.mitre_technique_id) {
    const refs = [];
    if (f.cwe) refs.push('CWE-' + f.cwe);
    if (f.mitre_technique_id) refs.push(f.mitre_technique_id);
    finding.appendChild(el('div', 'fmeta', 'refs: ' + refs.join(', ')));
  }

  wrap.appendChild(finding);
  det.appendChild(wrap);
  return det;
}

/* ---------- copy (event delegation) ---------- */
$('groups').addEventListener('click', async (e) => {
  const btn = e.target.closest('.copy-btn');
  if (!btn) return;
  const finding = btn.closest('.finding');
  const blocks = [];
  const desc = finding.querySelector('.fdesc');
  if (desc) blocks.push(desc.textContent);
  const raw = finding.querySelector('.fraw');
  if (raw) blocks.push(raw.textContent);
  try {
    await navigator.clipboard.writeText(blocks.join('\n'));
    btn.textContent = 'copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  } catch (err) {
    btn.textContent = 'err';
  }
});

/* ---------- wiring ---------- */
$('runBtn').addEventListener('click', startScan);
if ($('stopBtn')) $('stopBtn').addEventListener('click', cancelScan);
$('targetInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') startScan();
});
$('targetInput').addEventListener('input', updateTargetContext);
$('authCheck').addEventListener('change', updateAuthorizationState);
$('themeToggle').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  setTheme(next, true);
});
$('viewLiveBtn').addEventListener('click', () => setResultsMode('live'));
$('viewSummaryBtn').addEventListener('click', () => setResultsMode('summary'));

window.addEventListener('scroll', () => {
  if (!livePinned) return;
  const doc = document.documentElement;
  const nearBottom = (doc.scrollHeight - (doc.scrollTop + window.innerHeight)) < 80;
  if (!nearBottom) setLivePinned(false);
}, { passive: true });
const pinEl = $('livePinned');
if (pinEl) pinEl.addEventListener('click', () => {
  setLivePinned(!livePinned);
  if (livePinned) scrollLiveToBottom();
});

const colorScheme = window.matchMedia('(prefers-color-scheme: dark)');
colorScheme.addEventListener('change', (event) => {
  if (!localStorage.getItem('obsidian-theme')) setTheme(event.matches ? 'dark' : 'light', false);
});

setTheme(document.documentElement.dataset.theme || 'light', false);
updateAuthorizationState();
updateTargetContext();

const storedScan = sessionStorage.getItem('obsidian_scan');
if (storedScan) {
  const scanData = JSON.parse(storedScan);
  if (scanData.scan_id) {
    // Restore previous scan findings
    renderResults({
      scan_id: scanData.scan_id,
      target_url: scanData.target_url || '',
      name: scanName || scanData.scan_id,
      findings: scanData.findings,
      mode: scanData.mode || 'summary',
      result: scanData,
      elapsedMs: 0,
      handoff: null,
    });
  }
}

$('devScopedCheck').addEventListener('change', updateDevScopedState);
loadDevScopedSettings();
