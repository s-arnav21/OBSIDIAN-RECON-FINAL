'use strict';

const $ = (id) => document.getElementById(id);
const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];

let renderedFindings = 0;
let liveSev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
let livePinned = true;
let scanName = null;

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
}
function setBusy(busy) {
  $('runBtn').disabled = busy;
}
function statusLine(msg, cls) {
  const s = $('statusLine');
  s.className = 'statusline' + (cls ? ' ' + cls : '');
  s.textContent = msg;
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
    const url = f.evidence.url || f.evidence.recheck_status
      ? (f.evidence.url || f.endpoint || '')
      : '';
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
  err.textContent = 'scan failed: ' + msg;
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
}

/* ---------- progress bar ---------- */
function setProgress(done, total, state) {
  const bar = $('progressBar');
  bar.className = 'progress-fill' + (state === 'running' ? ' live' : ' ' + state);
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : (state === 'running' ? 0 : 100);
  bar.style.width = pct + '%';
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
  ordered.forEach((s) => {
    const tick = el('div', 'tick ' + (s.status || ''));
    tick.appendChild(el('span', 'mark', tickMark(s)));
    let label = s.label;
    const fc = s.findings_count != null ? s.findings_count : (s.findings || 0);
    if (fc) label += ' · ' + fc + ' finding' + (fc === 1 ? '' : 's');
    if (s.error) label += ' — ' + s.error;
    tick.appendChild(el('span', 'tlabel', label));
    if (s.duration_ms != null) tick.appendChild(el('span', 'ttime', (s.duration_ms / 1000).toFixed(1) + 's'));
    list.appendChild(tick);
  });
  if (nearBottom) box.scrollTop = box.scrollHeight;
}

function sortBySeq(a, b) {
  const as = a.seq == null ? 1e9 : Number(a.seq);
  const bs = b.seq == null ? 1e9 : Number(b.seq);
  return as - bs;
}

function tickMark(s) {
  switch (s.status) {
    case 'done': return '✓';
    case 'failed': return '✗';
    case 'running': return '›';
    case 'skipped': return '·';
    default: return '○';
  }
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
    p.textContent = v ? 'following newest' : 'paused — not following (click to resume)';
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
    card.appendChild(el('span', 'sev-chip ' + sev, sev.toUpperCase().slice(0, 2)));
    const body = el('div', 'lf-body', '');
    body.appendChild(el('div', 'lf-desc', findingDesc(f)));
    const meta = el('div', 'lf-meta', '');
    meta.appendChild(el('span', 'host', esc(f.host || f.target || '') + ' '));
    if (f.port != null) meta.appendChild(el('span', '', ':' + esc(f.port) + (f.service ? '/' + esc(f.service) : '') + ' '));
    if (f.source) meta.appendChild(el('span', '', '· ' + f.source));
    if (f.url || f.endpoint) meta.appendChild(el('span', '', '· ' + esc(f.url || f.endpoint)));
    body.appendChild(meta);
    if (f.evidence && Object.keys(f.evidence).length) {
      body.appendChild(el('div', 'lf-raw', esc(JSON.stringify(f.evidence).slice(0, 500))));
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
  };
}

async function postJSON(path, body, method) {
  const res = await fetch(path, {
    method: method || 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body == null ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data && (data.detail || data.error)) || ('HTTP ' + res.status));
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
    $('stopBtn').hidden = true;
    setBusy(false);
    return;
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
    statusLine('scan failed: ' + (job.error || 'unknown'), 'err');
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
  renderResults(job.result || {}, elapsed);
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
    statusLine('stop failed: ' + err.message, 'err');
  }
}

/* ---------- completed results ---------- */
function renderResults(data, elapsedMs) {
  const findings = data.findings || [];
  const eligible = findings.filter((f) => ['confirmed', 'manual_review'].includes(f.validation_status));

  setLivePinned(false);

  $('metaScanName').textContent = scanName || data.scan_id || '—';
  $('metaTarget').textContent = data.target_url || '—';
  $('metaCanonical').textContent = data.target_url || '—';
  $('metaDuration').textContent = fmtDur(elapsedMs);
  $('metaFindings').textContent = findings.length + ' (' + eligible.length + ' eligible for exploitation)';

  renderSevBar(findings);
  renderPills(data.skill_runs || []);
  renderGroups(findings);

  summaryReady = true;
  setResultsMode('summary');
  document.getElementById('results').scrollIntoView({ block: 'start' });

  if (findings.length) {
    $('toExploitCard').hidden = false;
    const eligibleN = eligible.length;
    const strong = eligibleN ? eligibleN + ' finding' + (eligibleN === 1 ? '' : 's') + ' ready for exploitation.' : 'Scan complete — findings are ready to analyze.';
    $('toExploitCard').querySelector('strong').textContent = strong;
    $('toExploitBtn').textContent = eligibleN ? 'Attack these →' : 'Open Exploit Console →';
    $('toExploitCard').querySelector('.confirm-copy').textContent = eligibleN
      ? eligibleN + ' eligible target' + (eligibleN === 1 ? '' : 's') + ' passed forward to phase 2'
      : 'Open the exploit console to analyze the full recon picture';
  }
  $('toExploitBtn').addEventListener('click', () => {
    sessionStorage.setItem('obsidian_scan', JSON.stringify({
      scan_id: data.scan_id,
      scan_name: scanName || data.scan_id,
      target_url: data.target_url || '',
    }));
    window.location.href = '/exploit';
  });
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
    if (!s.success) pill.appendChild(el('span', '', '✗'));
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
    const h = el('div', '', sev.toUpperCase());
    h.style.cssText = 'font-family:var(--font-mono);font-size:11px;font-weight:700;letter-spacing:1px;color:var(--ui-05);margin:16px 0 8px;';
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
  summary.appendChild(el('span', 'chev', '▶'));
  summary.appendChild(el('span', 'sev-chip ' + sevClass(f.severity), '1'));
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
  setLivePinned(true);
  scrollLiveToBottom();
});