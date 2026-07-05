/**
 * NexShell v2 — Dashboard App Logic  (app.js)
 * Real-time updates via WebSocket, REST fallback on disconnect.
 */

// ── State ─────────────────────────────────────────────────────────────────
const state = {
  currentView:  'dashboard',
  sessions:     [],
  hosts:        [],
  findings:     [],
  loot:         [],
  stats:        {},
  operation:    null,
  mitre:        [],
  activityLog:  [],
  filter:       '',
  ws:           null,
  wsRetries:    0,
  lastUpdate:   null,
};

// ── Navigation ────────────────────────────────────────────────────────────
function show(view) {
  // Hide all views
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  // Show target view
  const el = document.getElementById('view-' + view);
  if (el) el.classList.add('active');

  // Activate nav item
  const navEl = document.querySelector(`[data-view="${view}"]`);
  if (navEl) navEl.classList.add('active');

  // Update title
  const titles = {
    dashboard: 'Dashboard',
    sessions:  'Sessions',
    hosts:     'Asset Inventory',
    findings:  'Security Findings',
    loot:      'Loot Collector',
    mitre:     'MITRE ATT&CK',
    operation: 'Operation Details',
  };
  document.getElementById('view-title').textContent   = titles[view] || view;
  document.getElementById('breadcrumb').textContent   = 'Overview / ' + (titles[view] || view);
  state.currentView = view;
}

// ── Clock ─────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ── WebSocket ─────────────────────────────────────────────────────────────
function connectWS() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl    = `${protocol}//${location.host}/ws`;
  const ws       = new WebSocket(wsUrl);

  ws.onopen = () => {
    state.wsRetries = 0;
    setWsStatus(true);
    addActivity('sys', 'Dashboard connected', 'session');
  };

  ws.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      handleMessage(msg);
    } catch (e) { console.warn('WS parse error', e); }
  };

  ws.onclose = () => {
    setWsStatus(false);
    const delay = Math.min(1000 * Math.pow(2, state.wsRetries++), 15000);
    setTimeout(connectWS, delay);
  };

  ws.onerror = () => ws.close();
  state.ws = ws;
}

function setWsStatus(connected) {
  const el  = document.getElementById('ws-status');
  const dot = el.querySelector('.dot');
  if (connected) {
    dot.className = 'dot dot-green';
    el.innerHTML = `<span class="dot dot-green"></span> Live`;
  } else {
    dot.className = 'dot dot-red';
    el.innerHTML = `<span class="dot dot-red"></span> Reconnecting…`;
  }
}

// ── Message Router ────────────────────────────────────────────────────────
function handleMessage(msg) {
  const { type, data } = msg;
  state.lastUpdate = new Date();

  if (type === 'snapshot') {
    applySnapshot(data);
    return;
  }

  // Live events
  switch (type) {
    case 'session':
      addActivity('New session', `${data.host || data.id}`, 'session');
      fetchSnapshot();
      break;
    case 'finding':
      addActivity('Finding', `${data.severity?.toUpperCase()} – ${data.title || data.id}`, 'finding');
      fetchSnapshot();
      break;
    case 'loot':
      addActivity('Loot', `[${data.category || '?'}] ${data.host_ip || ''}`, 'loot');
      fetchSnapshot();
      break;
    case 'host':
      addActivity('Host added', data.ip || data.host_ip, 'host');
      fetchSnapshot();
      break;
    case 'cred':
      addActivity('Credential', `${data.username || '?'}@${data.host_ip || '?'}`, 'cred');
      fetchSnapshot();
      break;
  }
}

// ── Snapshot Application ──────────────────────────────────────────────────
function applySnapshot(snap) {
  if (!snap) return;
  if (snap.sessions)  { state.sessions  = snap.sessions;  renderSessions(); }
  if (snap.hosts)     { state.hosts     = snap.hosts;     renderHosts(); }
  if (snap.findings)  { state.findings  = snap.findings;  renderFindings(); }
  if (snap.loot)      { state.loot      = snap.loot;      renderLoot(); }
  if (snap.stats)     { state.stats     = snap.stats;     renderStats(); }
  if (snap.operation !== undefined) { state.operation = snap.operation; renderOperation(); }
  if (snap.mitre)     { state.mitre     = snap.mitre;     renderMitre(); }
  updateBadges();
}

function updateBadges() {
  const b = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };
  b('badge-sessions', state.sessions.length || 0);
  b('badge-hosts',    state.hosts.length    || 0);
  b('badge-findings', state.findings.length || 0);
  b('badge-loot',     state.loot.length     || 0);
}

// ── Fetch ─────────────────────────────────────────────────────────────────
async function fetchSnapshot() {
  try {
    const r = await fetch('/api/snapshot');
    if (!r.ok) return;
    const snap = await r.json();
    applySnapshot(snap);
  } catch (e) { /* offline */ }
}

// ── Renderers ─────────────────────────────────────────────────────────────

function renderStats() {
  const s = state.stats;
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (val !== undefined && val !== null) ? val : '0';
  };
  set('stat-sessions', s.sessions  ?? state.sessions.length);
  set('stat-hosts',    s.hosts     ?? state.hosts.length);
  set('stat-findings', s.findings  ?? state.findings.length);
  set('stat-loot',     s.loot_items ?? state.loot.length);
}

function renderSessions() {
  const tbody = document.querySelector('#tbl-sessions tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!state.sessions.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-dim);padding:24px">No sessions</td></tr>`;
    return;
  }

  state.sessions.forEach(s => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><code>${s.id ?? s.session_id ?? '?'}</code></td>
      <td><code>${s.host ?? '?'}</code></td>
      <td>${s.user ?? s.username ?? '?'}</td>
      <td>${s.os   ?? '?'}</td>
      <td><span class="cat">${s.type ?? 'shell'}</span></td>
      <td>${qualityBar(s.quality ?? s.shell_quality)}</td>
      <td style="color:var(--text-dim)">${fmtTime(s.created_at ?? s.ts)}</td>
    `;
    tbody.appendChild(row);
  });
}

function renderHosts() {
  const tbody = document.querySelector('#tbl-hosts tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!state.hosts.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:24px">No hosts</td></tr>`;
    return;
  }

  state.hosts.forEach(h => {
    const risk  = h.risk_score ?? 0;
    const rClass = risk >= 80 ? 'risk-critical' : risk >= 60 ? 'risk-high' : risk >= 40 ? 'risk-medium' : 'risk-low';
    const row   = document.createElement('tr');
    row.innerHTML = `
      <td><code>${h.ip ?? h.host_ip ?? '?'}</code></td>
      <td>${h.hostname ?? '—'}</td>
      <td>${h.os ?? '?'}</td>
      <td><span class="${rClass}">${risk > 0 ? risk + '/100' : '—'}</span></td>
      <td>${(h.tags ?? []).join(', ') || '—'}</td>
      <td style="color:var(--text-dim)">${fmtTime(h.added_at ?? h.ts)}</td>
    `;
    tbody.appendChild(row);
  });
}

let allFindings = [];
function renderFindings(filter) {
  if (!filter) filter = state.filter;
  allFindings = state.findings;

  const tbody = document.querySelector('#tbl-findings tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const items = filter
    ? state.findings.filter(f => (f.severity ?? '').toLowerCase() === filter)
    : state.findings;

  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:24px">No findings</td></tr>`;
    // Also update recent findings table
    renderRecentFindings([]);
    return;
  }

  items.forEach(f => {
    const sev = (f.severity ?? 'info').toLowerCase();
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="sev sev-${sev}">${sev}</span></td>
      <td style="color:var(--text-primary);font-weight:500">${f.title ?? f.finding_type ?? '?'}</td>
      <td><code>${f.host ?? f.host_ip ?? '?'}</code></td>
      <td style="color:var(--accent);font-size:11px">${f.mitre_id ?? '—'}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.recommendation ?? '—'}</td>
      <td style="color:var(--text-dim)">${fmtTime(f.ts ?? f.created_at)}</td>
    `;
    tbody.appendChild(row);
  });

  renderRecentFindings(items.slice(0, 5));
}

function renderRecentFindings(items) {
  const tbody = document.querySelector('#tbl-recent-findings tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:16px">No findings yet</td></tr>`;
    return;
  }
  items.forEach(f => {
    const sev = (f.severity ?? 'info').toLowerCase();
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="sev sev-${sev}">${sev}</span></td>
      <td style="color:var(--text-primary)">${f.title ?? f.finding_type ?? '?'}</td>
      <td><code>${f.host ?? f.host_ip ?? '?'}</code></td>
      <td style="color:var(--text-dim)">${fmtTime(f.ts ?? f.created_at)}</td>
    `;
    tbody.appendChild(row);
  });
}

function renderLoot() {
  const tbody = document.querySelector('#tbl-loot tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!state.loot.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:24px">No loot items</td></tr>`;
    return;
  }

  state.loot.forEach(l => {
    const row = document.createElement('tr');
    const preview = (l.data ?? l.content ?? l.value ?? '').substring(0, 80);
    row.innerHTML = `
      <td><span class="cat">${l.category ?? l.loot_type ?? '?'}</span></td>
      <td><code>${l.host_ip ?? l.host ?? '?'}</code></td>
      <td style="color:var(--text-muted)">${l.source ?? l.command ?? '?'}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent-2);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(preview)}</td>
      <td style="color:var(--text-dim)">${fmtTime(l.ts)}</td>
    `;
    tbody.appendChild(row);
  });
}

function renderMitre() {
  const grid = document.getElementById('mitre-grid');
  if (!grid) return;
  grid.innerHTML = '';

  if (!state.mitre.length) {
    grid.innerHTML = `<div class="no-data" style="padding:16px">No MITRE techniques observed</div>`;
    return;
  }

  state.mitre.forEach(t => {
    const card = document.createElement('div');
    card.className = 'mitre-card';
    card.innerHTML = `
      <div class="mitre-id">${t.id}</div>
      <div class="mitre-name">${t.name ?? '?'}</div>
      <div class="mitre-tactic">${t.tactic ?? '?'}</div>
    `;
    grid.appendChild(card);
  });
}

function renderOperation() {
  const op = state.operation;

  // Sidebar op-panel (dashboard view)
  const panel = document.getElementById('op-panel');
  if (panel) {
    if (!op) {
      panel.innerHTML = `<div class="no-data">No active operation</div>`;
    } else {
      panel.innerHTML = `
        <div class="op-name">${escHtml(op.name ?? '?')}</div>
        <div class="op-meta">${escHtml(op.client ?? '')} · ${op.status ?? 'active'}</div>
        ${(op.scope ?? []).map(s => `<div class="op-scope">⊳ ${escHtml(s)}</div>`).join('')}
        ${(op.objectives ?? []).map(o => `<div class="op-obj">${escHtml(o)}</div>`).join('')}
      `;
    }
  }

  // Full operation detail view
  const detail = document.getElementById('op-detail');
  if (detail) {
    if (!op) {
      detail.innerHTML = `<div class="no-data">No active operation. Use <code>operation new &lt;name&gt;</code> in NexShell CLI.</div>`;
    } else {
      const field = (label, value) =>
        `<div class="op-field">
           <div class="op-field-label">${label}</div>
           <div class="op-field-value">${escHtml(String(value ?? '—'))}</div>
         </div>`;
      detail.innerHTML = `
        ${field('Name', op.name)}
        ${field('Client', op.client)}
        ${field('Status', op.status)}
        ${field('Start Date', op.start_date)}
        ${field('Scope', (op.scope ?? []).join(', '))}
        <div class="op-field">
          <div class="op-field-label">Objectives</div>
          ${(op.objectives ?? []).map(o => `<div class="op-obj">${escHtml(o)}</div>`).join('') || '<div class="op-field-value">—</div>'}
        </div>
      `;
    }
  }
}

// ── Activity Feed ─────────────────────────────────────────────────────────
function addActivity(label, detail, type) {
  const ul = document.getElementById('activity-feed');
  if (!ul) return;

  const li = document.createElement('li');
  li.innerHTML = `
    <span class="feed-dot ${type}"></span>
    <span>
      <strong style="color:var(--text-primary)">${escHtml(label)}</strong>
      &nbsp;${escHtml(detail)}
    </span>
    <span class="feed-time">${new Date().toTimeString().slice(0,8)}</span>
  `;

  ul.prepend(li);

  // Keep feed at max 50 entries
  while (ul.children.length > 50) ul.removeChild(ul.lastChild);
}

// ── Filter Findings ───────────────────────────────────────────────────────
function filterFindings(severity) {
  state.filter = severity;
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active',
      b.textContent.toLowerCase() === (severity || 'all')
    );
  });
  renderFindings(severity);
}

// ── Utilities ─────────────────────────────────────────────────────────────
function fmtTime(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    if (isNaN(d)) return ts;
    const now  = new Date();
    const diff = Math.floor((now - d) / 1000);
    if (diff < 60)   return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
    if (diff < 86400)return `${Math.floor(diff/3600)}h ago`;
    return d.toLocaleDateString();
  } catch { return ts; }
}

function escHtml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function qualityBar(q) {
  if (q === undefined || q === null) return '—';
  const n = parseInt(q) || 0;
  const pct = Math.min(Math.max(n, 0), 100);
  const color = pct >= 75 ? 'var(--success)' : pct >= 40 ? 'var(--warning)' : 'var(--danger)';
  return `<div style="display:flex;align-items:center;gap:6px">
    <div style="width:60px;height:5px;background:var(--bg-card);border-radius:3px;overflow:hidden">
      <div style="width:${pct}%;height:100%;background:${color};border-radius:3px;transition:width .4s"></div>
    </div>
    <span style="font-size:10px;color:var(--text-muted)">${pct}%</span>
  </div>`;
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.altKey) {
    const keys = { '1':'dashboard','2':'sessions','3':'hosts','4':'findings','5':'loot','6':'mitre','7':'operation' };
    if (keys[e.key]) { e.preventDefault(); show(keys[e.key]); }
  }
});

// ── Init ──────────────────────────────────────────────────────────────────
(function init() {
  // Initial data fetch
  fetchSnapshot();

  // WebSocket for live updates
  connectWS();

  // Polling fallback (in case WS disconnects)
  setInterval(() => {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
      fetchSnapshot();
    }
  }, 10000);

  // Add startup activity
  addActivity('NexShell', 'Dashboard initialized', 'session');
})();
