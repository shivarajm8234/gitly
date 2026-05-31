// ============================================================
// public/js/app.js — SPA Controller
// ============================================================

(() => {
  // ── State ────────────────────────────────────────────
  let allFindings = [];
  let filteredFindings = [];
  let activeSev = 'all';
  let searchQuery = '';
  let scanActive = false;

  // ── Init ─────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    console.log('[App] DOMContentLoaded — initializing...');
    loadPatternCount();
    try {
      bindEvents();
      console.log('[App] bindEvents OK');
    } catch (e) {
      console.error('[App] bindEvents FAILED:', e);
    }
    checkRateLimit();
    UI.show('hero-section');
    UI.hide('scan-progress');
    UI.hide('dashboard');
    console.log('[App] Init complete');
  });

  async function loadPatternCount() {
    try {
      const res = await fetch('/api/patterns');
      const patterns = await res.json();
      const el = document.getElementById('pattern-count');
      if (el) el.textContent = patterns.length + '+';
    } catch {}
  }

  async function checkRateLimit(token) {
    try {
      const res = await fetch('/api/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: 'https://github.com/octocat/Hello-World', token: token || '' }),
      });
      const data = await res.json();
      if (data.rateLimit) {
        const { remaining, limit } = data.rateLimit;
        const el = document.getElementById('rate-limit-text');
        if (el) el.textContent = `API: ${remaining}/${limit} req remaining`;
        const dot = document.querySelector('.rate-dot');
        if (dot) dot.style.background = remaining < 10 ? 'var(--rose)' : remaining < 50 ? 'var(--amber)' : 'var(--emerald)';
      }
    } catch {}
  }

  // ── Event Bindings ────────────────────────────────────
  function bindEvents() {
    // Scan button
    document.getElementById('scan-btn').addEventListener('click', startScan);

    // Enter key on URL field
    document.getElementById('repo-url').addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan();
    });

    // Cancel
    document.getElementById('cancel-btn').addEventListener('click', () => {
      Scanner.abort();
      scanActive = false;
      UI.toast('Scan cancelled.', 'warning');
      UI.show('hero-section');
      UI.hide('scan-progress');
      setScanBtn(false);
    });

    // New scan
    document.getElementById('new-scan-btn').addEventListener('click', () => {
      Dashboard.destroyAll();
      allFindings = []; filteredFindings = [];
      UI.show('hero-section');
      UI.hide('dashboard');
      UI.hide('scan-progress');
    });

    // Custom rules toggle
    document.getElementById('toggle-custom-rules').addEventListener('click', () => {
      const wrap = document.getElementById('custom-rules-wrap');
      wrap.style.display = wrap.style.display === 'none' ? '' : 'none';
    });

    // Severity filter chips
    document.querySelectorAll('.chip[data-sev]').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('.chip[data-sev]').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        activeSev = chip.dataset.sev;
        applyFilters();
      });
    });

    // Search
    document.getElementById('findings-search').addEventListener('input', e => {
      searchQuery = e.target.value.toLowerCase();
      applyFilters();
    });

    // Export buttons
    document.getElementById('export-json-btn').addEventListener('click', () => Reports.exportJSON());
    document.getElementById('export-csv-btn').addEventListener('click', () => Reports.exportCSV());
    document.getElementById('export-pdf-btn').addEventListener('click', () => Reports.exportPDF());
  }

  // ── Scan Flow ─────────────────────────────────────────
  async function startScan() {
    console.log('[App] startScan called');
    const repoUrl = document.getElementById('repo-url').value.trim();
    if (!repoUrl) { UI.toast('Please enter a GitHub repository URL.', 'warning'); return; }
    if (!repoUrl.includes('github.com')) { UI.toast('URL must be a GitHub repository (github.com/owner/repo).', 'error'); return; }
    if (scanActive) { console.log('[App] scan already active, ignoring'); return; }

    scanActive = true;
    allFindings = []; filteredFindings = [];
    setScanBtn(true);
    clearProgress();

    UI.hide('hero-section');
    UI.hide('dashboard');
    UI.show('scan-progress');
    Dashboard.destroyAll();

    // Debug: verify scan-progress is now visible
    const progEl = document.getElementById('scan-progress');
    console.log('[App] scan-progress display:', progEl?.style.display, 'offsetHeight:', progEl?.offsetHeight);

    UI.log(`Starting scan: ${repoUrl}`, 'info');
    console.log('[App] Calling Scanner.startScan...');

    await Scanner.startScan({
      repoUrl,
      token:        document.getElementById('github-token').value.trim(),
      mode:         document.getElementById('scan-mode').value,
      maxCommits:   document.getElementById('max-commits').value,
      maxBranches:  document.getElementById('max-branches').value,
      entropy:      document.getElementById('entropy-toggle').checked,
      customRules:  document.getElementById('custom-rules').value,
    }, {
      onRepoInfo(info) {
        console.log('[App] onRepoInfo:', info.fullName);
        UI.log(`Repo: ${info.fullName} (${info.language || 'mixed'}, ${info.stars} )`, 'info');
      },
      onStatus(data) {
        UI.log(data.message, 'info');
        if (data.total) UI.setProgress(5, data.message);
      },
      onProgress({ percent, label, files, findings, commits }) {
        if (percent !== null && percent !== undefined) UI.setProgress(percent, label || '');
        UI.updateScanStats({ files, findings, commits });
      },
      onFinding(f) {
        allFindings.push(f);
        UI.log(`[${f.severity}] ${f.label} — ${f.file}:${f.line}`, 'finding');
        if (f.severity === 'CRITICAL') UI.toast(` CRITICAL: ${f.label} in ${f.file.split('/').pop()}`, 'error', 6000);
        else if (f.severity === 'HIGH') UI.toast(` HIGH: ${f.label}`, 'warning', 4000);
        // Live update table
        applyFilters();
      },
      onMeta(data) {
        if (data.branches) UI.log(`Branches: ${data.branches.join(', ')}`, 'info');
      },
      onComplete({ findings, repoInfo, summary }) {
        scanActive = false;
        setScanBtn(false);
        UI.setProgress(100, ` Scan complete — ${summary.total} findings`);
        UI.log(`Scan complete. Total: ${summary.total}, Critical: ${summary.critical}, High: ${summary.high}`, 'info');

        allFindings = findings;
        Reports.setData(allFindings, repoInfo, summary);
        showDashboard(repoInfo, summary);
        checkRateLimit(document.getElementById('github-token').value.trim());
      },
      onError(msg) {
        scanActive = false;
        setScanBtn(false);
        UI.log(`Error: ${msg}`, 'error');
        UI.toast(`Scan error: ${msg}`, 'error', 8000);
        setTimeout(() => {
          UI.show('hero-section');
          UI.hide('scan-progress');
        }, 2000);
      },
    });
  }

  // ── Dashboard ─────────────────────────────────────────
  function showDashboard(repoInfo, summary) {
    // Repo header
    document.getElementById('dash-repo-name').textContent = repoInfo.fullName || repoInfo.repo || '—';
    document.getElementById('dash-repo-meta').textContent =
      `${repoInfo.description || 'No description'} · ${repoInfo.language || 'mixed'} · ${repoInfo.branches || 0} branches`;

    UI.setHealthScore(summary.healthScore || 0);
    UI.renderRepoIntel(repoInfo);
    Dashboard.renderAll(allFindings, summary);
    renderKeysSection(allFindings);
    applyFilters();

    UI.hide('scan-progress');
    UI.show('dashboard');

    if (summary.total === 0) UI.toast(' No secrets found! Repository looks clean.', 'success', 6000);
    else if (summary.critical > 0) UI.toast(` ${summary.critical} CRITICAL findings require immediate action!`, 'error', 8000);
  }

  // ── Keys Section (current vs history) ─────────────────
  function renderKeysSection(findings) {
    const current = findings.filter(f => f.source === 'latest');
    const history = findings.filter(f => f.source === 'history');
    const total   = findings.length;

    // Badge
    const badge = document.getElementById('keys-total-badge');
    if (badge) badge.textContent = `${total} found`;

    // Render both panels
    renderKeysPanel('keys-current-body', current, 'current');
    renderKeysPanel('keys-history-body', history, 'history');
  }

  function renderKeysPanel(containerId, items, type) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (items.length === 0) {
      const label = type === 'current' ? 'current codebase' : 'commit history';
      el.innerHTML = `<div class="keys-empty"> No exposed secrets found in ${label}.</div>`;
      return;
    }

    el.innerHTML = items.map(f => {
      const sev = UI.sevBadge(f.severity);
      const conf = UI.confBar(f.confidence);
      const commitInfo = f.commitShort
        ? `<span> ${f.commitShort}</span><span> ${f.author || '—'}</span><span> ${f.timestamp ? new Date(f.timestamp).toLocaleDateString() : '—'}</span>`
        : `<span> ${f.branch || 'main'}</span>`;
      const fileLink = f.fileUrl
        ? `<a href="${f.fileUrl}" target="_blank" style="color:var(--cyan);text-decoration:none">${f.file}</a>`
        : UI.escHtml(f.file);

      return `
        <div class="key-card sev-${f.severity}">
          <div class="key-card-header">
            <div style="display:flex;align-items:center;gap:8px">
              ${sev}
              <span class="key-card-type">${UI.escHtml(f.label)}</span>
            </div>
            ${conf}
          </div>
          <div class="key-card-file">${fileLink}:${f.line || '—'}</div>
          <div class="key-card-value">${UI.escHtml(f.value || f.lineContent || '—')}</div>
          <div class="key-card-meta">${commitInfo}</div>
        </div>`;
    }).join('');
  }

  // ── Filter & Search ───────────────────────────────────
  function applyFilters() {
    filteredFindings = allFindings.filter(f => {
      if (activeSev !== 'all' && f.severity !== activeSev) return false;
      if (searchQuery) {
        const haystack = [f.label, f.type, f.file, f.author, f.commitShort, f.lineContent, f.branch]
          .join(' ').toLowerCase();
        if (!haystack.includes(searchQuery)) return false;
      }
      return true;
    });

    // Sort: critical first
    const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    filteredFindings.sort((a, b) => (ORDER[a.severity] || 9) - (ORDER[b.severity] || 9));

    const countEl = document.getElementById('findings-count');
    if (countEl) countEl.textContent = `${filteredFindings.length} finding${filteredFindings.length !== 1 ? 's' : ''}`;

    const body = document.getElementById('findings-body');
    if (body) UI.renderFindingsTable(filteredFindings, body);
  }

  // ── Helpers ───────────────────────────────────────────
  function setScanBtn(loading) {
    const btn = document.getElementById('scan-btn');
    if (!btn) return;
    btn.disabled = loading;
    btn.innerHTML = loading
      ? `<span style="display:inline-block;animation:spin .8s linear infinite">⟳</span> Scanning...`
      : `<span></span> Start Scan`;
  }

  function clearProgress() {
    document.getElementById('progress-log').innerHTML = '';
    document.getElementById('progress-bar').style.width = '0%';
    document.getElementById('progress-label').textContent = 'Initializing...';
    UI.updateScanStats({ files: 0, findings: 0, commits: 0 });
  }
})();

// ── Spin keyframe ────────────────────────────────────────
const style = document.createElement('style');
style.textContent = '@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}';
document.head.appendChild(style);

// ── Keys tab switcher (global, called from onclick) ──────
function switchKeysTab(tab) {
  const cur = document.getElementById('keys-current-panel');
  const his = document.getElementById('keys-history-panel');
  if (!cur || !his) return;

  cur.style.display = tab === 'current' ? 'block' : 'none';
  his.style.display = tab === 'history' ? 'block' : 'none';

  // Update tab button styles
  document.querySelectorAll('.keys-tab').forEach(btn => {
    const isActive = btn.dataset.tab === tab;
    btn.style.background = isActive ? 'var(--accent)' : 'transparent';
    btn.style.color      = isActive ? '#fff' : 'var(--text-3)';
    btn.classList.toggle('active', isActive);
  });
}
