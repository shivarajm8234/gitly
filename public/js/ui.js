// ============================================================
// public/js/ui.js — Component Helpers & Utilities
// ============================================================

const UI = (() => {
  // ── Toast ──────────────────────────────────────────────
  function toast(msg, type = 'info', duration = 4000) {
    const icons = { success:'', error:'', warning:'', info:'' };
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span style="font-size:1.1rem">${icons[type]||''}</span><span>${msg}</span>`;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity='0'; el.style.transform='translateY(20px)'; el.style.transition='.3s'; setTimeout(()=>el.remove(),300); }, duration);
  }

  // ── Progress log ──────────────────────────────────────
  function log(msg, type = 'info') {
    const el = document.getElementById('progress-log');
    if (!el) return;
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    el.appendChild(entry);
    el.scrollTop = el.scrollHeight;
  }

  // ── Section show/hide ─────────────────────────────────
  function show(id) { const el = document.getElementById(id); if (el) el.style.display = 'block'; }
  function hide(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }

  // ── Progress bar ─────────────────────────────────────
  function setProgress(pct, label) {
    const bar = document.getElementById('progress-bar');
    const lbl = document.getElementById('progress-label');
    if (bar) bar.style.width = Math.min(100, pct) + '%';
    if (lbl && label) lbl.textContent = label;
  }

  // ── Severity badge HTML ───────────────────────────────
  function sevBadge(sev) {
    const icons = { CRITICAL:'', HIGH:'', MEDIUM:'', LOW:'', INFO:'' };
    return `<span class="sev-badge ${sev}">${icons[sev]||''} ${sev}</span>`;
  }

  // ── Confidence bar HTML ───────────────────────────────
  function confBar(conf) {
    const color = conf >= 80 ? 'var(--rose)' : conf >= 60 ? 'var(--amber)' : 'var(--low)';
    return `<div class="conf-bar"><div class="conf-track"><div class="conf-fill" style="width:${conf}%;background:${color}"></div></div><span>${conf}%</span></div>`;
  }

  // ── Source badge HTML ─────────────────────────────────
  function srcBadge(src) {
    return `<span class="source-badge ${src}">${src === 'history' ? ' history' : ' latest'}</span>`;
  }

  // ── Health score ring ─────────────────────────────────
  function setHealthScore(score) {
    const num = document.getElementById('health-score-num');
    const fill = document.getElementById('health-ring-fill');
    const grade = document.getElementById('health-grade');
    if (!num || !fill || !grade) return;

    num.textContent = score;
    const circ = 2 * Math.PI * 36;
    const offset = circ - (score / 100) * circ;
    fill.style.strokeDasharray = circ;
    fill.style.strokeDashoffset = offset;

    let color, label;
    if (score >= 80)      { color = 'var(--emerald)'; label = 'Excellent'; }
    else if (score >= 60) { color = 'var(--cyan)';    label = 'Good'; }
    else if (score >= 40) { color = 'var(--amber)';   label = 'Fair'; }
    else if (score >= 20) { color = 'var(--high)';    label = 'Poor'; }
    else                  { color = 'var(--crit)';    label = 'Critical'; }

    fill.style.stroke = color;
    grade.textContent = label;
    grade.style.color = color;
  }

  // ── Update scan stats ─────────────────────────────────
  function updateScanStats({ files = 0, findings = 0, commits = 0 }) {
    const f = document.getElementById('prog-files');
    const fi = document.getElementById('prog-findings');
    const c = document.getElementById('prog-commits');
    if (f) f.textContent = files;
    if (fi) fi.textContent = findings;
    if (c) c.textContent = commits;
  }

  // ── Format date ───────────────────────────────────────
  function fmtDate(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString();
  }

  // ── Render findings table ─────────────────────────────
  function renderFindingsTable(findings, container) {
    if (!findings || findings.length === 0) {
      container.innerHTML = `<div class="empty-findings"><div class="empty-icon"></div><div class="empty-title">No secrets found</div><div class="empty-sub">This repository appears clean under the scanned scope.</div></div>`;
      return;
    }

    const table = document.createElement('table');
    table.className = 'findings-table';
    table.innerHTML = `<thead><tr>
      <th>Severity</th>
      <th>Type</th>
      <th>File</th>
      <th>Line</th>
      <th>Source</th>
      <th>Author</th>
      <th>Confidence</th>
    </tr></thead>`;

    const tbody = document.createElement('tbody');
    findings.forEach((f, idx) => {
      // Main row
      const tr = document.createElement('tr');
      tr.dataset.id = f.id;
      tr.innerHTML = `
        <td>${sevBadge(f.severity)}</td>
        <td style="font-size:.8rem;font-weight:600;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${f.label}">${f.label}</td>
        <td><div class="file-path" title="${f.file}">${f.file}</div></td>
        <td class="mono" style="color:var(--text-2)">${f.line || '—'}</td>
        <td>${srcBadge(f.source)}</td>
        <td style="font-size:.78rem;color:var(--text-2);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.author || '—'}</td>
        <td>${confBar(f.confidence)}</td>
      `;
      tr.addEventListener('click', () => toggleDetail(f, detailRow));
      tbody.appendChild(tr);

      // Detail row
      const detailRow = document.createElement('tr');
      detailRow.innerHTML = `<td colspan="7" style="padding:0"><div class="finding-detail" id="detail-${f.id}"></div></td>`;
      tbody.appendChild(detailRow);
    });

    table.appendChild(tbody);
    container.innerHTML = '';
    container.appendChild(table);
  }

  function toggleDetail(f, detailRow) {
    const panel = detailRow.querySelector('.finding-detail');
    if (panel.classList.contains('open')) {
      panel.classList.remove('open');
      return;
    }
    // Close others
    document.querySelectorAll('.finding-detail.open').forEach(p => p.classList.remove('open'));

    const remedSteps = (f.remediation?.steps || []).map(s => `<li>${s}</li>`).join('');
    const revokeBtn = f.remediation?.revocationUrl
      ? `<a href="${f.remediation.revocationUrl}" target="_blank" class="revoke-link"> Revoke at ${f.remediation.provider}</a>`
      : '';

    panel.innerHTML = `
      <div class="detail-grid">
        <div>
          <h4> AI Analysis</h4>
          <p class="explanation-text">${f.explanation || '—'}</p>
          <div class="meta-pills" style="margin-top:12px">
            ${f.isTest ? '<div class="meta-pill"> <span>Likely Test Data</span></div>' : ''}
            ${f.isActive ? '<div class="meta-pill"> <span>Possibly Active</span></div>' : ''}
            ${f.commitShort ? `<div class="meta-pill"> <span>${f.commitShort}</span></div>` : ''}
            ${f.branch ? `<div class="meta-pill"> <span>${f.branch}</span></div>` : ''}
            ${f.timestamp ? `<div class="meta-pill"> <span>${fmtDate(f.timestamp)}</span></div>` : ''}
          </div>
          ${f.fileUrl ? `<div style="margin-top:12px"><a href="${f.fileUrl}" target="_blank" class="revoke-link" style="color:var(--cyan);border-color:rgba(34,211,238,.3);background:rgba(34,211,238,.08)"> View in GitHub</a></div>` : ''}
        </div>
        <div>
          <h4> Matched Line</h4>
          <div class="code-block">${escHtml(f.lineContent || '—')}</div>
          <h4 style="margin-top:16px"> Remediation</h4>
          <ul class="remediation-list">${remedSteps}</ul>
          ${revokeBtn}
        </div>
      </div>`;
    panel.classList.add('open');
  }

  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Render repo intel cards ───────────────────────────
  function renderRepoIntel(info) {
    const el = document.getElementById('repo-intel');
    if (!el || !info) return;
    const cards = [
      { icon:'', label:'Stars', val: info.stars?.toLocaleString() || 0 },
      { icon:'', label:'Default Branch', val: info.defaultBranch || '—' },
      { icon:'', label:'Language', val: info.language || 'Mixed' },
      { icon:'', label:'Repo Size', val: info.size ? `${(info.size/1024).toFixed(1)} MB` : '—' },
      { icon:'', label:'Created', val: info.createdAt ? new Date(info.createdAt).toLocaleDateString() : '—' },
      { icon:'', label:'Last Push', val: info.pushedAt ? new Date(info.pushedAt).toLocaleDateString() : '—' },
    ];
    el.innerHTML = cards.map(c => `<div class="stat-card" style="padding:14px 16px">
      <div style="font-size:1.2rem">${c.icon}</div>
      <div style="font-size:.95rem;font-weight:700;margin-top:4px">${c.val}</div>
      <div class="stat-card-lbl">${c.label}</div>
    </div>`).join('');
  }

  return { toast, log, show, hide, setProgress, sevBadge, confBar, srcBadge, setHealthScore,
           updateScanStats, fmtDate, renderFindingsTable, renderRepoIntel, escHtml };
})();
