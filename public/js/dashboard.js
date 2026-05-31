// ============================================================
// public/js/dashboard.js — Chart.js Visualizations
// ============================================================

const Dashboard = (() => {
  let severityChart = null;
  let categoryChart = null;
  let timelineChart = null;

  const SEV_COLORS = {
    CRITICAL: 'rgba(244,63,94,0.85)',
    HIGH:     'rgba(251,146,60,0.85)',
    MEDIUM:   'rgba(245,158,11,0.85)',
    LOW:      'rgba(34,211,238,0.85)',
    INFO:     'rgba(148,163,184,0.5)',
  };

  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 }, boxWidth: 12 } },
      tooltip: {
        backgroundColor: 'rgba(13,15,26,0.95)',
        borderColor: 'rgba(255,255,255,0.1)',
        borderWidth: 1,
        titleColor: '#f1f5f9',
        bodyColor: '#94a3b8',
      },
    },
  };

  function destroyAll() {
    [severityChart, categoryChart, timelineChart].forEach(c => { if (c) c.destroy(); });
    severityChart = categoryChart = timelineChart = null;
  }

  // ── Severity Donut ────────────────────────────────────
  function renderSeverityChart(findings) {
    const ctx = document.getElementById('severity-chart');
    if (!ctx || typeof Chart === 'undefined') return;
    if (severityChart) { severityChart.destroy(); severityChart = null; }

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

    const labels = Object.keys(counts).filter(k => counts[k] > 0);
    const data   = labels.map(k => counts[k]);
    const colors = labels.map(k => SEV_COLORS[k]);

    severityChart = new Chart(ctx, {
      type: 'doughnut',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 2, borderColor: '#0d0f1a', hoverOffset: 8 }] },
      options: {
        ...chartDefaults,
        cutout: '65%',
        plugins: {
          ...chartDefaults.plugins,
          legend: { position: 'bottom', labels: { ...chartDefaults.plugins.legend.labels } },
        },
      },
    });
  }

  // ── Category Bar ──────────────────────────────────────
  function renderCategoryChart(findings) {
    const ctx = document.getElementById('category-chart');
    if (!ctx || typeof Chart === 'undefined') return;
    if (categoryChart) { categoryChart.destroy(); categoryChart = null; }

    const cats = {};
    findings.forEach(f => { cats[f.category || 'generic'] = (cats[f.category || 'generic'] || 0) + 1; });
    const sorted = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 10);

    const labels = sorted.map(([k]) => k.charAt(0).toUpperCase() + k.slice(1));
    const data   = sorted.map(([, v]) => v);
    const gradient_colors = [
      'rgba(99,102,241,0.8)','rgba(139,92,246,0.8)','rgba(34,211,238,0.8)',
      'rgba(16,185,129,0.8)','rgba(245,158,11,0.8)','rgba(251,146,60,0.8)',
      'rgba(244,63,94,0.8)','rgba(168,85,247,0.8)','rgba(236,72,153,0.8)','rgba(59,130,246,0.8)',
    ];

    categoryChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Findings',
          data,
          backgroundColor: labels.map((_, i) => gradient_colors[i % gradient_colors.length]),
          borderRadius: 6,
          borderSkipped: false,
        }],
      },
      options: {
        ...chartDefaults,
        indexAxis: 'y',
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', font: { size: 11 } } },
          y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 11 } } },
        },
        plugins: { ...chartDefaults.plugins, legend: { display: false } },
      },
    });
  }

  // ── Timeline Chart ────────────────────────────────────
  function renderTimelineChart(findings) {
    const ctx = document.getElementById('timeline-chart');
    if (!ctx || typeof Chart === 'undefined') return;
    if (timelineChart) { timelineChart.destroy(); timelineChart = null; }

    // Group by date
    const byDate = {};
    findings
      .filter(f => f.timestamp)
      .forEach(f => {
        const d = new Date(f.timestamp).toISOString().split('T')[0];
        byDate[d] = (byDate[d] || 0) + 1;
      });

    if (Object.keys(byDate).length === 0) {
      // No timestamped findings
      const el = ctx.parentElement;
      el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-3);font-size:.85rem">No timestamped history findings to display. Run a Deep Scan to see commit timeline.</div>`;
      return;
    }

    const sorted = Object.entries(byDate).sort(([a], [b]) => a.localeCompare(b));
    const labels = sorted.map(([d]) => d);
    const data   = sorted.map(([, v]) => v);

    timelineChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Secrets Found',
          data,
          borderColor: 'rgba(99,102,241,0.9)',
          backgroundColor: 'rgba(99,102,241,0.15)',
          fill: true,
          tension: 0.4,
          pointBackgroundColor: 'var(--accent)',
          pointRadius: 4,
          pointHoverRadius: 7,
        }],
      },
      options: {
        ...chartDefaults,
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', font: { size: 10 }, maxTicksLimit: 12 } },
          y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', font: { size: 10 }, stepSize: 1 } },
        },
      },
    });
  }

  // ── Update stats cards ────────────────────────────────
  function updateStats(summary) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('stat-total', summary.total || 0);
    set('stat-crit',  summary.critical || 0);
    set('stat-high',  summary.high || 0);
    set('stat-med',   summary.medium || 0);
    set('stat-low',   summary.low || 0);
    set('stat-files', summary.filesScanned || 0);
  }

  function renderAll(findings, summary) {
    destroyAll();
    renderSeverityChart(findings);
    renderCategoryChart(findings);
    renderTimelineChart(findings);
    updateStats(summary);
  }

  return { renderAll, renderSeverityChart, renderCategoryChart, renderTimelineChart, updateStats, destroyAll };
})();
