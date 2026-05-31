// ============================================================
// public/js/reports.js — JSON / CSV / PDF Export
// ============================================================

const Reports = (() => {
  let _findings = [];
  let _repoInfo = {};
  let _summary  = {};

  function setData(findings, repoInfo, summary) {
    _findings = findings || [];
    _repoInfo = repoInfo || {};
    _summary  = summary  || {};
  }

  // ── Helpers ───────────────────────────────────────────
  function download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function timestamp() {
    return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  }

  // ── JSON Export ───────────────────────────────────────
  function exportJSON() {
    if (!_findings.length) { UI.toast('No findings to export.', 'warning'); return; }
    const payload = {
      generatedAt: new Date().toISOString(),
      scanner: 'Gitly v1.0',
      repository: _repoInfo,
      summary: _summary,
      findings: _findings.map(f => ({
        id: f.id, type: f.type, label: f.label, category: f.category,
        severity: f.severity, confidence: f.confidence,
        isActive: f.isActive, isTest: f.isTest,
        file: f.file, line: f.line,
        value: f.value, // masked
        lineContent: f.lineContent,
        commit: f.commit, commitMessage: f.commitMessage,
        author: f.author, authorEmail: f.authorEmail,
        timestamp: f.timestamp, branch: f.branch,
        source: f.source, fileUrl: f.fileUrl,
        explanation: f.explanation,
        remediation: f.remediation,
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    download(blob, `gitly-scan-${_repoInfo.repo || 'report'}-${timestamp()}.json`);
    UI.toast('JSON report downloaded.', 'success');
  }

  // ── CSV Export ────────────────────────────────────────
  function exportCSV() {
    if (!_findings.length) { UI.toast('No findings to export.', 'warning'); return; }
    const headers = [
      'Severity','Confidence','Type','Label','Category',
      'File','Line','Value (masked)','Source','Commit','Author',
      'Timestamp','Branch','Is Active','Is Test','File URL',
    ];
    const rows = _findings.map(f => [
      f.severity, f.confidence, f.type, f.label, f.category,
      f.file, f.line, f.value,
      f.source, f.commitShort || '', f.author || '',
      f.timestamp || '', f.branch || '',
      f.isActive ? 'Yes' : 'No', f.isTest ? 'Yes' : 'No',
      f.fileUrl || '',
    ].map(v => `"${String(v).replace(/"/g, '""')}"`));

    const csv = [headers.map(h => `"${h}"`).join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    download(blob, `gitly-scan-${_repoInfo.repo || 'report'}-${timestamp()}.csv`);
    UI.toast('CSV report downloaded.', 'success');
  }

  // ── PDF Export ────────────────────────────────────────
  function exportPDF() {
    if (!_findings.length) { UI.toast('No findings to export.', 'warning'); return; }
    if (!window.jspdf) { UI.toast('PDF export unavailable (jsPDF not loaded). Use JSON or CSV instead.', 'warning'); return; }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const PW = 210, PH = 297, M = 15;
    let y = M;

    const addPage = () => { doc.addPage(); y = M; };
    const checkPage = (need = 10) => { if (y + need > PH - M) addPage(); };
    const line = (text, fontSize = 10, color = [241, 245, 249], indent = 0) => {
      checkPage(fontSize * 0.5 + 2);
      doc.setFontSize(fontSize);
      doc.setTextColor(...color);
      doc.text(text, M + indent, y);
      y += fontSize * 0.45 + 2;
    };
    const rule = (color = [30, 35, 60]) => {
      checkPage(3);
      doc.setDrawColor(...color);
      doc.line(M, y, PW - M, y);
      y += 3;
    };

    // Background
    doc.setFillColor(7, 8, 15);
    doc.rect(0, 0, PW, PH, 'F');

    // Title
    doc.setFillColor(20, 22, 40);
    doc.roundedRect(M, M, PW - M * 2, 30, 4, 4, 'F');
    y = M + 8;
    line('🔍 GITLY SECURITY SCAN REPORT', 16, [99, 102, 241]);
    line(`Repository: ${_repoInfo.fullName || _repoInfo.repo || '—'}`, 10, [148, 163, 184]);
    line(`Generated: ${new Date().toLocaleString()}  |  Scanner: Gitly v1.0`, 9, [71, 85, 105]);
    y = M + 36;
    rule();

    // Summary
    line('EXECUTIVE SUMMARY', 12, [99, 102, 241]);
    y += 2;
    const sev = [
      ['Total Findings', _summary.total || 0, [241, 245, 249]],
      ['CRITICAL', _summary.critical || 0, [244, 63, 94]],
      ['HIGH', _summary.high || 0, [251, 146, 60]],
      ['MEDIUM', _summary.medium || 0, [245, 158, 11]],
      ['LOW', _summary.low || 0, [34, 211, 238]],
      ['Health Score', `${_summary.healthScore || 0}/100`, [16, 185, 129]],
    ];
    sev.forEach(([label, val, color]) => {
      checkPage(6);
      doc.setFontSize(10); doc.setTextColor(148, 163, 184);
      doc.text(`${label}:`, M + 2, y);
      doc.setFontSize(10); doc.setTextColor(...color);
      doc.text(String(val), M + 55, y);
      y += 6;
    });
    y += 4; rule();

    // Findings
    line('FINDINGS DETAIL', 12, [99, 102, 241]);
    y += 2;

    const sevColor = { CRITICAL:[244,63,94], HIGH:[251,146,60], MEDIUM:[245,158,11], LOW:[34,211,238], INFO:[148,163,184] };

    _findings.slice(0, 200).forEach((f, idx) => {
      checkPage(28);
      doc.setFillColor(18, 21, 42);
      doc.roundedRect(M, y, PW - M * 2, 26, 3, 3, 'F');
      const fy = y + 5;
      doc.setFontSize(9); doc.setTextColor(...(sevColor[f.severity] || [148,163,184]));
      doc.text(`[${f.severity}]`, M + 3, fy);
      doc.setTextColor(241, 245, 249);
      doc.text(f.label.substring(0, 40), M + 22, fy);
      doc.setTextColor(148, 163, 184);
      doc.text(`Confidence: ${f.confidence}%`, PW - M - 35, fy);
      doc.setFontSize(8);
      doc.setTextColor(34, 211, 238);
      doc.text(`File: ${f.file.substring(0, 60)}`, M + 3, fy + 6);
      doc.setTextColor(99, 102, 241);
      doc.text(`Line: ${f.line || '—'}  |  Source: ${f.source}  |  Branch: ${f.branch || '—'}`, M + 3, fy + 12);
      if (f.author) {
        doc.setTextColor(71, 85, 105);
        doc.text(`Author: ${f.author}  |  ${f.timestamp ? new Date(f.timestamp).toLocaleDateString() : ''}`, M + 3, fy + 18);
      }
      y += 30;
    });

    if (_findings.length > 200) {
      y += 4;
      line(`... and ${_findings.length - 200} more findings. Export JSON/CSV for complete list.`, 9, [71, 85, 105]);
    }

    doc.save(`gitly-scan-${_repoInfo.repo || 'report'}-${timestamp()}.pdf`);
    UI.toast('PDF report downloaded.', 'success');
  }

  return { setData, exportJSON, exportCSV, exportPDF };
})();
