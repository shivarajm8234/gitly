// ============================================================
// public/js/scanner.js — SSE Scan Orchestration
// ============================================================

const Scanner = (() => {
  let _evtSource = null;
  let _findings  = [];
  let _repoInfo  = {};
  let _summary   = {};
  let _onFinding = null;
  let _onComplete = null;
  let _onError   = null;
  let _progFiles = 0;
  let _progCommits = 0;
  let _totalFiles = 0;

  function reset() {
    _findings = []; _repoInfo = {}; _summary = {};
    _progFiles = _progCommits = _totalFiles = 0;
  }

  function abort() {
    if (_evtSource) { _evtSource.close(); _evtSource = null; }
  }

  function parseCustomRules(raw) {
    if (!raw || !raw.trim()) return [];
    return raw.trim().split('\n').map(line => {
      const [name, pattern, severity] = line.split('::').map(s => s.trim());
      return name && pattern ? { name, pattern, severity: severity || 'MEDIUM' } : null;
    }).filter(Boolean);
  }

  /**
   * Start a scan via SSE.
   * callbacks: { onFinding, onProgress, onStatus, onComplete, onError }
   */
  async function startScan(params, callbacks) {
    abort();
    reset();
    _onFinding  = callbacks.onFinding  || (() => {});
    _onComplete = callbacks.onComplete || (() => {});
    _onError    = callbacks.onError    || (() => {});

    const body = {
      repoUrl:       params.repoUrl,
      token:         params.token || '',
      mode:          params.mode || 'quick',
      customPatterns: parseCustomRules(params.customRules),
      options: {
        maxCommits:  parseInt(params.maxCommits, 10) || 100,
        maxBranches: parseInt(params.maxBranches, 10) || 5,
        entropy:     params.entropy !== false,
      },
    };

    // Use fetch + ReadableStream to handle SSE from POST
    let response;
    try {
      console.log('[Scanner] Fetching /api/scan...');
      response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      console.log('[Scanner] Fetch response:', response.status, response.statusText);
    } catch (err) {
      console.error('[Scanner] Fetch error:', err);
      callbacks.onError && callbacks.onError(err.message);
      return;
    }

    if (!response.ok) {
      console.error('[Scanner] Bad response:', response.status);
      callbacks.onError && callbacks.onError(`Server error: ${response.status}`);
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // Parse SSE messages from buffer
        const messages = buffer.split('\n\n');
        buffer = messages.pop(); // keep incomplete message

        for (const msg of messages) {
          if (!msg.trim()) continue;
          const lines = msg.split('\n');
          let event = 'message', data = '';
          for (const l of lines) {
            if (l.startsWith('event: ')) event = l.slice(7).trim();
            else if (l.startsWith('data: ')) data = l.slice(6).trim();
          }
          try {
            const parsed = JSON.parse(data);
            handleEvent(event, parsed, callbacks);
          } catch {}
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        callbacks.onError && callbacks.onError(err.message);
      }
    }
  }

  function handleEvent(event, data, callbacks) {
    switch (event) {
      case 'repo_info':
        _repoInfo = data;
        callbacks.onRepoInfo && callbacks.onRepoInfo(data);
        break;

      case 'status':
        callbacks.onStatus && callbacks.onStatus(data);
        if (data.total) _totalFiles = data.total;
        break;

      case 'progress':
        _progFiles = data.processed || _progFiles;
        const pct = _totalFiles > 0 ? Math.round((_progFiles / _totalFiles) * 80) : 0;
        callbacks.onProgress && callbacks.onProgress({
          percent: pct,
          label: `Scanning files: ${_progFiles}/${_totalFiles} — ${data.file || ''}`,
          files: _progFiles,
          findings: _findings.length,
          commits: _progCommits,
        });
        break;

      case 'history_progress':
        _progCommits++;
        callbacks.onProgress && callbacks.onProgress({
          percent: 80 + Math.min(18, _progCommits * 0.1),
          label: `History: commit ${data.commitShort} on ${data.branch} — ${data.message || ''}`,
          files: _progFiles,
          findings: _findings.length,
          commits: _progCommits,
        });
        break;

      case 'finding':
        _findings.push(data);
        _onFinding(data);
        callbacks.onProgress && callbacks.onProgress({
          percent: null, // keep current
          label: null,
          files: _progFiles,
          findings: _findings.length,
          commits: _progCommits,
        });
        break;

      case 'meta':
        callbacks.onMeta && callbacks.onMeta(data);
        break;

      case 'complete':
        _summary = data;
        callbacks.onProgress && callbacks.onProgress({ percent: 100, label: 'Scan complete!', files: _progFiles, findings: _findings.length, commits: _progCommits });
        _onComplete({ findings: _findings, repoInfo: _repoInfo, summary: data });
        break;

      case 'error':
        _onError(data.message || 'Unknown error');
        break;
    }
  }

  function getFindings()  { return _findings; }
  function getRepoInfo()  { return _repoInfo; }
  function getSummary()   { return _summary; }

  return { startScan, abort, getFindings, getRepoInfo, getSummary };
})();
