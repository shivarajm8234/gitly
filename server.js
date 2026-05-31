require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const github  = require('./src/github');
const { scanContent, shouldSkipPath } = require('./src/analyzer');
const { scanHistory, dedup } = require('./src/historian');
const { calcHealthScore } = require('./src/classifier');
const PATTERNS = require('./src/patterns');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// ── COOP header: allow Firebase Auth popup to communicate ──
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');
  res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Simple auth gate ───────────────────────────────────────────────────────
const ALLOWED_EMAILS = new Set([
  'shivarajmani2005@gmail.com',
  'rockybai8234@gmail.com',
]);
const SESSIONS = new Set(); // in-memory tokens (reset on server restart)

app.post('/api/auth/login', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ ok: false, error: 'Email required.' });
  if (!ALLOWED_EMAILS.has(email)) return res.status(403).json({ ok: false, error: `Access denied for ${email}.` });
  const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
  SESSIONS.add(token);
  res.json({ ok: true, token, email });
});

app.post('/api/auth/verify', (req, res) => {
  const token = req.body.token || '';
  res.json({ ok: SESSIONS.has(token) });
});


function sse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const SCANABLE_EXTS = new Set([
  'js','jsx','ts','tsx','mjs','cjs','vue','svelte',
  'py','rb','php','go','java','kt','cs','rs','cpp','c','h','hpp',
  'yaml','yml','json','toml','ini','cfg','conf','properties',
  'env','envrc','sh','bash','zsh','fish',
  'tf','tfvars','hcl',
  'md','txt','rst',
  'Dockerfile','Makefile','Procfile',
  'gradle','pom',
  'gemspec',
]);

function isScanable(filePath) {
  if (shouldSkipPath(filePath)) return false;
  const parts = filePath.split('.');
  if (parts.length === 1) {
    const base = filePath.split('/').pop().toLowerCase();
    return ['dockerfile','makefile','procfile','jenkinsfile','vagrantfile'].includes(base);
  }
  const ext = parts.pop().toLowerCase();
  return SCANABLE_EXTS.has(ext);
}

// ── Routes ─────────────────────────────────────────────────────────────────

/** Validate repo and get basic info */
app.post('/api/validate', async (req, res) => {
  try {
    const { repoUrl, token } = req.body;
    const { owner, repo } = github.parseRepoUrl(repoUrl);
    const info = await github.getRepoInfo(owner, repo, token || process.env.GITHUB_TOKEN);
    const rateLimit = await github.getRateLimit(token || process.env.GITHUB_TOKEN);
    res.json({ ok: true, info, rateLimit });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

/** List available patterns */
app.get('/api/patterns', (_, res) => {
  res.json(PATTERNS.map(p => ({
    type: p.type,
    label: p.label,
    category: p.category,
  })));
});

/** Main scan endpoint — streams findings via SSE */
app.post('/api/scan', async (req, res) => {
  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const {
    repoUrl,
    token,
    mode = 'quick',         // 'quick' | 'deep'
    customPatterns = [],
    options = {},
  } = req.body || {};

  const authToken = token || process.env.GITHUB_TOKEN || null;
  const allFindings = [];

  try {
    // ── Phase 1: Init ────────────────────────────────────────
    sse(res, 'status', { phase: 'init', message: 'Parsing repository URL...' });
    const { owner, repo } = github.parseRepoUrl(repoUrl);

    sse(res, 'status', { phase: 'init', message: 'Fetching repository info...' });
    const repoInfo = await github.getRepoInfo(owner, repo, authToken);

    sse(res, 'repo_info', {
      owner, repo,
      fullName:      repoInfo.full_name,
      description:   repoInfo.description,
      defaultBranch: repoInfo.default_branch,
      stars:         repoInfo.stargazers_count,
      language:      repoInfo.language,
      size:          repoInfo.size,
      isPrivate:     repoInfo.private,
      htmlUrl:       repoInfo.html_url,
      createdAt:     repoInfo.created_at,
      pushedAt:      repoInfo.pushed_at,
    });

    const defaultBranch = repoInfo.default_branch || 'main';

    // ── Phase 2: Branches & Tags ─────────────────────────────
    sse(res, 'status', { phase: 'init', message: 'Fetching branches...' });
    let branches = [];
    try { branches = await github.getBranches(owner, repo, authToken); } catch {}

    let tags = [];
    try { tags = await github.getTags(owner, repo, authToken); } catch {}

    sse(res, 'meta', { branches: branches.map(b => b.name), tags: tags.map(t => t.name) });

    // ── Phase 3: File Tree ───────────────────────────────────
    sse(res, 'status', { phase: 'files', message: `Building file tree for ${defaultBranch}...` });
    const tree = await github.getFileTree(owner, repo, defaultBranch, authToken);
    const scanableFiles = tree.filter(f => isScanable(f.path));

    sse(res, 'status', {
      phase: 'files',
      message: `Scanning ${scanableFiles.length} files...`,
      total: scanableFiles.length,
    });

    // ── Phase 4: Scan Files ──────────────────────────────────
    for (let i = 0; i < scanableFiles.length; i++) {
      const file = scanableFiles[i];

      if (i % 5 === 0 || i === scanableFiles.length - 1) {
        sse(res, 'progress', {
          phase: 'files',
          processed: i + 1,
          total: scanableFiles.length,
          file: file.path,
        });
      }

      const content = await github.getFileContent(owner, repo, file.path, defaultBranch, authToken);
      if (!content) continue;

      const findings = scanContent(content, file.path, PATTERNS, customPatterns, {
        entropy: options.entropy !== false,
      });

      for (const f of findings) {
        f.branch   = defaultBranch;
        f.fileUrl  = `https://github.com/${owner}/${repo}/blob/${defaultBranch}/${f.file}#L${f.line}`;
      }

      if (findings.length > 0) {
        allFindings.push(...findings);
        for (const f of findings) sse(res, 'finding', f);
      }

      await sleep(20);
    }

    // ── Phase 5: History Scan ────────────────────────────────
    if (mode === 'deep') {
      sse(res, 'status', { phase: 'history', message: 'Scanning git history...' });

      const historyFindings = await scanHistory(
        owner, repo, authToken,
        PATTERNS, customPatterns,
        { maxCommits: options.maxCommits || 150, entropy: options.entropy !== false, maxBranches: options.maxBranches || 5 },
        (prog) => sse(res, 'history_progress', prog)
      );

      const fresh = dedup(historyFindings, allFindings);
      allFindings.push(...fresh);
      for (const f of fresh) {
        f.fileUrl = f.commitUrl
          ? `${f.commitUrl}#diff-${Buffer.from(f.file).toString('hex')}`
          : null;
        sse(res, 'finding', f);
      }
    }

    // ── Phase 6: Complete ────────────────────────────────────
    const healthScore = calcHealthScore(allFindings);

    const summary = {
      total:    allFindings.length,
      critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
      high:     allFindings.filter(f => f.severity === 'HIGH').length,
      medium:   allFindings.filter(f => f.severity === 'MEDIUM').length,
      low:      allFindings.filter(f => f.severity === 'LOW').length,
      info:     allFindings.filter(f => f.severity === 'INFO').length,
      healthScore,
      filesScanned: scanableFiles.length,
      branches: branches.length,
      tags: tags.length,
    };

    sse(res, 'complete', summary);

  } catch (err) {
    const msg = err.message === 'RATE_LIMIT_EXCEEDED'
      ? 'GitHub API rate limit exceeded. Add a Personal Access Token for 5000 req/hour.'
      : err.message;
    sse(res, 'error', { message: msg });
  } finally {
    res.end();
  }
});

// ── Serve SPA ──────────────────────────────────────────────────────────────
app.get('*', (_, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🔍 Gitly Security Scanner`);
  console.log(`   Running at: http://localhost:${PORT}`);
  console.log(`   GitHub token: ${process.env.GITHUB_TOKEN ? '✅ configured' : '⚠️  not set (60 req/hr limit)'}`);
  console.log('');
});
