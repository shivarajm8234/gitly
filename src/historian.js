// ============================================================
// src/historian.js — Git History Traversal
// ============================================================

const github = require('./github');
const { scanContent } = require('./analyzer');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * Parse a unified diff, returning per-file added-line content for scanning.
 */
function parseDiff(diffText) {
  if (!diffText) return [];
  const segments = [];
  let currentFile = null;
  let addedLines = [];

  for (const line of diffText.split('\n')) {
    if (line.startsWith('+++ b/')) {
      if (currentFile && addedLines.length) {
        segments.push({ file: currentFile, content: addedLines.join('\n') });
      }
      currentFile = line.substring(6).trim();
      addedLines = [];
    } else if (line.startsWith('+') && !line.startsWith('+++')) {
      addedLines.push(line.substring(1));
    }
  }
  if (currentFile && addedLines.length) {
    segments.push({ file: currentFile, content: addedLines.join('\n') });
  }
  return segments;
}

/**
 * Deduplicate findings: skip if same (type, rawValue, file) already seen.
 */
function dedup(newFindings, existing) {
  const seen = new Set(existing.map(f => `${f.type}:${(f.rawValue || '').substring(0, 20)}:${f.file}`));
  return newFindings.filter(f => {
    const k = `${f.type}:${(f.rawValue || '').substring(0, 20)}:${f.file}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Scan full git history across branches.
 */
async function scanHistory(owner, repo, token, patterns, customPatterns, options, onProgress) {
  const findings = [];
  const maxCommitsPerBranch = options.maxCommits || 100;

  let branches;
  try {
    const allBranches = await github.getBranches(owner, repo, token);
    // Limit branches to scan (default main + up to 4 others)
    const branchNames = allBranches.map(b => b.name);
    branches = branchNames.slice(0, options.maxBranches || 5);
  } catch {
    branches = ['main'];
  }

  let totalProcessed = 0;

  for (const branchName of branches) {
    let commits;
    try {
      commits = await github.getCommits(owner, repo, branchName, token, maxCommitsPerBranch);
    } catch {
      continue;
    }

    for (const commit of commits) {
      totalProcessed++;
      const sha = commit.sha;

      if (onProgress) {
        onProgress({
          type: 'history_progress',
          branch: branchName,
          commitShort: sha.substring(0, 7),
          message: commit.commit?.message?.split('\n')[0]?.substring(0, 60) || '',
          processed: totalProcessed,
        });
      }

      let diff;
      try {
        diff = await github.getCommitDiff(owner, repo, sha, token);
      } catch {
        await sleep(100);
        continue;
      }

      const segments = parseDiff(diff);
      for (const seg of segments) {
        const segFindings = scanContent(
          seg.content, seg.file, patterns, customPatterns,
          { entropy: options.entropy !== false }
        );

        for (const f of segFindings) {
          f.source      = 'history';
          f.commit      = sha;
          f.commitShort = sha.substring(0, 7);
          f.commitMessage = commit.commit?.message?.split('\n')[0]?.substring(0, 100) || '';
          f.author      = commit.commit?.author?.name || 'Unknown';
          f.authorEmail = commit.commit?.author?.email || '';
          f.timestamp   = commit.commit?.author?.date || null;
          f.branch      = branchName;
          f.commitUrl   = `https://github.com/${owner}/${repo}/commit/${sha}`;
        }
        findings.push(...segFindings);
      }

      await sleep(80); // Be kind to the API
    }
  }

  return findings;
}

module.exports = { scanHistory, dedup };
