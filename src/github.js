// ============================================================
// src/github.js — GitHub API Client
// ============================================================

const axios = require('axios');

const BASE = 'https://api.github.com';
const RAW  = 'https://raw.githubusercontent.com';

function makeHeaders(token) {
  const headers = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'Gitly-Security-Scanner/1.0',
  };
  if (token) headers['Authorization'] = `token ${token}`;
  return headers;
}

async function apiGet(url, token, params = {}) {
  try {
    const res = await axios.get(url, {
      headers: makeHeaders(token),
      params,
      timeout: 20000,
    });
    return res.data;
  } catch (err) {
    if (err.response) {
      const status = err.response.status;
      if (status === 403) {
        const remaining = err.response.headers['x-ratelimit-remaining'];
        if (remaining === '0') throw new Error('RATE_LIMIT_EXCEEDED');
      }
      if (status === 404) throw new Error(`NOT_FOUND: ${url}`);
      throw new Error(`GitHub API error ${status}: ${err.response.data?.message || err.message}`);
    }
    throw err;
  }
}

/**
 * Parse a GitHub URL into { owner, repo }.
 */
function parseRepoUrl(url) {
  const clean = url.trim().replace(/\.git$/, '').replace(/\/$/, '');
  const match = clean.match(/github\.com[/:]([^/]+)\/([^/]+)/);
  if (!match) throw new Error('Invalid GitHub URL. Expected: https://github.com/owner/repo');
  return { owner: match[1], repo: match[2] };
}

/**
 * Get basic repository information.
 */
async function getRepoInfo(owner, repo, token) {
  return apiGet(`${BASE}/repos/${owner}/${repo}`, token);
}

/**
 * Get repository branches.
 */
async function getBranches(owner, repo, token) {
  const branches = [];
  let page = 1;
  while (true) {
    const data = await apiGet(`${BASE}/repos/${owner}/${repo}/branches`, token, { per_page: 100, page });
    if (!data || data.length === 0) break;
    branches.push(...data);
    if (data.length < 100) break;
    page++;
  }
  return branches;
}

/**
 * Get tags.
 */
async function getTags(owner, repo, token) {
  try {
    const data = await apiGet(`${BASE}/repos/${owner}/${repo}/tags`, token, { per_page: 50 });
    return data || [];
  } catch { return []; }
}

/**
 * Get the full file tree for a given branch/commit.
 */
async function getFileTree(owner, repo, treeSha, token) {
  try {
    const data = await apiGet(
      `${BASE}/repos/${owner}/${repo}/git/trees/${treeSha}`,
      token,
      { recursive: '1' }
    );
    return (data.tree || []).filter(f => f.type === 'blob');
  } catch { return []; }
}

/**
 * Get raw file content (by path + branch).
 */
async function getFileContent(owner, repo, path, ref, token) {
  try {
    // Use raw content URL (faster, no base64)
    const url = `${RAW}/${owner}/${repo}/${ref}/${path}`;
    const res = await axios.get(url, {
      headers: makeHeaders(token),
      timeout: 15000,
      responseType: 'text',
      maxContentLength: 2 * 1024 * 1024, // 2MB max
    });
    return res.data;
  } catch {
    return null;
  }
}

/**
 * Get commits for a branch, up to maxCount.
 */
async function getCommits(owner, repo, sha, token, maxCount = 200) {
  const commits = [];
  let page = 1;
  const perPage = Math.min(100, maxCount);

  while (commits.length < maxCount) {
    const data = await apiGet(
      `${BASE}/repos/${owner}/${repo}/commits`,
      token,
      { sha, per_page: perPage, page }
    );
    if (!data || data.length === 0) break;
    commits.push(...data);
    if (data.length < perPage) break;
    page++;
  }

  return commits.slice(0, maxCount);
}

/**
 * Get a single commit's diff.
 */
async function getCommitDiff(owner, repo, sha, token) {
  try {
    const res = await axios.get(
      `${BASE}/repos/${owner}/${repo}/commits/${sha}`,
      {
        headers: {
          ...makeHeaders(token),
          'Accept': 'application/vnd.github.v3.diff',
        },
        timeout: 20000,
        responseType: 'text',
      }
    );
    return res.data;
  } catch { return null; }
}

/**
 * Get releases.
 */
async function getReleases(owner, repo, token) {
  try {
    return await apiGet(`${BASE}/repos/${owner}/${repo}/releases`, token, { per_page: 30 }) || [];
  } catch { return []; }
}

/**
 * Rate limit status.
 */
async function getRateLimit(token) {
  try {
    const data = await apiGet(`${BASE}/rate_limit`, token);
    return data.resources?.core || null;
  } catch { return null; }
}

module.exports = {
  parseRepoUrl,
  getRepoInfo,
  getBranches,
  getTags,
  getFileTree,
  getFileContent,
  getCommits,
  getCommitDiff,
  getReleases,
  getRateLimit,
};
