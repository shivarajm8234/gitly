// ============================================================
// src/entropy.js — Shannon Entropy Calculator
// ============================================================

/**
 * Calculate Shannon entropy of a string.
 * High entropy (>3.5) indicates random-looking data (e.g. secrets, tokens).
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

/**
 * Check if a string looks like a high-entropy secret.
 * Thresholds tuned to minimize false positives.
 */
function isHighEntropy(value, threshold = 3.5) {
  if (value.length < 16) return false;
  const entropy = shannonEntropy(value);
  return entropy >= threshold;
}

/**
 * Extract candidate high-entropy strings from a line of text.
 * Returns array of { value, entropy } objects.
 */
function extractHighEntropyStrings(line) {
  const results = [];
  // Match quoted strings or assignment values
  const patterns = [
    /["'`]([A-Za-z0-9+/=_\-]{20,})["'`]/g,
    /[:=]\s*([A-Za-z0-9+/=_\-]{20,})\b/g,
  ];
  for (const pattern of patterns) {
    let match;
    const re = new RegExp(pattern.source, pattern.flags);
    while ((match = re.exec(line)) !== null) {
      const value = match[1];
      const entropy = shannonEntropy(value);
      if (entropy >= 3.5 && value.length >= 16) {
        results.push({ value, entropy: parseFloat(entropy.toFixed(2)) });
      }
    }
  }
  return results;
}

module.exports = { shannonEntropy, isHighEntropy, extractHighEntropyStrings };
