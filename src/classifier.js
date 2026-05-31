// ============================================================
// src/classifier.js — Severity & Confidence Scoring
// ============================================================

const SEVERITY_MAP = {
  // CRITICAL — immediate financial/infrastructure risk
  AWS_ACCESS_KEY:        'CRITICAL',
  AWS_SECRET_KEY:        'CRITICAL',
  STRIPE_SECRET_KEY:     'CRITICAL',
  GCP_SERVICE_ACCOUNT:   'CRITICAL',
  AZURE_CLIENT_SECRET:   'CRITICAL',
  PRIVATE_KEY:           'CRITICAL',
  DATABASE_URL:          'CRITICAL',
  GITHUB_TOKEN:          'CRITICAL',

  // HIGH — significant data exposure risk
  OPENAI_API_KEY:        'HIGH',
  ANTHROPIC_API_KEY:     'HIGH',
  GROQ_API_KEY:          'HIGH',
  TWILIO_AUTH_TOKEN:     'HIGH',
  SENDGRID_API_KEY:      'HIGH',
  MAILGUN_API_KEY:       'HIGH',
  FIREBASE_API_KEY:      'HIGH',
  FIREBASE_CONFIG:       'HIGH',
  JWT_SECRET:            'HIGH',
  NPM_TOKEN:             'HIGH',
  CLOUDFLARE_API_TOKEN:  'HIGH',
  HEROKU_API_KEY:        'HIGH',
  DIGITALOCEAN_TOKEN:    'HIGH',
  SLACK_TOKEN:           'HIGH',
  DISCORD_TOKEN:         'HIGH',

  // MEDIUM — potential abuse with additional context
  GCP_API_KEY:           'MEDIUM',
  HUGGINGFACE_TOKEN:     'MEDIUM',
  SLACK_WEBHOOK:         'MEDIUM',
  DISCORD_WEBHOOK:       'MEDIUM',
  GITHUB_APP_SECRET:     'MEDIUM',
  STRIPE_RESTRICTED_KEY: 'MEDIUM',
  SMTP_CREDENTIALS:      'MEDIUM',
  OAUTH_TOKEN:           'MEDIUM',
  TELEGRAM_BOT_TOKEN:    'MEDIUM',
  PAYPAL_CLIENT_SECRET:  'MEDIUM',
  SHOPIFY_SECRET:        'MEDIUM',

  // LOW — informational but should be investigated
  GENERIC_SECRET:        'LOW',
  HIGH_ENTROPY_STRING:   'LOW',
  PRIVATE_URL:           'LOW',
  ENV_VARIABLE:          'LOW',
  STRIPE_PUBLISHABLE:    'INFO',

  // INFO
  COMMENT_CREDENTIAL:    'INFO',
  POSSIBLE_PASSWORD:     'INFO',
};

const SEVERITY_SCORE = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

// Patterns that indicate test/fake data (reduce confidence)
const TEST_INDICATORS = [
  /test/i, /fake/i, /dummy/i, /example/i, /placeholder/i,
  /your[-_]?key/i, /your[-_]?secret/i, /your[-_]?token/i,
  /xxx+/i, /aaa+/i, /123456/i, /abc123/i, /changeme/i,
  /replace[-_]?me/i, /todo/i, /fixme/i, /sample/i,
  /demo/i, /mock/i, /not[-_]?real/i, /invalid/i,
  /^sk[-_]test/i, /^pk[-_]test/i, // Stripe test keys
];

// Patterns that suggest the credential is active
const ACTIVE_INDICATORS = [
  /production/i, /prod/i, /live/i, /real/i, /actual/i,
];

/**
 * Classify a finding: assign severity, confidence, active status.
 */
function classify(finding) {
  const { type, value, file, line, context } = finding;

  // Base severity
  const severity = SEVERITY_MAP[type] || 'LOW';

  // Base confidence
  let confidence = 70;

  // Boost confidence based on context
  if (context) {
    const ctx = context.toLowerCase();
    if (ctx.includes('production') || ctx.includes('prod')) confidence += 15;
    if (ctx.includes('secret') || ctx.includes('key') || ctx.includes('token')) confidence += 10;
    if (ctx.includes('password') || ctx.includes('pwd') || ctx.includes('passwd')) confidence += 10;
  }

  // Reduce confidence for test indicators
  const valueAndCtx = (value || '') + ' ' + (context || '');
  for (const pattern of TEST_INDICATORS) {
    if (pattern.test(valueAndCtx)) {
      confidence -= 30;
      break;
    }
  }

  // Reduce confidence for certain file paths
  if (file) {
    const f = file.toLowerCase();
    if (f.includes('test') || f.includes('spec') || f.includes('mock') || f.includes('fixture')) {
      confidence -= 20;
    }
    if (f.includes('example') || f.includes('sample') || f.includes('demo')) {
      confidence -= 20;
    }
    if (f.includes('readme') || f.includes('.md')) {
      confidence -= 15; // Could be docs
    }
    // Boost for env/config files
    if (f.endsWith('.env') || f.includes('config') || f.includes('secret')) {
      confidence += 10;
    }
  }

  // Boost for CRITICAL types
  if (severity === 'CRITICAL') confidence += 10;

  // Clamp
  confidence = Math.max(5, Math.min(100, confidence));

  // Active heuristic
  const isActive = ACTIVE_INDICATORS.some(p => p.test(valueAndCtx)) && !TEST_INDICATORS.some(p => p.test(valueAndCtx));
  const isTest = TEST_INDICATORS.some(p => p.test(valueAndCtx));

  return {
    severity,
    severityScore: SEVERITY_SCORE[severity] || 1,
    confidence,
    isActive,
    isTest,
  };
}

/**
 * Calculate repository health score (0-100, higher = healthier).
 */
function calcHealthScore(findings) {
  if (!findings || findings.length === 0) return 100;

  let penalty = 0;
  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': penalty += 20; break;
      case 'HIGH':     penalty += 10; break;
      case 'MEDIUM':   penalty += 5;  break;
      case 'LOW':      penalty += 2;  break;
      case 'INFO':     penalty += 1;  break;
    }
  }

  return Math.max(0, Math.min(100, 100 - penalty));
}

module.exports = { classify, calcHealthScore, SEVERITY_MAP, SEVERITY_SCORE };
