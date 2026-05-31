// ============================================================
// src/analyzer.js — Core Secret Detection Engine
// ============================================================

const { extractHighEntropyStrings } = require('./entropy');
const { classify } = require('./classifier');
const { getRemediation } = require('./remediator');

let _idCounter = 0;
const genId = () => `f${++_idCounter}-${Date.now()}`;

const SKIP_EXTENSIONS = new Set([
  '.png','.jpg','.jpeg','.gif','.svg','.ico','.webp','.bmp',
  '.mp4','.mp3','.wav','.ogg','.pdf','.zip','.tar','.gz',
  '.woff','.woff2','.ttf','.eot','.bin','.exe','.dll','.so',
]);

const SKIP_PATHS = [
  /node_modules\//i, /vendor\//i, /\.git\//i,
  /package-lock\.json$/i, /yarn\.lock$/i, /pnpm-lock\.yaml$/i,
  /composer\.lock$/i, /poetry\.lock$/i, /Gemfile\.lock$/i,
  /\.min\.js\.map$/i,
];

const EXPLANATIONS = {
  AWS_ACCESS_KEY:      'AWS Access Key IDs (AKIA…) authenticate API calls to AWS. With the matching secret, an attacker gains full control of AWS resources — S3, EC2, Lambda, IAM.',
  AWS_SECRET_KEY:      'AWS Secret Access Keys are the password half of AWS credentials. Combined with the access key ID, they allow unrestricted API access to all permitted AWS services.',
  GCP_API_KEY:         'Google Cloud API keys (AIza…) grant access to GCP services. Depending on restrictions, an attacker can hit Maps, Vision, Translation APIs — potentially incurring large bills.',
  GCP_SERVICE_ACCOUNT: 'A GCP Service Account JSON key allows impersonation of the service account and full access to all cloud resources it controls.',
  AZURE_CONNECTION_STRING:'Azure Storage connection strings contain a full account key, granting read/write access to all blobs, tables, and queues in that storage account.',
  AZURE_CLIENT_SECRET: 'Azure client secrets allow an application to authenticate with Azure AD and obtain tokens to access Azure resources.',
  AZURE_SAS_TOKEN:     'An Azure Shared Access Signature token grants time-limited access to specific Azure Storage resources without exposing the account key.',
  GITHUB_TOKEN:        'GitHub tokens (ghp_, ghs_, etc.) allow API access with the issuing user\'s permissions — code push, secret reading, repo deletion, and more.',
  GITHUB_APP_SECRET:   'GitHub App webhook secrets are used to verify webhook payloads. Exposure allows forging fake webhook events.',
  STRIPE_SECRET_KEY:   'Stripe secret keys (sk_live_) provide full access to charges, refunds, customers, and financial records. Exposure risks direct financial fraud.',
  STRIPE_RESTRICTED_KEY:'Stripe restricted keys still grant API access within defined scopes and should not be public.',
  STRIPE_PUBLISHABLE:  'Stripe publishable keys are client-side but hardcoding them in server-side code indicates poor secrets hygiene.',
  OPENAI_API_KEY:      'OpenAI API keys grant access to GPT-4, DALL-E, and Embeddings APIs. Unauthorized usage generates billing charges to the account holder.',
  ANTHROPIC_API_KEY:   'Anthropic API keys grant access to Claude models. Exposure results in unauthorized usage and billing.',
  GROQ_API_KEY:        'Groq API keys enable fast LLM inference. Exposed keys can be exploited for unauthorized model calls.',
  HUGGINGFACE_TOKEN:   'HuggingFace tokens can read private models/datasets and (if write-scoped) push malicious model weights — a supply-chain risk.',
  FIREBASE_API_KEY:    'Firebase API keys initialize the Firebase SDK. Paired with misconfigured security rules, they allow unauthorized database and storage access.',
  FIREBASE_CONFIG:     'Firebase config objects contain API keys and project references. Ensure Firebase Security Rules are strict.',
  FIREBASE_FCM_KEY:    'Firebase Cloud Messaging server keys allow sending push notifications to any device subscribed to your Firebase project.',
  SLACK_TOKEN:         'Slack tokens (xoxb-/xoxp-) provide message reading, posting, and admin actions across workspaces the bot/user belongs to.',
  SLACK_WEBHOOK:       'Slack webhook URLs allow anyone to post messages to a specific channel, enabling spam or social engineering.',
  DISCORD_TOKEN:       'Discord bot tokens give full control of the bot — reading messages, managing servers, and impersonating the bot.',
  DISCORD_WEBHOOK:     'Discord webhooks allow message injection into channels. Can be used for phishing or spam.',
  TWILIO_AUTH_TOKEN:   'Twilio auth tokens provide full account access including sending SMS/voice calls and accessing logs. Risk of toll fraud.',
  TWILIO_SID:          'Twilio Account SIDs identify your account. Combined with an auth token, they grant full API access.',
  SENDGRID_API_KEY:    'SendGrid API keys allow sending email, managing contacts, and modifying account settings. Risk of phishing campaigns via your domain.',
  MAILGUN_API_KEY:     'Mailgun API keys allow email sending and log access from your domain. Risk of phishing.',
  DATABASE_URL:        'Database connection strings contain credentials for direct database access. Exposure grants full read/write access to all data.',
  JWT_SECRET:          'JWT secrets are used to sign tokens. An exposed secret allows forging valid session tokens for any user, bypassing authentication entirely.',
  JWT_TOKEN:           'An encoded JWT may contain sensitive user data in its payload (decodable without the secret) and reveals your authentication scheme.',
  PRIVATE_KEY:         'Private cryptographic keys (RSA/EC/SSH/PGP) are the highest-sensitivity credential. They decrypt communications and enable server impersonation.',
  NPM_TOKEN:           'npm auth tokens can publish packages. A leaked write token enables supply-chain attacks by publishing malicious versions of your package.',
  HEROKU_API_KEY:      'Heroku API keys allow full control of Heroku apps including environment variable access, which may expose more secrets.',
  DIGITALOCEAN_TOKEN:  'DigitalOcean tokens (dop_v1_) provide full API access to cloud infrastructure — droplets, databases, Kubernetes clusters.',
  CLOUDFLARE_API_TOKEN:'Cloudflare API tokens can modify DNS, firewall rules, SSL certs — enabling traffic interception or site takeover.',
  TELEGRAM_BOT_TOKEN:  'Telegram bot tokens give full control of the bot. Attackers can read messages and send content to any user or group.',
  SMTP_CREDENTIALS:    'SMTP credentials allow sending email as your domain. Risk of phishing and spam campaigns.',
  OAUTH_TOKEN:         'OAuth access tokens grant delegated API access. Depending on scope, an attacker can access user data and perform actions on their behalf.',
  GENERIC_SECRET:      'This appears to be a hardcoded secret or API credential. Hardcoded secrets in source code are trivially discoverable and must be rotated.',
  POSSIBLE_PASSWORD:   'A hardcoded password was detected. If valid, an attacker can use it to authenticate to the associated system.',
  PRIVATE_URL:         'URLs with embedded credentials (user:pass@host) expose login information in logs, browser history, and network traffic.',
  HIGH_ENTROPY_STRING: 'High Shannon entropy indicates a randomly generated secret, key, or token. Manual verification is recommended.',
  ENV_VARIABLE:        'A sensitive environment variable with a secret-like name is hardcoded in source. It should be injected at runtime via a secrets manager.',
};

function shouldSkipPath(filePath) {
  const ext = '.' + filePath.split('.').pop().toLowerCase();
  if (SKIP_EXTENSIONS.has(ext)) return true;
  return SKIP_PATHS.some(p => p.test(filePath));
}

function getContext(lines, idx, radius = 2) {
  const s = Math.max(0, idx - radius);
  const e = Math.min(lines.length - 1, idx + radius);
  return lines.slice(s, e + 1).join('\n');
}

function maskValue(v) {
  if (!v || v.length <= 8) return '****';
  const keep = Math.min(6, Math.floor(v.length * 0.15));
  return v.substring(0, keep) + '••••' + v.slice(-2);
}

function isBinary(content) {
  const sample = content.substring(0, 512);
  return (sample.match(/[\x00-\x08\x0E-\x1F\x7F]/g) || []).length > sample.length * 0.1;
}

/**
 * Scan file content for secrets.
 * Returns array of finding objects.
 */
function scanContent(content, filePath, patterns, customPatterns = [], options = {}) {
  if (!content || typeof content !== 'string') return [];
  if (content.length > 1024 * 1024) return []; // skip > 1MB
  if (isBinary(content)) return [];
  if (shouldSkipPath(filePath)) return [];

  const findings = [];
  const seen = new Set();
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.trim().length < 6) continue;

    // ── Built-in patterns ──────────────────────────────────
    for (const pat of patterns) {
      let re;
      try { re = new RegExp(pat.pattern.source, 'gi'); } catch { continue; }
      let m;
      while ((m = re.exec(line)) !== null) {
        const val = m[1] || m[0];
        if (!val || val.length < 8) continue;
        const dedupKey = `${pat.type}:${val.substring(0, 18)}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);

        const ctx = getContext(lines, i);
        const cls = classify({ type: pat.type, value: val, file: filePath, line: i + 1, context: ctx });

        findings.push({
          id: genId(),
          type: pat.type,
          label: pat.label,
          category: pat.category || 'generic',
          severity: cls.severity,
          severityScore: cls.severityScore,
          confidence: cls.confidence,
          isActive: cls.isActive,
          isTest: cls.isTest,
          value: maskValue(val),
          rawValue: val,
          file: filePath,
          line: i + 1,
          lineContent: line.trim().substring(0, 250),
          context: ctx,
          explanation: EXPLANATIONS[pat.type] || `A ${pat.label} was detected in source code.`,
          remediation: getRemediation(pat.type),
          source: 'latest',
          commit: null, commitShort: null, commitMessage: null,
          author: null, authorEmail: null, timestamp: null, branch: null, commitUrl: null,
        });
      }
    }

    // ── Custom user patterns ───────────────────────────────
    for (const custom of (customPatterns || [])) {
      if (!custom.pattern) continue;
      let re;
      try { re = new RegExp(custom.pattern, 'gi'); } catch { continue; }
      let m;
      while ((m = re.exec(line)) !== null) {
        const val = m[1] || m[0];
        if (!val) continue;
        const dedupKey = `CUSTOM:${custom.name}:${val.substring(0, 18)}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);
        const ctx = getContext(lines, i);
        findings.push({
          id: genId(),
          type: 'CUSTOM', label: custom.name || 'Custom Rule', category: 'custom',
          severity: custom.severity || 'MEDIUM', severityScore: 3, confidence: 65,
          isActive: false, isTest: false,
          value: maskValue(val), rawValue: val,
          file: filePath, line: i + 1,
          lineContent: line.trim().substring(0, 250),
          context: ctx,
          explanation: `Matched custom rule "${custom.name}". Pattern: ${custom.pattern}`,
          remediation: getRemediation('GENERIC_SECRET'),
          source: 'latest',
          commit: null, commitShort: null, commitMessage: null,
          author: null, authorEmail: null, timestamp: null, branch: null, commitUrl: null,
        });
      }
    }

    // ── Entropy analysis ───────────────────────────────────
    if (options.entropy !== false) {
      const entropyHits = extractHighEntropyStrings(line);
      for (const eh of entropyHits) {
        const alreadyCovered = findings.some(f => f.rawValue && f.rawValue.includes(eh.value.substring(0, 8)));
        if (alreadyCovered) continue;
        const dedupKey = `ENTROPY:${eh.value.substring(0, 18)}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);
        const ctx = getContext(lines, i);
        const cls = classify({ type: 'HIGH_ENTROPY_STRING', value: eh.value, file: filePath, line: i + 1, context: ctx });
        if (cls.confidence < 35) continue;
        findings.push({
          id: genId(),
          type: 'HIGH_ENTROPY_STRING', label: 'High Entropy String', category: 'entropy',
          severity: 'LOW', severityScore: 2, confidence: cls.confidence,
          isActive: false, isTest: false,
          value: maskValue(eh.value), rawValue: eh.value,
          file: filePath, line: i + 1,
          lineContent: line.trim().substring(0, 250),
          context: ctx,
          explanation: EXPLANATIONS.HIGH_ENTROPY_STRING + ` (entropy: ${eh.entropy})`,
          remediation: getRemediation('GENERIC_SECRET'),
          source: 'latest',
          commit: null, commitShort: null, commitMessage: null,
          author: null, authorEmail: null, timestamp: null, branch: null, commitUrl: null,
        });
      }
    }
  }

  return findings;
}

module.exports = { scanContent, shouldSkipPath };
