// ============================================================
// src/remediator.js — Remediation Suggestion Generator
// ============================================================

const PROVIDER_REVOCATION = {
  AWS_ACCESS_KEY:       { name: 'AWS',        url: 'https://console.aws.amazon.com/iam/home#/security_credentials', action: 'Deactivate access key in IAM console' },
  AWS_SECRET_KEY:       { name: 'AWS',        url: 'https://console.aws.amazon.com/iam/home#/security_credentials', action: 'Rotate access keys in IAM console' },
  GCP_API_KEY:          { name: 'Google Cloud', url: 'https://console.cloud.google.com/apis/credentials', action: 'Delete or restrict this API key' },
  GCP_SERVICE_ACCOUNT:  { name: 'Google Cloud', url: 'https://console.cloud.google.com/iam-admin/serviceaccounts', action: 'Rotate service account credentials' },
  AZURE_CLIENT_SECRET:  { name: 'Azure',      url: 'https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps', action: 'Regenerate client secret in Azure AD' },
  STRIPE_SECRET_KEY:    { name: 'Stripe',     url: 'https://dashboard.stripe.com/apikeys', action: 'Roll secret key in Stripe Dashboard' },
  STRIPE_RESTRICTED_KEY:{ name: 'Stripe',     url: 'https://dashboard.stripe.com/apikeys', action: 'Delete and recreate restricted key' },
  OPENAI_API_KEY:       { name: 'OpenAI',     url: 'https://platform.openai.com/api-keys', action: 'Revoke API key in OpenAI platform' },
  ANTHROPIC_API_KEY:    { name: 'Anthropic',  url: 'https://console.anthropic.com/settings/keys', action: 'Delete API key in Anthropic console' },
  GROQ_API_KEY:         { name: 'Groq',       url: 'https://console.groq.com/keys', action: 'Delete API key in Groq console' },
  HUGGINGFACE_TOKEN:    { name: 'HuggingFace', url: 'https://huggingface.co/settings/tokens', action: 'Revoke access token' },
  GITHUB_TOKEN:         { name: 'GitHub',     url: 'https://github.com/settings/tokens', action: 'Delete personal access token' },
  GITHUB_APP_SECRET:    { name: 'GitHub',     url: 'https://github.com/settings/apps', action: 'Reset webhook secret on GitHub App' },
  SLACK_TOKEN:          { name: 'Slack',      url: 'https://api.slack.com/apps', action: 'Revoke token in Slack App settings' },
  SLACK_WEBHOOK:        { name: 'Slack',      url: 'https://api.slack.com/apps', action: 'Regenerate incoming webhook URL' },
  DISCORD_TOKEN:        { name: 'Discord',    url: 'https://discord.com/developers/applications', action: 'Reset bot token in Developer Portal' },
  DISCORD_WEBHOOK:      { name: 'Discord',    url: 'https://discord.com/developers/applications', action: 'Delete and recreate webhook' },
  TWILIO_AUTH_TOKEN:    { name: 'Twilio',     url: 'https://www.twilio.com/console', action: 'Rotate auth token in Twilio Console' },
  SENDGRID_API_KEY:     { name: 'SendGrid',   url: 'https://app.sendgrid.com/settings/api_keys', action: 'Delete and recreate API key' },
  FIREBASE_API_KEY:     { name: 'Firebase',   url: 'https://console.firebase.google.com', action: 'Restrict API key in Firebase/GCP console' },
  JWT_SECRET:           { name: 'JWT',        url: null, action: 'Rotate JWT secret and invalidate all existing tokens' },
  PRIVATE_KEY:          { name: 'SSH/TLS',    url: null, action: 'Revoke this key pair and generate a new one' },
  NPM_TOKEN:            { name: 'npm',        url: 'https://www.npmjs.com/settings/tokens', action: 'Revoke token in npm settings' },
  MAILGUN_API_KEY:      { name: 'Mailgun',    url: 'https://app.mailgun.com/app/account/security/api_keys', action: 'Revoke API key' },
  CLOUDFLARE_API_TOKEN: { name: 'Cloudflare', url: 'https://dash.cloudflare.com/profile/api-tokens', action: 'Delete API token' },
  HEROKU_API_KEY:       { name: 'Heroku',     url: 'https://dashboard.heroku.com/account', action: 'Regenerate API key in Account settings' },
  DIGITALOCEAN_TOKEN:   { name: 'DigitalOcean', url: 'https://cloud.digitalocean.com/account/api/tokens', action: 'Delete personal access token' },
  DATABASE_URL:         { name: 'Database',   url: null, action: 'Rotate database credentials immediately' },
  GENERIC_SECRET:       { name: 'Generic',    url: null, action: 'Rotate this credential and audit its usage' },
};

const GENERAL_STEPS = [
  'Remove the secret from source code immediately',
  'Rotate / revoke the exposed credential as soon as possible',
  'Audit git history and purge with `git filter-repo` or BFG Repo Cleaner',
  'Move the secret to a secrets manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager)',
  'Use environment variables (.env) with a secure injection mechanism at runtime',
  'Add the secret pattern to a pre-commit hook (e.g., detect-secrets, gitleaks)',
  'Enable branch protection and require code reviews to prevent future leaks',
];

/**
 * Generate remediation guidance for a finding.
 */
function getRemediation(type) {
  const provider = PROVIDER_REVOCATION[type] || PROVIDER_REVOCATION['GENERIC_SECRET'];
  const steps = [...GENERAL_STEPS];

  const specific = {
    action: provider.action,
    provider: provider.name,
    revocationUrl: provider.url,
    steps,
    urgency: isUrgent(type) ? 'IMMEDIATE' : 'HIGH',
  };

  return specific;
}

function isUrgent(type) {
  const urgent = [
    'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'STRIPE_SECRET_KEY',
    'GCP_SERVICE_ACCOUNT', 'PRIVATE_KEY', 'DATABASE_URL',
    'GITHUB_TOKEN', 'OPENAI_API_KEY', 'AZURE_CLIENT_SECRET',
  ];
  return urgent.includes(type);
}

module.exports = { getRemediation };
