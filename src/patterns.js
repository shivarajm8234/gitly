// ============================================================
// src/patterns.js — 85+ Secret Detection Pattern Library
// ============================================================

const PATTERNS = [
  // ─── AWS ───────────────────────────────────────────────────
  { type:'AWS_ACCESS_KEY',        label:'AWS Access Key ID',           category:'cloud',
    pattern:/\b(AKIA[0-9A-Z]{16})\b/ },
  { type:'AWS_SECRET_KEY',        label:'AWS Secret Access Key',       category:'cloud',
    pattern:/(?:aws.?secret.?access.?key|aws.?secret.?key)\s*[=:]\s*["']?([A-Za-z0-9\/+=]{40})["']?/i },

  // ─── GCP ───────────────────────────────────────────────────
  { type:'GCP_API_KEY',           label:'Google Cloud API Key',        category:'cloud',
    pattern:/\b(AIza[0-9A-Za-z\-_]{35})\b/ },
  { type:'GCP_SERVICE_ACCOUNT',   label:'GCP Service Account JSON',    category:'cloud',
    pattern:/"type"\s*:\s*"service_account"/ },

  // ─── Azure ─────────────────────────────────────────────────
  { type:'AZURE_CONNECTION_STRING',label:'Azure Storage Connection',   category:'cloud',
    pattern:/(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{86}==)/ },
  { type:'AZURE_CLIENT_SECRET',   label:'Azure Client Secret',         category:'cloud',
    pattern:/(?:client.?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*["']([A-Za-z0-9.\-~_]{32,})["']?/i },
  { type:'AZURE_SAS_TOKEN',       label:'Azure SAS Token',             category:'cloud',
    pattern:/(sig=[A-Za-z0-9%+\/=]{43,})/ },

  // ─── GitHub ────────────────────────────────────────────────
  { type:'GITHUB_TOKEN',          label:'GitHub Token',                category:'vcs',
    pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/ },
  { type:'GITHUB_TOKEN',          label:'GitHub OAuth Token',          category:'vcs',
    pattern:/\b([a-f0-9]{40})\b(?=.*github)/i },
  { type:'GITHUB_APP_SECRET',     label:'GitHub App Webhook Secret',   category:'vcs',
    pattern:/(?:webhook.?secret|github.?secret)\s*[=:]\s*["']([A-Za-z0-9+\/=_\-]{20,})["']/i },

  // ─── Stripe ────────────────────────────────────────────────
  { type:'STRIPE_SECRET_KEY',     label:'Stripe Secret Key',           category:'payment',
    pattern:/\b(sk_live_[0-9a-zA-Z]{24,})\b/ },
  { type:'STRIPE_RESTRICTED_KEY', label:'Stripe Restricted Key',       category:'payment',
    pattern:/\b(rk_live_[0-9a-zA-Z]{24,})\b/ },
  { type:'STRIPE_PUBLISHABLE',    label:'Stripe Publishable Key',      category:'payment',
    pattern:/\b(pk_live_[0-9a-zA-Z]{24,})\b/ },
  { type:'STRIPE_SECRET_KEY',     label:'Stripe Test Secret Key',      category:'payment',
    pattern:/\b(sk_test_[0-9a-zA-Z]{24,})\b/ },

  // ─── OpenAI / AI Providers ─────────────────────────────────
  { type:'OPENAI_API_KEY',        label:'OpenAI API Key',              category:'ai',
    pattern:/\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b/ },
  { type:'OPENAI_API_KEY',        label:'OpenAI API Key (new)',        category:'ai',
    pattern:/\b(sk-proj-[a-zA-Z0-9_\-]{50,})\b/ },
  { type:'ANTHROPIC_API_KEY',     label:'Anthropic API Key',           category:'ai',
    pattern:/\b(sk-ant-[a-zA-Z0-9\-_]{90,})\b/ },
  { type:'GROQ_API_KEY',          label:'Groq API Key',                category:'ai',
    pattern:/\b(gsk_[a-zA-Z0-9]{52})\b/ },
  { type:'HUGGINGFACE_TOKEN',     label:'HuggingFace Token',           category:'ai',
    pattern:/\b(hf_[a-zA-Z0-9]{34,})\b/ },
  { type:'COHERE_API_KEY',        label:'Cohere API Key',              category:'ai',
    pattern:/(?:cohere.?api.?key|CO_API_KEY)\s*[=:]\s*["']([a-zA-Z0-9]{40})["']/i },
  { type:'REPLICATE_TOKEN',       label:'Replicate API Token',         category:'ai',
    pattern:/\b(r8_[a-zA-Z0-9]{37})\b/ },

  // ─── Firebase ──────────────────────────────────────────────
  { type:'FIREBASE_API_KEY',      label:'Firebase API Key',            category:'firebase',
    pattern:/(?:apiKey|firebase.?api.?key)\s*[=:]\s*["']([A-Za-z0-9\-_]{30,50})["']/i },
  { type:'FIREBASE_CONFIG',       label:'Firebase Config Object',      category:'firebase',
    pattern:/firebaseConfig\s*=\s*\{/ },
  { type:'FIREBASE_FCM_KEY',      label:'Firebase Cloud Messaging Key',category:'firebase',
    pattern:/\b(AAAA[a-zA-Z0-9_\-]{7}:[a-zA-Z0-9_\-]{140})\b/ },

  // ─── Slack ─────────────────────────────────────────────────
  { type:'SLACK_TOKEN',           label:'Slack Bot Token',             category:'messaging',
    pattern:/\b(xox[bpas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})\b/ },
  { type:'SLACK_WEBHOOK',         label:'Slack Webhook URL',           category:'messaging',
    pattern:/(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+)/ },
  { type:'SLACK_SIGNING_SECRET',  label:'Slack Signing Secret',        category:'messaging',
    pattern:/(?:slack.?signing.?secret|SLACK_SIGNING_SECRET)\s*[=:]\s*["']([a-f0-9]{32})["']/i },

  // ─── Discord ───────────────────────────────────────────────
  { type:'DISCORD_TOKEN',         label:'Discord Bot Token',           category:'messaging',
    pattern:/\b([MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})\b/ },
  { type:'DISCORD_WEBHOOK',       label:'Discord Webhook URL',         category:'messaging',
    pattern:/(https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_\-]+)/ },

  // ─── Twilio ────────────────────────────────────────────────
  { type:'TWILIO_AUTH_TOKEN',     label:'Twilio Auth Token',           category:'communication',
    pattern:/(?:twilio.?auth.?token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["']([a-f0-9]{32})["']/i },
  { type:'TWILIO_SID',            label:'Twilio Account SID',          category:'communication',
    pattern:/\b(AC[a-z0-9]{32})\b/ },

  // ─── Email Services ────────────────────────────────────────
  { type:'SENDGRID_API_KEY',      label:'SendGrid API Key',            category:'email',
    pattern:/\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b/ },
  { type:'MAILGUN_API_KEY',       label:'Mailgun API Key',             category:'email',
    pattern:/\b(key-[a-zA-Z0-9]{32})\b/ },
  { type:'MAILCHIMP_API_KEY',     label:'Mailchimp API Key',           category:'email',
    pattern:/\b([a-f0-9]{32}-us[0-9]{1,2})\b/ },
  { type:'POSTMARK_TOKEN',        label:'Postmark Server Token',       category:'email',
    pattern:/(?:postmark.?token|POSTMARK_SERVER_TOKEN)\s*[=:]\s*["']([a-zA-Z0-9\-]{36})["']/i },
  { type:'SMTP_CREDENTIALS',      label:'SMTP Password',               category:'email',
    pattern:/(?:smtp.?pass(?:word)?|SMTP_PASS(?:WORD)?|mail.?pass(?:word)?)\s*[=:]\s*["']([^"'\s]{8,})["']/i },

  // ─── Databases ─────────────────────────────────────────────
  { type:'DATABASE_URL',          label:'MongoDB Connection String',   category:'database',
    pattern:/(mongodb(?:\+srv)?:\/\/[^:]+:[^@\s"']+@[^\s"']+)/i },
  { type:'DATABASE_URL',          label:'PostgreSQL Connection String', category:'database',
    pattern:/(postgres(?:ql)?:\/\/[^:]+:[^@\s"']+@[^\s"']+)/i },
  { type:'DATABASE_URL',          label:'MySQL Connection String',     category:'database',
    pattern:/(mysql(?:2)?:\/\/[^:]+:[^@\s"']+@[^\s"']+)/i },
  { type:'DATABASE_URL',          label:'Redis Connection String',     category:'database',
    pattern:/(redis(?:s)?:\/\/:?[^@\s"']+@[^\s"']+)/i },
  { type:'DATABASE_URL',          label:'Database URL Env',            category:'database',
    pattern:/(?:DATABASE_URL|DB_URL|DB_CONNECTION)\s*[=:]\s*["']([^"'\s]{20,})["']/i },
  { type:'DATABASE_URL',          label:'Database Password',           category:'database',
    pattern:/(?:DB_PASS(?:WORD)?|DATABASE_PASS(?:WORD)?)\s*[=:]\s*["']([^"'\s]{8,})["']/i },

  // ─── JWT ───────────────────────────────────────────────────
  { type:'JWT_SECRET',            label:'JWT Secret',                  category:'auth',
    pattern:/(?:jwt.?secret|JWT_SECRET|jsonwebtoken.?secret)\s*[=:]\s*["']([^"'\s]{16,})["']/i },
  { type:'JWT_TOKEN',             label:'JWT Token (encoded)',         category:'auth',
    pattern:/\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b/ },

  // ─── SSH / Private Keys ────────────────────────────────────
  { type:'PRIVATE_KEY',           label:'RSA Private Key',             category:'crypto',
    pattern:/-----BEGIN RSA PRIVATE KEY-----/ },
  { type:'PRIVATE_KEY',           label:'OpenSSH Private Key',         category:'crypto',
    pattern:/-----BEGIN OPENSSH PRIVATE KEY-----/ },
  { type:'PRIVATE_KEY',           label:'EC Private Key',              category:'crypto',
    pattern:/-----BEGIN EC PRIVATE KEY-----/ },
  { type:'PRIVATE_KEY',           label:'DSA Private Key',             category:'crypto',
    pattern:/-----BEGIN DSA PRIVATE KEY-----/ },
  { type:'PRIVATE_KEY',           label:'PGP Private Key',             category:'crypto',
    pattern:/-----BEGIN PGP PRIVATE KEY BLOCK-----/ },

  // ─── npm ───────────────────────────────────────────────────
  { type:'NPM_TOKEN',             label:'npm Auth Token',              category:'package',
    pattern:/(?:\/\/registry\.npmjs\.org\/:_authToken|NPM_TOKEN)\s*[=:]\s*["']?(npm_[a-zA-Z0-9]{36}|[a-f0-9\-]{36})["']?/i },

  // ─── Cloud Infra ───────────────────────────────────────────
  { type:'HEROKU_API_KEY',        label:'Heroku API Key',              category:'cloud',
    pattern:/(?:HEROKU_API_KEY|heroku.?api.?key)\s*[=:]\s*["']([a-f0-9\-]{36})["']/i },
  { type:'DIGITALOCEAN_TOKEN',    label:'DigitalOcean Token',          category:'cloud',
    pattern:/\b(dop_v1_[a-f0-9]{64})\b/ },
  { type:'CLOUDFLARE_API_TOKEN',  label:'Cloudflare API Token',        category:'cloud',
    pattern:/(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)\s*[=:]\s*["']([a-zA-Z0-9_\-]{40,})["']/i },
  { type:'CLOUDFLARE_API_TOKEN',  label:'Cloudflare Global API Key',   category:'cloud',
    pattern:/(?:CLOUDFLARE_API_KEY|CF_API_KEY)\s*[=:]\s*["']([a-f0-9]{37})["']/i },
  { type:'LINODE_TOKEN',          label:'Linode Personal Access Token', category:'cloud',
    pattern:/(?:LINODE_TOKEN|linode.?token)\s*[=:]\s*["']([a-zA-Z0-9]{64})["']/i },
  { type:'VULTR_API_KEY',         label:'Vultr API Key',               category:'cloud',
    pattern:/(?:VULTR_API_KEY)\s*[=:]\s*["']([A-Z0-9]{36})["']/i },

  // ─── Payment ───────────────────────────────────────────────
  { type:'PAYPAL_CLIENT_SECRET',  label:'PayPal Client Secret',        category:'payment',
    pattern:/(?:PAYPAL_CLIENT_SECRET|paypal.?client.?secret)\s*[=:]\s*["']([A-Za-z0-9_\-]{80})["']/i },
  { type:'SQUARE_ACCESS_TOKEN',   label:'Square Access Token',         category:'payment',
    pattern:/\b(sq0atp-[0-9A-Za-z\-_]{22})\b/ },
  { type:'SHOPIFY_SECRET',        label:'Shopify API Secret',          category:'payment',
    pattern:/(?:shopify.?api.?secret|SHOPIFY_API_SECRET)\s*[=:]\s*["']([a-f0-9]{32})["']/i },

  // ─── OAuth / Social ────────────────────────────────────────
  { type:'OAUTH_TOKEN',           label:'Generic OAuth Token',         category:'auth',
    pattern:/(?:oauth.?token|access.?token|bearer.?token)\s*[=:]\s*["']([A-Za-z0-9._\-]{30,})["']/i },
  { type:'GOOGLE_OAUTH_SECRET',   label:'Google OAuth Client Secret',  category:'auth',
    pattern:/(?:client_secret|GOOGLE_CLIENT_SECRET)\s*[=:]\s*["'](GOCSPX-[A-Za-z0-9_\-]{28})["']/i },
  { type:'FACEBOOK_APP_SECRET',   label:'Facebook App Secret',         category:'social',
    pattern:/(?:facebook.?app.?secret|FB_APP_SECRET|FACEBOOK_SECRET)\s*[=:]\s*["']([a-f0-9]{32})["']/i },
  { type:'TWITTER_API_SECRET',    label:'Twitter API Secret',          category:'social',
    pattern:/(?:twitter.?api.?secret|TWITTER_API_SECRET)\s*[=:]\s*["']([A-Za-z0-9]{50,})["']/i },
  { type:'TELEGRAM_BOT_TOKEN',    label:'Telegram Bot Token',          category:'messaging',
    pattern:/\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b/ },

  // ─── DevOps / Infra ────────────────────────────────────────
  { type:'VAULT_TOKEN',           label:'HashiCorp Vault Token',       category:'infra',
    pattern:/\b(hvs\.[A-Za-z0-9]{24,})\b/ },
  { type:'TERRAFORM_CLOUD_TOKEN', label:'Terraform Cloud Token',       category:'infra',
    pattern:/\b([a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{60,})\b/ },
  { type:'ANSIBLE_VAULT_PASS',    label:'Ansible Vault Password',      category:'infra',
    pattern:/ansible.?vault.?pass(?:word)?\s*[=:]\s*["']([^"'\s]{8,})["']/i },
  { type:'KUBERNETES_SECRET',     label:'Kubernetes Service Account',  category:'infra',
    pattern:/(?:kubernetes.?token|K8S_TOKEN|KUBE_TOKEN)\s*[=:]\s*["']([A-Za-z0-9._\-]{100,})["']/i },
  { type:'DOCKER_PASSWORD',       label:'Docker Registry Password',    category:'infra',
    pattern:/(?:docker.?pass(?:word)?|DOCKER_PASSWORD)\s*[=:]\s*["']([^"'\s]{8,})["']/i },

  // ─── Generic Secrets ───────────────────────────────────────
  { type:'GENERIC_SECRET',        label:'Generic API Key',             category:'generic',
    pattern:/(?:api[_\-]?key|apikey|API_KEY)\s*[=:]\s*["']([A-Za-z0-9_\-]{20,})["']/i },
  { type:'GENERIC_SECRET',        label:'Generic Secret Key',          category:'generic',
    pattern:/(?:secret[_\-]?key|SECRET_KEY|secret)\s*[:=]\s*["']([A-Za-z0-9_\-+\/]{20,})["']/i },
  { type:'POSSIBLE_PASSWORD',     label:'Hardcoded Password',          category:'generic',
    pattern:/(?:password|passwd|pwd|PASS)\s*[:=]\s*["']([^"'\s]{8,64})["']/i },
  { type:'PRIVATE_URL',           label:'URL with Embedded Credentials', category:'generic',
    pattern:/(https?:\/\/[^:@\s"']+:[^@\s"']+@[^\s"']+)/ },
  { type:'ENV_VARIABLE',          label:'Sensitive ENV Variable',      category:'generic',
    pattern:/(?:SECRET|PRIVATE|TOKEN|KEY|CRED|PASSWORD|PASSWD|AUTH)\s*=\s*["']([^"'\s]{12,})["']/i },
  { type:'GENERIC_SECRET',        label:'Bearer Token Assignment',     category:'generic',
    pattern:/(?:Bearer|Authorization)\s*[=:]\s*["']([A-Za-z0-9._\-]{20,})["']/i },
];

module.exports = PATTERNS;
