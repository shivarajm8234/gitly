// ============================================================
// public/js/auth.js — Simple server-side email auth gate
// ============================================================

const SESSION_KEY = 'gitly_auth_token';
const USER_KEY    = 'gitly_auth_email';

// ── Check existing session on load ─────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const token = localStorage.getItem(SESSION_KEY);
  const email = localStorage.getItem(USER_KEY);

  if (token) {
    // Verify token is still valid with server
    try {
      const res  = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const data = await res.json();
      if (data.ok) {
        showApp(email);
        return;
      }
    } catch {}
    // Token invalid — clear and show login
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(USER_KEY);
  }

  showLoginScreen();
});

// ── Sign in ─────────────────────────────────────────────────
async function signIn() {
  const emailInput = document.getElementById('auth-email');
  const email      = (emailInput?.value || '').trim().toLowerCase();

  if (!email) {
    setLoginError('Please enter your email address.');
    return;
  }

  setLoginLoading(true);

  try {
    const res  = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();

    if (data.ok) {
      localStorage.setItem(SESSION_KEY, data.token);
      localStorage.setItem(USER_KEY, data.email);
      showApp(data.email);
    } else {
      setLoginLoading(false);
      setLoginError(data.error || 'Access denied.');
    }
  } catch (err) {
    setLoginLoading(false);
    setLoginError('Could not reach server. Is it running?');
  }
}

// ── Sign out ────────────────────────────────────────────────
function signOut() {
  localStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(USER_KEY);
  showLoginScreen();
}

// ── Show login overlay ──────────────────────────────────────
function showLoginScreen() {
  document.getElementById('login-overlay').style.display = 'flex';
  document.getElementById('app-shell').style.display     = 'none';
  setLoginLoading(false);
  setLoginError('');
  const inp = document.getElementById('auth-email');
  if (inp) { inp.value = ''; setTimeout(() => inp.focus(), 100); }
}

// ── Show app ─────────────────────────────────────────────────
function showApp(email) {
  document.getElementById('login-overlay').style.display = 'none';
  document.getElementById('app-shell').style.display     = '';

  const badge = document.getElementById('user-badge');
  if (badge && email) {
    const initials = email[0].toUpperCase();
    badge.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;">
        <div style="width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:grid;place-items:center;font-size:.75rem;font-weight:700;color:#fff;flex-shrink:0;">${initials}</div>
        <span style="font-size:.78rem;color:#94a3b8;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${email}">${email}</span>
        <button id="logout-btn" title="Sign out"
          style="background:transparent;border:1px solid rgba(255,255,255,0.1);color:#64748b;border-radius:8px;padding:4px 9px;cursor:pointer;font-size:.72rem;transition:all .2s;"
          onmouseover="this.style.color='#f43f5e';this.style.borderColor='rgba(244,63,94,.4)';"
          onmouseout="this.style.color='#64748b';this.style.borderColor='rgba(255,255,255,0.1)';">
          ⏻
        </button>
      </div>`;
    document.getElementById('logout-btn').addEventListener('click', signOut);
  }
}

// ── UI helpers ───────────────────────────────────────────────
function setLoginLoading(loading) {
  const btn = document.getElementById('login-submit-btn');
  if (!btn) return;
  btn.disabled = loading;
  btn.innerHTML = loading
    ? `<span style="display:inline-block;animation:spin .8s linear infinite;">⟳</span> Checking...`
    : `<span>→</span> Continue`;
}

function setLoginError(msg) {
  const el = document.getElementById('login-message');
  if (!el) return;
  el.textContent    = msg;
  el.style.display  = msg ? '' : 'none';
  el.style.color    = '#f43f5e';
}
