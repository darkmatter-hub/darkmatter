
'use strict';

async function getStatus() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, resolve);
  });
}

async function init() {
  const status = await getStatus();

  if (!status?.signedIn) {
    // Not signed in — show sign in state
    document.getElementById('signin-state').style.display = '';
    document.getElementById('signedin-state').style.display = 'none';
    document.getElementById('status-dot').className = 'status-dot inactive';
    return;
  }

  // Signed in
  document.getElementById('signin-state').style.display = 'none';
  document.getElementById('signedin-state').style.display = '';

  const email = status.email || '';
  document.getElementById('avatar').textContent = (email[0] || '?').toUpperCase();
  document.getElementById('user-email').textContent = email;

  if (status.workspace) {
    const ws = document.getElementById('user-workspace');
    ws.textContent = status.workspace;
    ws.style.display = '';
  }

  // Status dot
  const dot = document.getElementById('status-dot');
  dot.className = status.pending > 0 ? 'status-dot pending' : 'status-dot active';

  // Stats
  document.getElementById('stat-pending').textContent = status.pending || '0';

  // Pending notice
  if (status.pending > 0) {
    document.getElementById('pending-notice').style.display = '';
    document.getElementById('pending-notice').textContent =
      `Saving ${status.pending} conversation${status.pending !== 1 ? 's' : ''}…`;
  }

  // Toggle state
  const toggle = document.getElementById('enabled-toggle');
  toggle.checked = status.enabled !== false;
  toggle.addEventListener('change', () => {
    chrome.runtime.sendMessage({ type: 'TOGGLE_ENABLED', enabled: toggle.checked });
    dot.className = toggle.checked ? 'status-dot active' : 'status-dot inactive';
  });

  // Platform indicators — greyed out if recording disabled
  const plats = ['claude','chatgpt','grok','gemini','perplexity'];
  plats.forEach(p => {
    const el = document.getElementById('p-' + p);
    if (!status.enabled) { el.className = 'plat-status off'; el.textContent = '○ Paused'; }
  });

  // Load today/week stats
  loadStats();

  // Sign out
  document.getElementById('signout-btn').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'SIGN_OUT' });
    location.reload();
  });
}

async function loadStats() {
  try {
    const s = await chrome.storage.local.get(['dmAuth']);
    if (!s.dmAuth?.api_key) return;

    const r = await fetch('https://darkmatterhub.ai/api/stats', {
      headers: { 'Authorization': `Bearer ${s.dmAuth.api_key}` }
    });
    if (!r.ok) return;
    const d = await r.json();
    if (d.today !== undefined)  document.getElementById('stat-today').textContent = d.today;
    if (d.week !== undefined)   document.getElementById('stat-week').textContent = d.week;
  } catch(e) {}
}

// ── Auth from login redirect ──────────────────────────────────────────
// The extension login flow: user signs in at darkmatterhub.ai/login?ext=1
// After login, the page posts a message to the extension with auth data
chrome.storage.onChanged.addListener((changes) => {
  if (changes.dmAuth) init(); // re-render when auth changes
});

init();
