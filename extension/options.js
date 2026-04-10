
'use strict';

async function init() {
  const { dmAuth } = await chrome.storage.local.get('dmAuth');
  if (dmAuth?.email) {
    document.getElementById('current-account-wrap').style.display = '';
    document.getElementById('ca-icon').textContent = (dmAuth.email[0]||'?').toUpperCase();
    document.getElementById('ca-email').textContent = dmAuth.email;
    if (dmAuth.workspace_name) {
      const ws = document.getElementById('ca-ws');
      ws.textContent = dmAuth.workspace_name;
      ws.style.display = '';
    }
  }
}

document.getElementById('join-btn').addEventListener('click', async () => {
  const raw = document.getElementById('join-code-inp').value.trim();
  const msg  = document.getElementById('join-msg');
  if (!raw) { msg.className='msg err'; msg.textContent='Enter a join code or invite link.'; return; }

  const btn = document.getElementById('join-btn');
  btn.disabled = true; btn.textContent = 'Joining…';
  msg.textContent = '';

  const { dmAuth } = await chrome.storage.local.get('dmAuth');
  if (!dmAuth?.session_token) {
    msg.className='msg err';
    msg.textContent='Sign in first, then join a workspace.';
    btn.disabled = false; btn.textContent = 'Join workspace';
    return;
  }

  // Extract token from invite URL or use as join code directly
  let payload = {};
  if (raw.startsWith('http')) {
    const url = new URL(raw);
    const token = url.searchParams.get('token');
    payload = token ? { token } : { joinCode: raw.toUpperCase() };
  } else {
    payload = { joinCode: raw.toUpperCase() };
  }

  try {
    const r = await fetch('https://darkmatterhub.ai/api/workspace/join', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${dmAuth.session_token}` },
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (!r.ok) { msg.className='msg err'; msg.textContent = d.error || 'Join failed.'; return; }

    // Save updated auth with workspace info + new agent/key
    const updated = { ...dmAuth, agent_id: d.agentId, api_key: d.apiKey, workspace_name: d.workspace?.name };
    await chrome.storage.local.set({ dmAuth: updated });
    await chrome.runtime.sendMessage({ type: 'SET_AUTH', auth: updated });

    msg.className='msg ok';
    msg.textContent = `✓ Joined ${d.workspace?.name}. You're now connected to your team workspace.`;
    document.getElementById('ca-ws').textContent = d.workspace?.name;
    document.getElementById('ca-ws').style.display = '';
  } catch(e) {
    msg.className='msg err'; msg.textContent = 'Connection error. Check your internet and try again.';
  } finally {
    btn.disabled=false; btn.textContent='Join workspace';
  }
}); 

// Handle Enter key
document.getElementById('join-code-inp').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('join-btn').click();
});

init();
