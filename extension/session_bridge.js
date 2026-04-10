
/**
 * Session bridge — runs on darkmatterhub.ai after login
 * Passes the user's session to the DarkMatter extension.
 * Only runs when ?ext=1 query param is present.
 */
(async function() {
  if (!location.search.includes('ext=1') && !location.pathname.includes('/ext/callback')) return;

  // Wait for session to be available
  let attempts = 0;
  const tryBridge = async () => {
    attempts++;
    const raw = localStorage.getItem('dm_session');
    if (!raw && attempts < 20) { setTimeout(tryBridge, 500); return; }
    if (!raw) return;

    const session = JSON.parse(raw);
    if (!session?.access_token || !session?.user?.email) {
      if (attempts < 20) { setTimeout(tryBridge, 500); return; }
      return;
    }

    // Also get the first agent's API key for the extension
    let agentId = null, apiKey = null;
    try {
      const r = await fetch('/dashboard/agents', {
        headers: { 'Authorization': `Bearer ${session.access_token}` }
      });
      const agents = await r.json();
      if (agents[0]) { agentId = agents[0].agentId; apiKey = agents[0].apiKey; }
    } catch(e) {}

    // Check workspace membership
    let workspaceName = null;
    try {
      const wr = await fetch('/api/workspace', {
        headers: { 'Authorization': `Bearer ${session.access_token}` }
      });
      const wd = await wr.json();
      if (wd.workspace?.name) workspaceName = wd.workspace.name;
    } catch(e) {}

    const auth = {
      email:          session.user.email,
      session_token:  session.access_token,
      agent_id:       agentId,
      api_key:        apiKey,
      workspace_name: workspaceName,
    };

    // Send to extension via custom event
    window.dispatchEvent(new CustomEvent('dm_auth', { detail: auth }));

    // Extension listens for this event in content script
    // (Extension ID is hardcoded in the ext content script listener)
  };

  tryBridge();
})();
