require('dotenv').config();
const express  = require('express');
const path     = require('path');
const crypto   = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ── Supabase clients ─────────────────────────────────
// Service role for server-side operations (bypasses RLS)
const supabaseService = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY   // service_role key — never expose to client
);

// Anon key for auth operations
const supabaseAnon = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ── Helper: generate API key ─────────────────────────
function generateApiKey() {
  return 'dm_sk_' + crypto.randomBytes(24).toString('hex');
}

// ── Helper: generate agent ID ────────────────────────
function generateAgentId() {
  return 'dm_' + crypto.randomBytes(8).toString('hex');
}

// ── Middleware: validate Bearer token ────────────────
async function requireApiKey(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing API key. Use Authorization: Bearer dm_sk_...' });
  }

  const apiKey = auth.replace('Bearer ', '').trim();

  const { data, error } = await supabaseService
    .rpc('get_agent_by_api_key', { p_api_key: apiKey });

  if (error || !data || data.length === 0) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  req.agent = data[0]; // { agent_id, agent_name, user_id, public_key }
  next();
}

// ── Middleware: validate Supabase JWT (dashboard calls) ──
async function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const token = auth.replace('Bearer ', '').trim();
  const { data: { user }, error } = await supabaseAnon.auth.getUser(token);

  if (error || !user) {
    return res.status(401).json({ error: 'Invalid session' });
  }

  req.user = user;
  next();
}

// ═══════════════════════════════════════════════════
// PUBLIC ROUTES (no auth)
// ═══════════════════════════════════════════════════

// ── GET / ── serve homepage
// Handled by express.static above

// ── GET /login ── serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

// ── GET /signup ── serve signup page  
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/signup.html'));
});

// ── GET /dashboard ── serve dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

// ═══════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════

// ── POST /auth/signup ────────────────────────────────
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const { data, error } = await supabaseAnon.auth.signUp({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({ user: data.user, session: data.session });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/login ─────────────────────────────────
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const { data, error } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({ user: data.user, session: data.session });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/github ─── redirect to GitHub OAuth ──
app.get('/auth/github', async (req, res) => {
  try {
    const { data, error } = await supabaseAnon.auth.signInWithOAuth({
      provider: 'github',
      options: { redirectTo: `${process.env.APP_URL}/dashboard` }
    });
    if (error) return res.status(400).json({ error: error.message });
    res.redirect(data.url);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/logout ────────────────────────────────
app.post('/auth/logout', async (req, res) => {
  try {
    const auth = req.headers['authorization'];
    if (auth) {
      const token = auth.replace('Bearer ', '');
      await supabaseAnon.auth.admin.signOut(token);
    }
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true }); // always succeed
  }
});

// ═══════════════════════════════════════════════════
// DASHBOARD ROUTES (requires user session)
// ═══════════════════════════════════════════════════

// ── POST /dashboard/agents ── create a new agent ────
app.post('/dashboard/agents', requireAuth, async (req, res) => {
  try {
    const { agentName } = req.body;
    if (!agentName) return res.status(400).json({ error: 'agentName required' });

    const agentId = generateAgentId();
    const apiKey  = generateApiKey();

    const { data, error } = await supabaseService
      .from('agents')
      .insert({
        agent_id:   agentId,
        agent_name: agentName,
        user_id:    req.user.id,
        api_key:    apiKey,
      })
      .select()
      .single();

    if (error) throw error;

    res.json({
      agentId:   data.agent_id,
      agentName: data.agent_name,
      apiKey:    data.api_key,
      createdAt: data.created_at,
      note: 'Save your API key — use it as: Authorization: Bearer <apiKey>',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /dashboard/agents ── list user's agents ─────
app.get('/dashboard/agents', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, api_key, created_at, last_active')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data.map(a => ({
      agentId:    a.agent_id,
      agentName:  a.agent_name,
      apiKey:     a.api_key,
      createdAt:  a.created_at,
      lastActive: a.last_active,
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /dashboard/agents/:id ── delete agent ────
app.delete('/dashboard/agents/:agentId', requireAuth, async (req, res) => {
  try {
    const { agentId } = req.params;
    const { error } = await supabaseService
      .from('agents')
      .delete()
      .eq('agent_id', agentId)
      .eq('user_id', req.user.id);

    if (error) throw error;
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /dashboard/agents/:id/rotate ── new API key ─
app.post('/dashboard/agents/:agentId/rotate', requireAuth, async (req, res) => {
  try {
    const { agentId } = req.params;
    const newKey = generateApiKey();

    const { data, error } = await supabaseService
      .from('agents')
      .update({ api_key: newKey })
      .eq('agent_id', agentId)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) throw error;
    res.json({ agentId, apiKey: newKey, rotated: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /dashboard/commits ── user's commit history ─
app.get('/dashboard/commits', requireAuth, async (req, res) => {
  try {
    // Get all agent IDs for this user
    const { data: userAgents } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name')
      .eq('user_id', req.user.id);

    const agentIds = (userAgents || []).map(a => a.agent_id);
    const agentMap = Object.fromEntries((userAgents || []).map(a => [a.agent_id, a.agent_name]));

    if (agentIds.length === 0) return res.json([]);

    const { data, error } = await supabaseService
      .from('commits')
      .select('*')
      .or(`from_agent.in.(${agentIds.map(id=>`"${id}"`).join(',')}),to_agent.in.(${agentIds.map(id=>`"${id}"`).join(',')})`)
      .order('timestamp', { ascending: false })
      .limit(50);

    if (error) throw error;

    res.json((data || []).map(c => ({
      id:        c.id,
      from:      agentMap[c.from_agent] || c.from_agent,
      fromId:    c.from_agent,
      to:        agentMap[c.to_agent]   || c.to_agent,
      toId:      c.to_agent,
      verified:  c.verified,
      timestamp: c.timestamp,
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// AGENT API ROUTES (requires API key)
// ═══════════════════════════════════════════════════

// ── POST /api/commit ─────────────────────────────────
app.post('/api/commit', requireApiKey, async (req, res) => {
  try {
    const { toAgentId, context } = req.body;
    if (!toAgentId || !context) {
      return res.status(400).json({ error: 'toAgentId and context required' });
    }

    // Verify recipient exists
    const { data: toAgent } = await supabaseService
      .from('agents')
      .select('agent_id')
      .eq('agent_id', toAgentId)
      .single();

    if (!toAgent) return res.status(404).json({ error: `Agent ${toAgentId} not found` });

    const commitId  = 'commit_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
    const timestamp = new Date().toISOString();

    const { error } = await supabaseService
      .from('commits')
      .insert({
        id:                  commitId,
        from_agent:          req.agent.agent_id,
        to_agent:            toAgentId,
        context,
        verified:            true,
        verification_reason: 'API key authenticated',
        timestamp,
      });

    if (error) throw error;

    // Update last_active
    await supabaseService
      .from('agents')
      .update({ last_active: timestamp })
      .eq('agent_id', req.agent.agent_id);

    res.json({
      commitId,
      from:      req.agent.agent_name,
      to:        toAgentId,
      verified:  true,
      timestamp,
    });
  } catch (err) {
    console.error('commit error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/pull ─────────────────────────────────────
app.get('/api/pull', requireApiKey, async (req, res) => {
  try {
    const { data, error } = await supabaseService
      .from('commits')
      .select('*')
      .eq('to_agent', req.agent.agent_id)
      .eq('verified', true)
      .order('timestamp', { ascending: false });

    if (error) throw error;

    res.json({
      agentId:   req.agent.agent_id,
      agentName: req.agent.agent_name,
      commits:   (data || []).map(c => ({
        commitId:  c.id,
        from:      c.from_agent,
        context:   c.context,
        timestamp: c.timestamp,
        verified:  c.verified,
      })),
      count: (data || []).length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/me ── who am I? ──────────────────────────
app.get('/api/me', requireApiKey, async (req, res) => {
  res.json({
    agentId:   req.agent.agent_id,
    agentName: req.agent.agent_name,
  });
});

// ═══════════════════════════════════════════════════
// PUBLIC NETWORK STATS (no auth — for homepage)
// ═══════════════════════════════════════════════════

app.get('/api/stats', async (req, res) => {
  try {
    const [agentsRes, commitsRes] = await Promise.all([
      supabaseService.from('agents').select('agent_id', { count: 'exact', head: true }),
      supabaseService.from('commits').select('id, verified', { count: 'exact' }),
    ]);

    const commits   = commitsRes.data || [];
    const verified  = commits.filter(c => c.verified).length;
    const rejected  = commits.filter(c => !c.verified).length;

    res.json({
      agents:   agentsRes.count  || 0,
      commits:  commitsRes.count || 0,
      verified,
      rejected,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🌑 DarkMatter running on http://localhost:${PORT}\n`);
});

module.exports = app;
