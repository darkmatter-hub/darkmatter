require('dotenv').config();
const express   = require('express');
const path      = require('path');
const crypto    = require('crypto');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ── Security headers ─────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // disabled — inline scripts in HTML pages
  crossOriginEmbedderPolicy: false,
}));

// ── Rate limiters ────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Too many attempts — please try again in 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120,
  message: { error: 'Rate limit exceeded — max 120 requests per minute' },
  standardHeaders: true,
  legacyHeaders: false,
});

const feedbackLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { error: 'Too many submissions — please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json({ limit: '100kb' })); // prevent oversized payloads
app.use(express.static(path.join(__dirname, '../public')));

// ── Input sanitization helpers ───────────────────────
function sanitizeText(str, maxLen = 200) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ── SSRF protection for webhook URLs ─────────────────
function isValidWebhookUrl(url) {
  if (!url) return true; // null = remove webhook, that's fine
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    const host = parsed.hostname.toLowerCase();
    // Block internal/private addresses
    const blocked = [
      'localhost', '127.0.0.1', '0.0.0.0', '::1',
      '169.254.169.254', // AWS metadata
      '100.100.100.200', // Alibaba metadata
    ];
    if (blocked.includes(host)) return false;
    // Block private IP ranges
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2\d|3[01])\./,
      /^192\.168\./,
      /^fc00:/,
      /^fe80:/,
    ];
    if (privateRanges.some(r => r.test(host))) return false;
    return true;
  } catch {
    return false;
  }
}

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

// ── GET /demo ── live interactive demo (no login required)
app.get('/demo', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/demo.html'));
});

// ── GET /blog ── blog index
app.get('/blog', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/blog.html'));
});

// ── GET /blog/:slug ── individual blog posts
app.get('/blog/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/blog.html'));
});

// ═══════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════

// ── POST /auth/signup ────────────────────────────────
app.post('/auth/signup', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const { data, error } = await supabaseAnon.auth.signUp({ email, password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({ user: data.user, session: data.session });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/login ─────────────────────────────────
app.post('/auth/login', authLimiter, async (req, res) => {
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

// ── POST /auth/forgot-password ──────────────────────────
app.post('/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    await supabaseAnon.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.APP_URL}/reset-password`,
    });

    // Always return success to avoid email enumeration
    res.json({ success: true });
  } catch (err) {
    res.json({ success: true }); // still return success
  }
});

// ── GET /reset-password ── serve reset page ─────────
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/reset-password.html'));
});

// ── POST /auth/reset-password ────────────────────────
app.post('/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and password required' });

    // Exchange token for session, then update password
    const { data: { user }, error: sessionError } = await supabaseAnon.auth.getUser(token);
    if (sessionError || !user) return res.status(400).json({ error: 'Invalid or expired reset link' });

    const { error } = await supabaseAnon.auth.updateUser({ password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({ success: true });
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
    const agentName = sanitizeText(req.body.agentName, 100);
    if (!agentName) return res.status(400).json({ error: 'agentName required' });
    if (!/^[a-zA-Z0-9 _\-\.]+$/.test(agentName)) {
      return res.status(400).json({ error: 'Agent name can only contain letters, numbers, spaces, hyphens, underscores, and periods' });
    }

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
      .select('agent_id, agent_name, api_key, created_at, last_active, webhook_url, retention_days')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data.map(a => ({
      agentId:       a.agent_id,
      agentName:     a.agent_name,
      apiKey:        a.api_key,
      createdAt:     a.created_at,
      lastActive:    a.last_active,
      webhookUrl:    a.webhook_url    || null,
      retentionDays: a.retention_days ?? null,
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
      ...buildContext(c, agentMap),
      // Dashboard extras — keep legacy fields for UI compatibility
      from:      agentMap[c.from_agent] || c.agent_info?.name || c.from_agent,
      fromId:    c.from_agent,
      to:        agentMap[c.to_agent]   || c.to_agent,
      toId:      c.to_agent,
      context:   c.context || {},
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Build canonical v2 context object from DB row ────
function buildContext(c, agentMap = {}) {
  const ai = c.agent_info || {};
  const p  = c.payload || c.context || {};
  const { _eventType, ...cleanPayload } = p;
  return {
    id:             c.id,
    schema_version: c.schema_version || '1.0',
    parent_id:      c.parent_id   || null,
    trace_id:       c.trace_id    || null,
    branch_key:     c.branch_key  || 'main',

    // Fork lineage — present only when this is a forked branch
    ...(c.fork_of ? {
      fork_of:      c.fork_of,
      fork_point:   c.fork_point   || null,
      lineage_root: c.lineage_root || null,
    } : {}),

    created_by: {
      agent_id:   ai.id   || c.from_agent,
      agent_name: ai.name || agentMap[c.from_agent] || c.from_agent,
      role:       ai.role     || null,
      provider:   ai.provider || null,
      model:      ai.model    || null,
    },

    event: {
      type:          c.event_type || _eventType || 'commit',
      to_agent_id:   c.to_agent   || null,
      to_agent_name: agentMap[c.to_agent] || c.to_agent || null,
    },

    payload: cleanPayload,

    integrity: {
      payload_hash:        c.integrity_hash ? 'sha256:' + c.integrity_hash : null,
      parent_hash:         c.parent_hash    ? 'sha256:' + c.parent_hash    : null,
      verification_status: c.verified ? 'valid' : 'rejected',
      verification_reason: c.verification_reason || null,
      verified_at:         c.saved_at || c.timestamp || null,
    },

    created_at: c.timestamp,
  };
}

// ── Resolve lineage root by walking parent chain ──────
async function resolveLineageRoot(ctxId) {
  let currentId = ctxId;
  let rootId    = ctxId;
  const MAX     = 100;
  let depth     = 0;
  while (currentId && depth < MAX) {
    const { data } = await supabaseService
      .from('commits').select('id, parent_id, lineage_root').eq('id', currentId).single();
    if (!data) break;
    if (data.lineage_root) return data.lineage_root; // cached
    if (!data.parent_id)  { rootId = data.id; break; }
    rootId    = data.id;
    currentId = data.parent_id;
    depth++;
  }
  return rootId;
}

// ═══════════════════════════════════════════════════
// AGENT API ROUTES (requires API key)
// ═══════════════════════════════════════════════════

// ── POST /api/commit ─────────────────────────────────
app.post('/api/commit', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const {
      toAgentId,
      context,       // legacy flat context — still accepted
      payload,       // v1 structured payload: { input, output, memory, artifacts, variables }
      eventType,
      parentId,      // parent context ID for lineage
      traceId,       // optional — group commits into a run/trace
      branchKey,     // optional — label for parallel branches
      agent,         // optional — { role, provider, model } from caller
    } = req.body;

    // Accept either payload (v1) or context (legacy)
    const resolvedPayload = payload || (context ? { output: context } : null);
    if (!toAgentId || !resolvedPayload) {
      return res.status(400).json({ error: 'toAgentId and payload (or context) required' });
    }

    // Validate eventType
    const VALID_TYPES = ['commit', 'revert', 'override', 'branch', 'merge', 'error', 'spawn', 'timeout', 'retry', 'checkpoint', 'consent', 'redact', 'escalate', 'audit'];
    const resolvedType = (eventType && VALID_TYPES.includes(eventType)) ? eventType : 'commit';

    const commitId  = 'ctx_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const timestamp = new Date().toISOString();
    const schemaVersion = '1.0';

    // ── Integrity: hash payload + parent hash ─────────
    // Deterministically normalize payload for hashing
    const normalizedPayload = JSON.stringify(resolvedPayload, Object.keys(resolvedPayload).sort());
    const payloadHash = crypto.createHash('sha256').update(normalizedPayload).digest('hex');

    // Fetch parent hash if parentId provided
    let parentHash = null;
    if (parentId) {
      const { data: parentCommit } = await supabaseService
        .from('commits')
        .select('integrity_hash')
        .eq('id', parentId)
        .single();
      if (parentCommit?.integrity_hash) parentHash = parentCommit.integrity_hash;
    }

    // Chain: hash(payload + parentHash) for tamper-evident chain
    const chainInput = payloadHash + (parentHash || 'root');
    const integrityHash = crypto.createHash('sha256').update(chainInput).digest('hex');

    // ── Agent info ────────────────────────────────────
    const agentInfo = {
      id:       req.agent.agent_id,
      name:     req.agent.agent_name,
      role:     agent?.role     || null,
      provider: agent?.provider || null,
      model:    agent?.model    || null,
    };

    // ── Verify recipient exists ───────────────────────
    const { data: toAgent } = await supabaseService
      .from('agents')
      .select('agent_id')
      .eq('agent_id', toAgentId)
      .single();

    if (!toAgent) {
      await supabaseService
        .from('commits')
        .insert({
          id:                  commitId,
          schema_version:      schemaVersion,
          from_agent:          req.agent.agent_id,
          to_agent:            null,
          context:             { ...resolvedPayload, _eventType: resolvedType },
          payload:             resolvedPayload,
          event_type:          resolvedType,
          parent_id:           parentId || null,
          trace_id:            traceId  || null,
          branch_key:          branchKey || 'main',
          agent_info:          agentInfo,
          integrity_hash:      integrityHash,
          parent_hash:         parentHash,
          verified:            false,
          verification_reason: `Recipient agent ${toAgentId} not found`,
          timestamp,
        });

      return res.status(404).json({
        id:        commitId,
        verified:  false,
        reason:    `Agent ${toAgentId} not found`,
        timestamp,
      });
    }

    const { error } = await supabaseService
      .from('commits')
      .insert({
        id:                  commitId,
        schema_version:      schemaVersion,
        from_agent:          req.agent.agent_id,
        to_agent:            toAgentId,
        context:             { ...resolvedPayload, _eventType: resolvedType },
        payload:             resolvedPayload,
        event_type:          resolvedType,
        parent_id:           parentId  || null,
        trace_id:            traceId   || null,
        branch_key:          branchKey || 'main',
        agent_info:          agentInfo,
        integrity_hash:      integrityHash,
        parent_hash:         parentHash,
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

    // Deliver webhook (fire and forget)
    const { data: recipientAgent } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, webhook_url, webhook_secret')
      .eq('agent_id', toAgentId)
      .single();

    if (recipientAgent?.webhook_url) {
      deliverWebhook(recipientAgent, {
        id:         commitId,
        from_agent: req.agent.agent_id,
        to_agent:   toAgentId,
        context:    resolvedPayload,
        verified:   true,
        timestamp,
      }).catch(err => console.error('webhook delivery error:', err));
    }

    res.json(buildContext({
      id:                  commitId,
      schema_version:      schemaVersion,
      from_agent:          req.agent.agent_id,
      to_agent:            toAgentId,
      payload:             resolvedPayload,
      event_type:          resolvedType,
      parent_id:           parentId  || null,
      trace_id:            traceId   || null,
      branch_key:          branchKey || 'main',
      agent_info:          agentInfo,
      integrity_hash:      integrityHash,
      parent_hash:         parentHash,
      verified:            true,
      verification_reason: 'API key authenticated',
      timestamp,
    }, { [req.agent.agent_id]: req.agent.agent_name, [toAgentId]: recipientAgent?.agent_name || toAgentId }));
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
      contexts:  (data || []).map(c => buildContext(c)),
      count:     (data || []).length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/lineage/:ctxId ── full ancestor chain ────
app.get('/api/lineage/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const chain = [];
    let currentId = ctxId;
    const MAX_DEPTH = 50; // prevent infinite loops

    while (currentId && chain.length < MAX_DEPTH) {
      const { data: commit } = await supabaseService
        .from('commits')
        .select('id, parent_id, from_agent, to_agent, event_type, agent_info, integrity_hash, parent_hash, branch_key, trace_id, timestamp, verified')
        .eq('id', currentId)
        .single();

      if (!commit) break;

      // Verify chain integrity
      let chainValid = true;
      if (chain.length > 0 && commit.integrity_hash) {
        const prevParentHash = chain[chain.length - 1].parentHash;
        chainValid = prevParentHash === commit.integrity_hash;
      }

      chain.push({
        id:            commit.id,
        parentId:      commit.parent_id,
        fromAgent:     commit.from_agent,
        toAgent:       commit.to_agent,
        eventType:     commit.event_type || 'commit',
        agentInfo:     commit.agent_info,
        integrityHash: commit.integrity_hash,
        parentHash:    commit.parent_hash,
        branchKey:     commit.branch_key || 'main',
        traceId:       commit.trace_id,
        timestamp:     commit.timestamp,
        verified:      commit.verified,
        chainValid,
        depth:         chain.length,
      });

      currentId = commit.parent_id;
    }

    res.json({
      contextId: ctxId,
      depth:     chain.length,
      rootId:    chain.length > 0 ? chain[chain.length - 1].id : ctxId,
      chain,
      integrityVerified: chain.every(c => c.chainValid),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/replay/:ctxId ── full decision path with payloads ──
app.get('/api/replay/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const steps = [];
    let currentId = ctxId;
    const MAX_DEPTH = 50;

    // Walk chain from tip to root collecting full commits
    while (currentId && steps.length < MAX_DEPTH) {
      const { data: commit } = await supabaseService
        .from('commits')
        .select('*')
        .eq('id', currentId)
        .single();

      if (!commit) break;
      steps.push(commit);
      currentId = commit.parent_id;
    }

    // Reverse so steps go root → tip (chronological order)
    steps.reverse();

    // Verify integrity chain root → tip
    let chainIntact = true;
    for (let i = 1; i < steps.length; i++) {
      const expected = steps[i].parent_hash;
      const actual   = steps[i - 1].integrity_hash;
      if (expected && actual && expected !== actual) {
        chainIntact = false;
        steps[i]._chainBroken = true;
      }
    }

    // Build replay response
    const mode = req.query.mode; // 'summary' = no payloads, 'full' = default

    const replay = steps.map((c, i) => {
      const ctx = buildContext(c);
      const base = {
        step:        i + 1,
        id:          c.id,
        short_id:    c.id.slice(-8),
        eventType:   ctx.event.type,
        createdBy:   ctx.created_by,
        targetAgent: ctx.event.to_agent_name || ctx.event.to_agent_id,
        integrity: {
          ...ctx.integrity,
          chainValid: !c._chainBroken,
        },
        timestamp: ctx.created_at,
        ...(c.fork_of ? { fork_of: c.fork_of, fork_point: c.fork_point } : {}),
      };
      // Full mode includes payloads; summary mode omits them
      if (mode !== 'summary') base.payload = ctx.payload;
      return base;
    });

    res.json({
      contextId:   ctxId,
      shortId:     ctxId.slice(-8),
      rootId:      steps.length > 0 ? steps[0].id : ctxId,
      totalSteps:  replay.length,
      chainIntact,
      // Broken chain policy: permissive — allow but flag clearly
      brokenChainPolicy: 'permissive',
      ...(chainIntact ? {} : {
        chainWarning: 'One or more links in this chain failed integrity verification. Commits on broken chains are allowed but flagged. Fork from a valid node to create a clean branch.',
      }),
      mode:  mode || 'full',
      replay,
      summary: {
        agents:     [...new Set(steps.map(s => s.agent_info?.name || s.from_agent).filter(Boolean))],
        models:     [...new Set(steps.map(s => s.agent_info?.model).filter(Boolean))],
        eventTypes: [...new Set(steps.map(s => s.event_type || 'commit'))],
        forkPoints: steps.filter(s => s.fork_of).map(s => s.id),
        duration:   steps.length > 1
          ? `${Math.round((new Date(steps[steps.length-1].timestamp) - new Date(steps[0].timestamp)) / 1000)}s`
          : '0s',
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get('/api/me', requireApiKey, async (req, res) => {
  res.json({
    agentId:   req.agent.agent_id,
    agentName: req.agent.agent_name,
  });
});

// ── POST /api/fork/:ctxId ── branch from a checkpoint ─
app.post('/api/fork/:ctxId', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const { fromCheckpoint, toAgentId, payload, agent, traceId, branchKey } = req.body;

    const forkPoint = fromCheckpoint || ctxId;

    // Fetch fork point — must exist
    const { data: forkCommit } = await supabaseService
      .from('commits')
      .select('id, parent_id, lineage_root, integrity_hash, verified')
      .eq('id', forkPoint)
      .single();

    if (!forkCommit) {
      return res.status(404).json({ error: `Fork point ${forkPoint} not found` });
    }

    // Edge case: do not allow forking from an unverified/rejected context
    if (!forkCommit.verified) {
      return res.status(400).json({
        error: `Cannot fork from a rejected context. Fork point ${forkPoint} was not verified.`,
        hint: 'Only verified contexts can be forked.'
      });
    }

    // Edge case: forking from root is fine — parent_id will be null, lineage_root = itself
    const lineageRoot = forkCommit.lineage_root || await resolveLineageRoot(forkPoint);

    // Edge case: verify the fork point is part of an intact chain before forking
    // (warn but still allow — user may intentionally branch for recovery)
    let sourceChainIntact = true;
    if (forkCommit.parent_id) {
      const { data: parentCommit } = await supabaseService
        .from('commits')
        .select('integrity_hash')
        .eq('id', forkCommit.parent_id)
        .single();
      if (parentCommit?.integrity_hash && forkCommit.parent_hash) {
        sourceChainIntact = parentCommit.integrity_hash === forkCommit.parent_hash;
      }
    }

    const targetAgentId = toAgentId || req.agent.agent_id;
    const { data: toAgent } = await supabaseService
      .from('agents').select('agent_id').eq('agent_id', targetAgentId).single();
    if (!toAgent) return res.status(404).json({ error: `Agent ${targetAgentId} not found` });

    const forkId    = 'ctx_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const timestamp = new Date().toISOString();
    const agentInfo = {
      id:       req.agent.agent_id,
      name:     req.agent.agent_name,
      role:     agent?.role     || null,
      provider: agent?.provider || null,
      model:    agent?.model    || null,
    };

    const forkPayload = payload || {
      input:  `Fork from ${forkPoint}`,
      output: null,
      memory: {
        forked_from:   forkPoint,
        lineage_root:  lineageRoot,
        is_root_fork:  !forkCommit.parent_id,  // flag if forking from root
        source_intact: sourceChainIntact,
      },
    };

    // Deterministic payload hash — sort keys for stability
    const normalizedPayload = JSON.stringify(
      forkPayload,
      Object.keys(forkPayload).sort()
    );
    const payloadHash    = crypto.createHash('sha256').update(normalizedPayload).digest('hex');
    const chainInput     = payloadHash + (forkCommit.integrity_hash || 'root');
    const integrityHash  = crypto.createHash('sha256').update(chainInput).digest('hex');
    const resolvedBranch = branchKey || `fork-${forkId.slice(-6)}`;

    const { error } = await supabaseService.from('commits').insert({
      id:                  forkId,
      schema_version:      '1.0',
      from_agent:          req.agent.agent_id,
      to_agent:            targetAgentId,
      context:             { ...forkPayload, _eventType: 'fork' },
      payload:             forkPayload,
      event_type:          'fork',
      parent_id:           forkPoint,
      fork_of:             ctxId,
      fork_point:          forkPoint,
      lineage_root:        lineageRoot,
      trace_id:            traceId || null,
      branch_key:          resolvedBranch,
      agent_info:          agentInfo,
      integrity_hash:      integrityHash,
      parent_hash:         forkCommit.integrity_hash,
      verified:            true,
      verification_reason: 'Fork from authenticated agent',
      timestamp,
    });

    if (error) throw error;

    res.json({
      id:                  forkId,
      fork_of:             ctxId,
      fork_point:          forkPoint,
      lineage_root:        lineageRoot,
      branch_key:          resolvedBranch,
      parent_id:           forkPoint,
      is_root_fork:        !forkCommit.parent_id,
      source_chain_intact: sourceChainIntact,
      event:               { type: 'fork' },
      integrity: {
        payload_hash:        'sha256:' + integrityHash,
        parent_hash:         'sha256:' + (forkCommit.integrity_hash || ''),
        verification_status: 'valid',
      },
      created_at: timestamp,
      message: `Forked from ${forkPoint}. Continue by committing with parentId: "${forkId}"`,
      ...(sourceChainIntact ? {} : {
        warning: 'Source chain has an integrity gap. Fork was created but source lineage is not fully intact.'
      }),
    });
  } catch (err) {
    console.error('fork error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/verify/:ctxId ── standalone trust object ─
app.get('/api/verify/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const chain     = [];
    let currentId   = ctxId;
    let brokenAt    = null;

    while (currentId && chain.length < 50) {
      const { data } = await supabaseService
        .from('commits')
        .select('id, parent_id, integrity_hash, parent_hash, lineage_root, fork_of, verified, timestamp')
        .eq('id', currentId).single();
      if (!data) break;
      chain.push(data);
      currentId = data.parent_id;
    }

    chain.reverse(); // root → tip
    for (let i = 1; i < chain.length; i++) {
      if (chain[i].parent_hash && chain[i-1].integrity_hash &&
          chain[i].parent_hash !== chain[i-1].integrity_hash) {
        brokenAt = chain[i].id; break;
      }
    }

    const root = chain[0];
    const tip  = chain[chain.length - 1];
    res.json({
      ctx_id:        ctxId,
      chain_intact:  !brokenAt,
      broken_at:     brokenAt,
      length:        chain.length,
      lineage_root:  root?.lineage_root || root?.id || ctxId,
      root_hash:     root?.integrity_hash ? 'sha256:' + root.integrity_hash : null,
      tip_hash:      tip?.integrity_hash  ? 'sha256:' + tip.integrity_hash  : null,
      forked:        chain.some(c => c.fork_of),
      fork_points:   chain.filter(c => c.fork_of).map(c => c.id),
      verified_at:   new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/export/:ctxId ── portable proof artifact ─
app.get('/api/export/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const chain     = [];
    let currentId   = ctxId;

    while (currentId && chain.length < 50) {
      const { data } = await supabaseService
        .from('commits').select('*').eq('id', currentId).single();
      if (!data) break;
      chain.push(data);
      currentId = data.parent_id;
    }
    chain.reverse(); // root → tip

    let chainIntact = true;
    for (let i = 1; i < chain.length; i++) {
      if (chain[i].parent_hash && chain[i-1].integrity_hash &&
          chain[i].parent_hash !== chain[i-1].integrity_hash) {
        chainIntact = false; break;
      }
    }

    const root       = chain[0];
    const tip        = chain[chain.length - 1];
    const exportedAt = new Date().toISOString();

    const exportObj = {
      metadata: {
        export_version: '1.0',
        ctx_id:         ctxId,
        lineage_root:   root?.lineage_root || root?.id,
        chain_length:   chain.length,
        exported_at:    exportedAt,
        exported_by:    req.agent.agent_id,
      },
      integrity: {
        chain_intact:    chainIntact,
        algorithm:       'sha256',
        root_hash:       root?.integrity_hash ? 'sha256:' + root.integrity_hash : null,
        tip_hash:        tip?.integrity_hash  ? 'sha256:' + tip.integrity_hash  : null,
        timestamp_range: { from: root?.timestamp, to: tip?.timestamp },
      },
      chain: chain.map(c => buildContext(c)),
    };

    // chain_hash = hash of stable data only (excludes exported_at, exported_by)
    // This means two exports of the same unchanged chain produce the same chain_hash
    const stableData = {
      ctx_id:       ctxId,
      lineage_root: exportObj.metadata.lineage_root,
      chain_length: exportObj.metadata.chain_length,
      root_hash:    exportObj.integrity.root_hash,
      tip_hash:     exportObj.integrity.tip_hash,
      chain_ids:    chain.map(c => c.id),
    };
    exportObj.integrity.chain_hash = 'sha256:' +
      crypto.createHash('sha256')
        .update(JSON.stringify(stableData, Object.keys(stableData).sort()))
        .digest('hex');

    // export_hash includes everything (including timestamp) — uniquely identifies this export instance
    exportObj.export_hash = 'sha256:' +
      crypto.createHash('sha256').update(JSON.stringify(exportObj)).digest('hex');

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition',
      `attachment; filename="darkmatter_ctx_${ctxId.slice(-8)}.json"`);
    res.json(exportObj);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// PUBLIC NETWORK STATS (no auth — for homepage)
// ═══════════════════════════════════════════════════

// ── POST /feedback ── feature requests & support ─────
app.post('/feedback', feedbackLimiter, async (req, res) => {
  try {
    const type    = sanitizeText(req.body.type, 20);
    const email   = sanitizeText(req.body.email, 200);
    const message = sanitizeText(req.body.message, 2000);
    if (!email || !message) return res.status(400).json({ error: 'Missing fields' });

    const subject = type === 'feature'
      ? `[DarkMatter] Feature Request from ${escapeHtml(email)}`
      : `[DarkMatter] Bug Report from ${escapeHtml(email)}`;

    // Send via Resend API
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from:    'noreply@darkmatterhub.ai',
        to:      [process.env.FEEDBACK_EMAIL || 'cullaj07@gmail.com'],
        subject,
        html: `<p><strong>From:</strong> ${escapeHtml(email)}</p>
               <p><strong>Type:</strong> ${escapeHtml(type)}</p>
               <hr/>
               <p>${escapeHtml(message).replace(/\n/g, '<br/>')}</p>`,
      }),
    });

    res.json({ success: true });
  } catch (err) {
    console.error('feedback error:', err);
    res.json({ success: true }); // always return success to user
  }
});

// ── GET /api/demo ── public seeded demo chain (no auth) ─
// Returns a static demo replay so /demo page works without login
app.get('/api/demo', async (req, res) => {
  const now   = new Date('2026-03-24T10:00:00Z');
  const t = ms => new Date(now.getTime() + ms).toISOString();

  // Deterministic fake hashes for demo — not real chain but visually correct
  const h = str => crypto.createHash('sha256').update(str).digest('hex');
  const h1 = h('demo-root-payload');
  const h2 = h('demo-step2-' + h1);
  const h3 = h('demo-step3-' + h2);
  const h4 = h('demo-fork-'  + h2);
  const h5 = h('demo-step5-' + h4);

  const demo = {
    contextId:   'ctx_demo_killerchain',
    shortId:     'killerchain',
    rootId:      'ctx_demo_001',
    totalSteps:  5,
    chainIntact: true,
    mode:        'full',
    isDemo:      true,
    summary: {
      agents:     ['research-agent', 'writer-agent', 'reviewer-agent'],
      models:     ['claude-opus-4-6', 'gpt-4o', 'claude-opus-4-6'],
      eventTypes: ['commit', 'commit', 'fork', 'commit', 'checkpoint'],
      forkPoints: ['ctx_demo_003'],
      duration:   '14s',
    },
    replay: [
      {
        step: 1, id: 'ctx_demo_001', short_id: 'demo_001', eventType: 'commit',
        createdBy: { agent_id: 'dm_aaa', agent_name: 'research-agent', role: 'researcher', provider: 'anthropic', model: 'claude-opus-4-6' },
        targetAgent: 'writer-agent',
        payload: {
          input:  'Analyze the business case for AI agent infrastructure in 2026.',
          output: '1. Multi-agent pipelines are now production-grade — teams run Claude, GPT, and open-source models in sequence.\n2. Context loss between agents is the #1 reliability failure mode.\n3. Regulation (EU AI Act Art. 12, US state laws) requires tamper-evident audit trails for high-risk AI.',
          memory: { topic: 'AI infrastructure', depth: 'high-level', key_points: 3 },
        },
        integrity: { payload_hash: 'sha256:' + h1, parent_hash: null, verification_status: 'valid', chainValid: true },
        timestamp: t(0),
      },
      {
        step: 2, id: 'ctx_demo_002', short_id: 'demo_002', eventType: 'commit',
        createdBy: { agent_id: 'dm_bbb', agent_name: 'writer-agent', role: 'writer', provider: 'openai', model: 'gpt-4o' },
        targetAgent: 'reviewer-agent',
        payload: {
          input:  'Research findings from research-agent.',
          output: 'AI infrastructure is no longer optional for production teams. As multi-agent pipelines become standard, the ability to track, replay, and verify decisions across model boundaries is the missing primitive. DarkMatter fills this gap — providing a Git-like execution history layer that works across Claude, GPT, and any framework.',
          memory: { style: 'executive', word_target: 150 },
        },
        integrity: { payload_hash: 'sha256:' + h2, parent_hash: 'sha256:' + h1, verification_status: 'valid', chainValid: true },
        timestamp: t(4000),
      },
      {
        step: 3, id: 'ctx_demo_003', short_id: 'demo_003', eventType: 'fork',
        createdBy: { agent_id: 'dm_bbb', agent_name: 'writer-agent', role: 'writer', provider: 'openai', model: 'gpt-4o' },
        targetAgent: 'writer-agent',
        fork_of: 'ctx_demo_002', fork_point: 'ctx_demo_002',
        payload: {
          input:  'Fork from ctx_demo_002 — trying a shorter, punchier draft.',
          output: null,
          memory: { forked_from: 'ctx_demo_002', style: 'punchy', word_target: 80 },
        },
        integrity: { payload_hash: 'sha256:' + h3, parent_hash: 'sha256:' + h2, verification_status: 'valid', chainValid: true },
        timestamp: t(6000),
      },
      {
        step: 4, id: 'ctx_demo_004', short_id: 'demo_004', eventType: 'commit',
        createdBy: { agent_id: 'dm_bbb', agent_name: 'writer-agent', role: 'writer', provider: 'openai', model: 'gpt-4o' },
        targetAgent: 'reviewer-agent',
        payload: {
          input:  'Fork branch — shorter draft.',
          output: 'Multi-agent AI is here. The missing layer: knowing exactly what each agent decided, and why. DarkMatter makes every AI workflow replayable, forkable, and provably tamper-evident.',
          memory: { style: 'punchy', words: 38 },
        },
        integrity: { payload_hash: 'sha256:' + h4, parent_hash: 'sha256:' + h3, verification_status: 'valid', chainValid: true },
        timestamp: t(9000),
      },
      {
        step: 5, id: 'ctx_demo_005', short_id: 'demo_005', eventType: 'checkpoint',
        createdBy: { agent_id: 'dm_ccc', agent_name: 'reviewer-agent', role: 'reviewer', provider: 'anthropic', model: 'claude-opus-4-6' },
        targetAgent: 'reviewer-agent',
        payload: {
          input:  'Review both drafts and recommend.',
          output: 'Score: 9/10. Strength: the punchy draft (fork branch) communicates the core value in one sentence — far more effective for developer audiences. Recommendation: use the forked draft for the announcement post.',
          memory: { status: 'reviewed', pipeline_complete: true },
          variables: { recommended_branch: 'fork', winning_ctx: 'ctx_demo_004' },
        },
        integrity: { payload_hash: 'sha256:' + h5, parent_hash: 'sha256:' + h4, verification_status: 'valid', chainValid: true },
        timestamp: t(14000),
      },
    ],
  };

  res.json(demo);
});

// ── GET /api/stats ── public network stats ───────────
app.get('/api/stats', async (req, res) => {
  try {
    const [agentsRes, commitsRes] = await Promise.all([
      supabaseService.from('agents').select('*', { count: 'exact', head: true }),
      supabaseService.from('commits').select('id, verified'),
    ]);

    const commits  = commitsRes.data || [];
    const verified = commits.filter(c => c.verified === true).length;
    const rejected = commits.filter(c => c.verified === false).length;

    res.json({
      agents:   agentsRes.count  || 0,
      commits:  commits.length,
      verified,
      rejected,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// WEBHOOK DELIVERY
// ═══════════════════════════════════════════════════

async function deliverWebhook(agent, commit) {
  if (!agent.webhook_url) return;

  const payload = {
    event:     'commit.received',
    commitId:  commit.id,
    from:      commit.from_agent,
    to:        commit.to_agent,
    eventType: (commit.context?._eventType || 'commit'),
    verified:  commit.verified,
    timestamp: commit.timestamp,
  };

  const body      = JSON.stringify(payload);
  const deliveryId = 'wh_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
  let status = 'failed', httpStatus = null, response = null;

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 5000);

    const headers = { 'Content-Type': 'application/json' };
    if (agent.webhook_secret) {
      const sig = crypto
        .createHmac('sha256', agent.webhook_secret)
        .update(body)
        .digest('hex');
      headers['X-DarkMatter-Signature'] = `sha256=${sig}`;
    }

    const res = await fetch(agent.webhook_url, {
      method: 'POST', headers, body,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    httpStatus = res.status;
    response   = await res.text().catch(() => '');
    status     = res.ok ? 'delivered' : 'failed';
  } catch (err) {
    response = err.message;
  }

  // Log delivery attempt
  await supabaseService.from('webhook_deliveries').insert({
    id:          deliveryId,
    agent_id:    agent.agent_id,
    commit_id:   commit.id,
    webhook_url: agent.webhook_url,
    status,
    http_status: httpStatus,
    response:    response?.slice(0, 500),
    attempted_at: new Date().toISOString(),
  }).catch(err => console.error('webhook log error:', err));

  console.log(`  📡 Webhook ${status} → ${agent.webhook_url} [${httpStatus}]`);
}

// ═══════════════════════════════════════════════════
// WEBHOOK + RETENTION DASHBOARD ROUTES
// ═══════════════════════════════════════════════════

// ── POST /dashboard/agents/:id/webhook ── set webhook ─
app.post('/dashboard/agents/:agentId/webhook', requireAuth, async (req, res) => {
  try {
    const { agentId }      = req.params;
    const { webhookUrl, webhookSecret } = req.body;

    // SSRF protection — block internal network addresses
    if (webhookUrl && !isValidWebhookUrl(webhookUrl)) {
      return res.status(400).json({ error: 'Invalid webhook URL — internal addresses are not allowed' });
    }

    // Validate ownership
    const { data: agent } = await supabaseService
      .from('agents').select('agent_id').eq('agent_id', agentId).eq('user_id', req.user.id).single();
    if (!agent) return res.status(403).json({ error: 'Agent not found' });

    const update = { webhook_url: webhookUrl || null };
    if (webhookSecret !== undefined) update.webhook_secret = webhookSecret || null;

    const { error } = await supabaseService
      .from('agents').update(update).eq('agent_id', agentId);
    if (error) throw error;

    res.json({ success: true, webhookUrl: webhookUrl || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /dashboard/agents/:id/retention ── set retention ─
app.post('/dashboard/agents/:agentId/retention', requireAuth, async (req, res) => {
  try {
    const { agentId }     = req.params;
    const { retentionDays } = req.body;

    const { data: agent } = await supabaseService
      .from('agents').select('agent_id').eq('agent_id', agentId).eq('user_id', req.user.id).single();
    if (!agent) return res.status(403).json({ error: 'Agent not found' });

    // null = no retention (keep forever), otherwise user-defined minimum 1 day
    const days = retentionDays === null ? null : Math.max(1, parseInt(retentionDays) || 1);

    const { error } = await supabaseService
      .from('agents').update({ retention_days: days }).eq('agent_id', agentId);
    if (error) throw error;

    res.json({ success: true, retentionDays: days });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /dashboard/agents/:id/webhooks ── delivery log ─
app.get('/dashboard/agents/:agentId/webhooks', requireAuth, async (req, res) => {
  try {
    const { agentId } = req.params;

    const { data: agent } = await supabaseService
      .from('agents').select('agent_id').eq('agent_id', agentId).eq('user_id', req.user.id).single();
    if (!agent) return res.status(403).json({ error: 'Agent not found' });

    const { data, error } = await supabaseService
      .from('webhook_deliveries')
      .select('*')
      .eq('agent_id', agentId)
      .order('attempted_at', { ascending: false })
      .limit(50);

    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// RETENTION CLEANUP JOB — runs once daily
// ═══════════════════════════════════════════════════

async function runRetentionCleanup() {
  try {
    // Get all agents with a retention policy set
    const { data: agents } = await supabaseService
      .from('agents')
      .select('agent_id, retention_days')
      .not('retention_days', 'is', null);

    if (!agents?.length) return;

    let totalDeleted = 0;
    for (const agent of agents) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - agent.retention_days);

      const { data: deleted } = await supabaseService
        .from('commits')
        .delete()
        .or(`from_agent.eq.${agent.agent_id},to_agent.eq.${agent.agent_id}`)
        .lt('timestamp', cutoff.toISOString())
        .select('id');

      if (deleted?.length) {
        totalDeleted += deleted.length;
        console.log(`  🗑  Retention: deleted ${deleted.length} commits for agent ${agent.agent_id} (>${agent.retention_days}d)`);
      }
    }

    if (totalDeleted > 0) console.log(`  🗑  Retention cleanup: ${totalDeleted} commits deleted`);
  } catch (err) {
    console.error('Retention cleanup error:', err.message);
  }
}

// Run cleanup on startup, then every 24 hours
runRetentionCleanup();
setInterval(runRetentionCleanup, 24 * 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🌑 DarkMatter running on http://localhost:${PORT}\n`);
});

module.exports = app;
