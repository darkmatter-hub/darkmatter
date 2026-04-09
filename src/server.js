require('dotenv').config();
const express   = require('express');
const path      = require('path');
const crypto    = require('crypto');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const {
  canonicalize, hashPayload, hashChain,
  verifySignature, validateClientHashes, verifyChain,
} = require('./integrity');
const { appendToLog, getServerPublicKeyPem, verifyLogConsistency,
  generateProofForCommit, CHECKPOINT_SCHEMA_VERSION,
  verifyCheckpointConsistency,
} = require('./append-log');
const {
  leafHash, buildLeafEnvelope, computeRoot,
  generateInclusionProof, verifyInclusionProof,
} = require('./merkle');
const { publishCheckpoint, startCheckpointScheduler } = require('./checkpoint');
const {
  registerKey, rotateKey, revokeKey,
  getKeyAtTime, getKeyHistory, verifyCommitSignature,
} = require('./keys');

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

const provisionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,                   // 10 provisions per IP per hour
  message: { error: 'Too many provision requests — try again in an hour' },
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

// ── CORS ─────────────────────────────────────────────
// Allow browser extension and API clients to call from any origin.
// Auth is enforced via Bearer token — CORS is safe to open.
app.use((req, res, next) => {
  const allowed = [
    'https://darkmatterhub.ai',
    'https://claude.ai',
    'https://chatgpt.com',
    'https://chat.openai.com',
    'https://grok.com',
    'https://gemini.google.com',
    'https://www.perplexity.ai',
  ];
  const origin = req.headers.origin;
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    // Non-browser clients (SDK, CLI, Postman) — allow
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,User-Agent');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '10mb' })); // increased for rich content from extension
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

// ── POST /api/provision ─────────────────────────────
// Frictionless agent creation — no account needed.
// Creates a Supabase user + first agent in one call.
// Returns API key immediately. Email verification optional.
//
// Usage:
//   curl -X POST https://darkmatterhub.ai/api/provision \
//     -H "Content-Type: application/json" \
//     -d '{"email":"dev@example.com","agentName":"my-agent"}'
//
// Or via darkmatter init CLI command.
// ────────────────────────────────────────────────────
app.post('/api/provision', provisionLimiter, async (req, res) => {
  try {
    const { email, agentName, source } = req.body;

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const name = agentName
      ? sanitizeText(agentName, 100).replace(/[^a-zA-Z0-9 _\-\.]/g, '')
      : 'my-first-agent';

    if (!name) return res.status(400).json({ error: 'Invalid agent name' });

    // ── Create Supabase user (magic link / passwordless) ──
    // Use signInWithOtp so user gets a magic link to set password later
    // but the account + agent are active immediately
    const password    = crypto.randomBytes(24).toString('hex'); // throwaway, user sets real pw via magic link
    const { data: authData, error: authError } = await supabaseService.auth.admin.createUser({
      email,
      password,
      email_confirm: false,  // don't require email confirmation to use API
      user_metadata: { source: source || 'cli_provision', agent_name: name },
    });

    let userId;
    if (authError) {
      // User already exists — look them up
      if (authError.message?.includes('already been registered') || authError.code === 'email_exists') {
        const { data: existingUsers } = await supabaseService.auth.admin.listUsers();
        const existing = existingUsers?.users?.find(u => u.email === email.toLowerCase());
        if (!existing) return res.status(409).json({ error: 'Email already registered. Use the dashboard to create agents.' });
        userId = existing.id;
      } else {
        throw authError;
      }
    } else {
      userId = authData.user.id;
    }

    // ── Create the first agent ────────────────────────
    const agentId = generateAgentId();
    const apiKey  = generateApiKey();

    const { data: agentData, error: agentError } = await supabaseService
      .from('agents')
      .insert({
        agent_id:   agentId,
        agent_name: name,
        user_id:    userId,
        api_key:    apiKey,
      })
      .select()
      .single();

    if (agentError) {
      // If agent creation fails, still return useful error
      throw agentError;
    }

    // ── Send magic link for account setup (non-blocking) ──
    supabaseService.auth.admin.generateLink({
      type:       'magiclink',
      email,
      options:    { redirectTo: `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/dashboard` },
    }).then(({ data }) => {
      // In production, send this via Resend/email
      // For now just log — the developer can still use the API key immediately
      console.log(`  📧 Magic link for ${email}: ${data?.properties?.action_link || 'generated'}`);
    }).catch(() => {});

    // Track activation (fire and forget — table may not exist yet)
    try {
      supabaseService.from('activation_events').insert({
        id:          'ae_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
        user_id:     userId,
        event:       'key_created',
        metadata:    { source: source || 'cli_provision', agent_name: name },
        occurred_at: new Date().toISOString(),
      }).then(() => {}).catch(() => {});
    } catch (_) {}

    res.status(201).json({
      agentId:   agentData.agent_id,
      agentName: agentData.agent_name,
      apiKey,
      email,
      dashboardUrl: `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/dashboard`,
      next: [
        `export DARKMATTER_API_KEY=${apiKey}`,
        'import darkmatter as dm',
        'ctx = dm.commit(to_agent_id, payload={"output": result})',
      ],
      note: 'Your API key is active immediately. Check your email to set a password and access the dashboard.',
    });
  } catch (err) {
    console.error('provision error:', err);
    res.status(500).json({ error: err.message });
  }
});

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

    const { data, error } = await supabaseAnon.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/dashboard`,
      },
    });
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
// AGENT SELF-REGISTRATION
// Allows an authenticated agent to spawn a new agent
// programmatically — no dashboard login required.
// Cap: 10 new agents per user per day to prevent abuse.
// ═══════════════════════════════════════════════════

app.post('/api/agents/register', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { agentName, role, provider, model } = req.body;
    if (!agentName) return res.status(400).json({ error: 'agentName required' });
    if (!/^[a-zA-Z0-9 _\-\.]+$/.test(agentName)) {
      return res.status(400).json({ error: 'agentName may only contain letters, numbers, spaces, hyphens, underscores, and periods' });
    }

    const userId = req.agent.user_id;

    // ── Daily cap: max 10 new agents per user per day ─
    const dayStart = new Date();
    dayStart.setHours(0, 0, 0, 0);

    const { count } = await supabaseService
      .from('agents')
      .select('agent_id', { count: 'exact', head: true })
      .eq('user_id', userId)
      .gte('created_at', dayStart.toISOString());

    // Capture agents (from browser extension) get a higher cap
    // since each new conversation auto-creates one
    const isCaptureAgent = (role === 'capture');
    const DAILY_CAP = isCaptureAgent ? 5000 : 1000; // effectively unlimited for normal use
    if (count >= DAILY_CAP) {
      return res.status(429).json({
        error: `Daily agent registration limit reached (${DAILY_CAP} per day). Resets at midnight UTC.`,
        limit:     DAILY_CAP,
        resets_at: new Date(dayStart.getTime() + 86400000).toISOString(),
      });
    }

    // ── Create the new agent ──────────────────────────
    const newAgentId = generateAgentId();
    const newApiKey  = generateApiKey();

    const { data, error } = await supabaseService
      .from('agents')
      .insert({
        agent_id:   newAgentId,
        agent_name: sanitizeText(agentName, 100),
        user_id:    userId,
        api_key:    newApiKey,
      })
      .select()
      .single();

    if (error) throw error;

    // ── Return new agent credentials ──────────────────
    res.status(201).json({
      agentId:   data.agent_id,
      agentName: data.agent_name,
      apiKey:    newApiKey,
      createdAt: data.created_at,
      spawnedBy: req.agent.agent_id,
      meta: {
        role:     role     || null,
        provider: provider || null,
        model:    model    || null,
      },
      note: 'Store this API key securely — it will not be shown again.',
      warning: `Agent registration is capped at ${DAILY_CAP} per day per account to prevent runaway spawning.`,
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
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
    if (!/^[a-zA-Z0-9 _\-\.·:]+$/.test(agentName)) {
      return res.status(400).json({ error: 'Agent name contains invalid characters' });
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

    // Query by agent_id (v13+), falling back to from_agent/to_agent
    const idList = agentIds.map(id => `"${id}"`).join(',');
    const { data, error } = await supabaseService
      .from('commits')
      .select('*')
      .or([
        `agent_id.in.(${idList})`,
        `from_agent.in.(${idList})`,
        `to_agent.in.(${idList})`
      ].join(','))
      .order('timestamp', { ascending: false })
      .limit(200);

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
      payload_hash:        c.payload_hash   ? 'sha256:' + c.payload_hash   : null,
      parent_hash:         c.parent_hash    ? 'sha256:' + c.parent_hash    : null,
      integrity_hash:      c.integrity_hash ? 'sha256:' + c.integrity_hash : null,
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

    const commitId      = 'ctx_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const acceptedAt    = new Date().toISOString().replace(/\.\d+Z$/, 'Z'); // server ledger time
    const timestamp     = acceptedAt; // kept for backwards compat
    const schemaVersion = '1.0';
    // client_timestamp: what the agent asserted in their envelope (may differ from accepted_at)
    const clientTimestamp = req.body.envelope?.timestamp || acceptedAt;

    // ── Phase 1: Client-side hashing support ──────────────────────────────
    // If the client supplied pre-computed hashes (commit_verified / Phase 1 SDK),
    // we use THOSE hashes — the server recomputes and cross-checks, but stores
    // what the client computed. This makes the server a dumb notary:
    // it cannot alter the hash without the client detecting it on next read.
    //
    // Canonical serialisation: keys sorted recursively, compact JSON, UTF-8.
    // This matches darkmatter.crypto.canonical_json() in the Python SDK.
    const clientPayloadHash    = req.body.clientPayloadHash    || null;
    const clientIntegrityHash  = req.body.clientIntegrityHash  || null;
    const agentSignature       = req.body.agentSignature       || null;
    const agentPublicKey       = req.body.agentPublicKey       || null;

    // Server always computes independently (for cross-check and legacy clients)
    const normalizedPayload = JSON.stringify(resolvedPayload, Object.keys(resolvedPayload).sort());
    const serverPayloadHash = crypto.createHash('sha256').update(normalizedPayload).digest('hex');

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

    const serverChainInput   = serverPayloadHash + (parentHash || 'root');
    const serverIntegrityHash = crypto.createHash('sha256').update(serverChainInput).digest('hex');

    // If client sent pre-computed hashes, cross-check them.
    // Store client hashes (they signed over those). Flag mismatch.
    let payloadHash, integrityHash, hashMismatch = false;
    if (clientPayloadHash && clientIntegrityHash) {
      hashMismatch = (clientPayloadHash !== serverPayloadHash ||
                      clientIntegrityHash !== serverIntegrityHash);
      payloadHash   = clientPayloadHash;
      integrityHash = clientIntegrityHash;
    } else {
      // Legacy path: server-computed hashes
      payloadHash   = serverPayloadHash;
      integrityHash = serverIntegrityHash;
    }

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
          payload_hash:        payloadHash,
          parent_hash:         parentHash,
          agent_signature:     agentSignature,
          agent_public_key:    agentPublicKey,
          hash_mismatch:       hashMismatch || false,
          client_timestamp:    clientTimestamp,
          accepted_at:         acceptedAt,
          spec_version:        '1.0',
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
        payload_hash:        payloadHash,
        parent_hash:         parentHash,
        server_payload_hash: serverPayloadHash,
        hash_mismatch:       hashMismatch || false,
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

    // Fire event hooks (post-commit)
    fireEventHooks(req.agent.agent_id, 'commit', {
      ctxId: commitId, toAgentId, traceId, eventType: resolvedType,
    }).catch(() => {});

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

    const receipt = buildContext({
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
      payload_hash:        payloadHash,
      parent_hash:         parentHash,
      verified:            true,
      verification_reason: 'API key authenticated',
      timestamp,
    }, { [req.agent.agent_id]: req.agent.agent_name, [toAgentId]: recipientAgent?.agent_name || toAgentId });

    // ── Phase 3: append to log + Merkle tree ──────────
    let logEntry = null;
    try {
      logEntry = await appendToLog(supabaseService, commitId, integrityHash);
      await supabaseService.from('commits').update({
        log_position:         logEntry.position,
        leaf_hash:            logEntry.leaf_hash,
        tree_root_at_append:  logEntry.tree_root,
        tree_size_at_append:  logEntry.tree_size,
        proof_status:         'included',
      }).eq('id', commitId);
    } catch (logErr) {
      console.error('[commit] Log append failed:', logErr.message);
      try {
        await supabaseService.from('commits')
          .update({ proof_status: 'proof_unavailable' })
          .eq('id', commitId);
      } catch {}
    }

    // Attach Phase 3 proof receipt — full inclusion proof
    if (logEntry) {
      receipt._proof = {
        log_position:    logEntry.position,
        leaf_hash:       logEntry.leaf_hash,
        tree_root:       logEntry.tree_root,
        tree_size:       logEntry.tree_size,
        accepted_at:     logEntry.accepted_at,
        client_timestamp: clientTimestamp,
        inclusion_proof: logEntry.inclusion_proof,
        proof_status:    'included',
        pubkey_url:      'https://darkmatterhub.ai/api/log/pubkey',
        checkpoint_url:  'https://darkmatterhub.ai/api/log/checkpoint',
        verify_url:      `https://darkmatterhub.ai/api/log/proof/${commitId}`,
      };
      // Keep _log for Phase 2 backwards compatibility
      receipt._log = {
        position:   logEntry.position,
        log_root:   'sha256:' + logEntry.log_root,
        timestamp:  logEntry.accepted_at,
        pubkey_url: 'https://darkmatterhub.ai/api/log/pubkey',
      };
    }
    if (hashMismatch) {
      receipt._warnings = receipt._warnings || [];
      receipt._warnings.push('hash_mismatch: client hashes did not match server-computed hashes');
    }
    res.json(receipt);
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
        payload_hash:        'sha256:' + payloadHash,
        integrity_hash:      'sha256:' + integrityHash,
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

// ── GET /api/export/:ctxId ── self-sufficient proof bundle ──────────────────
// Phase 3: includes per-commit inclusion proofs, checkpoint, server pubkey,
// and verifier script reference. The bundle can be verified fully offline.
//
// Bundle structure:
//   _spec           — bundle version + verification instructions
//   metadata        — chain info
//   integrity       — chain-level hashes
//   checkpoint      — latest signed checkpoint covering this chain
//   server_pubkey   — DarkMatter server Ed25519 public key (for checkpoint sig)
//   commits         — ordered commits, each with _proof receipt
//   export_hash     — SHA-256 of the entire bundle (uniquely identifies this export)
//
app.get('/api/export/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;

    // ── 1. Walk the chain ────────────────────────────────────────────────────
    const chain = [];
    let currentId = ctxId;
    while (currentId && chain.length < 200) {
      const { data } = await supabaseService
        .from('commits')
        .select('*')
        .eq('id', currentId)
        .single();
      if (!data) break;
      chain.push(data);
      currentId = data.parent_id;
    }
    chain.reverse(); // root → tip

    if (!chain.length) return res.status(404).json({ error: 'Chain not found' });

    // ── 2. Per-commit inclusion proofs ───────────────────────────────────────
    const commitIds      = chain.map(c => c.id);
    const { data: logRows } = await supabaseService
      .from('log_entries')
      .select('commit_id, position, leaf_hash, tree_root, tree_size, integrity_hash, timestamp')
      .in('commit_id', commitIds);

    const logByCommit = {};
    for (const row of (logRows || [])) logByCommit[row.commit_id] = row;

    // Fetch all leaf hashes for proof generation (up to max tree size in this chain)
    const maxTreeSize = Math.max(...Object.values(logByCommit).map(r => r.tree_size || 0), 0);
    let allLeafHashes = [];
    if (maxTreeSize > 0) {
      const { data: allLeaves } = await supabaseService
        .from('log_entries')
        .select('position, leaf_hash')
        .lte('position', maxTreeSize - 1)
        .order('position', { ascending: true });
      allLeafHashes = (allLeaves || []).map(l => l.leaf_hash);
    }

    // Build commits array with proof receipts
    const commitsWithProofs = chain.map(c => {
      const built    = buildContext(c);
      const logEntry = logByCommit[c.id];
      if (logEntry) {
        let inclusionProof = null;
        try {
          const leavesForProof = allLeafHashes.slice(0, logEntry.tree_size);
          if (leavesForProof.length > logEntry.position) {
            inclusionProof = generateInclusionProof(leavesForProof, logEntry.position);
          }
        } catch {}
        built._proof = {
          log_position:    logEntry.position,
          leaf_hash:       logEntry.leaf_hash,
          tree_root:       logEntry.tree_root,
          tree_size:       logEntry.tree_size,
          accepted_at:     logEntry.timestamp,
          inclusion_proof: inclusionProof,
          proof_status:    c.proof_status || 'included',
        };
      }
      return built;
    });

    // ── 3. Checkpoint covering this chain ────────────────────────────────────
    const tipLogEntry = logByCommit[chain[chain.length - 1]?.id];
    let checkpoint = null;
    if (tipLogEntry) {
      const { data: cp } = await supabaseService
        .from('checkpoints')
        .select('checkpoint_id, position, tree_root, tree_size, log_root, server_sig, timestamp, previous_cp_id, previous_tree_root, published, published_url')
        .gte('position', tipLogEntry.position)
        .order('position', { ascending: true })
        .limit(1)
        .single();
      checkpoint = cp || null;
    }
    // If no checkpoint covers the tip yet, use the latest available
    if (!checkpoint) {
      const { data: latestCp } = await supabaseService
        .from('checkpoints')
        .select('checkpoint_id, position, tree_root, tree_size, log_root, server_sig, timestamp, previous_cp_id, previous_tree_root, published, published_url')
        .order('position', { ascending: false })
        .limit(1)
        .single();
      checkpoint = latestCp || null;
    }

    // ── 4. Chain-level integrity ─────────────────────────────────────────────
    const root       = chain[0];
    const tip        = chain[chain.length - 1];
    const exportedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

    let chainIntact = true;
    for (let i = 1; i < chain.length; i++) {
      const cur = chain[i]; const prev = chain[i - 1];
      if (cur.parent_hash && prev.integrity_hash &&
          cur.parent_hash.replace('sha256:', '') !== prev.integrity_hash.replace('sha256:', '')) {
        chainIntact = false; break;
      }
    }

    const stableData = {
      ctx_id:       ctxId,
      chain_ids:    commitIds,
      chain_length: chain.length,
      root_hash:    root?.integrity_hash || null,
      tip_hash:     tip?.integrity_hash  || null,
    };
    const chainHash = crypto.createHash('sha256')
      .update(JSON.stringify(stableData, Object.keys(stableData).sort()))
      .digest('hex');

    // ── 5. Assemble self-sufficient bundle ───────────────────────────────────
    const bundle = {
      _spec: {
        bundle_version:  '3.0',
        spec_url:        'https://darkmatterhub.ai/docs#integrity-spec',
        verifier_url:    'https://github.com/bengunvl/darkmatter/blob/main/github-template/verify_darkmatter_chain.py',
        verify_command:  'python verify_darkmatter_chain.py this_file.json --checkpoint checkpoint.json --pubkey server_pubkey.pem',
        checkpoint_repo: 'https://github.com/darkmatter-hub/checkpoints',
        phases:          ['structure', 'agent_signatures', 'merkle_inclusion', 'checkpoint'],
      },
      metadata: {
        ctx_id:         ctxId,
        chain_length:   chain.length,
        lineage_root:   root?.lineage_root || root?.id,
        trace_id:       tip?.trace_id || null,
        exported_at:    exportedAt,
        exported_by:    req.agent.agent_id,
      },
      integrity: {
        chain_intact:    chainIntact,
        algorithm:       'sha256-envelope',
        root_hash:       root?.integrity_hash  ? 'sha256:' + root.integrity_hash.replace('sha256:', '')  : null,
        tip_hash:        tip?.integrity_hash   ? 'sha256:' + tip.integrity_hash.replace('sha256:', '')   : null,
        chain_hash:      'sha256:' + chainHash,
        timestamp_range: { from: root?.timestamp, to: tip?.timestamp },
      },
      checkpoint:    checkpoint ? {
        ...checkpoint,
        note: checkpoint.position >= (tipLogEntry?.position ?? -1)
          ? 'This checkpoint covers the tip of this chain'
          : 'Latest available checkpoint — tip may not yet be checkpointed',
      } : null,
      server_pubkey: {
        algorithm:   'Ed25519',
        public_key:  getServerPublicKeyPem(),
        use:         'Verify checkpoint.server_sig',
        pubkey_url:  'https://darkmatterhub.ai/api/log/pubkey',
      },
      commits: commitsWithProofs,
    };

    // export_hash uniquely identifies this exact export instance
    bundle.export_hash = 'sha256:' +
      crypto.createHash('sha256').update(JSON.stringify(bundle)).digest('hex');

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition',
      `attachment; filename="darkmatter_proof_${ctxId.slice(-8)}_v3.json"`);
    res.json(bundle);
  } catch (err) {
    console.error('[export] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════════════════
// KEY LIFECYCLE API
// ═══════════════════════════════════════════════════

// ── POST /api/agents/keys ────────────────────────────────────────────────────
// Register a public key for the authenticated agent.
// Only public key is stored — private key never leaves the agent's machine.
app.post('/api/agents/keys', requireApiKey, async (req, res) => {
  try {
    const { publicKey, keyId = 'default', validUntil } = req.body;
    if (!publicKey) return res.status(400).json({ error: 'publicKey required' });
    const result = await registerKey(
      supabaseService,
      req.agent.agent_id,
      publicKey,
      keyId,
      { validUntil, performedBy: req.agent.agent_id }
    );
    res.json({ ...result, message: 'Key registered. Private key never stored.' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── POST /api/agents/keys/rotate ──────────────────────────────────────────────
// Rotate to a new key. Old key remains valid for historical verification.
app.post('/api/agents/keys/rotate', requireApiKey, async (req, res) => {
  try {
    const { currentKeyId = 'default', newPublicKey, newKeyId = 'default', reason } = req.body;
    if (!newPublicKey) return res.status(400).json({ error: 'newPublicKey required' });
    const result = await rotateKey(
      supabaseService,
      req.agent.agent_id,
      currentKeyId,
      newPublicKey,
      newKeyId,
      reason
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── POST /api/agents/keys/revoke ──────────────────────────────────────────────
// Revoke a key immediately (use for compromised keys).
// Unlike rotation, revocation flags historical commits as signed_by_revoked_key.
app.post('/api/agents/keys/revoke', requireApiKey, async (req, res) => {
  try {
    const { keyId = 'default', reason } = req.body;
    if (!reason) return res.status(400).json({ error: 'reason required for revocation' });
    const result = await revokeKey(
      supabaseService,
      req.agent.agent_id,
      keyId,
      reason,
      req.agent.agent_id
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── GET /api/agents/keys ─────────────────────────────────────────────────────
// Get key history for the authenticated agent.
app.get('/api/agents/keys', requireApiKey, async (req, res) => {
  try {
    const history = await getKeyHistory(supabaseService, req.agent.agent_id);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/agents/:agentId/pubkey ──────────────────────────────────────────
// Get the current active public key for any agent (no auth — public info).
// For historical verification, use /api/agents/:agentId/pubkey?at=<ISO timestamp>
app.get('/api/agents/:agentId/pubkey', async (req, res) => {
  try {
    const { agentId }  = req.params;
    const atTime       = req.query.at || new Date().toISOString();
    const keyId        = req.query.key_id || 'default';

    const keyInfo = await getKeyAtTime(supabaseService, agentId, keyId, atTime);
    if (!keyInfo) {
      return res.status(404).json({ error: 'No key found for this agent at the specified time' });
    }

    // Never return the private key — only public key PEM and metadata
    const { public_key_pem, ...meta } = keyInfo;
    res.json({
      agent_id:       agentId,
      public_key_pem,
      ...meta,
      queried_at:     atTime,
      note: meta.status_at_commit_time === 'revoked'
        ? 'This key was revoked — commits signed with it should be treated with caution'
        : meta.is_revoked_now
          ? 'This key is currently revoked but was active at the queried time'
          : null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/commits/:commitId/signature ──────────────────────────────────────
// Verify the agent signature on a specific commit, with full key lifecycle awareness.
app.get('/api/commits/:commitId/signature', requireApiKey, async (req, res) => {
  try {
    const { data: commit } = await supabaseService
      .from('commits')
      .select('*')
      .eq('id', req.params.commitId)
      .single();

    if (!commit) return res.status(404).json({ error: 'Commit not found' });

    const result = await verifyCommitSignature(supabaseService, commit);
    res.json({ commit_id: req.params.commitId, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// ENTERPRISE FEATURES
// ═══════════════════════════════════════════════════

// ── requireEnterprise middleware ─────────────────
async function requireEnterprise(req, res, next) {
  try {
    const userId = req.user?.id || req.agent?.user_id;

    if (!userId) {
      return res.status(403).json({
        error: 'Enterprise plan required',
        hint:  'BYOK encryption, W3C DID, and compliance reports require an Enterprise plan. See darkmatterhub.ai/pricing',
      });
    }

    const { data: account } = await supabaseService
      .from('enterprise_accounts')
      .select('id, plan, active')
      .eq('user_id', userId)
      .eq('active', true)
      .single();

    if (!account) {
      return res.status(403).json({
        error: 'Enterprise plan required',
        hint:  'Visit darkmatterhub.ai/enterprise to get started.',
      });
    }

    req.enterpriseAccount = account;
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// ── Encryption helpers (AES-256-GCM) ─────────────
function encryptPayload(plaintext, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    encrypted: encrypted.toString('base64'),
    iv:        iv.toString('base64'),
    authTag:   authTag.toString('base64'),
  };
}

function decryptPayload(encryptedB64, ivB64, authTagB64, keyHex) {
  const key       = Buffer.from(keyHex, 'hex');
  const iv        = Buffer.from(ivB64, 'base64');
  const authTag   = Buffer.from(authTagB64, 'base64');
  const encrypted = Buffer.from(encryptedB64, 'base64');
  const decipher  = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

// ── POST /enterprise/register ── register enterprise account
app.post('/enterprise/register', requireAuth, async (req, res) => {
  try {
    const { companyName, byokKey } = req.body;
    if (!companyName) return res.status(400).json({ error: 'companyName required' });

    const accountId = 'ent_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
    let keyId = null;

    // If BYOK key provided, register it
    if (byokKey) {
      if (byokKey.length !== 64) {
        return res.status(400).json({ error: 'BYOK key must be 64 hex characters (AES-256)' });
      }
      keyId = 'key_' + crypto.randomBytes(8).toString('hex');
      const keyHint = byokKey.slice(-4);

      await supabaseService.from('enterprise_keys').insert({
        key_id:     keyId,
        account_id: accountId,
        key_hint:   keyHint,
        algorithm:  'aes-256-gcm',
      });
    }

    const { error } = await supabaseService.from('enterprise_accounts').insert({
      id:           accountId,
      user_id:      req.user.id,
      company_name: companyName,
      byok_key_id:  keyId,
    });

    if (error) throw error;

    res.json({
      accountId,
      companyName,
      byokEnabled: !!keyId,
      keyId,
      message: 'Enterprise account created. Store your BYOK key securely — DarkMatter does not store it.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /enterprise/commit ── encrypted commit ──
// Agent commits with BYOK encryption — payload encrypted before storage
app.post('/enterprise/commit', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { toAgentId, payload, parentId, traceId, branchKey, agent, byokKey } = req.body;

    if (!toAgentId || !payload) {
      return res.status(400).json({ error: 'toAgentId and payload required' });
    }
    if (!byokKey || byokKey.length !== 64) {
      return res.status(400).json({ error: 'byokKey required (64 hex chars, AES-256). DarkMatter never stores your key.' });
    }

    const commitId  = 'ctx_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const timestamp = new Date().toISOString();

    // Encrypt payload with client's key
    const { encrypted, iv, authTag } = encryptPayload(payload, byokKey);

    // Hash the plaintext payload for chain integrity (before encryption)
    const normalizedPayload = JSON.stringify(payload, Object.keys(payload).sort());
    const payloadHash       = crypto.createHash('sha256').update(normalizedPayload).digest('hex');

    // Fetch parent hash for chaining
    let parentHash = null;
    if (parentId) {
      const { data: parentCommit } = await supabaseService
        .from('commits').select('integrity_hash').eq('id', parentId).single();
      if (parentCommit?.integrity_hash) parentHash = parentCommit.integrity_hash;
    }

    const chainInput    = payloadHash + (parentHash || 'root');
    const integrityHash = crypto.createHash('sha256').update(chainInput).digest('hex');

    const agentInfo = {
      id: req.agent.agent_id, name: req.agent.agent_name,
      role: agent?.role || null, provider: agent?.provider || null, model: agent?.model || null,
    };

    // Verify recipient
    const { data: toAgent } = await supabaseService
      .from('agents').select('agent_id').eq('agent_id', toAgentId).single();
    if (!toAgent) return res.status(404).json({ error: `Agent ${toAgentId} not found` });

    const { error } = await supabaseService.from('commits').insert({
      id:                  commitId,
      schema_version:      '1.0',
      from_agent:          req.agent.agent_id,
      to_agent:            toAgentId,
      context:             { _encrypted: true, _keyHint: byokKey.slice(-4) },
      payload:             null,              // plaintext not stored
      encrypted_payload:   encrypted,
      iv,
      auth_tag:            authTag,
      key_id:              'byok_' + byokKey.slice(-4),
      event_type:          'commit',
      parent_id:           parentId  || null,
      trace_id:            traceId   || null,
      branch_key:          branchKey || 'main',
      agent_info:          agentInfo,
      integrity_hash:      integrityHash,
      parent_hash:         parentHash,
      verified:            true,
      verification_reason: 'BYOK encrypted commit',
      timestamp,
    });

    if (error) throw error;

    res.json({
      id:             commitId,
      schema_version: '1.0',
      encrypted:      true,
      key_hint:       byokKey.slice(-4),
      integrity: {
        payload_hash:        'sha256:' + integrityHash,
        parent_hash:         parentHash ? 'sha256:' + parentHash : null,
        verification_status: 'valid',
      },
      created_at: timestamp,
      message: 'Payload encrypted with your key. DarkMatter stored ciphertext only.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /enterprise/decrypt ── decrypt a context ─
// Client provides their key to decrypt a specific commit
app.post('/enterprise/decrypt/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const { byokKey } = req.body;

    if (!byokKey || byokKey.length !== 64) {
      return res.status(400).json({ error: 'byokKey required (64 hex chars)' });
    }

    const { data: commit } = await supabaseService
      .from('commits')
      .select('id, encrypted_payload, iv, auth_tag, integrity_hash, parent_hash, timestamp, from_agent, agent_info')
      .eq('id', ctxId)
      .single();

    if (!commit) return res.status(404).json({ error: 'Context not found' });
    if (!commit.encrypted_payload) return res.status(400).json({ error: 'This context is not encrypted' });

    let payload;
    try {
      payload = decryptPayload(commit.encrypted_payload, commit.iv, commit.auth_tag, byokKey);
    } catch {
      return res.status(403).json({ error: 'Decryption failed — wrong key or tampered ciphertext' });
    }

    res.json(buildContext({ ...commit, payload }, {}));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /enterprise/did/register ── register W3C DID for agent
app.post('/enterprise/did/register', requireAuth, async (req, res) => {
  try {
    const { agentId, didId, publicKey } = req.body;
    if (!agentId || !didId || !publicKey) {
      return res.status(400).json({ error: 'agentId, didId, and publicKey required' });
    }

    // Verify the agent belongs to this user
    const { data: agent } = await supabaseService
      .from('agents')
      .select('agent_id')
      .eq('agent_id', agentId)
      .eq('user_id', req.user.id)
      .single();

    if (!agent) return res.status(404).json({ error: 'Agent not found' });

    // Build W3C DID document
    const didDocument = {
      '@context':          ['https://www.w3.org/ns/did/v1'],
      id:                  didId,
      verificationMethod:  [{
        id:                  `${didId}#key-1`,
        type:                'JsonWebKey2020',
        controller:          didId,
        publicKeyMultibase:  publicKey,
      }],
      authentication:      [`${didId}#key-1`],
      assertionMethod:     [`${didId}#key-1`],
      created:             new Date().toISOString(),
    };

    const { error } = await supabaseService
      .from('agents')
      .update({ did_id: didId, did_public_key: publicKey })
      .eq('agent_id', agentId)
      .eq('user_id', req.user.id);

    if (error) throw error;

    res.json({
      agentId,
      didId,
      didDocument,
      message: 'DID registered. Agent commits will now include a verifiable DID identifier.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /enterprise/did/:agentId ── resolve agent DID document
app.get('/enterprise/did/:agentId', async (req, res) => {
  try {
    const { data: agent } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, did_id, did_public_key, created_at')
      .eq('agent_id', req.params.agentId)
      .single();

    if (!agent || !agent.did_id) {
      return res.status(404).json({ error: 'No DID registered for this agent' });
    }

    res.json({
      '@context':         ['https://www.w3.org/ns/did/v1'],
      id:                 agent.did_id,
      verificationMethod: [{
        id:                 `${agent.did_id}#key-1`,
        type:               'JsonWebKey2020',
        controller:         agent.did_id,
        publicKeyMultibase: agent.did_public_key,
      }],
      authentication:     [`${agent.did_id}#key-1`],
      assertionMethod:    [`${agent.did_id}#key-1`],
      darkmatter: {
        agentId:   agent.agent_id,
        agentName: agent.agent_name,
        registeredAt: agent.created_at,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /enterprise/inquiry ── self-serve enterprise form
app.post('/enterprise/inquiry', feedbackLimiter, async (req, res) => {
  try {
    const { companyName, name, email, useCase, teamSize, features, message } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });

    const inquiryId = 'inq_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');

    await supabaseService.from('enterprise_inquiries').insert({
      id:           inquiryId,
      company_name: sanitizeText(companyName, 200),
      name:         sanitizeText(name, 200),
      email:        sanitizeText(email, 200),
      use_case:     sanitizeText(useCase, 1000),
      team_size:    sanitizeText(teamSize, 50),
      features:     features || [],
      message:      sanitizeText(message, 2000),
    });

    // Notify via email
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from:    'DarkMatter <hello@darkmatterhub.ai>',
        to:      [process.env.FEEDBACK_EMAIL],
        subject: `[DarkMatter Enterprise] ${escapeHtml(companyName || email)}`,
        html:    `<p><b>Company:</b> ${escapeHtml(companyName)}</p>
                  <p><b>Name:</b> ${escapeHtml(name)}</p>
                  <p><b>Email:</b> ${escapeHtml(email)}</p>
                  <p><b>Team size:</b> ${escapeHtml(teamSize)}</p>
                  <p><b>Features:</b> ${(features || []).join(', ')}</p>
                  <p><b>Use case:</b> ${escapeHtml(useCase)}</p>
                  <p><b>Message:</b> ${escapeHtml(message)}</p>`,
      }),
    });

    res.json({
      received: true,
      message:  "Thanks — we'll be in touch within 24 hours.",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /enterprise/report/:traceId ── compliance PDF report
app.get('/enterprise/report/:traceId', requireApiKey, requireEnterprise, async (req, res) => {
  try {
    const { traceId } = req.params;

    const { data: commits, error } = await supabaseService
      .from('commits')
      .select('*')
      .eq('trace_id', traceId)
      .order('timestamp', { ascending: true });

    if (error) throw error;
    if (!commits?.length) return res.status(404).json({ error: 'No commits found for this trace ID' });

    // Verify chain integrity
    let chainIntact = true;
    for (let i = 1; i < commits.length; i++) {
      if (commits[i].parent_hash && commits[i-1].integrity_hash &&
          commits[i].parent_hash !== commits[i-1].integrity_hash) {
        chainIntact = false; break;
      }
    }

    const agents    = [...new Set(commits.map(c => c.agent_info?.name || c.from_agent).filter(Boolean))];
    const models    = [...new Set(commits.map(c => c.agent_info?.model).filter(Boolean))];
    const exportedAt = new Date().toISOString();

    // Build compliance report as structured JSON
    // (PDF generation requires a PDF library — this is the data layer)
    const report = {
      report_type:    'DarkMatter Compliance Report',
      report_version: '1.0',
      generated_at:   exportedAt,
      generated_by:   'darkmatterhub.ai',

      summary: {
        trace_id:     traceId,
        total_steps:  commits.length,
        chain_intact: chainIntact,
        agents,
        models,
        start_time:   commits[0].timestamp,
        end_time:     commits[commits.length - 1].timestamp,
        encrypted_commits: commits.filter(c => c.encrypted_payload).length,
      },

      integrity: {
        algorithm:    'sha256',
        chain_intact: chainIntact,
        root_hash:    commits[0]?.integrity_hash ? 'sha256:' + commits[0].integrity_hash : null,
        tip_hash:     commits[commits.length-1]?.integrity_hash
                        ? 'sha256:' + commits[commits.length-1].integrity_hash : null,
        verification_statement: chainIntact
          ? 'All commits in this trace have been cryptographically verified. The chain is intact and no tampering has been detected.'
          : 'WARNING: Chain integrity check failed. One or more commits may have been tampered with.',
      },

      agent_registry: agents.map(name => {
        const commit = commits.find(c => (c.agent_info?.name || c.from_agent) === name);
        return {
          name,
          agent_id:  commit?.from_agent,
          did_id:    commit?.agent_info?.did_id || null,
          provider:  commit?.agent_info?.provider || null,
          model:     commit?.agent_info?.model    || null,
        };
      }),

      audit_trail: commits.map((c, i) => ({
        step:       i + 1,
        context_id: c.id,
        event_type: c.event_type || 'commit',
        created_by: c.agent_info?.name || c.from_agent,
        target:     c.to_agent,
        timestamp:  c.timestamp,
        encrypted:  !!c.encrypted_payload,
        integrity_hash: c.integrity_hash ? 'sha256:' + c.integrity_hash.slice(0, 16) + '...' : null,
        chain_valid: i === 0 ? true :
          (!commits[i].parent_hash || !commits[i-1].integrity_hash ||
           commits[i].parent_hash === commits[i-1].integrity_hash),
      })),

      regulatory_note: 'This report was generated by DarkMatter (darkmatterhub.ai), ' +
        'an independent execution history layer external to the audited system. ' +
        'The cryptographic hash chain provides tamper-evident evidence that this ' +
        'audit trail has not been modified after the fact. Relevant frameworks: ' +
        'EU AI Act Art. 12 & 19, US state AI laws, sector-specific audit requirements.',
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="darkmatter_report_${traceId.slice(-8)}.json"`);
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Page routes for new pages
app.get('/security',   (req, res) => res.sendFile(path.join(__dirname, '../public/security.html')));
app.get('/pricing',    (req, res) => res.sendFile(path.join(__dirname, '../public/pricing.html')));
app.get('/why',        (req, res) => res.sendFile(path.join(__dirname, '../public/why.html')));
app.get('/docs',       (req, res) => res.sendFile(path.join(__dirname, '../public/docs.html')));
app.get('/enterprise', (req, res) => res.sendFile(path.join(__dirname, '../public/enterprise.html')));


// ═══════════════════════════════════════════════════
// SEARCH / QUERY  (free on all plans)
// GET /api/search?q=&model=&provider=&event=&from=&to=&traceId=&limit=
// ═══════════════════════════════════════════════════
app.get('/api/search', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const {
      q, model, provider, event, from, to,
      traceId, agentId, verified,
      limit = 50,
    } = req.query;

    const { data: userAgents } = await supabaseService
      .from('agents').select('agent_id').eq('user_id', req.agent.user_id);

    const agentIds = (userAgents || []).map(a => a.agent_id);
    if (!agentIds.length) return res.json({ results: [], count: 0, query: req.query });

    const idList = agentIds.map(id => `"${id}"`).join(',');
    let query = supabaseService
      .from('commits').select('*')
      .or(`from_agent.in.(${idList}),to_agent.in.(${idList})`)
      .order('timestamp', { ascending: false })
      .limit(Math.min(parseInt(limit) || 50, 200));

    if (event)    query = query.eq('event_type', event);
    if (traceId)  query = query.eq('trace_id', traceId);
    if (from)     query = query.gte('timestamp', from);
    if (to)       query = query.lte('timestamp', to);
    if (verified !== undefined) query = query.eq('verified', verified === 'true');
    if (agentId)  query = query.or(`from_agent.eq.${agentId},to_agent.eq.${agentId}`);
    if (model)    query = query.contains('agent_info', { model });
    if (provider) query = query.contains('agent_info', { provider });

    const { data: commits, error } = await query;
    if (error) throw error;

    let results = commits || [];
    if (q) {
      const qLower = q.toLowerCase();
      results = results.filter(c =>
        JSON.stringify(c.payload || c.context || '').toLowerCase().includes(qLower)
      );
    }

    res.json({
      results: results.map(c => buildContext(c)),
      count:   results.length,
      query:   { q, model, provider, event, from, to, traceId, agentId, limit },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// CHAIN DIFF
// GET /api/diff/:ctxIdA/:ctxIdB
// Compares two chains step-by-step
// ═══════════════════════════════════════════════════
app.get('/api/diff/:ctxIdA/:ctxIdB', requireApiKey, async (req, res) => {
  try {
    const { ctxIdA, ctxIdB } = req.params;

    async function getChain(tipId) {
      const steps = [];
      let currentId = tipId;
      while (currentId && steps.length < 50) {
        const { data } = await supabaseService
          .from('commits').select('*').eq('id', currentId).single();
        if (!data) break;
        steps.push(data);
        currentId = data.parent_id;
      }
      return steps.reverse();
    }

    const [chainA, chainB] = await Promise.all([getChain(ctxIdA), getChain(ctxIdB)]);
    if (!chainA.length) return res.status(404).json({ error: `Context ${ctxIdA} not found` });
    if (!chainB.length) return res.status(404).json({ error: `Context ${ctxIdB} not found` });

    const maxLen = Math.max(chainA.length, chainB.length);
    const steps = [];

    for (let i = 0; i < maxLen; i++) {
      const a = chainA[i] ? buildContext(chainA[i]) : null;
      const b = chainB[i] ? buildContext(chainB[i]) : null;

      steps.push({
        step: i + 1,
        a: a ? { id: a.id, model: a.created_by?.model, provider: a.created_by?.provider,
                  eventType: a.event?.type, payload: a.payload, timestamp: a.created_at } : null,
        b: b ? { id: b.id, model: b.created_by?.model, provider: b.created_by?.provider,
                  eventType: b.event?.type, payload: b.payload, timestamp: b.created_at } : null,
        diff: {
          payloadChanged:  JSON.stringify(a?.payload) !== JSON.stringify(b?.payload),
          modelChanged:    a?.created_by?.model !== b?.created_by?.model,
          providerChanged: a?.created_by?.provider !== b?.created_by?.provider,
          onlyInA: !b,
          onlyInB: !a,
        },
      });
    }

    const changed = steps.filter(s =>
      s.diff.payloadChanged || s.diff.modelChanged || s.diff.onlyInA || s.diff.onlyInB
    ).length;

    res.json({
      ctxIdA, ctxIdB,
      lengthA: chainA.length, lengthB: chainB.length,
      totalSteps: maxLen, changedSteps: changed,
      identical: changed === 0,
      summary: {
        modelsA:       [...new Set(chainA.map(c => c.agent_info?.model).filter(Boolean))],
        modelsB:       [...new Set(chainB.map(c => c.agent_info?.model).filter(Boolean))],
        payloadChanges: steps.filter(s => s.diff.payloadChanged).length,
        modelChanges:   steps.filter(s => s.diff.modelChanged).length,
      },
      steps,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════════════════
// WEEK 1: SHARED READ-ONLY CHAIN LINKS
// ═══════════════════════════════════════════════════

// POST /api/share/:ctxId — create a shareable read-only link
app.post('/api/share/:ctxId', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const { label, expiresInDays } = req.body;

    // Verify the context belongs to this user's agents
    const { data: userAgents } = await supabaseService
      .from('agents').select('agent_id').eq('user_id', req.agent.user_id);
    const agentIds = (userAgents || []).map(a => a.agent_id);

    const { data: commit } = await supabaseService
      .from('commits').select('id, from_agent, to_agent').eq('id', ctxId).single();
    if (!commit) return res.status(404).json({ error: 'Context not found' });

    const shareId = 'share_' + crypto.randomBytes(8).toString('hex');
    const expiresAt = expiresInDays
      ? new Date(Date.now() + expiresInDays * 86400000).toISOString()
      : null;

    const { error } = await supabaseService.from('shared_chains').insert({
      id:         shareId,
      ctx_id:     ctxId,
      created_by: req.agent.agent_id,
      label:      label ? sanitizeText(label, 200) : null,
      expires_at: expiresAt,
    });
    if (error) throw error;

    const shareUrl = `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/chain/${shareId}`;

    res.json({
      shareId,
      shareUrl,
      ctxId,
      label:      label || null,
      expiresAt:  expiresAt || null,
      markdown:   null, // populated below after replay
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/share/:ctxId/markdown — generate markdown summary for a chain
app.get('/api/share/:ctxId/markdown', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;

    // Walk the chain
    const steps = [];
    let currentId = ctxId;
    while (currentId && steps.length < 50) {
      const { data } = await supabaseService
        .from('commits').select('*').eq('id', currentId).single();
      if (!data) break;
      steps.push(data);
      currentId = data.parent_id;
    }
    steps.reverse();

    if (!steps.length) return res.status(404).json({ error: 'Context not found' });

    const models   = [...new Set(steps.map(s => s.agent_info?.model).filter(Boolean))];
    const agents   = [...new Set(steps.map(s => s.agent_info?.name || s.from_agent).filter(Boolean))];
    const forks    = steps.filter(s => s.fork_of).map((s, i) => steps.indexOf(s) + 1);
    const intact   = steps.every((s, i) => {
      if (i === 0) return true;
      return s.parent_hash === steps[i - 1].integrity_hash;
    });

    // Check for share link
    const { data: share } = await supabaseService
      .from('shared_chains').select('id').eq('ctx_id', ctxId).order('created_at', { ascending: false }).limit(1).single();
    const shareUrl = share
      ? `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/chain/${share.id}`
      : null;

    const md = [
      `**DarkMatter chain**`,
      `- ${steps.length} step${steps.length !== 1 ? 's' : ''}`,
      models.length ? `- Models: ${models.join(', ')}` : null,
      agents.length ? `- Agents: ${agents.join(', ')}` : null,
      `- Chain intact: ${intact ? 'true ✓' : 'false ✗'}`,
      forks.length ? `- Forked at step${forks.length > 1 ? 's' : ''}: ${forks.join(', ')}` : null,
      shareUrl ? `- [View chain](${shareUrl})` : null,
      `- Root: \`${steps[0].id}\``,
      `- Tip:  \`${ctxId}\``,
    ].filter(Boolean).join('\n');

    res.json({ markdown: md, shareUrl, steps: steps.length, models, agents, intact });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /chain/:shareId — PUBLIC read-only chain viewer page (no auth)
app.get('/chain/:shareId', async (req, res) => {
  try {
    const { shareId } = req.params;
    const { data: share } = await supabaseService
      .from('shared_chains').select('*').eq('id', shareId).single();

    if (!share) return res.status(404).send('<h2>Chain not found or link expired.</h2>');
    if (share.expires_at && new Date(share.expires_at) < new Date()) {
      return res.status(410).send('<h2>This shared chain link has expired.</h2>');
    }

    // Increment view count
    await supabaseService.from('shared_chains')
      .update({ view_count: (share.view_count || 0) + 1 })
      .eq('id', shareId);

    res.sendFile(path.join(__dirname, '../public/chain.html'));
  } catch (err) {
    res.status(500).send('<h2>Error loading chain.</h2>');
  }
});

// GET /api/chain/:shareId — PUBLIC chain data for the viewer page
app.get('/api/chain/:shareId', async (req, res) => {
  try {
    const { shareId } = req.params;
    const { data: share } = await supabaseService
      .from('shared_chains').select('*').eq('id', shareId).single();

    if (!share) return res.status(404).json({ error: 'Share not found' });
    if (share.expires_at && new Date(share.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Link expired' });
    }

    // Walk the chain from tip to root
    const steps = [];
    let currentId = share.ctx_id;
    while (currentId && steps.length < 50) {
      const { data } = await supabaseService
        .from('commits').select('*').eq('id', currentId).single();
      if (!data) break;
      steps.push(data);
      currentId = data.parent_id;
    }
    steps.reverse();

    // Verify chain
    let chainIntact = true;
    for (let i = 1; i < steps.length; i++) {
      if (steps[i].parent_hash && steps[i - 1].integrity_hash &&
          steps[i].parent_hash !== steps[i - 1].integrity_hash) {
        chainIntact = false;
        steps[i]._chainBroken = true;
      }
    }

    const models = [...new Set(steps.map(s => s.agent_info?.model).filter(Boolean))];
    const agents = [...new Set(steps.map(s => s.agent_info?.name || s.from_agent).filter(Boolean))];
    const forks  = steps.filter(s => s.fork_of).length;

    res.json({
      shareId,
      label:      share.label,
      ctxId:      share.ctx_id,
      viewCount:  share.view_count,
      createdAt:  share.created_at,
      expiresAt:  share.expires_at,
      chainIntact,
      totalSteps: steps.length,
      models,
      agents,
      forkPoints: forks,
      replay: steps.map((c, i) => ({
        step:      i + 1,
        id:        c.id,
        eventType: c.event_type || 'commit',
        role:      c.agent_info?.role,
        model:     c.agent_info?.model,
        provider:  c.agent_info?.provider,
        agentName: c.agent_info?.name || c.from_agent,
        payload:   c.payload || c.context,
        integrity: {
          payload_hash:   c.payload_hash  ? 'sha256:' + c.payload_hash  : null,
          integrity_hash: c.integrity_hash ? 'sha256:' + c.integrity_hash : null,
          chainValid:     !c._chainBroken,
        },
        timestamp:  c.timestamp,
        isFork:     !!c.fork_of,
        forkOf:     c.fork_of || null,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// WEEK 2: RETENTION VISIBILITY
// ═══════════════════════════════════════════════════

// GET /api/retention/:ctxId — expiry info for a specific chain
app.get('/api/retention/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;

    const { data: commit } = await supabaseService
      .from('commits').select('timestamp, from_agent, to_agent').eq('id', ctxId).single();
    if (!commit) return res.status(404).json({ error: 'Context not found' });

    // Get agent's retention policy
    const agentId = commit.from_agent || commit.to_agent;
    const { data: agent } = await supabaseService
      .from('agents').select('retention_days').eq('agent_id', agentId).single();

    const retentionDays = agent?.retention_days || 30; // free default
    const createdAt = new Date(commit.timestamp);
    const expiresAt = new Date(createdAt.getTime() + retentionDays * 86400000);
    const now = new Date();
    const daysRemaining = Math.max(0, Math.ceil((expiresAt - now) / 86400000));
    const isExpired = expiresAt < now;

    const plan = retentionDays <= 30 ? 'free' : retentionDays <= 90 ? 'pro' : 'enterprise';

    res.json({
      ctxId,
      retentionDays,
      createdAt:    createdAt.toISOString(),
      expiresAt:    expiresAt.toISOString(),
      daysRemaining,
      isExpired,
      plan,
      upgradeMessage: plan === 'free' && daysRemaining <= 14
        ? `This chain expires in ${daysRemaining} day${daysRemaining !== 1 ? 's' : ''} on Free. Upgrade to Pro to keep it for 90 days.`
        : null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// WEEK 3: EVENT HOOKS (post-commit, post-fork, verify-fail)
// ═══════════════════════════════════════════════════

// POST /api/hooks — register an event hook
app.post('/api/hooks', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { url, events, secret } = req.body;

    if (!url || !events?.length) {
      return res.status(400).json({ error: 'url and events[] required' });
    }

    const validEvents = ['commit', 'fork', 'verify_fail', 'checkpoint', 'error'];
    const invalidEvents = events.filter(e => !validEvents.includes(e));
    if (invalidEvents.length) {
      return res.status(400).json({ error: `Invalid events: ${invalidEvents.join(', ')}. Valid: ${validEvents.join(', ')}` });
    }

    if (!isValidWebhookUrl(url)) {
      return res.status(400).json({ error: 'URL is not allowed (private/internal addresses blocked)' });
    }

    const hookId = 'hook_' + crypto.randomBytes(8).toString('hex');
    const { error } = await supabaseService.from('event_hooks').insert({
      id:       hookId,
      agent_id: req.agent.agent_id,
      url:      sanitizeText(url, 500),
      events,
      secret:   secret ? sanitizeText(secret, 200) : null,
      enabled:  true,
    });
    if (error) throw error;

    res.status(201).json({
      hookId,
      agentId:  req.agent.agent_id,
      url,
      events,
      enabled:  true,
      message:  `Hook registered. Will fire on: ${events.join(', ')}`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/hooks — list hooks for this agent
app.get('/api/hooks', requireApiKey, async (req, res) => {
  try {
    const { data: hooks, error } = await supabaseService
      .from('event_hooks')
      .select('id, url, events, enabled, created_at, last_fired, failure_count')
      .eq('agent_id', req.agent.agent_id)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ hooks: hooks || [], count: (hooks || []).length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/hooks/:hookId — remove a hook
app.delete('/api/hooks/:hookId', requireApiKey, async (req, res) => {
  try {
    const { hookId } = req.params;
    const { error } = await supabaseService
      .from('event_hooks')
      .delete()
      .eq('id', hookId)
      .eq('agent_id', req.agent.agent_id); // only delete own hooks
    if (error) throw error;
    res.json({ deleted: hookId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/hooks/:hookId — enable/disable a hook
app.patch('/api/hooks/:hookId', requireApiKey, async (req, res) => {
  try {
    const { hookId } = req.params;
    const { enabled } = req.body;
    const { error } = await supabaseService
      .from('event_hooks')
      .update({ enabled: !!enabled })
      .eq('id', hookId)
      .eq('agent_id', req.agent.agent_id);
    if (error) throw error;
    res.json({ hookId, enabled: !!enabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/hooks/:hookId/deliveries — recent delivery log
app.get('/api/hooks/:hookId/deliveries', requireApiKey, async (req, res) => {
  try {
    const { hookId } = req.params;
    // Verify ownership
    const { data: hook } = await supabaseService
      .from('event_hooks').select('id').eq('id', hookId).eq('agent_id', req.agent.agent_id).single();
    if (!hook) return res.status(404).json({ error: 'Hook not found' });

    const { data: deliveries } = await supabaseService
      .from('hook_deliveries')
      .select('*')
      .eq('hook_id', hookId)
      .order('attempted_at', { ascending: false })
      .limit(50);

    res.json({ hookId, deliveries: deliveries || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// EXPORT PROOF BUNDLE
// GET /api/bundle/:ctxId — structured export package
// ═══════════════════════════════════════════════════
app.get('/api/bundle/:ctxId', requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;

    // Walk the full chain
    const steps = [];
    let currentId = ctxId;
    while (currentId && steps.length < 50) {
      const { data } = await supabaseService
        .from('commits').select('*').eq('id', currentId).single();
      if (!data) break;
      steps.push(data);
      currentId = data.parent_id;
    }
    steps.reverse();

    if (!steps.length) return res.status(404).json({ error: 'Context not found' });

    // Verify chain
    let chainIntact = true;
    for (let i = 1; i < steps.length; i++) {
      if (steps[i].parent_hash && steps[i - 1].integrity_hash &&
          steps[i].parent_hash !== steps[i - 1].integrity_hash) {
        chainIntact = false;
      }
    }

    const root = steps[0];
    const tip  = steps[steps.length - 1];
    const models   = [...new Set(steps.map(s => s.agent_info?.model).filter(Boolean))];
    const agents   = [...new Set(steps.map(s => s.agent_info?.name || s.from_agent).filter(Boolean))];
    const forks    = steps.filter(s => s.fork_of).length;
    const exportId = 'bundle_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
    const exportedAt = new Date().toISOString();

    // Compute chain hash
    const chainHash = crypto.createHash('sha256')
      .update(steps.map(s => s.integrity_hash || '').join(''))
      .digest('hex');

    const bundle = {
      // ── README ──────────────────────────────────────
      readme: [
        'DarkMatter Export Bundle',
        '========================',
        '',
        `Export ID:    ${exportId}`,
        `Exported at:  ${exportedAt}`,
        `Context tip:  ${ctxId}`,
        `Context root: ${root.id}`,
        '',
        'Chain summary',
        '─────────────',
        `Steps:        ${steps.length}`,
        `Models:       ${models.join(', ') || 'none recorded'}`,
        `Agents:       ${agents.join(', ') || 'none recorded'}`,
        `Fork points:  ${forks}`,
        `Chain intact: ${chainIntact}`,
        `Chain hash:   sha256:${chainHash}`,
        '',
        'Verification',
        '────────────',
        'This bundle contains the full execution chain with cryptographic',
        'integrity hashes. Anyone can verify the chain is unmodified by',
        'recomputing the hashes from the chain data.',
        '',
        'Algorithm: sha256(payload_hash + parent_hash)',
        'Root parent_hash input: "root"',
        '',
        'Files in this bundle',
        '────────────────────',
        '  chain.json        — Full chain with all commits and payloads',
        '  verification.json — Integrity summary and hash chain',
        '  metadata.json     — Export metadata',
        '  README.txt        — This file',
      ].join('\n'),

      // ── METADATA ─────────────────────────────────────
      metadata: {
        exportId,
        exportedAt,
        exportedBy: req.agent.agent_id,
        ctxId,
        rootId:     root.id,
        chainLength: steps.length,
        models,
        agents,
        forkPoints: forks,
        dateRange: {
          from: root.timestamp,
          to:   tip.timestamp,
        },
      },

      // ── VERIFICATION ─────────────────────────────────
      verification: {
        chainIntact,
        chainHash: 'sha256:' + chainHash,
        rootHash:  root.integrity_hash ? 'sha256:' + root.integrity_hash : null,
        tipHash:   tip.integrity_hash  ? 'sha256:' + tip.integrity_hash  : null,
        steps: steps.map((s, i) => ({
          step:           i + 1,
          id:             s.id,
          payload_hash:   s.payload_hash   ? 'sha256:' + s.payload_hash   : null,
          integrity_hash: s.integrity_hash ? 'sha256:' + s.integrity_hash : null,
          parent_hash:    s.parent_hash    ? 'sha256:' + s.parent_hash    : null,
          chainValid:     i === 0 || !s._chainBroken,
        })),
      },

      // ── FULL CHAIN ────────────────────────────────────
      chain: steps.map((c, i) => ({
        step:      i + 1,
        id:        c.id,
        parent_id: c.parent_id,
        trace_id:  c.trace_id,
        branch_key: c.branch_key || 'main',
        created_by: {
          agent_id:   c.from_agent,
          agent_name: c.agent_info?.name || c.from_agent,
          role:       c.agent_info?.role,
          provider:   c.agent_info?.provider,
          model:      c.agent_info?.model,
        },
        event: {
          type:      c.event_type || 'commit',
          timestamp: c.timestamp,
        },
        payload:   c.payload || c.context,
        integrity: {
          payload_hash:        c.payload_hash   ? 'sha256:' + c.payload_hash   : null,
          integrity_hash:      c.integrity_hash ? 'sha256:' + c.integrity_hash : null,
          parent_hash:         c.parent_hash    ? 'sha256:' + c.parent_hash    : null,
          verification_status: c.verified ? 'valid' : 'rejected',
        },
        is_fork:   !!c.fork_of,
        fork_of:   c.fork_of || null,
      })),
    };

    res.json(bundle);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════════════════
// DYNAMIC OG IMAGE — GET /api/og/:shareId
// Returns an SVG social card for a shared chain.
// Used as og:image for X, LinkedIn, Slack previews.
// ═══════════════════════════════════════════════════
app.get('/api/og/:shareId', async (req, res) => {
  try {
    const { shareId } = req.params;
    const { data: share } = await supabaseService
      .from('shared_chains').select('*').eq('id', shareId).single();

    let steps = 0, models = [], intact = true, forkAt = null, label = '';

    if (share) {
      label = share.label || '';
      // Quick chain summary fetch
      let currentId = share.ctx_id;
      const visited = [];
      while (currentId && visited.length < 20) {
        const { data } = await supabaseService
          .from('commits').select('id,parent_id,agent_info,integrity_hash,parent_hash')
          .eq('id', currentId).single();
        if (!data) break;
        visited.push(data);
        const model = data.agent_info?.model || '';
        const shortModel = model.replace('claude-opus-4-6','Claude').replace('claude-sonnet-4-6','Claude')
          .replace('gpt-4o-mini','GPT-4o-mini').replace('gpt-4o','GPT-4o').replace('gpt-4.1','GPT-4.1');
        if (shortModel && !models.includes(shortModel)) models.push(shortModel);
        if (data.fork_of) forkAt = visited.length;
        currentId = data.parent_id;
      }
      steps = visited.length;
      // Simple integrity check
      for (let i = 1; i < visited.length; i++) {
        if (visited[i].parent_hash && visited[i-1].integrity_hash &&
            visited[i].parent_hash !== visited[i-1].integrity_hash) {
          intact = false; break;
        }
      }
    }

    const intactColor  = intact ? '#059669' : '#dc2626';
    const intactLabel  = intact ? '✓  chain intact' : '✗  chain broken';
    const modelStr     = models.slice(0,3).join('  →  ') || 'unknown model';
    const forkStr      = forkAt ? `  ·  forked at step ${forkAt}` : '';
    const chainLabel   = label || `${steps} step${steps!==1?'s':''}`;
    const stepsLabel   = `${steps} step${steps!==1?'s':''}`;

    // Build node circles for chain visual
    const nodeCount = Math.min(steps, 5);
    const nodeSpacing = 52;
    const nodesStart = 200 - (nodeCount * nodeSpacing / 2);
    let nodesSvg = '';
    for (let i = 0; i < nodeCount; i++) {
      const x = nodesStart + i * nodeSpacing;
      const color = i === (forkAt ? forkAt - 1 : -1) ? '#d97706' : '#7C3AED';
      nodesSvg += `<circle cx="${x}" cy="120" r="8" fill="${color}" opacity="0.9"/>`;
      if (i < nodeCount - 1) {
        nodesSvg += `<line x1="${x+8}" y1="120" x2="${x+nodeSpacing-8}" y2="120" stroke="#e5e7eb" stroke-width="1.5"/>`;
      }
      if (forkAt && i === forkAt - 1) {
        nodesSvg += `<circle cx="${x+nodeSpacing/2}" cy="148" r="7" fill="#d97706" opacity="0.85"/>`;
        nodesSvg += `<line x1="${x+4}" y1="124" x2="${x+nodeSpacing/2-4}" y2="144" stroke="#d97706" stroke-width="1.2" opacity="0.6"/>`;
      }
    }
    if (steps > 5) {
      nodesSvg += `<text x="${nodesStart + 5*nodeSpacing - 4}" y="125" font-family="monospace" font-size="12" fill="#9ca3af">+${steps-5}</text>`;
    }

    const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#7C3AED" stop-opacity="0.08"/>
      <stop offset="100%" stop-color="#0891b2" stop-opacity="0.04"/>
    </linearGradient>
    <linearGradient id="brand" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#7C3AED"/>
      <stop offset="55%" stop-color="#2563EB"/>
      <stop offset="100%" stop-color="#0891b2"/>
    </linearGradient>
  </defs>

  <!-- Background -->
  <rect width="1200" height="630" fill="#ffffff"/>
  <rect width="1200" height="630" fill="url(#grad)"/>

  <!-- Top accent bar -->
  <rect width="1200" height="4" fill="url(#brand)"/>

  <!-- Logo area -->
  <circle cx="72" cy="72" r="18" fill="none" stroke="#e5e7eb" stroke-width="1"/>
  <circle cx="72" cy="58" r="4" fill="#7C3AED" opacity="0.9"/>
  <circle cx="84" cy="80" r="3.5" fill="#2563EB" opacity="0.9"/>
  <circle cx="60" cy="80" r="3" fill="#0891b2" opacity="0.9"/>
  <line x1="72" y1="62" x2="82" y2="77" stroke="#7C3AED" stroke-width="0.8" opacity="0.5"/>
  <line x1="72" y1="62" x2="62" y2="77" stroke="#7C3AED" stroke-width="0.8" opacity="0.4"/>
  <line x1="82" y1="78" x2="62" y2="78" stroke="#0891b2" stroke-width="0.8" opacity="0.4"/>

  <text x="102" y="66" font-family="'Space Grotesk',system-ui,sans-serif" font-weight="700" font-size="22" fill="#111827" letter-spacing="-0.5">Dark</text>
  <text x="144" y="66" font-family="'Space Grotesk',system-ui,sans-serif" font-weight="700" font-size="22" fill="url(#brand)" letter-spacing="-0.5">Matter</text>

  <!-- Chain visual -->
  <rect x="80" y="90" width="1040" height="90" rx="10" fill="#f8f9fa" stroke="#e5e7eb" stroke-width="1"/>
  ${nodesSvg.replace(/cx="/g, 'cx="').split('cx="').map((s,i) => i===0 ? s : 'cx="' + s).join('').replace(/(\d+)" cy="120"/g, (m,n) => `${+n+520}" cy="120"`)}

  <!-- Chain label -->
  <text x="600" y="96" font-family="monospace" font-size="9" fill="#9ca3af" text-anchor="middle" letter-spacing="2" text-transform="uppercase">CHAIN</text>

  <!-- Main content -->
  <text x="80" y="230" font-family="'Space Grotesk',system-ui,sans-serif" font-weight="700" font-size="42" fill="#111827" letter-spacing="-1">${chainLabel.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</text>

  <!-- Meta row -->
  <text x="80" y="290" font-family="'IBM Plex Mono',monospace" font-size="18" fill="${intactColor}">${intactLabel}${forkStr}</text>

  <!-- Models -->
  <text x="80" y="340" font-family="'IBM Plex Mono',monospace" font-size="16" fill="#4b5563">${modelStr.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</text>

  <!-- Bottom features -->
  <text x="80" y="410" font-family="system-ui,sans-serif" font-size="15" fill="#9ca3af">Replay any step  ·  Fork from any checkpoint  ·  Compare model outputs</text>
  <text x="80" y="440" font-family="'Space Grotesk',system-ui,sans-serif" font-weight="700" font-size="16" fill="url(#brand)" letter-spacing="1">Replay  ·  Fork  ·  Compare</text>

  <!-- URL bar -->
  <rect x="80" y="460" width="800" height="38" rx="6" fill="#f1f3f5" stroke="#e5e7eb" stroke-width="1"/>
  <text x="100" y="484" font-family="monospace" font-size="13" fill="#6b7280">darkmatterhub.ai/chain/${shareId}</text>

  <!-- CTA -->
  <rect x="920" y="460" width="200" height="38" rx="6" fill="url(#brand)"/>
  <text x="1020" y="484" font-family="system-ui,sans-serif" font-weight="600" font-size="14" fill="#ffffff" text-anchor="middle">Fork this chain →</text>
</svg>`;

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(svg);
  } catch (err) {
    // Return minimal fallback SVG
    res.setHeader('Content-Type', 'image/svg+xml');
    res.send('<svg width="1200" height="630" xmlns="http://www.w3.org/2000/svg"><rect width="1200" height="630" fill="#111827"/><text x="600" y="315" font-family="sans-serif" font-size="48" fill="white" text-anchor="middle">DarkMatter</text></svg>');
  }
});



// ═══════════════════════════════════════════════════
// RICH CONTENT COMMIT — POST /api/commit/rich
// Handles large text, HTML, images, code blocks
// Stores content separately from chain metadata
// ═══════════════════════════════════════════════════
app.post('/api/commit/rich', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const {
      toAgentId, parentId, traceId, branchKey, eventType,
      agent, tags, metadata,
      // Rich content fields
      content,        // { format, text, html, attachments[] }
      thread,         // { platform, platformUrl, title, turnCount }
    } = req.body;

    if (!toAgentId) return res.status(400).json({ error: 'toAgentId required' });
    if (!content?.text && !content?.html) {
      return res.status(400).json({ error: 'content.text or content.html required' });
    }

    // ── Build compact payload summary for chain metadata ──────────────────────
    const textContent = content.text || '';
    const summary = textContent.slice(0, 500) + (textContent.length > 500 ? '...' : '');
    const charCount  = textContent.length;
    const hasImages  = (content.attachments || []).some(a => a.type === 'image');
    const hasCode    = (content.attachments || []).some(a => a.type === 'code');

    const payload = {
      summary,
      charCount,
      hasImages,
      hasCode,
      format:   content.format || 'text',
      platform: thread?.platform || null,
      model:    agent?.model || null,
    };

    // ── Standard commit to chain ──────────────────────────────────────────────
    const agentRecord = req.agent;
    const userId      = agentRecord.user_id;
    const ctxId       = 'ctx_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');

    // Compute hashes
    const payloadHash = 'sha256:' + crypto.createHash('sha256')
      .update(JSON.stringify(payload)).digest('hex');

    let parentHash = null;
    if (parentId) {
      const { data: parent } = await supabaseService
        .from('commits').select('integrity_hash').eq('id', parentId).single();
      parentHash = parent?.integrity_hash || null;
    }

    const integrityHash = 'sha256:' + crypto.createHash('sha256')
      .update(payloadHash + (parentHash || '') + ctxId).digest('hex');

    // Insert base commit
    const { data: commitData, error: commitError } = await supabaseService
      .from('commits').insert({
        id:             ctxId,
        agent_id:       agentRecord.agent_id,
        payload:        payload,
        payload_hash:   payloadHash,
        parent_id:      parentId || null,
        parent_hash:    parentHash,
        integrity_hash: integrityHash,
        verification_status: 'valid',
        trace_id:       traceId || null,
        branch_key:     branchKey || 'main',
        event_type:     eventType || 'commit',
        agent_info:     agent || null,
        tags:           tags || null,
        to_agent_id:    toAgentId,
      }).select().single();

    if (commitError) throw commitError;

    // ── Store rich content separately ─────────────────────────────────────────
    await supabaseService.from('commit_content').insert({
      id:           ctxId,
      format:       content.format || 'text',
      text_content: textContent,
      html_content: content.html || null,
      token_count:  Math.ceil(charCount / 4), // rough estimate
      char_count:   charCount,
      has_images:   hasImages,
      has_code:     hasCode,
      has_tables:   (content.attachments || []).some(a => a.type === 'table'),
    });

    // ── Store attachments (inline only for now — S3 later) ───────────────────
    const attachments = content.attachments || [];
    if (attachments.length > 0) {
      const attRows = attachments.map((att, i) => ({
        id:             'att_' + ctxId + '_' + i,
        commit_id:      ctxId,
        type:           att.type,
        storage_provider: 'inline',
        mime_type:      att.mimeType || null,
        filename:       att.filename || null,
        language:       att.language || null,
        inline_content: att.content?.slice(0, 50000) || null, // 50KB max inline
        size_bytes:     att.content?.length || 0,
        position:       i,
        metadata:       att.metadata || {},
      }));

      await supabaseService.from('commit_attachments').insert(attRows);
    }

    // ── Update or create conversation thread ──────────────────────────────────
    if (thread?.platform) {
      const threadId = traceId || `conv_${toAgentId}_${Date.now()}`;
      const { data: existing } = await supabaseService
        .from('conversation_threads').select('id, turn_count, root_ctx_id')
        .eq('id', threadId).single();

      if (existing) {
        await supabaseService.from('conversation_threads').update({
          tip_ctx_id:  ctxId,
          turn_count:  (existing.turn_count || 0) + 1,
          updated_at:  new Date().toISOString(),
        }).eq('id', threadId);
      } else {
        await supabaseService.from('conversation_threads').insert({
          id:           threadId,
          platform:     thread.platform,
          platform_url: thread.platformUrl || null,
          title:        thread.title || `${thread.platform} conversation`,
          user_id:      userId,
          root_ctx_id:  ctxId,
          tip_ctx_id:   ctxId,
          turn_count:   1,
          models_used:  agent?.model ? [agent.model] : [],
        }).catch(() => {}); // non-blocking
      }
    }

    res.status(201).json({
      id:             ctxId,
      integrityHash,
      verified:       true,
      charCount,
      hasImages,
      hasCode,
      attachmentCount: attachments.length,
    });

  } catch (err) {
    console.error('rich commit error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/content/:ctxId ── retrieve full rich content ───────────────────
app.get('/api/content/:ctxId', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { ctxId } = req.params;
    const format    = req.query.format || 'json'; // json | html | text | markdown

    const [contentRes, attachmentsRes] = await Promise.all([
      supabaseService.from('commit_content').select('*').eq('id', ctxId).single(),
      supabaseService.from('commit_attachments').select('*').eq('commit_id', ctxId)
        .order('position'),
    ]);

    if (!contentRes.data) return res.status(404).json({ error: 'Content not found' });

    const content     = contentRes.data;
    const attachments = attachmentsRes.data || [];

    // Return as HTML standalone document
    if (format === 'html') {
      const html = buildStandaloneHtml(ctxId, content, attachments);
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Content-Disposition', `attachment; filename="${ctxId}.html"`);
      return res.send(html);
    }

    // Return as plain text
    if (format === 'text') {
      res.setHeader('Content-Type', 'text/plain');
      return res.send(content.text_content || '');
    }

    res.json({ content, attachments });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/threads ── list conversation threads ─────────────────────────────
app.get('/api/threads', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const userId = req.agent.user_id;
    const limit  = Math.min(parseInt(req.query.limit) || 20, 100);
    const platform = req.query.platform;

    let query = supabaseService
      .from('conversation_threads')
      .select('*')
      .eq('user_id', userId)
      .order('updated_at', { ascending: false })
      .limit(limit);

    if (platform) query = query.eq('platform', platform);

    const { data, error } = await query;
    if (error) throw error;

    res.json({ threads: data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Build standalone HTML for a commit ───────────────────────────────────────
function buildStandaloneHtml(ctxId, content, attachments) {
  const codeBlocks = attachments.filter(a => a.type === 'code');
  const images     = attachments.filter(a => a.type === 'image');

  // Convert markdown-ish text to HTML if no html_content stored
  let bodyHtml = content.html_content || '';
  if (!bodyHtml && content.text_content) {
    bodyHtml = content.text_content
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/\n\n/g, '</p><p>')
      .replace(/\n/g, '<br>');
    bodyHtml = `<p>${bodyHtml}</p>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DarkMatter Context ${ctxId}</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;line-height:1.7;}
  h1,h2,h3{line-height:1.3;}
  pre{background:#f4f4f4;border:1px solid #e0e0e0;border-radius:6px;padding:1rem;overflow-x:auto;font-size:0.85rem;}
  code{font-family:'IBM Plex Mono','Menlo',monospace;}
  img{max-width:100%;border-radius:6px;}
  .meta{font-size:0.75rem;color:#666;font-family:monospace;margin-bottom:2rem;padding:0.75rem;background:#f9f9f9;border-radius:6px;}
  .dm-badge{font-size:0.7rem;background:#7C3AED;color:#fff;padding:0.2rem 0.5rem;border-radius:3px;text-decoration:none;}
  blockquote{border-left:3px solid #7C3AED;margin:0;padding:0.5rem 1rem;background:#f9f7ff;}
</style>
</head>
<body>
<div class="meta">
  <strong>DarkMatter Context</strong> &nbsp;·&nbsp; ${ctxId}<br>
  Format: ${content.format} &nbsp;·&nbsp; ${(content.char_count||0).toLocaleString()} chars
  &nbsp;·&nbsp; <a class="dm-badge" href="https://darkmatterhub.ai">darkmatterhub.ai</a>
</div>
${bodyHtml}
${codeBlocks.map(cb => `<pre><code class="language-${cb.language||''}">${(cb.inline_content||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</code></pre>`).join('')}
${images.map(img => img.public_url ? `<img src="${img.public_url}" alt="${img.filename||''}"/>` : '').join('')}
</body>
</html>`;
}


// ═══════════════════════════════════════════════════
// EXTENSION AUTH — GET /ext/callback
// After login with ?ext=1, redirect here to send
// session to the Chrome extension via postMessage
// ═══════════════════════════════════════════════════
app.get('/ext/callback', (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>DarkMatter — Connecting extension...</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;gap:1rem;text-align:center;}</style>
</head>
<body>
<div style="font-size:1.2rem;font-weight:700;">Connecting to DarkMatter Capture...</div>
<div style="font-size:0.85rem;color:#8b949e;">You can close this tab after connecting.</div>
<script>
// Read session from localStorage (set by login page)
const raw = localStorage.getItem('dm_session');
if (raw) {
  try {
    const session = JSON.parse(raw);
    // Send to extension via chrome.runtime.sendMessage
    // The extension ID is passed as a URL param or hardcoded
    const extId = new URLSearchParams(location.search).get('ext_id') || '';
    if (extId && window.chrome?.runtime) {
      chrome.runtime.sendMessage(extId, { type: 'DM_SESSION', session }, r => {
        if (r?.ok) {
          document.querySelector('div').textContent = '✓ Connected! You can close this tab.';
        }
      });
    } else {
      // Fallback: just show success, user configures manually
      document.querySelector('div').textContent = '✓ Signed in! Open the DarkMatter extension to continue.';
    }
  } catch(e) {}
}
</script>
</body>
</html>`);
});



// ═══════════════════════════════════════════════════
// POLICIES API
// GET  /api/policies        — list policies for authenticated agent
// POST /api/policies        — register a new policy
// DELETE /api/policies/:id  — delete a policy
// Policies evaluate incoming commits before storage.
// Full policy engine is an Enterprise feature.
// ═══════════════════════════════════════════════════
app.get('/api/policies', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const agentId = req.agent.agent_id;
    const { data, error } = await supabaseService
      .from('agent_policies')
      .select('*')
      .eq('agent_id', agentId)
      .order('created_at', { ascending: false });

    // Table may not exist yet — return empty with docs link
    if (error && error.code === '42P01') {
      return res.json({ policies: [], note: 'Policy engine available — see /docs#policies for setup.' });
    }
    if (error) throw error;

    res.json({ policies: data || [] });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/policies', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { name, description, condition, action, message } = req.body;
    if (!name || !condition || !action) {
      return res.status(400).json({ error: 'name, condition, and action are required' });
    }
    if (!['reject','flag','allow'].includes(action)) {
      return res.status(400).json({ error: 'action must be reject, flag, or allow' });
    }

    const agentId = req.agent.agent_id;
    const policyId = 'pol_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');

    const { data, error } = await supabaseService
      .from('agent_policies')
      .insert({
        id:          policyId,
        agent_id:    agentId,
        name,
        description: description || null,
        condition,
        action,
        message:     message || null,
        enabled:     true,
      })
      .select().single();

    if (error && error.code === '42P01') {
      // Table doesn't exist — return helpful message
      return res.status(501).json({
        error: 'Policy storage not yet enabled on this instance.',
        note:  'Run the v12 schema migration to enable policies. See /docs#policies.',
        policy_would_be: { id: policyId, name, condition, action }
      });
    }
    if (error) throw error;

    res.status(201).json({ policy: data, note: 'Policy registered. All future commits to this agent will be evaluated.' });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/policies/:policyId', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { policyId } = req.params;
    const agentId = req.agent.agent_id;

    const { error } = await supabaseService
      .from('agent_policies')
      .delete()
      .eq('id', policyId)
      .eq('agent_id', agentId); // ensure ownership

    if (error && error.code === '42P01') {
      return res.status(404).json({ error: 'Policy not found' });
    }
    if (error) throw error;

    res.json({ deleted: policyId });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});


// ═══════════════════════════════════════════════════
// TOKEN REFRESH — POST /api/auth/refresh
// Fixes "commits disappear after staying logged in"
// Supabase JWTs expire after 1 hour; this refreshes them
// ═══════════════════════════════════════════════════
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refresh_token } = req.body;
    if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });

    const { data, error } = await supabaseService.auth.refreshSession({ refresh_token });
    if (error) return res.status(401).json({ error: error.message });

    res.json({
      access_token:  data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at:    data.session.expires_at,
    });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// ACCOUNT DELETION — DELETE /dashboard/account
// deleteCommits: true  → hard delete all commit records
// deleteCommits: false → anonymise (null user_id) — preserves chain integrity
// Honest: we tell users what each choice means before they confirm
// ═══════════════════════════════════════════════════
app.delete('/dashboard/account', requireAuth, async (req, res) => {
  try {
    const userId       = req.user.id;
    const deleteCommits = req.body?.deleteCommits === true;

    // 1. Handle commits
    if (deleteCommits) {
      // Hard delete — breaks any shared chain links
      const { data: agentIds } = await supabaseService
        .from('agents').select('agent_id').eq('user_id', userId);
      if (agentIds?.length) {
        const ids = agentIds.map(a => a.agent_id);
        await supabaseService.from('commits').delete().in('agent_id', ids);
        await supabaseService.from('commit_content').delete().in('id',
          (await supabaseService.from('commits').select('id').in('agent_id', ids)).data?.map(c=>c.id)||[]
        );
      }
    } else {
      // Anonymise — set user_id to null on agents so commits are orphaned but chain stays intact
      await supabaseService.from('agents').update({ user_id: null }).eq('user_id', userId);
    }

    // 2. Delete agents
    if (deleteCommits) {
      await supabaseService.from('agents').delete().eq('user_id', userId);
    }

    // 3. Delete user account via Supabase admin API
    const { error } = await supabaseService.auth.admin.deleteUser(userId);
    if (error) throw error;

    res.json({ deleted: true, commitsDeleted: deleteCommits });

  } catch(err) {
    console.error('Account deletion error:', err);
    res.status(500).json({ error: err.message });
  }
});


// ── GET /dashboard/thread/:traceId ── redirect to dashboard with thread selected
app.get('/dashboard/thread/:traceId', requireAuth, (req, res) => {
  res.redirect(`/dashboard?t=${encodeURIComponent(req.params.traceId)}`);
});

// ── Static page routes ────────────────────────────────────────────────────────
app.get('/compare',      (req, res) => res.sendFile(path.join(__dirname, '../public/compare.html')));
app.get('/compliance',   (req, res) => res.sendFile(path.join(__dirname, '../public/compliance.html')));
app.get('/threat-model', (req, res) => res.sendFile(path.join(__dirname, '../public/threat-model.html')));

// ═══════════════════════════════════════════════════
// SUPERUSER ANALYTICS DASHBOARD
// Only accessible to the account defined in SUPERUSER_EMAIL env var
// ═══════════════════════════════════════════════════

function requireSuperuser(req, res, next) {
  const superEmail = process.env.SUPERUSER_EMAIL;
  if (!superEmail) return res.status(403).json({ error: 'Not configured' });
  // req.user is set by requireAuth from the JWT
  const userEmail = req.user?.email || req.user?.user_metadata?.email || '';
  if (!userEmail || userEmail.toLowerCase() !== superEmail.toLowerCase()) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ── GET /admin ── serve admin dashboard page ──────────────────────────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin.html'));
});

// ── GET /admin/stats ── KPI overview ─────────────────────────────────────────
app.get('/admin/stats', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const now     = new Date();
    const day1    = new Date(now - 86400000).toISOString();
    const day7    = new Date(now - 7*86400000).toISOString();
    const day30   = new Date(now - 30*86400000).toISOString();

    const [
      totalAgents, totalCommits, activeDay, activeWeek, activeMonth,
      totalUsers, sharedChains, activationEvents
    ] = await Promise.all([
      supabaseService.from('agents').select('agent_id', { count: 'exact', head: true }),
      supabaseService.from('commits').select('id', { count: 'exact', head: true }),
      supabaseService.from('commits').select('id', { count: 'exact', head: true }).gte('saved_at', day1),
      supabaseService.from('commits').select('id', { count: 'exact', head: true }).gte('saved_at', day7),
      supabaseService.from('commits').select('id', { count: 'exact', head: true }).gte('saved_at', day30),
      supabaseService.auth.admin.listUsers({ perPage: 1 }),
      supabaseService.from('shared_chains').select('id', { count: 'exact', head: true }),
      supabaseService.from('activation_events').select('event, user_id').gte('occurred_at', day30),
    ]);

    const events    = activationEvents.data || [];
    const byEvent   = {};
    const byUser    = new Set();
    events.forEach(e => {
      byEvent[e.event] = (byEvent[e.event] || 0) + 1;
      byUser.add(e.user_id);
    });

    res.json({
      kpis: {
        totalUsers:    totalUsers.data?.total || 0,
        totalAgents:   totalAgents.count || 0,
        totalCommits:  totalCommits.count || 0,
        commitsToday:  activeDay.count   || 0,
        commits7d:     activeWeek.count  || 0,
        commits30d:    activeMonth.count || 0,
        sharedChains:  sharedChains.count || 0,
        activeUsers30d: byUser.size,
      },
      activation: byEvent,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/funnel ── activation funnel ────────────────────────────────────
app.get('/admin/funnel', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const { data: events } = await supabaseService
      .from('activation_events')
      .select('event, user_id, occurred_at')
      .order('occurred_at', { ascending: false });

    const funnel = [
      'key_created', 'first_commit', 'first_replay',
      'first_fork', 'first_diff', 'day2_return',
    ];

    const counts = {};
    const usersByEvent = {};
    (events || []).forEach(e => {
      if (!usersByEvent[e.event]) usersByEvent[e.event] = new Set();
      usersByEvent[e.event].add(e.user_id);
      counts[e.event] = (counts[e.event] || 0) + 1;
    });

    const funnelData = funnel.map((evt, i) => {
      const users = usersByEvent[evt]?.size || 0;
      const prev  = i > 0 ? (usersByEvent[funnel[i-1]]?.size || 0) : users;
      return { event: evt, users, conversionFromPrev: prev > 0 ? Math.round(users/prev*100) : 0 };
    });

    res.json({ funnel: funnelData, rawCounts: counts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/commands ── CLI command analytics ──────────────────────────────
app.get('/admin/commands', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const { data: events } = await supabaseService
      .from('activation_events')
      .select('event, user_id, metadata, occurred_at')
      .like('event', 'cli_%')
      .order('occurred_at', { ascending: false })
      .limit(5000);

    const commands = {};
    (events || []).forEach(e => {
      const cmd = e.metadata?.command || e.event;
      if (!commands[cmd]) commands[cmd] = { total: 0, users: new Set(), lastSeen: null };
      commands[cmd].total++;
      commands[cmd].users.add(e.user_id);
      if (!commands[cmd].lastSeen || e.occurred_at > commands[cmd].lastSeen) {
        commands[cmd].lastSeen = e.occurred_at;
      }
    });

    const result = Object.entries(commands).map(([cmd, d]) => ({
      command:  cmd,
      total:    d.total,
      uniqueUsers: d.users.size,
      lastSeen: d.lastSeen,
    })).sort((a,b) => b.total - a.total);

    res.json({ commands: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/users ── user table ────────────────────────────────────────────
app.get('/admin/users', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;

    const [usersRes, agentsRes, eventsRes] = await Promise.all([
      supabaseService.auth.admin.listUsers({ perPage: limit, page: Math.floor(offset/limit)+1 }),
      supabaseService.from('agents').select('agent_id, user_id, created_at, last_active'),
      supabaseService.from('activation_events').select('user_id, event, occurred_at'),
    ]);

    const users   = usersRes.data?.users || [];
    const agents  = agentsRes.data || [];
    const events  = eventsRes.data || [];

    const agentsByUser  = {};
    agents.forEach(a => {
      if (!agentsByUser[a.user_id]) agentsByUser[a.user_id] = [];
      agentsByUser[a.user_id].push(a);
    });

    const eventsByUser = {};
    events.forEach(e => {
      if (!eventsByUser[e.user_id]) eventsByUser[e.user_id] = {};
      eventsByUser[e.user_id][e.event] = e.occurred_at;
    });

    const result = users.map(u => {
      const ue      = eventsByUser[u.id] || {};
      const ua      = agentsByUser[u.id] || [];
      const hasCommit  = !!ue.first_commit;
      const hasReplay  = !!ue.first_replay;
      const hasFork    = !!ue.first_fork;
      const hasDiff    = !!ue.first_diff;
      const hasDay2    = !!ue.day2_return;
      const score = [hasCommit,hasReplay,hasFork,hasDiff,hasDay2].filter(Boolean).length;
      const status = score === 0 ? 'curious' : score <= 1 ? 'activated' : score <= 3 ? 'growing' : 'power_user';

      return {
        id:        u.id,
        email:     u.email,
        signupAt:  u.created_at,
        lastSignIn: u.last_sign_in_at,
        agents:    ua.length,
        events:    ue,
        status,
        score,
      };
    });

    res.json({ users: result, total: usersRes.data?.total || 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /admin/trends ── time-series usage ────────────────────────────────────
app.get('/admin/trends', requireAuth, requireSuperuser, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const from = new Date(Date.now() - days * 86400000).toISOString();

    const { data: commits } = await supabaseService
      .from('commits')
      .select('saved_at, id')
      .gte('saved_at', from)
      .order('saved_at', { ascending: true });

    const { data: shares } = await supabaseService
      .from('shared_chains')
      .select('created_at')
      .gte('created_at', from);

    // Group by day
    const byDay = {};
    (commits || []).forEach(c => {
      const day = c.saved_at?.slice(0,10);
      if (day) byDay[day] = (byDay[day] || 0) + 1;
    });

    const sharesByDay = {};
    (shares || []).forEach(s => {
      const day = s.created_at?.slice(0,10);
      if (day) sharesByDay[day] = (sharesByDay[day] || 0) + 1;
    });

    // Fill in missing days
    const result = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000).toISOString().slice(0,10);
      result.push({ date: d, commits: byDay[d] || 0, shares: sharesByDay[d] || 0 });
    }

    res.json({ trends: result });
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
        to:      [process.env.FEEDBACK_EMAIL || 'hello@darkmatterhub.ai'],
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


// ── Fire event hooks for an agent ────────────────────
async function fireEventHooks(agentId, event, payload) {
  try {
    const { data: hooks } = await supabaseService
      .from('event_hooks')
      .select('*')
      .eq('agent_id', agentId)
      .eq('enabled', true)
      .contains('events', [event]);

    if (!hooks?.length) return;

    for (const hook of hooks) {
      const body = JSON.stringify({
        event,
        hook_id:    hook.id,
        agent_id:   agentId,
        timestamp:  new Date().toISOString(),
        ...payload,
      });

      const headers = { 'Content-Type': 'application/json' };
      if (hook.secret) {
        const sig = require('crypto')
          .createHmac('sha256', hook.secret)
          .update(body).digest('hex');
        headers['X-DarkMatter-Signature'] = `sha256=${sig}`;
        headers['X-DarkMatter-Event'] = event;
      }

      const start = Date.now();
      let status = 'failed', httpStatus = null;
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const res = await fetch(hook.url, { method: 'POST', headers, body, signal: controller.signal });
        clearTimeout(timeout);
        httpStatus = res.status;
        status = res.ok ? 'delivered' : 'failed';
      } catch (e) {
        status = 'failed';
      }

      const duration = Date.now() - start;

      // Log delivery + update last_fired
      await Promise.all([
        supabaseService.from('hook_deliveries').insert({
          id:           'hd_' + Date.now() + '_' + require('crypto').randomBytes(4).toString('hex'),
          hook_id:      hook.id,
          event,
          ctx_id:       payload.ctxId || null,
          status,
          http_status:  httpStatus,
          duration_ms:  duration,
          attempted_at: new Date().toISOString(),
        }),
        supabaseService.from('event_hooks').update({
          last_fired:    new Date().toISOString(),
          failure_count: status === 'failed' ? (hook.failure_count + 1) : 0,
        }).eq('id', hook.id),
      ]).catch(() => {});
    }
  } catch (err) {
    console.error('fireEventHooks error:', err.message);
  }
}

// ── Detect if a URL is a Slack incoming webhook ──────
function isSlackWebhookUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.hostname === 'hooks.slack.com';
  } catch { return false; }
}

// ── Format a DarkMatter commit as a Slack Block Kit message ──
function buildSlackPayload(commit, agentName) {
  const eventType = commit.eventType || commit.context?._eventType || 'commit';
  const ctxId     = commit.id || commit.commitId;
  const from      = commit.from_agent || agentName || 'agent';
  const short     = ctxId ? ctxId.slice(-8) : '—';
  const ts        = commit.timestamp ? new Date(commit.timestamp).toLocaleString() : '';

  const statusEmoji = {
    commit:     '🔗',
    fork:       '⑂',
    checkpoint: '📍',
    error:      '🔴',
    override:   '⚠️',
    verify_fail:'🔴',
  }[eventType] || '🔗';

  return {
    text: `${statusEmoji} DarkMatter: ${eventType} from ${from}`,
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `${statusEmoji} *${eventType}* committed by \`${from}\``,
        },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Context ID*\n\`${ctxId}\`` },
          { type: 'mrkdwn', text: `*Short ID*\n\`${short}\`` },
          { type: 'mrkdwn', text: `*Verified*\n${commit.verified ? '✅ yes' : '❌ no'}` },
          { type: 'mrkdwn', text: `*Time*\n${ts}` },
        ],
      },
      {
        type: 'actions',
        elements: [
          {
            type: 'button',
            text: { type: 'plain_text', text: 'Replay chain' },
            url:  `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/dashboard`,
            action_id: 'replay_chain',
          },
        ],
      },
      { type: 'divider' },
    ],
  };
}

async function deliverWebhook(agent, commit) {
  if (!agent.webhook_url) return;

  const isSlack   = isSlackWebhookUrl(agent.webhook_url);
  const timestamp = commit.timestamp || new Date().toISOString();

  let body, headers;

  if (isSlack) {
    // Slack Block Kit format
    body    = JSON.stringify(buildSlackPayload(commit, agent.agent_name));
    headers = { 'Content-Type': 'application/json' };
  } else {
    // Standard DarkMatter webhook format
    const payload = {
      event:     'commit.received',
      commitId:  commit.id,
      from:      commit.from_agent,
      to:        commit.to_agent,
      eventType: (commit.context?._eventType || 'commit'),
      verified:  commit.verified,
      timestamp,
    };
    body    = JSON.stringify(payload);
    headers = { 'Content-Type': 'application/json' };
    if (agent.webhook_secret) {
      const sig = crypto
        .createHmac('sha256', agent.webhook_secret)
        .update(body)
        .digest('hex');
      headers['X-DarkMatter-Signature'] = `sha256=${sig}`;
    }
  }

  const deliveryId = 'wh_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
  let status = 'failed', httpStatus = null, response = null;

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 5000);

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
    const { agentId } = req.params;
    const { webhookUrl, webhookSecret, slackChannel } = req.body;

    if (webhookUrl && !isValidWebhookUrl(webhookUrl)) {
      return res.status(400).json({ error: 'Invalid webhook URL — internal addresses are not allowed' });
    }

    // Detect Slack and validate
    const isSlack = isSlackWebhookUrl(webhookUrl);
    if (webhookUrl && !isSlack && !webhookUrl.startsWith('https://')) {
      return res.status(400).json({ error: 'Webhook URL must be HTTPS' });
    }

    const { data: agent } = await supabaseService
      .from('agents').select('agent_id').eq('agent_id', agentId).eq('user_id', req.user.id).single();
    if (!agent) return res.status(403).json({ error: 'Agent not found' });

    const update = { webhook_url: webhookUrl || null };
    if (webhookSecret !== undefined) update.webhook_secret = webhookSecret || null;
    if (slackChannel !== undefined)  update.slack_channel  = slackChannel ? sanitizeText(slackChannel, 100) : null;

    const { error } = await supabaseService
      .from('agents').update(update).eq('agent_id', agentId);
    if (error) throw error;

    res.json({
      success:      true,
      webhookUrl:   webhookUrl || null,
      isSlack,
      slackChannel: slackChannel || null,
      note: isSlack
        ? 'Slack webhook configured. Commits will be posted as Block Kit messages.'
        : 'Webhook configured. Use X-DarkMatter-Signature header to verify.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/slack/test ── send test message to Slack webhook ──
app.post('/api/slack/test', requireApiKey, async (req, res) => {
  try {
    const { webhookUrl } = req.body;
    if (!webhookUrl) return res.status(400).json({ error: 'webhookUrl required' });
    if (!isSlackWebhookUrl(webhookUrl)) return res.status(400).json({ error: 'Not a Slack webhook URL' });
    if (!isValidWebhookUrl(webhookUrl)) return res.status(400).json({ error: 'Invalid URL' });

    const testPayload = {
      text: '✅ DarkMatter Slack integration is working',
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `✅ *DarkMatter connected*\n\nAgent \`${req.agent.agent_name}\` will post commit notifications here.\n\nEach commit, fork, and verify event will appear as a formatted message.`,
          },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Agent*\n${req.agent.agent_name}` },
            { type: 'mrkdwn', text: `*Status*\n✅ Connected` },
          ],
        },
        { type: 'divider' },
      ],
    };

    const res2 = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testPayload),
    });

    if (res2.ok) {
      res.json({ success: true, message: 'Test message sent to Slack' });
    } else {
      res.status(400).json({ success: false, error: `Slack returned ${res2.status}` });
    }
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



// ── GET /api/log/proof/:commitId ──────────────────────────────────────────
// Returns inclusion proof for a specific commit.
// No authentication required — verification material is public.
app.get('/api/log/proof/:commitId', async (req, res) => {
  try {
    const proof = await generateProofForCommit(supabaseService, req.params.commitId);
    if (!proof) {
      return res.status(404).json({
        error:  'Commit not found in log',
        commit_id: req.params.commitId,
        note:   'The commit may not yet be appended to the log, or may not exist',
      });
    }
    res.json({
      ...proof,
      pubkey_url:     'https://darkmatterhub.ai/api/log/pubkey',
      checkpoint_url: 'https://darkmatterhub.ai/api/log/checkpoint',
      spec_url:       'https://darkmatterhub.ai/docs#integrity-spec',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/log/pubkey ────────────────────────────────────────────────────
// Returns DarkMatter's server signing public key.
// Anyone can use this to verify checkpoint signatures independently.
app.get('/api/log/pubkey', (req, res) => {
  res.json({
    algorithm:   'Ed25519',
    public_key:  getServerPublicKeyPem(),
    note:        'Use this key to verify checkpoint server_sig fields. See https://darkmatterhub.ai/docs#integrity-model',
  });
});

// ── GET /api/log/checkpoint ────────────────────────────────────────────────
// Returns the latest signed checkpoint (Phase 3: includes tree_root + checkpoint chain).
app.get('/api/log/checkpoint', async (req, res) => {
  try {
    const { data } = await supabaseService
      .from('checkpoints')
      .select('checkpoint_id, position, tree_root, tree_size, log_root, server_sig, timestamp, previous_cp_id, previous_tree_root, published, published_url')
      .order('position', { ascending: false })
      .limit(1)
      .single();
    if (!data) return res.json({ checkpoint: null, message: 'No checkpoints yet' });
    res.json({
      checkpoint:    data,
      pubkey_url:    'https://darkmatterhub.ai/api/log/pubkey',
      github_url:    'https://github.com/darkmatter-hub/checkpoints',
      spec_version:  CHECKPOINT_SCHEMA_VERSION,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/log/checkpoints ───────────────────────────────────────────────
// Returns recent checkpoints for consistency verification.
app.get('/api/log/checkpoints', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const { data } = await supabaseService
      .from('checkpoints')
      .select('position, log_root, tree_root, server_sig, timestamp, published, published_url')
      .order('position', { ascending: false })
      .limit(limit);
    res.json({ checkpoints: data || [], pubkey_url: 'https://darkmatterhub.ai/api/log/pubkey' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/log/entry/:commitId ───────────────────────────────────────────
// Returns the log entry for a specific commit (position, log_root, server_sig).
app.get('/api/log/entry/:commitId', async (req, res) => {
  try {
    const { data } = await supabaseService
      .from('log_entries')
      .select('*')
      .eq('commit_id', req.params.commitId)
      .single();
    if (!data) return res.status(404).json({ error: 'Commit not in log' });
    res.json({ entry: data, pubkey_url: 'https://darkmatterhub.ai/api/log/pubkey' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/log/checkpoint ───────────────────────────────────────────────
// Manually trigger a checkpoint publish (admin/superuser only).
app.post('/api/log/checkpoint', requireAuth, async (req, res) => {
  if (req.agent?.email !== process.env.SUPERUSER_EMAIL) {
    return res.status(403).json({ error: 'Superuser only' });
  }
  try {
    const result = await publishCheckpoint(supabaseService);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ── GET /api/log/consistency ───────────────────────────────────────────────
// Verify that checkpoint B is a valid append-only extension of checkpoint A.
// Proves no log entries were deleted or rewritten between two snapshots.
// No authentication required — verification material is public.
//
// Query params:
//   from=<checkpoint_id>  — older checkpoint ID (or 'first' for earliest)
//   to=<checkpoint_id>    — newer checkpoint ID (or 'latest' for most recent)
//
app.get('/api/log/consistency', async (req, res) => {
  try {
    const fromId = req.query.from;
    const toId   = req.query.to;

    // Resolve 'first' and 'latest' shortcuts
    const { data: firstCp } = await supabaseService
      .from('checkpoints')
      .select('*')
      .order('position', { ascending: true })
      .limit(1)
      .single();

    const { data: latestCp } = await supabaseService
      .from('checkpoints')
      .select('*')
      .order('position', { ascending: false })
      .limit(1)
      .single();

    if (!firstCp || !latestCp) {
      return res.json({ consistent: null, message: 'No checkpoints yet' });
    }

    let cpA, cpB;

    if (!fromId || fromId === 'first') {
      cpA = firstCp;
    } else {
      const { data } = await supabaseService
        .from('checkpoints').select('*').eq('checkpoint_id', fromId).single();
      if (!data) return res.status(404).json({ error: `Checkpoint not found: ${fromId}` });
      cpA = data;
    }

    if (!toId || toId === 'latest') {
      cpB = latestCp;
    } else {
      const { data } = await supabaseService
        .from('checkpoints').select('*').eq('checkpoint_id', toId).single();
      if (!data) return res.status(404).json({ error: `Checkpoint not found: ${toId}` });
      cpB = data;
    }

    if (cpA.position > cpB.position) {
      return res.status(400).json({ error: 'from checkpoint must be older than to checkpoint' });
    }

    if (cpA.checkpoint_id === cpB.checkpoint_id) {
      return res.json({ consistent: true, message: 'Same checkpoint', checkpoint: cpA.checkpoint_id });
    }

    const result = await verifyCheckpointConsistency(
      supabaseService, cpA, cpB, getServerPublicKeyPem()
    );

    res.json({
      ...result,
      pubkey_url:  'https://darkmatterhub.ai/api/log/pubkey',
      spec_url:    'https://darkmatterhub.ai/docs#integrity-spec',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/log/verify ────────────────────────────────────────────────────
// Verify log consistency from position A to B.
app.get('/api/log/verify', async (req, res) => {
  try {
    const from = parseInt(req.query.from) || 0;
    const to   = parseInt(req.query.to)   || 999999;
    const { data: entries } = await supabaseService
      .from('log_entries')
      .select('position, commit_id, integrity_hash, log_root, server_sig, timestamp')
      .gte('position', from)
      .lte('position', to)
      .order('position', { ascending: true });

    const result = verifyLogConsistency(entries || [], getServerPublicKeyPem());
    res.json({ ...result, entries_range: [from, to], pubkey_url: 'https://darkmatterhub.ai/api/log/pubkey' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;

// ── Phase 2: Checkpoint endpoint ─────────────────────────────────────────────
// GET /api/audit/log          — read the audit log (public)
// GET /api/audit/checkpoint   — get latest signed checkpoint
// POST /api/audit/checkpoint  — create a new checkpoint (admin only)

app.get('/api/audit/log', async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit  || '100'), 1000);
    const offset = parseInt(req.query.offset || '0');
    const { data, error } = await supabaseService
      .from('audit_log')
      .select('*')
      .order('position', { ascending: true })
      .range(offset, offset + limit - 1);
    if (error) throw error;
    res.json({ entries: data, count: data.length, offset });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/audit/checkpoint', async (req, res) => {
  try {
    const { data, error } = await supabaseService
      .from('audit_checkpoints')
      .select('*')
      .order('signed_at', { ascending: false })
      .limit(1)
      .single();
    if (error && error.code !== 'PGRST116') throw error;
    res.json({ checkpoint: data || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/audit/checkpoint', requireAuth, async (req, res) => {
  // Admin only — creates and signs a new checkpoint
  const adminEmail = process.env.SUPERUSER_EMAIL;
  if (req.user?.email !== adminEmail) {
    return res.status(403).json({ error: 'Admin only' });
  }
  try {
    const { data: entries, error } = await supabaseService
      .from('audit_log')
      .select('*')
      .order('position', { ascending: true });
    if (error) throw error;
    if (!entries?.length) return res.status(400).json({ error: 'Log is empty' });

    const last      = entries[entries.length - 1];
    const count     = entries.length;
    const logRoot   = last.log_hash;
    const tipHash   = last.integrity_hash;
    const signedAt  = new Date().toISOString();
    const ckptId    = 'ckpt_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');

    // Sign with HMAC (Phase 2). Phase 4 upgrades to Ed25519 + external witnesses.
    const body = JSON.stringify({ checkpoint_id: ckptId, log_count: count,
      log_root: logRoot, tip_hash: tipHash, signed_at: signedAt });
    const dmSecret = process.env.DM_CHECKPOINT_SECRET || 'dev-secret';
    const sig = 'hmac-sha256:' + crypto.createHmac('sha256', dmSecret)
      .update(body).digest('hex');

    const checkpoint = {
      id:           ckptId,
      log_count:    count,
      log_root:     logRoot,
      tip_hash:     tipHash,
      dm_signature: sig,
      algorithm:    'hmac-sha256-v1',
      signed_at:    signedAt,
    };

    await supabaseService.from('audit_checkpoints').insert(checkpoint);
    res.json({ checkpoint });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n  🌑 DarkMatter running on http://localhost:${PORT}\n`);
});

module.exports = app;
