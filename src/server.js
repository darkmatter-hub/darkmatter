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
      id:        c.id,
      from:      agentMap[c.from_agent] || c.from_agent,
      fromId:    c.from_agent,
      to:        agentMap[c.to_agent]   || c.to_agent,
      toId:      c.to_agent,
      verified:  c.verified,
      timestamp: c.timestamp,
      context:   c.context || {},
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
// AGENT API ROUTES (requires API key)
// ═══════════════════════════════════════════════════

// ── POST /api/commit ─────────────────────────────────
app.post('/api/commit', apiLimiter, requireApiKey, async (req, res) => {
  try {
    const { toAgentId, context, eventType } = req.body;
    if (!toAgentId || !context) {
      return res.status(400).json({ error: 'toAgentId and context required' });
    }

    // Validate eventType
    const VALID_TYPES = ['commit', 'revert', 'override', 'branch', 'merge', 'error', 'spawn', 'timeout', 'retry', 'checkpoint', 'consent', 'redact', 'escalate', 'audit'];
    const resolvedType = (eventType && VALID_TYPES.includes(eventType)) ? eventType : 'commit';

    const commitId  = 'commit_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
    const timestamp = new Date().toISOString();

    // Verify recipient exists
    const { data: toAgent } = await supabaseService
      .from('agents')
      .select('agent_id')
      .eq('agent_id', toAgentId)
      .single();

    if (!toAgent) {
      // Store as rejected commit — agent not found
      await supabaseService
        .from('commits')
        .insert({
          id:                  commitId,
          from_agent:          req.agent.agent_id,
          to_agent:            null,
          context:             { ...context, _eventType: resolvedType },
          verified:            false,
          verification_reason: `Recipient agent ${toAgentId} not found`,
          timestamp,
        });

      return res.status(404).json({
        commitId,
        verified:  false,
        reason:    `Agent ${toAgentId} not found`,
        timestamp,
      });
    }

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

    // Deliver webhook to recipient agent if configured (fire and forget)
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
        context:    { ...context, _eventType: resolvedType },
        verified:   true,
        timestamp,
      }).catch(err => console.error('webhook delivery error:', err));
    }

    res.json({
      commitId,
      from:      req.agent.agent_name,
      to:        toAgentId,
      verified:  true,
      eventType: resolvedType,
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

// ── GET /api/stats ── public network stats ───────────
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
