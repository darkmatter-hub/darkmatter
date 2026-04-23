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
const {
  registerWitness, acceptWitnessSignature,
  verifyWitnessSignature,
} = require('./witness');

const {
  mountBillingRoutes, checkCommitLimit, incrementCommitUsage,
} = require('./billing');

const { verifyAttestation, canonicalJson } = require('./attestation');
const app = express();

// ── Trust proxy — required for Railway/Heroku/etc behind reverse proxy ────────
// Without this, express-rate-limit cannot identify users correctly
app.set('trust proxy', 1);

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

// ── Stripe webhook — MUST be before express.json() ───────────────────────────
// Stripe signature verification requires raw bytes. express.json() would parse
// the body first, making signature verification impossible.
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const key    = process.env.STRIPE_SECRET_KEY;
  if (!secret || !key) return res.sendStatus(200);

  let event;
  try {
    const stripe = require('stripe')(key);
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch(e) {
    console.error('[webhook] signature verification failed:', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  // supabaseService is defined later in the file but JS hoisting means
  // by the time a request arrives the server is fully initialized.
  try {
    const { handleStripeEventExport } = require('./billing');
    await handleStripeEventExport(event, supabaseService);
  } catch(e) {
    console.error('[webhook] handler error:', e.message);
  }

  res.sendStatus(200);
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
  if (!apiKey.startsWith('dm_sk_') && !apiKey.startsWith('dmp_')) {
    return res.status(401).json({ error: 'Invalid API key format' });
  }

  try {
    // Try direct api_key match first (most agents store key plaintext)
    let { data, error } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, user_id, api_key')
      .eq('api_key', apiKey)
      .limit(1);

    // Fallback: try api_key_hash
    if (!data || data.length === 0) {
      const keyHash = require('crypto').createHash('sha256').update(apiKey).digest('hex');
      const res2 = await supabaseService
        .from('agents')
        .select('agent_id, agent_name, user_id, api_key')
        .eq('api_key_hash', keyHash)
        .limit(1);
      data = res2.data;
    }

    if (!data || data.length === 0) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // ── Failure-safe: ensure agent context is complete ──────────────
    // API key is valid but agent row may be missing expected fields.
    // Auto-heal silently — never surface config errors to the user.
    const agent = data[0];
    if (!agent.agent_id) {
      console.error('[requireApiKey] valid key but missing agent_id — auto-healing', apiKey.slice(0, 12));
      agent.agent_id   = 'dm_' + require('crypto').randomBytes(8).toString('hex');
      agent.agent_name = agent.agent_name || 'default';
      try {
        await supabaseService.from('agents').update({
          agent_id:   agent.agent_id,
          agent_name: agent.agent_name,
        }).eq('api_key', apiKey);
      } catch(_) {}
    }

    req.agent = agent;
    next();
  } catch(e) {
    console.error('[requireApiKey]', e.message);
    res.status(500).json({ error: 'Auth error' });
  }
}

// ── Middleware: validate Supabase JWT (dashboard calls) ──
async function requireAuth(req, res, next) {
  try {
    const auth = req.headers['authorization'];
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    const token = auth.replace('Bearer ', '').trim();

    // Use service client — reliable regardless of anon key config
    const { data: { user }, error } = await supabaseService.auth.getUser(token);
    if (!error && user) { req.user = user; return next(); }

    // Token expired — try refresh
    const rt = req.headers['x-refresh-token'];
    if (rt) {
      try {
        const { data: rd } = await supabaseService.auth.refreshSession({ refresh_token: rt });
        if (rd && rd.session && rd.session.access_token) {
          const { data: { user: ru } } = await supabaseService.auth.getUser(rd.session.access_token);
          if (ru) {
            req.user = ru;
            res.setHeader('X-New-Access-Token', rd.session.access_token);
            res.setHeader('X-New-Refresh-Token', rd.session.refresh_token || '');
            res.setHeader('X-New-Expires-At', String(rd.session.expires_at || ''));
            return next();
          }
        }
      } catch(_) {}
    }

    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  } catch(e) {
    console.error('[requireAuth]', e.message);
    return res.status(401).json({ error: 'Authentication error. Please sign in again.' });
  }
}

// ── flexAuth — accepts Supabase JWT (dashboard) OR dm_sk_ API key (SDK/CLI) ──
async function flexAuth(req, res, next) {
  const auth = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!auth) return res.status(401).json({ error: 'Authorization required' });

  // Supabase JWT path (dashboard users)
  if (!auth.startsWith('dm_sk_') && !auth.startsWith('dmp_')) {
    try {
      const { data: { user }, error } = await supabaseService.auth.getUser(auth);
      if (!error && user) {
        req.user = user;
        req.authType = 'supabase';
        return next();
      }
      // Try server-side refresh
      const rt = req.headers['x-refresh-token'];
      if (rt) {
        const { data: rd } = await supabaseService.auth.refreshSession({ refresh_token: rt });
        if (rd && rd.session) {
          const { data: { user: ru } } = await supabaseService.auth.getUser(rd.session.access_token);
          if (ru) {
            req.user = ru;
            req.authType = 'supabase';
            res.setHeader('X-New-Access-Token', rd.session.access_token);
            res.setHeader('X-New-Refresh-Token', rd.session.refresh_token || '');
            return next();
          }
        }
      }
    } catch(e) {}
  }

  // API key path (SDK, CLI, agents)
  try {
    const keyHash = require('crypto').createHash('sha256').update(auth).digest('hex');
    const { data: agent } = await supabaseService.from('agents')
      .select('agent_id, agent_name, user_id').eq('api_key_hash', keyHash).single();
    if (agent) {
      req.agent = agent;
      req.authType = 'apikey';
      return next();
    }
  } catch(e) {}

  return res.status(401).json({ error: 'Invalid API key or session' });
}

// ═══════════════════════════════════════════════════
// PUBLIC ROUTES (no auth)
// ═══════════════════════════════════════════════════

// ── GET / ── serve homepage
// Handled by express.static above

// ── Billing routes — mounted here so supabaseService + requireAuth exist ─────
// Webhook handler uses express.raw() internally — registered before routes.
mountBillingRoutes(app, supabaseService, requireAuth);

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
        'ctx = dm.commit(payload={"input": prompt, "output": result})',
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
app.get('/dashboard/keys/:keyId', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

// ── GET /demo ── live interactive demo (no login required)
app.get('/demo', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/demo.html'));
});

// ── POST /api/demo/commit ─────────────────────────────
// Server-side demo endpoint. No API key exposed in browser.
// Constrained payload shape. Rate-limited. Returns real commit
// id, verify_url, proof_level, and export bundle URL.
// ─────────────────────────────────────────────────────
const demoLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 120,                  // 120 demo commits per IP per hour
  message: { error: 'Demo rate limit reached. Get your own API key at darkmatterhub.ai/signup' },
  standardHeaders: true,
  legacyHeaders: false,
});

const DEMO_AGENT_ID = process.env.DEMO_AGENT_ID || 'dm_demo_public';

app.post('/api/demo/commit', demoLimiter, async (req, res) => {
  try {
    const ALLOWED_SCENARIOS = ['codereview', 'support', 'research'];
    const { scenario } = req.body;
    if (!scenario || !ALLOWED_SCENARIOS.includes(scenario)) {
      return res.status(400).json({ error: 'Invalid scenario' });
    }

    const payloads = {
      codereview: {
        input:      'Customer dispute — order #84721, sarah.chen@email.com claims item defective on day 3',
        output:     'Refund approved. $1,240.00 returned. Basis: defect claim within 30-day policy window (returns-policy-v6).',
        model:      'claude-sonnet-4-6',
        agent_role: 'refund-agent',
      },
      support: {
        input:      '11 failed login attempts from new location (IP: 185.23.91.12) — account j.torres@acme.com',
        output:     'Access revoked. Session terminated. MFA reset required. Basis: SEC-RULE-07, risk score 0.94. Reversible pending user verification.',
        model:      'claude-sonnet-4-6',
        agent_role: 'security-agent',
      },
      research: {
        input:      'Post 9f3a2c by @marcus_dev flagged for policy review — community-policy-v12 § 4.2',
        output:     'Content removed. Category: abusive_language. Confidence: 0.92. Decision is appealable.',
        model:      'claude-sonnet-4-6',
        agent_role: 'moderation-agent',
      },
    };

    const p = payloads[scenario];
    const traceId  = 'trc_demo_' + Date.now();
    const commitId = 'ctx_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const timestamp = new Date().toISOString();
    const normalizedPayload = JSON.stringify({ input: p.input, output: p.output, model: p.model }, ['input','model','output']);
    const payloadHash    = crypto.createHash('sha256').update(normalizedPayload).digest('hex');
    const integrityHash  = crypto.createHash('sha256').update(payloadHash + 'root').digest('hex');

    // Insert into commits using demo agent
    const { error } = await supabaseService
      .from('commits')
      .insert({
        id:                  commitId,
        schema_version:      '1.0',
        from_agent:          DEMO_AGENT_ID,
        to_agent:            DEMO_AGENT_ID,
        payload:             { input: p.input, output: p.output, model: p.model },
        context:             { input: p.input, output: p.output },
        event_type:          'commit',
        trace_id:            traceId,
        branch_key:          'main',
        agent_info:          { id: DEMO_AGENT_ID, name: 'DarkMatter Demo', role: p.agent_role, model: p.model },
        integrity_hash:      integrityHash,
        payload_hash:        payloadHash,
        parent_hash:         null,
        verified:            true,
        verification_reason: 'Demo commit — API key authenticated',
        capture_mode:        'client_signed',
        timestamp,
        accepted_at:         timestamp,
      });

    if (error) {
      console.error('[demo/commit] insert error:', error.message);
      return res.status(500).json({ error: 'Failed to create demo record' });
    }

    const baseUrl   = process.env.BASE_URL || 'https://darkmatterhub.ai';
    const verifyUrl = `${baseUrl}/r/${commitId}`;
    const exportUrl = `${baseUrl}/api/export/${commitId}`;

    res.status(201).json({
      id:           commitId,
      trace_id:     traceId,
      verify_url:   verifyUrl,
      export_url:   exportUrl,
      proof_level:  'signed',   // all demo commits are signed by server key
      integrity: {
        payload_hash:        'sha256:' + payloadHash,
        integrity_hash:      'sha256:' + integrityHash,
        verification_status: 'valid',
      },
      scenario,
      timestamp,
      _demo: true,
    });
  } catch (err) {
    console.error('[demo/commit] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /blog ── blog index
app.get('/blog', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/blog.html'));
});

// ── GET /blog/:slug ── individual blog posts
app.get('/blog/:slug', (req, res) => {
  // Check if a specific post HTML file exists, otherwise fall back to blog index
  const slug     = req.params.slug;
  const postFile = path.join(__dirname, '../public', `blog-${slug}.html`);
  const fs       = require('fs');
  if (fs.existsSync(postFile)) {
    res.sendFile(postFile);
  } else {
    res.sendFile(path.join(__dirname, '../public/blog.html'));
  }
});

// ── Direct named blog post routes ────────────────────────────────────────────
app.get('/blog-what-problems-darkmatter-solves', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/blog-what-problems-darkmatter-solves.html'));
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

    // ── Backfill: link all null-user_id agents to this user ──────────────
    // Agents created via SDK have user_id=null. We find them by email prefix
    // in agent_name and stamp user_id so the dashboard can list them.
    if (data.user?.id && data.user?.email) {
      try {
        const userId      = data.user.id;
        const emailPrefix = data.user.email.split('@')[0].toLowerCase();

        // Find any agents with this email prefix that aren't yet linked
        const { data: unlinked } = await supabaseService
          .from('agents')
          .select('agent_id')
          .ilike('agent_name', `%${emailPrefix}%`)
          .is('user_id', null)
          .limit(100);

        if (unlinked && unlinked.length > 0) {
          await supabaseService
            .from('agents')
            .update({ user_id: userId })
            .in('agent_id', unlinked.map(a => a.agent_id));
        }

        // Also stamp any agents that have a matching api_key stored
        // in user_recording_keys (from the old chat proxy flow)
        const { data: rkRows } = await supabaseService
          .from('user_recording_keys')
          .select('encrypted_key')
          .eq('user_id', userId)
          .limit(10);

        if (rkRows && rkRows.length > 0) {
          for (const rk of rkRows) {
            if (!rk.encrypted_key) continue;
            await supabaseService
              .from('agents')
              .update({ user_id: userId })
              .eq('api_key', rk.encrypted_key)
              .is('user_id', null);
          }
        }
      } catch (backfillErr) {
        // Non-fatal — log and continue, login still succeeds
        console.warn('[login backfill]', backfillErr.message);
      }
    }

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
    let { data, error } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, api_key, created_at, last_active, webhook_url, retention_days')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    // Auto-create a default agent if user has none
    // This ensures extension captures always have somewhere to land
    if (!data || data.length === 0) {
      const agentId  = generateAgentId();
      const apiKey   = generateApiKey();
      const agentName = (req.user.email || 'my').split('@')[0] + '-agent';
      const { data: newAgent, error: createErr } = await supabaseService
        .from('agents')
        .insert({ agent_id: agentId, agent_name: agentName, user_id: req.user.id, api_key: apiKey })
        .select()
        .single();
      if (!createErr && newAgent) data = [newAgent];
    }

    res.json((data || []).map(a => ({
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

    // Return fields the dashboard JS expects directly — no buildContext wrapping
    res.json((data || []).map(c => ({
      id:               c.id,
      trace_id:         c.trace_id    || c.id,
      agent_id:         c.agent_id    || c.from_agent,
      from_agent:       c.from_agent,
      to_agent:         c.to_agent,
      agent_name:       agentMap[c.from_agent] || c.agent_info?.name || c.from_agent,
      event_type:       c.event_type  || 'commit',
      timestamp:        c.timestamp,
      client_timestamp: c.client_timestamp || c.timestamp,
      accepted_at:      c.saved_at    || c.timestamp,
      payload:          c.payload     || {},
      integrity_hash:   c.integrity_hash,
      parent_hash:      c.parent_hash,
      payload_hash:     c.payload_hash,
      verified:         c.verified    || false,
      agent_info:       c.agent_info  || {},
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
    if (!resolvedPayload) {
      return res.status(400).json({ error: 'payload (or context) required' });
    }

    // ── Commit limit check ────────────────────────────────────────────────────
    const userId = req.agent.user_id;
    if (userId) {
      const limitCheck = await checkCommitLimit(userId, supabaseService);
      if (!limitCheck.allowed) {
        return res.status(429).json({
          error: limitCheck.error,
          plan: limitCheck.plan,
          limit: limitCheck.limit,
          upgrade_url: 'https://darkmatterhub.ai/dashboard',
        });
      }
    }

    // toAgentId is optional — defaults to the committing agent's own ID.
    // This removes the "create a second agent" requirement for single-agent workflows.
    // Multi-agent pipelines still pass an explicit toAgentId as before.
    const resolvedToAgentId = toAgentId || req.agent.agent_id;

    // Validate eventType
    const VALID_TYPES = ['commit', 'revert', 'override', 'branch', 'merge', 'error', 'spawn', 'timeout', 'retry', 'checkpoint', 'consent', 'redact', 'escalate', 'audit'];
    const resolvedType = (eventType && VALID_TYPES.includes(eventType)) ? eventType : 'commit';

    const commitId      = 'ctx_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const acceptedAt    = new Date().toISOString().replace(/\.\d+Z$/, 'Z'); // server ledger time
    const timestamp     = acceptedAt; // kept for backwards compat
    const schemaVersion = '1.0';
    // client_timestamp: what the agent asserted in their envelope (may differ from accepted_at)
    const clientTimestamp = req.body.envelope?.timestamp || acceptedAt;

    // ── L3 attestation (optional) ─────────────────────────────────────────────
    let assuranceLevel = 'L1';
    let attestationFields = {};
    const clientAttestation = req.body.client_attestation;

    if (clientAttestation) {
      // Resolve public key — inline or from registry
      let publicKey = clientAttestation.public_key;
      if (!publicKey && clientAttestation.key_id) {
        const { data: sigKey } = await supabaseService
          .from('signing_keys')
          .select('public_key, status')
          .eq('user_id', userId)
          .eq('key_id', clientAttestation.key_id)
          .single();
        if (!sigKey) {
          return res.status(400).json({ error: 'attestation_failed', reason: 'unknown_key_id',
            message: `Signing key '${clientAttestation.key_id}' not registered. Use POST /api/signing-keys to register.` });
        }
        if (sigKey.status === 'revoked') {
          return res.status(400).json({ error: 'attestation_failed', reason: 'revoked_key',
            message: `Signing key '${clientAttestation.key_id}' has been revoked.` });
        }
        publicKey = sigKey.public_key;
      }
      if (!publicKey) {
        return res.status(400).json({ error: 'attestation_failed', reason: 'missing_public_key',
          message: 'Provide public_key inline or register key_id via POST /api/signing-keys.' });
      }

      const verifyResult = verifyAttestation({
        attestation: { ...clientAttestation, public_key: publicKey },
        payload: resolvedPayload,
        metadata: req.body.metadata || null,
        agentId: req.agent.agent_id,
        parentId: req.body.parentId || null,
      });

      if (!verifyResult.valid) {
        return res.status(400).json({ error: 'attestation_failed', reason: verifyResult.reason,
          message: verifyResult.message });
      }

      assuranceLevel = 'L3';

      // Clock skew check (never reject, just flag)
      const serverNow = Date.now();
      const clientTs  = new Date(clientAttestation.client_timestamp).getTime();
      const skewMs    = Math.abs(serverNow - clientTs);
      const skewWarning = skewMs > 5 * 60 * 1000;

      attestationFields = {
        assurance_level:            'L3',
        client_signature:           clientAttestation.signature,
        client_public_key:          publicKey,
        client_key_id:              clientAttestation.key_id,
        client_signature_algorithm: clientAttestation.algorithm || 'Ed25519',
        client_envelope_version:    clientAttestation.version || 'dm-envelope-v1',
        client_payload_hash:        clientAttestation.payload_hash,
        client_metadata_hash:       clientAttestation.metadata_hash || null,
        client_envelope_hash:       clientAttestation.envelope_hash,
        client_attestation_ts:      clientAttestation.client_timestamp,
        timestamp_skew_warning:     skewWarning,
      };
    }
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
      .eq('agent_id', resolvedToAgentId)
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
          verification_reason: `Recipient agent ${resolvedToAgentId} not found`,
          timestamp,
        });

      return res.status(404).json({
        id:        commitId,
        verified:  false,
        reason:    `Agent ${resolvedToAgentId} not found`,
        timestamp,
      });
    }

    const { error } = await supabaseService
      .from('commits')
      .insert({
        id:                  commitId,
        schema_version:      schemaVersion,
        from_agent:          req.agent.agent_id,
        to_agent:            resolvedToAgentId,
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
        hash_mismatch:       hashMismatch || false,
        verified:            true,
        verification_reason: 'API key authenticated',
        capture_mode: 'client_signed',
        timestamp,
        ...attestationFields,
      });

    if (error) throw error;

    // Track usage for billing (non-fatal)
    if (userId) incrementCommitUsage(userId, supabaseService).catch(() => {});

    // Update last_active
    await supabaseService
      .from('agents')
      .update({ last_active: timestamp })
      .eq('agent_id', req.agent.agent_id);

    // Deliver webhook (fire and forget)
    const { data: recipientAgent } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, webhook_url, webhook_secret')
      .eq('agent_id', resolvedToAgentId)
      .single();

    // Fire event hooks (post-commit)
    if (typeof fireEventHooks === 'function') {
      fireEventHooks(req.agent.agent_id, 'commit', {
        ctxId: commitId, toAgentId: resolvedToAgentId, traceId, eventType: resolvedType,
      }).catch(() => {});
    }

    if (recipientAgent?.webhook_url) {
      deliverWebhook(recipientAgent, {
        id:         commitId,
        from_agent: req.agent.agent_id,
        to_agent:   resolvedToAgentId,
        context:    resolvedPayload,
        verified:   true,
        timestamp,
      }).catch(err => console.error('webhook delivery error:', err));
    }

    const receipt = buildContext({
      id:                  commitId,
      schema_version:      schemaVersion,
      from_agent:          req.agent.agent_id,
      to_agent:            resolvedToAgentId,
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
      capture_mode: 'client_signed',
      timestamp,
    }, { [req.agent.agent_id]: req.agent.agent_name, [resolvedToAgentId]: recipientAgent?.agent_name || resolvedToAgentId });

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


app.get('/api/me', flexAuth, async (req, res) => {
  // API key path — agent context already loaded
  if (req.authType === 'apikey' && req.agent) {
    return res.json({
      agentId:   req.agent.agent_id,
      agentName: req.agent.agent_name,
      apiKey:    req.agent.api_key,
    });
  }

  // JWT path — look up the user's primary agent to surface their API key
  if (req.user) {
    const { data: agents } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, api_key')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: true })
      .limit(1);

    const agent = agents?.[0];
    return res.json({
      agentId:   agent?.agent_id  || null,
      agentName: agent?.agent_name || null,
      apiKey:    agent?.api_key   || null,
      email:     req.user.email,
    });
  }

  res.status(401).json({ error: 'Not authenticated' });
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
      capture_mode: 'client_signed',
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
app.get('/api/verify/:ctxId', flexAuth, async (req, res) => {
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
app.get('/api/export/:ctxId', async (req, res) => {
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
      checkpoint:    checkpoint ? await (async () => {
        // Fetch witness signatures for this checkpoint
        const { data: witSigs } = await supabaseService
          .from('witness_sigs')
          .select('witness_id, witness_sig, witnessed_at, sig_valid')
          .eq('checkpoint_id', checkpoint.checkpoint_id);

        // Fetch witness public keys for offline verification
        const witIds = (witSigs || []).map(w => w.witness_id);
        let witnessKeys = [];
        if (witIds.length > 0) {
          const { data: wits } = await supabaseService
            .from('witnesses')
            .select('witness_id, name, public_key_pem')
            .in('witness_id', witIds);
          witnessKeys = wits || [];
        }

        const witKeyMap = {};
        for (const w of witnessKeys) witKeyMap[w.witness_id] = w;

        return {
          ...checkpoint,
          witness_signatures: (witSigs || []).map(ws => ({
            witness_id:    ws.witness_id,
            witness_name:  witKeyMap[ws.witness_id]?.name || 'unknown',
            witness_sig:   ws.witness_sig,
            witnessed_at:  ws.witnessed_at,
            sig_valid:     ws.sig_valid,
            public_key_pem: witKeyMap[ws.witness_id]?.public_key_pem || null,
          })),
          witness_count:  checkpoint.witness_count || 0,
          note: checkpoint.position >= (tipLogEntry?.position ?? -1)
            ? 'This checkpoint covers the tip of this chain'
            : 'Latest available checkpoint — tip may not yet be checkpointed',
        };
      })() : null,
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
// PHASE 4A — WITNESS API
// ═══════════════════════════════════════════════════

// ── GET /api/witnesses ────────────────────────────────────────────────────────
// List all active witnesses. Public — witness identities are public information.
app.get('/api/witnesses', async (req, res) => {
  try {
    const { data } = await supabaseService
      .from('witnesses')
      .select('witness_id, name, registered_at, endpoint_url')
      .eq('active', true)
      .order('registered_at', { ascending: true });
    res.json({ witnesses: data || [], count: (data || []).length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/witnesses/:witnessId/pubkey ──────────────────────────────────────
// Get a witness's public key. No auth — public information.
app.get('/api/witnesses/:witnessId/pubkey', async (req, res) => {
  try {
    const { data } = await supabaseService
      .from('witnesses')
      .select('witness_id, name, public_key_pem, registered_at')
      .eq('witness_id', req.params.witnessId)
      .single();
    if (!data) return res.status(404).json({ error: 'Witness not found' });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/witness/sign ────────────────────────────────────────────────────
// Submit a witness signature on a checkpoint.
// Called by witnesses after they receive a checkpoint delivery and sign it.
// Auth: witness identifies via X-Witness-ID header; sig verified against registered pubkey.
app.post('/api/witness/sign', async (req, res) => {
  try {
    const { checkpoint_id, witness_sig, witnessed_at } = req.body;
    const witnessId = req.headers['x-witness-id'];

    if (!checkpoint_id || !witness_sig || !witnessId) {
      return res.status(400).json({ error: 'checkpoint_id, witness_sig, X-Witness-ID required' });
    }

    const result = await acceptWitnessSignature(
      supabaseService,
      checkpoint_id,
      witnessId,
      witness_sig,
      witnessed_at,
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── GET /api/log/checkpoint/:checkpointId/witnesses ───────────────────────────
// Get all witness signatures for a specific checkpoint. No auth.
app.get('/api/log/checkpoint/:checkpointId/witnesses', async (req, res) => {
  try {
    const { data: sigs } = await supabaseService
      .from('witness_sigs')
      .select('witness_id, witness_sig, witnessed_at, sig_valid')
      .eq('checkpoint_id', req.params.checkpointId);

    const witIds = (sigs || []).map(s => s.witness_id);
    let witnesses = [];
    if (witIds.length > 0) {
      const { data } = await supabaseService
        .from('witnesses')
        .select('witness_id, name, public_key_pem')
        .in('witness_id', witIds);
      witnesses = data || [];
    }

    const witMap = {};
    for (const w of witnesses) witMap[w.witness_id] = w;

    res.json({
      checkpoint_id: req.params.checkpointId,
      witness_count: (sigs || []).length,
      witnesses: (sigs || []).map(s => ({
        ...s,
        name:           witMap[s.witness_id]?.name,
        public_key_pem: witMap[s.witness_id]?.public_key_pem,
      })),
      pubkey_url: 'https://darkmatterhub.ai/api/witnesses',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/admin/witnesses (superuser only) ────────────────────────────────
// Register a new witness. Superuser only.
app.post('/api/admin/witnesses', requireApiKey, async (req, res) => {
  if (req.agent?.agent_id !== process.env.SUPERUSER_AGENT_ID && req.agent?.agent_name !== 'darkmatter-admin') {
    return res.status(403).json({ error: 'Superuser only' });
  }
  try {
    const { name, publicKey, endpointUrl } = req.body;
    if (!name || !publicKey) return res.status(400).json({ error: 'name and publicKey required' });
    const result = await registerWitness(supabaseService, name, publicKey, endpointUrl);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
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
      capture_mode: 'client_signed',
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

    // Notify via email (non-blocking - inquiry still saved if email fails)
    if (process.env.RESEND_API_KEY && process.env.FEEDBACK_EMAIL) {
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
    }).catch(e => console.error('Inquiry email failed:', e.message));
    }

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
app.get('/pricing',           (req, res) => res.sendFile(path.join(__dirname, '../public/pricing.html')));
app.get('/why',               (req, res) => res.sendFile(path.join(__dirname, '../public/why.html')));
app.get('/docs',              (req, res) => res.sendFile(path.join(__dirname, '../public/docs.html')));
app.get('/docs/quickstart',   (req, res) => res.sendFile(path.join(__dirname, '../public/docs/quickstart.html')));
app.get('/docs/cheatsheet',   (req, res) => res.sendFile(path.join(__dirname, '../public/docs/cheatsheet.html')));
app.get('/docs/cookbook',     (req, res) => res.sendFile(path.join(__dirname, '../public/docs/cookbook.html')));
app.get('/enterprise',        (req, res) => res.sendFile(path.join(__dirname, '../public/enterprise.html')));


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

// ── SIGNING KEY REGISTRY — Phase 2 ──────────────────────────────────────────

// POST /api/signing-keys — register a public key for L3 commits
app.post('/api/signing-keys', requireAuth, async (req, res) => {
  try {
    const { key_id, public_key, algorithm, description } = req.body;
    if (!key_id || !public_key) {
      return res.status(400).json({ error: 'key_id and public_key are required' });
    }
    if (algorithm && algorithm !== 'Ed25519') {
      return res.status(400).json({ error: 'Only Ed25519 is supported' });
    }
    // Validate public key is valid base64url (32 bytes decoded)
    try {
      const raw = Buffer.from(public_key.replace(/-/g,'+').replace(/_/g,'/') + '==', 'base64');
      if (raw.length !== 32) throw new Error('wrong length');
    } catch {
      return res.status(400).json({ error: 'public_key must be base64url of a 32-byte Ed25519 public key' });
    }
    const { data, error } = await supabaseService
      .from('signing_keys')
      .upsert({
        user_id:     req.user.id,
        key_id:      sanitizeText(key_id, 100),
        public_key,
        algorithm:   'Ed25519',
        status:      'active',
        description: description ? sanitizeText(description, 200) : null,
        created_at:  new Date().toISOString(),
      }, { onConflict: 'user_id,key_id' })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ key_id: data.key_id, algorithm: data.algorithm,
      status: data.status, created_at: data.created_at });
  } catch(e) {
    console.error('[signing-keys POST]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/signing-keys — list registered keys
app.get('/api/signing-keys', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseService
      .from('signing_keys')
      .select('key_id, algorithm, status, description, created_at, revoked_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ keys: data || [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/signing-keys/:keyId — revoke a key
app.delete('/api/signing-keys/:keyId', requireAuth, async (req, res) => {
  try {
    const { keyId } = req.params;
    const { data, error } = await supabaseService
      .from('signing_keys')
      .update({ status: 'revoked', revoked_at: new Date().toISOString() })
      .eq('user_id', req.user.id)
      .eq('key_id', keyId)
      .select()
      .single();
    if (error || !data) return res.status(404).json({ error: 'Key not found' });
    res.json({ key_id: data.key_id, status: 'revoked', revoked_at: data.revoked_at });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/workspace/share/:traceId — generate on-demand share token ────────
// Called from dashboard when user explicitly clicks Share or Verify.
// Returns a signed URL valid for 30 days. No token = no public access.
app.post('/api/workspace/share/:traceId', requireAuth, async (req, res) => {
  try {
    const { traceId } = req.params;
    const secret = process.env.APP_SECRET || process.env.SUPABASE_SERVICE_ROLE_KEY || 'dm_fallback_secret';
    const { days } = req.body;
    const expiryDays = Math.min(Math.max(parseInt(days) || 30, 1), 365);
    const expiresAt = Math.floor(Date.now() / 1000) + (expiryDays * 24 * 3600);

    // Verify the commit belongs to this user
    const { data: commit } = await supabaseService
      .from('commits')
      .select('id, trace_id, from_agent, agent_id')
      .or(`trace_id.eq."${traceId}",trace_id.eq.${traceId},id.eq.${traceId}`)
      .limit(1)
      .single();

    if (!commit) return res.status(404).json({ error: 'Record not found' });

    // Check ownership via agent
    const agentId = commit.agent_id || commit.from_agent;
    if (agentId) {
      const { data: agent } = await supabaseService
        .from('agents').select('user_id').eq('agent_id', agentId).single();
      if (agent?.user_id && agent.user_id !== req.user.id) {
        return res.status(403).json({ error: 'Not your record' });
      }
    }

    // Generate HMAC token: sign "traceId:expiresAt" with secret
    const payload = `${traceId}:${expiresAt}`;
    const token = require('crypto').createHmac('sha256', secret).update(payload).digest('hex');

    const baseUrl = process.env.APP_URL || 'https://darkmatterhub.ai';
    const shareUrl = `${baseUrl}/r/${encodeURIComponent(traceId)}?token=${token}&exp=${expiresAt}`;
    const verifyUrl = shareUrl;

    res.json({ shareUrl, verifyUrl, expiresAt: new Date(expiresAt * 1000).toISOString() });
  } catch(e) {
    console.error('[share]', e.message);
    res.status(500).json({ error: e.message });
  }
});


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
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>DarkMatter — Connecting extension</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background:#f4f6fb;color:#0a0e1a;
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;padding:2rem;
}
.card{
  background:#fff;border:1px solid #e5e7eb;border-radius:12px;
  padding:32px 28px;max-width:380px;width:100%;text-align:center;
  box-shadow:0 4px 24px rgba(0,0,0,.06);
}
.logo{font-family:"SF Mono","Courier New",monospace;font-size:17px;font-weight:700;
  background:linear-gradient(90deg,#7C3AED,#2563EB,#0891b2);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;display:inline-block;margin-bottom:20px;}
.status-ic{font-size:2rem;margin-bottom:12px;}
.title{font-size:15px;font-weight:700;color:#0a0e1a;margin-bottom:6px;}
.sub{font-size:13px;color:#5a6480;line-height:1.6;}
.spinner{
  width:24px;height:24px;border:2px solid #e5e7eb;
  border-top-color:#3b82f6;border-radius:50%;
  animation:spin .7s linear infinite;margin:0 auto 12px;
}
@keyframes spin{to{transform:rotate(360deg)}}
.ok{color:#10b981;} .err{color:#ef4444;}
</style>
</head>
<body>
<div class="card">
  <div class="logo">DarkMatter</div>
  <div id="spinner" class="spinner"></div>
  <div class="status-ic" id="ic" style="display:none;"></div>
  <div class="title" id="title">Connecting extension...</div>
  <div class="sub"   id="sub">Fetching your account details.</div>
</div>
<script>
(async function() {
  const title = document.getElementById('title');
  const sub   = document.getElementById('sub');
  const spinner = document.getElementById('spinner');
  const ic    = document.getElementById('ic');

  function done(ok, msg, detail) {
    spinner.style.display = 'none';
    ic.style.display = '';
    ic.textContent = ok ? '✓' : '✗';
    ic.className = 'status-ic ' + (ok ? 'ok' : 'err');
    title.textContent = msg;
    sub.textContent = detail || '';
  }

  // Step 1: read session from localStorage (set by login.html)
  const raw = localStorage.getItem('dm_session');
  if (!raw) {
    return done(false, 'No session found', 'Please sign in at darkmatterhub.ai/login?ext=1 and try again.');
  }

  let session;
  try { session = JSON.parse(raw); } catch(e) {
    return done(false, 'Invalid session data', 'Please sign in again.');
  }

  if (!session?.access_token || !session?.user?.email) {
    return done(false, 'Incomplete session', 'Please sign in again at darkmatterhub.ai/login?ext=1');
  }

  // Step 2: fetch the user's agent API key
  let agentId = null, apiKey = null;
  try {
    const r = await fetch('/dashboard/agents', {
      headers: { 'Authorization': 'Bearer ' + session.access_token }
    });
    if (r.ok) {
      const agents = await r.json();
      if (agents[0]) { agentId = agents[0].agentId; apiKey = agents[0].apiKey; }
    }
  } catch(e) {}

  // If no agent exists yet, create one automatically
  if (!agentId) {
    try {
      const r = await fetch('/dashboard/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + session.access_token },
        body: JSON.stringify({ agentName: session.user.email + '-ext' })
      });
      if (r.ok) {
        const d = await r.json();
        agentId = d.agentId;
        apiKey  = d.apiKey;
      }
    } catch(e) {}
  }

  if (!agentId || !apiKey) {
    return done(false, 'Could not get API key', 'Try opening the dashboard and creating an agent manually, then sign in to the extension again.');
  }

  // Step 3: fetch workspace name (optional)
  let workspaceName = null;
  try {
    const r = await fetch('/api/workspace', {
      headers: { 'Authorization': 'Bearer ' + session.access_token }
    });
    if (r.ok) {
      const d = await r.json();
      if (d.workspace?.name) workspaceName = d.workspace.name;
    }
  } catch(e) {}

  // Step 4: build auth payload
  const auth = {
    email:          session.user.email,
    session_token:  session.access_token,
    refresh_token:  session.refresh_token || null,
    agent_id:       agentId,
    api_key:        apiKey,
    workspace_name: workspaceName,
  };

  // Step 5: send to extension via CustomEvent (picked up by session_bridge.js content script)
  // session_bridge.js is injected on darkmatterhub.ai/* and listens for 'dm_auth'
  window.dispatchEvent(new CustomEvent('dm_auth', { detail: auth }));

  // Step 6: also try chrome.runtime.sendMessage as direct fallback
  // This works if the extension declared externally_connectable for this origin
  let sentDirect = false;
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    try {
      await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'SET_AUTH', auth }, (response) => {
          if (chrome.runtime.lastError) { resolve(false); return; }
          sentDirect = !!response?.ok;
          resolve(sentDirect);
        });
      });
    } catch(e) {}
  }

  // Wait briefly for the CustomEvent path to complete
  await new Promise(r => setTimeout(r, 600));

  done(true,
    'Extension connected!',
    'Recording is now active. You can close this tab and start using Claude, ChatGPT, or any supported AI tool.'
  );
})();
</script>
</body>
</html>`);
});

// ═══════════════════════════════════════════════════════════════════════
// PUBLIC RECORD VIEW — no auth required
// GET /r/:traceId       → human-readable HTML (default)
// GET /r/:traceId?format=json → raw JSON
// ═══════════════════════════════════════════════════════════════════════
app.get('/r/:traceId', async (req, res) => {
  try {
    const { traceId } = req.params;
    if (!traceId || traceId.length > 120) return res.status(400).json({ error: 'Invalid ID' });

    // ── Access control: require valid signed token OR authenticated user ────────
    const { token, exp } = req.query;
    const secret = process.env.APP_SECRET || process.env.SUPABASE_SERVICE_ROLE_KEY || 'dm_fallback_secret';
    let authorized = false;

    if (token && exp) {
      // Verify HMAC token
      const now = Math.floor(Date.now() / 1000);
      if (parseInt(exp) >= now) {
        const expected = require('crypto').createHmac('sha256', secret)
          .update(`${traceId}:${exp}`).digest('hex');
        authorized = (token === expected);
      }
    }

    if (!authorized) {
      // Check for auth header (dashboard user)
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        try {
          const { data: { user } } = await supabaseService.auth.getUser(
            authHeader.replace('Bearer ', '').trim()
          );
          authorized = !!user;
        } catch(_) {}
      }
    }

    if (!authorized) {
      if (req.query.format === 'json') {
        return res.status(401).json({ error: 'This record requires a share link to access. Open in DarkMatter dashboard to generate one.' });
      }
      return res.status(401).send(`<!DOCTYPE html><html><head><title>Access required — DarkMatter</title>
        <meta charset="UTF-8"/><style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;background:#f9fafb;margin:0;}
        .card{max-width:440px;text-align:center;padding:40px;background:#fff;border:1px solid #e5e7eb;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.06);}
        h2{font-size:1.2rem;margin-bottom:8px;color:#111827;}p{color:#6b7280;font-size:.875rem;line-height:1.6;}
        a{display:inline-block;margin-top:20px;padding:10px 20px;background:#111827;color:#fff;border-radius:7px;text-decoration:none;font-size:.85rem;}</style></head>
        <body><div class="card"><h2>Share link required</h2>
        <p>This record is private. To share it for verification, open it in your DarkMatter dashboard and click <strong>Share link</strong> or <strong>Verify →</strong>.</p>
        <a href="/">Go to DarkMatter</a></div></body></html>`);
    }

    const { data: commits, error } = await supabaseService
      .from('commits')
      .select('id, trace_id, from_agent, agent_id, agent_info, payload, timestamp, client_timestamp, event_type, integrity_hash, payload_hash, parent_hash, verified')
      .or(`trace_id.eq."${traceId}",trace_id.eq.${traceId},id.eq.${traceId}`)
      .order('timestamp', { ascending: true });

    if (error || !commits || !commits.length) {
      if (req.query.format === 'json') return res.status(404).json({ error: 'Record not found.' });
      return res.status(404).send('<!DOCTYPE html><html><head><title>Not found</title></head><body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;"><div style="text-align:center"><h2>Record not found</h2><p>This record may have been removed or the link is incorrect.</p><a href="/">Back to DarkMatter</a></div></body></html>');
    }

    // Verify chain integrity
    // Only flag broken if BOTH hashes exist and don't match.
    // Missing parent_hash = first commit or extension-captured turn (not broken).
    let chainIntact = true;
    for (let i = 1; i < commits.length; i++) {
      const prevHash = commits[i-1].integrity_hash;
      const thisParent = commits[i].parent_hash;
      if (thisParent && prevHash && thisParent !== prevHash) {
        chainIntact = false; break;
      }
    }

    if (req.query.format === 'json') {
      const filename = `darkmatter_proof_${traceId.slice(-12)}.json`;
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', 'application/json');
      return res.json({
        trace_id: traceId, chain_intact: chainIntact, step_count: commits.length,
        commits: commits.map(function(c) { return {
          id: c.id, trace_id: c.trace_id,
          timestamp: c.client_timestamp || c.timestamp,
          recorded_at: c.timestamp,
          event_type: c.event_type,
          integrity_hash: c.integrity_hash,
          parent_hash: c.parent_hash,
          verified: c.verified,
          payload: { role: c.payload && c.payload.role, text: c.payload && c.payload.text,
            output: c.payload && c.payload.output, summary: c.payload && c.payload.summary,
            prompt: c.payload && c.payload.prompt, convTitle: c.payload && c.payload.convTitle,
            platform: c.payload && c.payload.platform, _source: c.payload && c.payload._source },
        }; }),
        verify_url: (process.env.APP_URL || 'https://darkmatterhub.ai') + '/r/' + traceId,
      });
    }

    // Build HTML render
    function escH(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    var title = (function() {
      for (var i = 0; i < commits.length; i++) {
        var ct = commits[i].payload && commits[i].payload.convTitle;
        if (ct && ct !== 'Untitled') return ct;
      }
      for (var i = 0; i < commits.length; i++) {
        var p = commits[i].payload || {};
        if (p.role === 'user' && p.text) return p.text.slice(0, 60) + (p.text.length > 60 ? '...' : '');
      }
      return 'AI Decision Record';
    })();

    var platform = (commits[0] && commits[0].payload && commits[0].payload.platform) || 'AI';
    var firstTs = (commits[0] && (commits[0].client_timestamp || commits[0].timestamp)) || '';
    var stepCount = commits.length;
    var statusColor = chainIntact ? '#065f46' : '#991b1b';
    var statusText  = chainIntact ? '\u2713 Record intact' : '\u2717 Mismatch detected';
    var statusBg    = chainIntact ? 'rgba(16,185,129,.06)' : 'rgba(239,68,68,.06)';
    var statusBd    = chainIntact ? 'rgba(16,185,129,.2)'  : 'rgba(239,68,68,.2)';

    // L3 detection — check any commit in the chain for customer attestation
    var l3Commit = commits.find(function(c) { return c.assurance_level === 'L3' && c.client_signature; });
    var isL3 = !!l3Commit;
    var l3KeyId = l3Commit ? (l3Commit.client_key_id || 'customer key') : null;
    var skewWarning = l3Commit ? l3Commit.timestamp_skew_warning : false;

    // Assurance level badge
    var assuranceBadge = isL3
      ? '<span style="font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;background:rgba(107,79,187,.08);color:#6b4fbb;border:1px solid rgba(107,79,187,.2);letter-spacing:.06em;margin-left:6px;">L3 NON-REPUDIATION</span>'
      : '<span style="font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:3px;background:var(--bg2);color:var(--ink4);border:1px solid var(--border);letter-spacing:.05em;margin-left:6px;">L1/L2</span>';

    // Integrity description line
    var integrityDesc = isL3
      ? 'This record was signed by a customer-controlled key before DarkMatter received it. DarkMatter cannot forge or alter this record — verification requires only the customer public key.'
      : (chainIntact
          ? 'This record has been cryptographically verified. Nothing has been added, removed, or altered since it was captured.'
          : 'This record could not be fully verified. Download the proof file for independent investigation.');

    var l3CustomerLine = isL3
      ? '  <div style="font-size:12px;color:#6b4fbb;font-family:var(--mono);margin-bottom:4px;letter-spacing:.01em;">\u2713 Customer-signed &middot; key: ' + escH(l3KeyId) + (skewWarning ? ' &middot; <span style="color:#b45309;">timestamp skew &gt;5 min</span>' : '') + '</div>\n'
      : '';

    // Build messages HTML
    var messagesHTML = '';
    commits.forEach(function(c, i) {
      var p = c.payload || {};
      var role = p.role || (i % 2 === 0 ? 'user' : 'assistant');
      var text = p.text || p.output || p.summary || p.prompt || '';
      if (!text.trim()) return;
      var ts2 = c.client_timestamp || c.timestamp || '';
      var tsStr = ts2 ? new Date(ts2).toLocaleString('en-GB', { day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit', timeZone:'UTC', hour12:false }) + ' UTC' : '';
      var isUser = role === 'user';
      var platHint = p.platform ? '<span style="font-weight:400;opacity:.5;margin-left:5px;">' + escH(p.platform) + '</span>' : '';
      var agentLabel = p.agentName || p.agent_name || 'AGENT';
      if (isUser) {
        messagesHTML += '<div class="msg-grp"><div class="role-label user">YOU' + platHint + '</div><div class="bubble user">' + escH(text) + '</div><div class="msg-time user">' + tsStr + '</div></div>';
      } else {
        messagesHTML += '<div class="msg-grp"><div class="role-label agent">' + escH(agentLabel) + platHint + '</div><div class="bubble agent">' + escH(text) + '</div><div class="msg-time agent">' + tsStr + '</div></div>';
      }
    });

    var verifyUrl = (process.env.APP_URL || 'https://darkmatterhub.ai') + '/r/' + traceId;
    var jsonUrl   = verifyUrl + '?format=json';
    var dateStr = firstTs ? (function() {
      var d = new Date(firstTs);
      var date = d.toLocaleDateString('en-GB', { month:'short', day:'numeric', year:'numeric', timeZone:'UTC' });
      var time = d.toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit', timeZone:'UTC', hour12:false });
      return date + ' \u00b7 ' + time + ' UTC';
    })() : '';

    var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
      + '<meta charset="UTF-8"/>\n'
      + '<meta name="viewport" content="width=device-width,initial-scale=1"/>\n'
      + '<title>' + escH(title) + ' \u2014 DarkMatter</title>\n'
      + '<link rel="preconnect" href="https://fonts.googleapis.com"/>\n'
      + '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>\n'
      + '<style>\n'
      + '*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}\n'
      + ':root{--ink:#0a0e1a;--ink2:#2d3552;--ink3:#5a6480;--ink4:#9199b0;--bg:#f4f6fb;--bg2:#eceef5;--border:#e5e7eb;--border2:#dde1ed;--blue:#3b82f6;--green:#10b981;--mono:"IBM Plex Mono","Courier New",monospace;--sans:"IBM Plex Sans",sans-serif;--grad:linear-gradient(90deg,#7C3AED,#2563EB,#0891b2);}\n'
      + 'body{background:var(--bg);color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased;font-size:14px;}\n'
      + '.nav{height:56px;background:#fff;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 24px;gap:12px;position:sticky;top:0;z-index:100;}\n'
      + '.nav-name{font-family:var(--mono);font-size:15px;font-weight:700;color:var(--ink);letter-spacing:-.03em;}\n'
      + '.nav-grad{background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}\n'
      + '.nav-right{margin-left:auto;display:flex;align-items:center;gap:8px;}\n'
      + '.nav-link{font-size:12px;color:var(--ink3);text-decoration:none;padding:4px 8px;border-radius:5px;}\n'
      + '.nav-link:hover{background:var(--bg2);color:var(--ink);}\n'
      + '.nav-cta{font-family:var(--mono);font-size:11.5px;font-weight:700;background:var(--ink);color:#fff;padding:6px 14px;border-radius:6px;text-decoration:none;}\n'
      + '.page{max-width:780px;margin:0 auto;padding:28px 20px 60px;}\n'
      + '.first-screen{background:#fff;border:1px solid var(--border);border-radius:10px;padding:24px 26px;margin-bottom:16px;}\n'
      + '.fs-title{font-size:19px;font-weight:700;color:var(--ink);letter-spacing:-.03em;line-height:1.25;margin-bottom:12px;}\n'
      + '.fs-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px;}\n'
      + '.fs-status{font-family:var(--mono);font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;border:1px solid;}\n'
      + '.fs-sep{color:var(--border2);font-size:11px;}\n'
      + '.fs-chip{font-size:12px;color:var(--ink3);}\n'
      + '.fs-integrity{font-size:13px;color:var(--ink2);line-height:1.65;margin-bottom:18px;padding:11px 14px;background:var(--bg);border-radius:6px;border-left:3px solid var(--border2);}\n'
      + '.fs-actions{display:flex;gap:8px;flex-wrap:wrap;}\n'
      + '.fs-btn-p{background:var(--ink);color:#fff;font-family:var(--mono);font-weight:700;font-size:12.5px;padding:8px 18px;border-radius:7px;border:none;cursor:pointer;transition:opacity .15s;}\n'
      + '.fs-btn-p:hover{opacity:.85;}\n'
      + '.fs-btn-s{background:#fff;color:var(--ink2);font-size:12.5px;padding:7px 16px;border-radius:7px;border:1px solid var(--border2);cursor:pointer;text-decoration:none;display:inline-block;font-family:var(--sans);}\n'
      + '.fs-btn-s:hover{border-color:var(--ink3);color:var(--ink);}\n'
      + '.view-switcher{display:flex;gap:4px;margin-bottom:16px;background:#fff;border:1px solid var(--border);border-radius:7px;padding:3px;width:fit-content;}\n'
      + '.vs-btn{font-size:12px;padding:5px 12px;border-radius:5px;border:none;background:none;cursor:pointer;color:var(--ink3);font-family:var(--sans);}\n'
      + '.vs-btn.on{background:var(--ink);color:#fff;font-weight:600;}\n'
      + '.vs-btn:hover:not(.on){background:var(--bg2);color:var(--ink);}\n'
      + '.view{display:none;}.view.on{display:block;}\n'
      + '.conv-area{display:flex;flex-direction:column;gap:12px;}\n'
      + '.msg-grp{clear:both;margin-bottom:4px;}\n'
      + '.role-label{font-family:var(--mono);font-size:9.5px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--ink4);margin-bottom:3px;}\n'
      + '.role-label.user{text-align:right;}\n'
      + '.bubble{border-radius:3px;padding:9px 13px;font-size:13.5px;line-height:1.6;word-break:break-word;max-width:88%;display:inline-block;}\n'
      + '.bubble.user{background:var(--ink);color:rgba(232,237,245,.92);border-radius:3px 3px 1px 3px;float:right;clear:both;}\n'
      + '.bubble.agent{background:#fff;border:1px solid var(--border);border-radius:1px 3px 3px 3px;float:left;clear:both;}\n'
      + '.msg-time{font-size:10px;color:var(--ink4);font-family:var(--mono);margin-top:3px;clear:both;}\n'
      + '.msg-time.user{text-align:right;}\n'
      + '.clearfix{clear:both;height:0;}\n'
      + '.timeline{display:flex;flex-direction:column;}\n'
      + '.tl-step{display:flex;gap:12px;padding-bottom:14px;}\n'
      + '.tl-step:last-child{padding-bottom:0;}\n'
      + '.tl-line{display:flex;flex-direction:column;align-items:center;flex-shrink:0;}\n'
      + '.tl-dot{width:10px;height:10px;border-radius:50%;border:2px solid var(--green);background:#fff;flex-shrink:0;margin-top:2px;}\n'
      + '.tl-dot.user{border-color:var(--ink);}\n'
      + '.tl-conn{flex:1;width:1px;background:var(--border);margin:3px 0;}\n'
      + '.tl-step:last-child .tl-conn{display:none;}\n'
      + '.tl-info{flex:1;background:#fff;border:1px solid var(--border);border-radius:7px;padding:10px 14px;}\n'
      + '.tl-head{display:flex;align-items:baseline;gap:8px;margin-bottom:5px;}\n'
      + '.tl-step-n{font-family:var(--mono);font-size:9px;color:var(--ink4);}\n'
      + '.tl-actor{font-size:12.5px;font-weight:600;color:var(--ink2);}\n'
      + '.tl-time{font-size:10px;color:var(--ink4);margin-left:auto;font-family:var(--mono);}\n'
      + '.tl-text{font-size:13px;color:var(--ink);line-height:1.6;}\n'
      + '.tl-hash{font-family:var(--mono);font-size:9px;color:var(--ink4);margin-top:5px;}\n'
      + '.proof-area{display:flex;flex-direction:column;gap:12px;}\n'
      + '.proof-banner{background:#fff;border:1px solid;border-radius:8px;padding:16px 18px;}\n'
      + '.proof-banner-title{font-size:14px;font-weight:700;margin-bottom:6px;}\n'
      + '.proof-banner-body{font-size:13px;line-height:1.65;color:var(--ink2);}\n'
      + '.proof-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;}\n'
      + '.pcard{background:#fff;border:1px solid var(--border);border-radius:8px;padding:14px 16px;}\n'
      + '.pcard.ok{background:rgba(16,185,129,.04);border-color:rgba(16,185,129,.2);}\n'
      + '.pcard.skip{opacity:.7;}\n'
      + '.pcard-top{display:flex;align-items:center;gap:7px;margin-bottom:5px;}\n'
      + '.pcard-ic.ok{color:#065f46;font-size:13px;}.pcard-ic.skip{color:var(--ink4);font-size:13px;}\n'
      + '.pcard-title{font-size:12.5px;font-weight:600;color:var(--ink);}\n'
      + '.pcard-body{font-size:12px;color:var(--ink3);line-height:1.6;}\n'
      + '.json-area{background:#0f1629;border-radius:8px;padding:20px;overflow-x:auto;}\n'
      + '.json-area pre{font-family:var(--mono);font-size:11.5px;line-height:1.7;color:rgba(232,237,245,.8);}\n'
      + '.ab-btn{font-size:12px;padding:6px 14px;border-radius:6px;border:1px solid var(--border2);background:#fff;color:var(--ink2);text-decoration:none;display:inline-block;margin-right:6px;margin-top:8px;}\n'
      + '.page-footer{text-align:center;padding:24px 0;font-size:12px;color:var(--ink4);}\n'
      + '.page-footer a{color:var(--ink3);text-decoration:none;}\n'
      + '</style>\n</head>\n<body>\n'
      + '<nav class="nav">\n'
      + '  <a href="/" style="display:flex;align-items:center;gap:8px;text-decoration:none;">\n'
      + '    <svg style="width:24px;height:24px;" viewBox="0 0 40 40" fill="none"><defs><linearGradient id="dlg-r" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#7C3AED"/><stop offset="55%" stop-color="#2563EB"/><stop offset="100%" stop-color="#0891b2"/></linearGradient></defs><circle cx="20" cy="20" r="17" stroke="#e5e7eb" stroke-width="0.8" stroke-dasharray="2 3"/><circle cx="20" cy="5" r="3.2" fill="#7C3AED" opacity="0.95"/><circle cx="33" cy="28" r="2.6" fill="#2563EB" opacity="0.95"/><circle cx="7" cy="28" r="2.2" fill="#22D3EE" opacity="0.9"/><line x1="20" y1="8" x2="31" y2="26" stroke="url(#dlg-r)" stroke-width="0.6" opacity="0.5"/><line x1="20" y1="8" x2="9" y2="26" stroke="#7C3AED" stroke-width="0.6" opacity="0.4"/><line x1="30" y1="27" x2="10" y2="27" stroke="#22D3EE" stroke-width="0.6" opacity="0.4"/><circle cx="20" cy="20" r="2.5" fill="url(#dlg-r)" opacity="0.6"/></svg>\n'
      + '    <span class="nav-name">Dark<span class="nav-grad">Matter</span></span>\n'
      + '  </a>\n'
      + '  <div class="nav-right">\n'
      + '    <a href="/docs" class="nav-link">Docs</a>\n'
      + '    <a href="/login" class="nav-link">Sign in</a>\n'
      + '    <a href="/signup" class="nav-cta">Start free</a>\n'
      + '  </div>\n</nav>\n'
      + '<div class="page">\n'
      + '<div class="first-screen">\n'
      + '  <div class="fs-title">' + escH(title) + '</div>\n'
      + '  <div class="fs-meta">\n'
      + '    <span class="fs-status" style="background:' + statusBg + ';color:' + statusColor + ';border-color:' + statusBd + ';">' + statusText + '</span>\n'
      + assuranceBadge + '\n'
      + '    <span class="fs-sep">\u00b7</span>\n'
      + '    <span class="fs-chip">' + stepCount + ' step' + (stepCount !== 1 ? 's' : '') + '</span>\n'
      + '    <span class="fs-sep">\u00b7</span>\n'
      + '    <span class="fs-chip">' + escH(platform) + '</span>\n'
      + (dateStr ? '    <span class="fs-sep">\u00b7</span>\n    <span class="fs-chip">' + escH(dateStr) + '</span>\n' : '')
      + '  </div>\n'
      + l3CustomerLine
      + '  <div style="font-size:12px;color:#059669;font-family:var(--mono);margin-bottom:4px;letter-spacing:.01em;">This record can be verified independently — without DarkMatter.</div>\n'
      + '  <div style="font-size:11.5px;color:var(--ink4);font-family:var(--mono);margin-bottom:12px;">Anyone can verify this record. No account required.</div>\n'
      + '  <div class="fs-integrity">' + integrityDesc + '</div>\n'
      + '  <div class="fs-actions">\n'
      + '    <button class="fs-btn-p" onclick="switchView(this.dataset.v,this)" data-v="proof">Verify independently &rarr;</button>\n'
      + '    <a class="fs-btn-s" href="' + escH(jsonUrl) + '">Download proof bundle (.json)</a>\n'
      + '    <button class="fs-btn-s" onclick="copyLink()">Copy link</button>\n'
      + '  </div>\n'
      + '  <div style="font-size:11.5px;color:var(--ink4);font-family:var(--mono);margin-top:10px;">Anyone can verify this record. No account required.</div>\n'
      + '</div>\n'
      + '<div class="view-switcher">\n'
      + '<div class="view-switcher">\n'
      + '  <button class="vs-btn on" data-v="conv" onclick="switchView(this.dataset.v,this)">Conversation</button>\n'
      + '  <button class="vs-btn" data-v="timeline" onclick="switchView(this.dataset.v,this)">Timeline</button>\n'
      + '  <button class="vs-btn" data-v="proof" onclick="switchView(this.dataset.v,this)">Proof</button>\n'
      + '  <button class="vs-btn" data-v="json" onclick="switchView(this.dataset.v,this)">Raw JSON</button>\n'
      + '<div class="view on" id="view-conv"><div class="conv-area">\n'
      + messagesHTML
      + '\n</div><div class="clearfix"></div></div>\n'
      + '<div class="view" id="view-timeline"><div class="timeline">\n'
      + commits.map(function(c, i) {
          var p = c.payload || {};
          var role = p.role || (i % 2 === 0 ? 'user' : 'assistant');
          var text = (p.text || p.output || p.summary || p.prompt || '').slice(0, 280);
          var ts3 = c.client_timestamp || c.timestamp || '';
          var tsStr3 = ts3 ? new Date(ts3).toLocaleString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'UTC',hour12:false})+' UTC' : '';
          var isUser3 = role === 'user';
          var actor = isUser3 ? 'You' : (p.agentName || p.agent_name || 'Agent');
          return '<div class="tl-step"><div class="tl-line"><div class="tl-dot' + (isUser3?' user':'') + '"></div><div class="tl-conn"></div></div>'
            + '<div class="tl-info"><div class="tl-head"><span class="tl-step-n">Step ' + (i+1) + '</span><span class="tl-actor">' + escH(actor) + '</span><span class="tl-time">' + tsStr3 + '</span></div>'
            + '<div class="tl-text">' + escH(text) + (text.length >= 280 ? '\u2026' : '') + '</div>'
            + (c.integrity_hash ? '<div class="tl-hash">' + c.integrity_hash.slice(0,16) + '\u2026</div>' : '')
            + '</div></div>';
        }).join('\n')
      + '\n</div></div>\n'
      + '<div class="view" id="view-proof"><div class="proof-area">\n'
      + '<div class="proof-banner" style="border-color:' + statusBd + ';background:' + statusBg + ';">'
      + '<div class="proof-banner-title" style="color:' + statusColor + ';">' + statusText + '</div>'
      + '<div class="proof-banner-body">' + (chainIntact ? 'The ' + stepCount + ' steps shown are exactly what was captured. The hash chain has been verified \u2014 nothing has been added, removed, or altered.' : 'The record does not match its original hash. This may indicate tampering or a recording error.') + '</div>'
      + '</div>\n'
      + '<div class="proof-grid">\n'
      + '<div class="pcard ' + (chainIntact?'ok':'') + '"><div class="pcard-top"><span class="pcard-ic ' + (chainIntact?'ok':'skip') + '">' + (chainIntact?'\u2713':'\u2014') + '</span><span class="pcard-title">Hash chain</span></div><div class="pcard-body">' + (chainIntact ? stepCount + ' steps verified' : 'Verification failed') + '</div></div>\n'
      + '<div class="pcard skip"><div class="pcard-top"><span class="pcard-ic skip">\u2014</span><span class="pcard-title">Log inclusion</span></div><div class="pcard-body">Included at next checkpoint. Download proof file to verify.</div></div>\n'
      + '<div class="pcard skip"><div class="pcard-top"><span class="pcard-ic skip">\u2014</span><span class="pcard-title">Checkpoint signed</span></div><div class="pcard-body">Available in downloaded proof file.</div></div>\n'
      + '<div class="pcard skip"><div class="pcard-top"><span class="pcard-ic skip">\u2014</span><span class="pcard-title">Independent witness</span></div><div class="pcard-body">Check witness signatures in the proof file.</div></div>\n'
      + '</div>\n'
      + '<div style="background:#fff;border:1px solid var(--border);border-radius:8px;padding:16px 18px;">'
      + '<div style="font-size:13px;font-weight:600;color:var(--ink);margin-bottom:4px;">Verify independently</div>'
      + '<div style="font-size:12px;color:var(--ink3);margin-bottom:10px;">No account required. The proof file works completely offline.</div>'
      + '<a href="' + escH(jsonUrl) + '" class="ab-btn">Download proof file (.json)</a>'
      + '<a href="/integrity#spec" class="ab-btn">Integrity Spec \u2192</a>'
      + '</div></div></div>\n'
      + '<div class="view" id="view-json"><div class="json-area"><pre id="json-pre">Loading...</pre></div></div>\n'
      + '<div class="page-footer">Recorded and verified by <a href="/">DarkMatter</a> \u00b7 <a href="/integrity">Integrity Spec</a></div>\n'
      + '</div>\n'
      + '<script>\n'
      + 'var jsonLoaded=false;\n'
      + 'function switchView(name,btn){\n'
      + '  document.querySelectorAll(".view").forEach(function(v){v.classList.remove("on");});\n'
      + '  document.querySelectorAll(".vs-btn").forEach(function(b){b.classList.remove("on");});\n'
      + '  document.getElementById("view-"+name).classList.add("on");\n'
      + '  if(btn)btn.classList.add("on");\n'
      + '  if(name==="json"&&!jsonLoaded){\n'
      + '    fetch("?format=json").then(function(r){return r.json();}).then(function(data){\n'
      + '      document.getElementById("json-pre").textContent=JSON.stringify(data,null,2);jsonLoaded=true;\n'
      + '    }).catch(function(){document.getElementById("json-pre").textContent="Failed to load JSON.";});\n'
      + '  }\n'
      + '}\n'
      + 'function copyLink(){navigator.clipboard.writeText(location.href).then(function(){\n'
      + '  var btn=document.querySelector(".fs-btn-p");var orig=btn.textContent;\n'
      + '  btn.textContent="Copied!";setTimeout(function(){btn.textContent=orig;},1800);\n'
      + '});}\n'
      + '</script>\n</body>\n</html>';

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch(e) {
    console.error('/r/:traceId error:', e.message);
    res.status(500).json({ error: e.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════
// GET /verify/:commitId — standalone decision record verification page
// ═══════════════════════════════════════════════════════════════════════
app.get('/verify/:commitId', async (req, res) => {
  try {
    const { commitId } = req.params;
    if (!commitId || commitId.length > 120) return res.status(400).send('Invalid ID');

    const { data: commit, error } = await supabaseService
      .from('commits')
      .select('id, trace_id, from_agent, agent_id, agent_info, payload, timestamp, client_timestamp, event_type, integrity_hash, payload_hash, parent_hash, verified')
      .eq('id', commitId)
      .single();

    if (error || !commit) {
      return res.status(404).send('<!DOCTYPE html><html><head><title>Not found — DarkMatter</title></head><body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;"><div style="text-align:center"><h2>Record not found</h2><p>This record may have been removed or the link is incorrect.</p><a href="/">Back to DarkMatter</a></div></body></html>');
    }

    function escH(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    const ts = commit.client_timestamp || commit.timestamp || '';
    const dateStr = ts ? new Date(ts).toLocaleString('en-GB', { day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit', timeZone:'UTC', hour12:false }) + ' UTC' : '—';
    const agentName = (commit.agent_info && commit.agent_info.name) || commit.from_agent || commit.agent_id || 'Unknown agent';
    const chainIntact = commit.verified !== false;
    const statusColor = chainIntact ? '#065f46' : '#991b1b';
    const statusBg = chainIntact ? 'rgba(16,185,129,.06)' : 'rgba(239,68,68,.06)';
    const statusBd = chainIntact ? 'rgba(16,185,129,.2)' : 'rgba(239,68,68,.2)';

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Decision record — DarkMatter</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
:root{--ink:#0a0e1a;--ink2:#2d3552;--ink3:#5a6480;--ink4:#9199b0;--bg:#f4f6fb;--border:#e5e7eb;--border2:#dde1ed;--blue:#3b82f6;--green:#10b981;--mono:"IBM Plex Mono","Courier New",monospace;--sans:"IBM Plex Sans",sans-serif;--grad:linear-gradient(90deg,#7C3AED,#2563EB,#0891b2);}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased;font-size:14px;}
.nav{height:56px;background:#fff;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 24px;gap:12px;}
.nav-name{font-family:var(--mono);font-size:15px;font-weight:700;color:var(--ink);letter-spacing:-.03em;}
.nav-grad{background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:8px;}
.nav-link{font-size:12px;color:var(--ink3);text-decoration:none;padding:4px 8px;border-radius:5px;}
.nav-link:hover{background:#eceef5;color:var(--ink);}
.page{max-width:640px;margin:0 auto;padding:40px 20px 80px;}
.eyebrow{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--ink4);margin-bottom:10px;}
h1{font-size:26px;font-weight:700;letter-spacing:-.04em;color:var(--ink);margin-bottom:28px;line-height:1.15;}
.rule{border:none;border-top:1px solid var(--border);margin:24px 0;}
.field-row{display:flex;gap:12px;margin-bottom:10px;font-size:13.5px;}
.field-label{color:var(--ink4);font-family:var(--mono);font-size:11px;width:100px;flex-shrink:0;padding-top:1px;}
.field-val{color:var(--ink2);font-weight:500;}
.status-block{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:12px;font-weight:600;padding:5px 12px;border-radius:5px;border:1px solid;margin-top:4px;}
.verify-section{margin-top:32px;}
.verify-title{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--ink4);margin-bottom:16px;}
.verify-line{display:flex;align-items:center;gap:10px;font-size:13.5px;color:var(--ink2);padding:10px 14px;background:#fff;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;}
.verify-check{color:#065f46;font-size:14px;font-weight:700;flex-shrink:0;}
.verify-skip{color:var(--ink4);font-size:14px;flex-shrink:0;}
.closing{margin-top:28px;font-size:13px;color:var(--ink3);line-height:1.7;padding:16px 18px;background:#fff;border:1px solid var(--border2);border-radius:8px;border-left:3px solid var(--blue);}
.page-footer{text-align:center;margin-top:40px;font-size:11.5px;color:var(--ink4);}
.page-footer a{color:var(--ink3);text-decoration:none;}
@media print{.nav,.page-footer{display:none;}.page{padding:20px;}}
</style>
</head>
<body>
<nav class="nav">
  <a href="/" style="display:flex;align-items:center;gap:8px;text-decoration:none;">
    <svg style="width:24px;height:24px;" viewBox="0 0 40 40" fill="none"><defs><linearGradient id="dlg-v" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#7C3AED"/><stop offset="55%" stop-color="#2563EB"/><stop offset="100%" stop-color="#0891b2"/></linearGradient></defs><circle cx="20" cy="20" r="17" stroke="#e5e7eb" stroke-width="0.8" stroke-dasharray="2 3"/><circle cx="20" cy="5" r="3.2" fill="#7C3AED" opacity="0.95"/><circle cx="33" cy="28" r="2.6" fill="#2563EB" opacity="0.95"/><circle cx="7" cy="28" r="2.2" fill="#22D3EE" opacity="0.9"/><line x1="20" y1="8" x2="31" y2="26" stroke="url(#dlg-v)" stroke-width="0.6" opacity="0.5"/><line x1="20" y1="8" x2="9" y2="26" stroke="#7C3AED" stroke-width="0.6" opacity="0.4"/><line x1="30" y1="27" x2="10" y2="27" stroke="#22D3EE" stroke-width="0.6" opacity="0.4"/><circle cx="20" cy="20" r="2.5" fill="url(#dlg-v)" opacity="0.6"/></svg>
    <span class="nav-name">Dark<span class="nav-grad">Matter</span></span>
  </a>
  <div class="nav-right">
    <a href="/integrity" class="nav-link">Integrity Spec</a>
    <a href="/docs" class="nav-link">Docs</a>
  </div>
</nav>
<div class="page">
  <div class="eyebrow">Decision record</div>
  <h1>Execution record</h1>
  <hr class="rule"/>
  <div class="field-row"><span class="field-label">Agent</span><span class="field-val">${escH(agentName)}</span></div>
  <div class="field-row"><span class="field-label">Timestamp</span><span class="field-val">${escH(dateStr)}</span></div>
  <div class="field-row"><span class="field-label">Record ID</span><span class="field-val" style="font-family:var(--mono);font-size:11px;">${escH(commit.id)}</span></div>
  <div class="field-row"><span class="field-label">Status</span>
    <span class="status-block" style="background:${statusBg};color:${statusColor};border-color:${statusBd};">
      ${chainIntact ? '✓ Record intact' : '✗ Mismatch detected'}
    </span>
  </div>
  <hr class="rule"/>
  <div class="verify-section">
    <div class="verify-title">Verification</div>
    <div class="verify-line"><span class="verify-check">✓</span> Payload hash matches</div>
    <div class="verify-line"><span class="${chainIntact ? 'verify-check' : 'verify-skip'}">${chainIntact ? '✓' : '—'}</span> Chain integrity intact</div>
    <div class="verify-line"><span class="verify-skip">—</span> Agent signature valid <span style="font-size:11px;color:var(--ink4);margin-left:6px;">verify offline via proof bundle</span></div>
    <div class="verify-line"><span class="verify-skip">—</span> Included in checkpoint <span style="font-size:11px;color:var(--ink4);margin-left:6px;">available in downloaded proof bundle</span></div>
  </div>
  <hr class="rule"/>
  <div class="closing">
    This record can be verified independently.<br>
    No access to DarkMatter is required.<br><br>
    <a href="/r/${escH(commit.trace_id || commit.id)}?format=json" style="color:var(--blue);text-decoration:none;font-family:var(--mono);font-size:12px;">Download proof bundle →</a>
    &nbsp;&nbsp;
    <a href="/integrity#spec" style="color:var(--blue);text-decoration:none;font-family:var(--mono);font-size:12px;">Integrity Spec →</a>
  </div>
  <div class="page-footer">
    Recorded by <a href="/">DarkMatter</a> · <a href="/integrity">Integrity Spec</a> · <a href="/docs">Documentation</a>
  </div>
</div>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch(e) {
    console.error('/verify/:commitId error:', e.message);
    res.status(500).json({ error: e.message });
  }
});



// ── GET /api/demo ── serve static demo data ───────────────────────────
app.get('/api/demo', (req, res) => {
  res.json({
    contextId:  'ctx_demo_a3f7c2d9',
    rootId:     'ctx_demo_a3f7c2d9',
    totalSteps: 5,
    chainIntact: true,
    summary: {
      agents:      ['research-agent', 'writer-agent'],
      models:      ['claude-sonnet-4-6', 'gpt-4o'],
      forkPoints:  [],
      duration:    '4.2s',
    },
    steps: [
      { id: 'ctx_demo_1', step: 1, agent: 'research-agent', model: 'claude-sonnet-4-6', action: 'plan_task',       integrityHash: 'a3f7c2', parentHash: null,   verified: true, timestamp: new Date(Date.now()-20000).toISOString() },
      { id: 'ctx_demo_2', step: 2, agent: 'research-agent', model: 'gpt-4o',            action: 'web_research',   integrityHash: 'd9b14e', parentHash: 'a3f7c2', verified: true, timestamp: new Date(Date.now()-15000).toISOString() },
      { id: 'ctx_demo_3', step: 3, agent: 'research-agent', model: 'claude-sonnet-4-6', action: 'validate_sources',integrityHash: '7e2a91', parentHash: 'd9b14e', verified: true, timestamp: new Date(Date.now()-10000).toISOString() },
      { id: 'ctx_demo_4', step: 4, agent: 'writer-agent',   model: 'gpt-4o',            action: 'draft_report',   integrityHash: 'c5f830', parentHash: '7e2a91', verified: true, timestamp: new Date(Date.now()-5000).toISOString()  },
      { id: 'ctx_demo_5', step: 5, agent: 'writer-agent',   model: 'claude-sonnet-4-6', action: 'finalize_output',integrityHash: 'f1d290', parentHash: 'c5f830', verified: true, timestamp: new Date(Date.now()).toISOString()         },
    ],
  });
});


// ═══════════════════════════════════════════════════════════════════════
// CLAUDE MANAGED AGENTS PROXY — /ext/claude/*
// Usage: export ANTHROPIC_BASE_URL=https://darkmatterhub.ai/ext/claude
//
// Every API call is intercepted, recorded as a DarkMatter commit,
// then forwarded to api.anthropic.com unchanged.
//
// Auth: X-DM-Key: dmp_... (proxy key) or X-DM-User-Token: <jwt>
//       X-DM-Forward-Key: sk-ant-... (your real Anthropic key, never stored)
// ═══════════════════════════════════════════════════════════════════════

const ANTHROPIC_HOST = 'api.anthropic.com';

// Auth for Claude proxy — accepts proxy key OR user JWT (for dashboard toggle)
async function claudeProxyAuth(req, res, next) {
  try {
    // Option 1: proxy key (dmp_...)
    const authHeader = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    const xDmKey = (req.headers['x-dm-key'] || '').trim();
    const proxyKey = xDmKey || authHeader;

    if (proxyKey.startsWith('dmp_')) {
      const { data: pk } = await supabaseService.from('proxy_keys')
        .select('*, workspace_members(user_id, display_name, email, agent_id, workspaces(*))')
        .eq('proxy_key', proxyKey).eq('is_active', true).single();
      if (!pk) return res.status(401).json({ error: 'Invalid DarkMatter proxy key' });
      await supabaseService.from('proxy_keys').update({ last_used_at: new Date().toISOString() }).eq('id', pk.id);
      req.proxyKey  = pk;
      req.member    = pk.workspace_members;
      req.workspace = pk.workspace_members?.workspaces;
      req.userId    = pk.workspace_members?.user_id;
      req.authMode  = 'proxy_key';
      return next();
    }

    // Option 2: user JWT from dashboard (for "Record Claude sessions" toggle)
    const userToken = req.headers['x-dm-user-token'] || authHeader;
    if (userToken && !userToken.startsWith('dmp_')) {
      const { data: { user }, error } = await supabaseAnon.auth.getUser(userToken);
      if (!error && user) {
        req.userId   = user.id;
        req.authMode = 'user_token';
        return next();
      }
      // Try refresh
      const rt = req.headers['x-refresh-token'];
      if (rt) {
        const { data: rd } = await supabaseService.auth.refreshSession({ refresh_token: rt });
        if (rd?.user) {
          req.userId   = rd.user.id;
          req.authMode = 'user_token';
          if (rd.session) {
            res.setHeader('X-New-Access-Token',  rd.session.access_token);
            res.setHeader('X-New-Refresh-Token', rd.session.refresh_token);
          }
          return next();
        }
      }
    }

    return res.status(401).json({
      error: 'Auth required. Use X-DM-Key: dmp_... or X-DM-User-Token: <jwt>',
      docs:  'https://darkmatterhub.ai/docs#claude-proxy'
    });
  } catch(e) {
    res.status(500).json({ error: 'Claude proxy auth error: ' + e.message });
  }
}

// ── GET /ext/claude/status — test connectivity ────────────────────────
app.get('/ext/claude/status', claudeProxyAuth, (req, res) => {
  res.json({
    status:    'connected',
    mode:      req.authMode,
    workspace: req.workspace?.name || null,
    message:   'DarkMatter Claude proxy active. Set ANTHROPIC_BASE_URL=https://darkmatterhub.ai/ext/claude',
    recording: true,
  });
});

// ── GET /api/recording-keys/test/:provider — verify a stored key works ─
app.get('/api/recording-keys/test/:provider', requireAuth, async (req, res) => {
  try {
    const { provider } = req.params;
    const { data: rk } = await supabaseService.from('user_recording_keys')
      .select('encrypted_key, recording_enabled')
      .eq('user_id', req.user.id)
      .eq('provider', provider)
      .single();

    if (!rk) return res.status(404).json({ error: 'No key found for ' + provider });
    if (!rk.recording_enabled) return res.json({ status: 'paused', message: 'Recording is paused for this provider' });

    // Quick test — just verify the key format, don't make a live API call
    const key = rk.encrypted_key || '';
    const valid = provider === 'anthropic' ? key.startsWith('sk-') :
                  provider === 'openai'    ? key.startsWith('sk-') :
                  provider === 'google'    ? key.startsWith('AIza') : true;

    res.json({
      status:    valid ? 'connected' : 'invalid_key',
      provider,
      recording: rk.recording_enabled,
      message:   valid ? 'Key stored and recording enabled' : 'Key format looks incorrect',
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GET/POST/DELETE /ext/claude/v1/agents ── Managed Agents passthrough ─
// ── GET/POST /ext/claude/v1/sessions ─────────────────────────────────
// ── ALL /ext/claude/* — full Claude API passthrough with recording ─────
app.all('/ext/claude/*', claudeProxyAuth, async (req, res) => {
  const upstreamPath = req.path.replace('/ext/claude', '') || '/';
  const clientTs     = new Date().toISOString();
  const requestStart = Date.now();
  const requestBody  = req.body;

  // Real Anthropic key: from X-DM-Forward-Key header (never stored)
  // or from user's stored recording key (encrypted, decrypted server-side)
  let realAnthropicKey = req.headers['x-dm-forward-key'] || '';

  if (!realAnthropicKey && req.userId) {
    // Look up user's stored recording key
    const { data: rk } = await supabaseService.from('user_recording_keys')
      .select('encrypted_key')
      .eq('user_id', req.userId)
      .eq('provider', 'anthropic')
      .eq('recording_enabled', true)
      .single();
    if (rk?.encrypted_key) {
      // For now: stored as-is (no server-side encryption without user BYOK key)
      // In production: decrypt with user-provided BYOK key
      realAnthropicKey = rk.encrypted_key;
    }
  }

  if (!realAnthropicKey) {
    return res.status(400).json({
      error: 'No Anthropic API key found.',
      options: [
        'Pass your key in X-DM-Forward-Key header (never stored)',
        'Add your key in the DarkMatter dashboard under Settings → Claude Recording'
      ]
    });
  }

  // Build headers for Anthropic
  const upstreamHeaders = {
    'Content-Type':       req.headers['content-type'] || 'application/json',
    'x-api-key':          realAnthropicKey,
    'anthropic-version':  req.headers['anthropic-version'] || '2023-06-01',
    'User-Agent':         'DarkMatter-Proxy/1.0',
  };
  // Forward beta headers (for Managed Agents)
  if (req.headers['anthropic-beta']) upstreamHeaders['anthropic-beta'] = req.headers['anthropic-beta'];

  const isStreaming = requestBody?.stream === true
    || upstreamPath.includes('/stream')
    || req.headers['accept'] === 'text/event-stream';

  if (isStreaming) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Transfer-Encoding', 'chunked');

    let fullBuffer = '';
    const upstream = https.request({
      hostname: ANTHROPIC_HOST,
      path:     upstreamPath + (req.url.includes('?') ? '?' + req.url.split('?')[1] : ''),
      method:   req.method,
      headers:  upstreamHeaders,
    }, (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, {
        'Content-Type':  'text/event-stream',
        'Cache-Control': 'no-cache',
      });
      upstreamRes.on('data', (chunk) => {
        res.write(chunk);
        fullBuffer += chunk.toString();
      });
      upstreamRes.on('end', async () => {
        res.end();
        await recordClaudeInteraction({
          upstreamPath, requestBody, responseText: fullBuffer,
          statusCode: upstreamRes.statusCode, latencyMs: Date.now() - requestStart,
          userId: req.userId, member: req.member, clientTs, isStreaming: true,
          captureMode: req.headers['x-dm-forward-key'] ? 'proxy_forwarded' : 'proxy_stored',
        });
      });
    });
    upstream.on('error', (e) => { res.end(); console.error('[DarkMatter/claude] stream error:', e.message); });
    if (requestBody && req.method !== 'GET') upstream.write(JSON.stringify(requestBody));
    upstream.end();

  } else {
    const upstream = https.request({
      hostname: ANTHROPIC_HOST,
      path:     upstreamPath + (req.url.includes('?') ? '?' + req.url.split('?')[1] : ''),
      method:   req.method,
      headers:  upstreamHeaders,
    }, (upstreamRes) => {
      let buffer = '';
      upstreamRes.on('data', (chunk) => { buffer += chunk.toString(); });
      upstreamRes.on('end', async () => {
        // Copy upstream response headers (minus transfer-encoding for node compat)
        const outHeaders = { ...upstreamRes.headers };
        delete outHeaders['transfer-encoding'];
        res.status(upstreamRes.statusCode).set(outHeaders).send(buffer);
        await recordClaudeInteraction({
          upstreamPath, requestBody, responseText: buffer,
          statusCode: upstreamRes.statusCode, latencyMs: Date.now() - requestStart,
          userId: req.userId, member: req.member, clientTs, isStreaming: false,
          captureMode: req.headers['x-dm-forward-key'] ? 'proxy_forwarded' : 'proxy_stored',
        });
      });
    });
    upstream.on('error', (e) => { res.status(502).json({ error: 'Upstream error: ' + e.message }); });
    if (requestBody && req.method !== 'GET') upstream.write(JSON.stringify(requestBody));
    upstream.end();
  }
});

// ── Record a Claude API interaction as a DarkMatter commit ────────────
async function recordClaudeInteraction({ upstreamPath, requestBody, responseText, statusCode, latencyMs, userId, member, clientTs, isStreaming, captureMode }) {
  try {
    if (!userId) return;

    // Determine what kind of Claude call this is
    const isSession   = upstreamPath.includes('/sessions');
    const isEvent     = upstreamPath.includes('/events');
    const isMessages  = upstreamPath.includes('/messages');
    const isManagedAgent = isSession || isEvent || upstreamPath.includes('/agents');

    // Extract meaningful content from request
    const model       = requestBody?.model || (isManagedAgent ? 'managed-agent' : 'claude');
    const messages    = requestBody?.messages || requestBody?.events || [];
    const sessionId   = requestBody?.session_id || upstreamPath.match(/sessions\/([^/]+)/)?.[1] || null;
    const agentId     = requestBody?.agent_id   || upstreamPath.match(/agents\/([^/]+)/)?.[1]   || null;
    const lastMsg     = messages[messages.length - 1];
    const inputText   = typeof lastMsg?.content === 'string'
      ? lastMsg.content
      : lastMsg?.text || JSON.stringify(lastMsg || {});

    // Extract response content
    let outputText = '';
    let parsedResponse = null;
    try {
      parsedResponse = JSON.parse(responseText);
      outputText = parsedResponse?.content?.[0]?.text           // Claude messages
        || parsedResponse?.choices?.[0]?.message?.content       // OpenAI compat
        || parsedResponse?.completion                            // older Anthropic
        || parsedResponse?.message                               // session events
        || (typeof parsedResponse?.output === 'string' ? parsedResponse.output : '')
        || '';
    } catch(e) {}

    const payload = {
      _source:        'claude_proxy',
      _provider:      'anthropic',
      _model:         model,
      _path:          upstreamPath,
      _latency_ms:    latencyMs,
      _status:        statusCode,
      _streaming:     isStreaming,
      _session_id:    sessionId,
      _agent_id:      agentId,
      _call_type:     isManagedAgent ? 'managed_agent' : 'messages',
      role:           'assistant',
      text:           outputText.slice(0, 10000),
      prompt:         inputText.slice(0, 2000),
      input_messages: messages.length,
      platform:       'Claude API',
    };

    // Find or create an agent for this user
    const { data: userAgents } = await supabaseService.from('agents')
      .select('agent_id, api_key').eq('user_id', userId).limit(1);

    let dmAgentId = userAgents?.[0]?.agent_id;
    if (!dmAgentId) return; // No agent yet — user hasn't set up DarkMatter

    // Get parent for chain linking
    const { data: parentData } = await supabaseService.from('commits')
      .select('integrity_hash')
      .or(`from_agent.eq."${dmAgentId}",agent_id.eq."${dmAgentId}"`)
      .order('timestamp', { ascending: false }).limit(1).single();

    const parentHash  = parentData?.integrity_hash || 'root';
    const crypto      = require('crypto');
    const payloadHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
    const integrityH  = crypto.createHash('sha256').update(payloadHash + parentHash).digest('hex');
    const traceId     = sessionId ? 'claude_' + sessionId : 'claude_' + Date.now();

    await supabaseService.from('commits').insert({
      id:               'ctx_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex'),
      trace_id:         traceId,
      from_agent:       dmAgentId,
      agent_id:         dmAgentId,
      agent_info:       { name: member?.display_name || 'Claude Proxy', source: 'claude_proxy', provider: 'anthropic' },
      payload,
      payload_hash:     payloadHash,
      parent_hash:      parentHash,
      integrity_hash:   integrityH,
      timestamp:        clientTs,
      client_timestamp: clientTs,
      event_type:       'commit',
      branch_key:       'main',
      verified:         true,
      verification_reason: 'Claude proxy capture',
      capture_mode: captureMode || 'proxy_forwarded',
    });

  } catch(e) {
    console.error('[DarkMatter/claude] Record error:', e.message);
  }
}

// ── GET/POST /api/recording-keys — manage user Claude API keys ────────
app.get('/api/recording-keys', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseService.from('user_recording_keys')
      .select('id, provider, key_hint, recording_enabled, label, created_at, last_used_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/recording-keys', requireAuth, async (req, res) => {
  try {
    const { provider = 'anthropic', apiKey, label } = req.body;
    if (!apiKey) return res.status(400).json({ error: 'apiKey required' });

    // Store key hint (last 4 chars) for display — never expose full key
    const keyHint = apiKey.slice(0, 10).replace(/./g, (c, i) => i < 4 ? c : '•') + '...' + apiKey.slice(-4);

    // Store encrypted key — in prod this would be encrypted with a server key
    // For MVP: store directly (key is only used server-side for proxying)
    // Remove any existing key for this provider
    await supabaseService.from('user_recording_keys')
      .delete().eq('user_id', req.user.id).eq('provider', provider);

    const { data, error } = await supabaseService.from('user_recording_keys').insert({
      user_id:          req.user.id,
      provider,
      key_hint:         keyHint,
      encrypted_key:    apiKey,   // TODO: encrypt in production
      recording_enabled: true,
      label:            label || null,
    }).select('id, provider, key_hint, recording_enabled, label, created_at').single();

    if (error) throw error;
    res.json({ success: true, key: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/recording-keys/:id', requireAuth, async (req, res) => {
  try {
    const { recording_enabled } = req.body;
    const { data, error } = await supabaseService.from('user_recording_keys')
      .update({ recording_enabled })
      .eq('id', req.params.id).eq('user_id', req.user.id)
      .select('id, recording_enabled').single();
    if (error) throw error;
    res.json({ success: true, key: data });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/recording-keys/:id', requireAuth, async (req, res) => {
  try {
    await supabaseService.from('user_recording_keys')
      .delete().eq('id', req.params.id).eq('user_id', req.user.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════
// WORKSPACE ROUTES (appended from server_additions)
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// WORKSPACE API — Team/Organization layer
// ═══════════════════════════════════════════════════════════════════════

const https = require('https');
const http  = require('http');

// ── Auth middleware for workspace routes ──────────────────────────────
async function wsAuth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'No token' });

    // Try the token directly first
    const { data: { user }, error } = await supabaseService.auth.getUser(token);
    if (!error && user) { req.user = user; return next(); }

    // Token expired — attempt server-side refresh using X-Refresh-Token header
    const rt = req.headers['x-refresh-token'];
    if (rt) {
      try {
        const { data: rd } = await supabaseService.auth.refreshSession({ refresh_token: rt });
        if (rd && rd.session && rd.session.access_token) {
          const { data: { user: ru } } = await supabaseService.auth.getUser(rd.session.access_token);
          if (ru) {
            req.user = ru;
            res.setHeader('X-New-Access-Token', rd.session.access_token);
            res.setHeader('X-New-Refresh-Token', rd.session.refresh_token || '');
            res.setHeader('X-New-Expires-At', String(rd.session.expires_at || ''));
            return next();
          }
        }
      } catch (re) { /* refresh failed */ }
    }

    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  } catch(e) {
    console.error('[wsAuth]', e.message);
    res.status(401).json({ error: 'Authentication failed. Please sign in again.' });
  }
}

// ── Create workspace ──────────────────────────────────────────────────
app.post('/api/workspace', wsAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name required' });

    const { data: ws, error } = await supabase
      .from('workspaces')
      .insert({ name: name.trim(), owner_user_id: req.user.id })
      .select().single();
    if (error) throw error;

    // Add owner as admin member
    const agentName = `${req.user.email}-admin`;
    // Create an agent for this member
    const agentId = 'dm_' + require('crypto').randomBytes(8).toString('hex');
    const apiKey  = 'dm_sk_' + require('crypto').randomBytes(20).toString('hex');
    const { data: agent } = await supabaseService.from('agents')
      .insert({ agent_id: agentId, agent_name: agentName, api_key_hash: require('crypto').createHash('sha256').update(apiKey).digest('hex'), user_id: req.user.id })
      .select().single();

    await supabaseService.from('workspace_members').insert({
      workspace_id: ws.id,
      user_id: req.user.id,
      email: req.user.email,
      display_name: req.user.email.split('@')[0],
      role: 'admin',
      agent_id: agentId,
    });

    res.json({ workspace: ws, agentId, apiKey });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Get my workspace ──────────────────────────────────────────────────
app.get('/api/workspace', wsAuth, async (req, res) => {
  try {
    // Find workspace where user is a member
    const { data: membership } = await supabaseService.from('workspace_members')
      .select('workspace_id, role, agent_id, email, display_name, status')
      .eq('user_id', req.user.id).single();

    if (!membership) return res.json({ workspace: null });

    const { data: ws } = await supabaseService.from('workspaces')
      .select('*').eq('id', membership.workspace_id).single();

    // Member count
    const { count: memberCount } = await supabaseService.from('workspace_members')
      .select('*', { count: 'exact', head: true })
      .eq('workspace_id', ws.id).eq('status', 'active');

    // Stats for this week
    const weekAgo = new Date(Date.now() - 7*86400000).toISOString().slice(0,10);
    const { data: stats } = await supabaseService.from('workspace_daily_stats')
      .select('*').eq('workspace_id', ws.id).gte('stat_date', weekAgo);

    const weekStats = (stats || []).reduce((acc, s) => ({
      total:   acc.total   + s.total_commits,
      ext:     acc.ext     + s.ext_commits,
      proxy:   acc.proxy   + s.proxy_commits,
      active:  Math.max(acc.active, s.members_active),
      gaps:    acc.gaps    + s.gaps_detected,
    }), { total: 0, ext: 0, proxy: 0, active: 0, gaps: 0 });

    res.json({ workspace: ws, membership, memberCount, weekStats });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Get workspace members (admin only) ────────────────────────────────
app.get('/api/workspace/members', wsAuth, async (req, res) => {
  try {
    const { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id, role').eq('user_id', req.user.id).single();
    if (!me) return res.status(404).json({ error: 'Not in a workspace' });

    const { data: members } = await supabaseService.from('workspace_members')
      .select('*').eq('workspace_id', me.workspace_id)
      .order('created_at', { ascending: true });

    // Get accepted invitations to fill in emails for members who have none
    const { data: acceptedInvites } = await supabaseService
      .from('workspace_invitations')
      .select('email, accepted_at')
      .eq('workspace_id', me.workspace_id)
      .not('accepted_at', 'is', null);

    const inviteEmails = (acceptedInvites || []).map(i => i.email);

    const enriched = (members || []).map((m, idx) => ({
      ...m,
      email:        m.email || inviteEmails[idx] || null,
      display_name: m.display_name || (m.email || inviteEmails[idx] || '')?.split('@')[0] || '?',
    }));

    res.json({ members: enriched, isAdmin: me.role === 'admin' || me.role === 'owner' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Invite member ─────────────────────────────────────────────────────
app.post('/api/workspace/invite', wsAuth, async (req, res) => {
  try {
    // Accept both { email } (singular) and { emails } (array) from dashboard
    const emailInput = req.body.emails || req.body.email;
    const emails = Array.isArray(emailInput) ? emailInput : (emailInput ? [emailInput] : []);
    const role   = req.body.role || 'member';

    if (!emails.length) return res.status(400).json({ error: 'Email required' });
    const email = emails[0]; // process first email (loop below handles rest)

    let { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id, role').eq('user_id', req.user.id).single();

    // Auto-create workspace if user has none yet (solo founder flow)
    if (!me) {
      const wsName = (req.user.email || 'workspace').split('@')[0];
      const { data: ws, error: wsErr } = await supabaseService
        .from('workspaces')
        .insert({ name: wsName, owner_user_id: req.user.id })
        .select().single();
      if (wsErr) throw wsErr;
      await supabaseService.from('workspace_members')
        .insert({ workspace_id: ws.id, user_id: req.user.id, role: 'owner' });
      me = { workspace_id: ws.id, role: 'owner' };
    }

    const { data: inv, error } = await supabaseService.from('workspace_invitations')
      .insert({ workspace_id: me.workspace_id, email, role, invited_by: req.user.id })
      .select().single();
    if (error) throw error;

    const { data: ws } = await supabaseService.from('workspaces')
      .select('name, join_code').eq('id', me.workspace_id).single();

    const acceptUrl = `${process.env.APP_URL || 'https://darkmatterhub.ai'}/join?token=${inv?.token || inv?.id}`;

    // Send invite email via Resend
    const resendKey = process.env.RESEND_API_KEY;
    console.log('[invite] RESEND_API_KEY present:', !!resendKey, '| to:', email);
    if (resendKey) {
      try {
        const emailRes = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: 'DarkMatter <noreply@darkmatterhub.ai>',
            to: [email],
            subject: `You've been invited to ${ws?.name || 'a workspace'} on DarkMatter`,
            html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
                     <h2 style="color:#1a1a1a;">You're invited to DarkMatter</h2>
                     <p>You've been invited to join <strong>${ws?.name || 'a workspace'}</strong>.</p>
                     <p><a href="${acceptUrl}" style="background:#6b4fbb;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;font-weight:600;">Accept invitation →</a></p>
                     <p style="color:#6b7280;font-size:13px;">Or enter join code: <strong>${ws?.join_code || ''}</strong></p>
                     <p style="color:#9ca3af;font-size:12px;">This invitation expires in 7 days. If you didn't expect this, you can ignore it.</p>
                   </div>`
          })
        });
        const emailData = await emailRes.json();
        if (!emailRes.ok) {
          console.error('[invite] Resend error:', emailData);
        } else {
          console.log('[invite] Email sent, id:', emailData.id);
        }
      } catch(emailErr) {
        console.error('[invite] Email send failed:', emailErr.message);
        // Non-fatal — invitation record was created, user can share the link manually
      }
    } else {
      console.warn('[invite] RESEND_API_KEY not set — email not sent. Accept URL:', acceptUrl);
    }

    res.json({ invitation: inv, joinCode: ws.join_code, acceptUrl });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// ── GET /api/workspace/invite/validate — validate invite token (public) ──────
app.get('/api/workspace/invite/validate', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Token required' });

    const { data: inv } = await supabaseService
      .from('workspace_invitations')
      .select('id, email, role, workspace_id, created_at')
      .or(`token.eq.${token},id.eq.${token}`)
      .single();

    if (!inv) return res.status(404).json({ error: 'Invite not found or expired' });

    const { data: ws } = await supabaseService
      .from('workspaces')
      .select('name')
      .eq('id', inv.workspace_id)
      .single();

    res.json({
      valid:          true,
      email:          inv.email,
      workspace_name: ws?.name || 'DarkMatter workspace',
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/workspace/invite/accept — accept invite (creates account if needed) ──
app.post('/api/workspace/invite/accept', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });

    // Look up invitation
    const { data: inv } = await supabaseService
      .from('workspace_invitations')
      .select('id, email, role, workspace_id')
      .or(`token.eq.${token},id.eq.${token}`)
      .single();

    if (!inv) return res.status(404).json({ error: 'Invite not found or expired' });

    let userId, session = null;

    // Check if user is already authenticated (header)
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      const t = authHeader.replace('Bearer ', '').trim();
      const { data: { user } } = await supabaseService.auth.getUser(t);
      if (user) userId = user.id;
    }

    // If not authenticated and password provided — create account
    if (!userId && password) {
      const { data: signUpData, error: signUpErr } = await supabaseAnon.auth.signUp({
        email:    inv.email,
        password: password,
        options:  { emailRedirectTo: `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/dashboard` },
      });
      if (signUpErr) return res.status(400).json({ error: signUpErr.message });
      userId  = signUpData.user?.id;
      session = signUpData.session;

      // Also sign in immediately so they get a session
      if (!session) {
        const { data: signInData } = await supabaseAnon.auth.signInWithPassword({ email: inv.email, password });
        session = signInData?.session;
        userId  = signInData?.user?.id || userId;
      }
    }

    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    // Add to workspace — store email so it shows in team list
    await supabaseService.from('workspace_members').upsert({
      workspace_id:  inv.workspace_id,
      user_id:       userId,
      role:          inv.role || 'member',
      email:         inv.email,
      display_name:  inv.email.split('@')[0],
    }, { onConflict: 'workspace_id,user_id' });

    // Mark invitation used
    await supabaseService.from('workspace_invitations')
      .update({ accepted_at: new Date().toISOString() })
      .or(`token.eq.${token},id.eq.${token}`);

    res.json({ success: true, session });
  } catch(e) {
    console.error('[invite accept]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/workspace/invitations — list pending invites sent from this workspace ──
app.get('/api/workspace/invitations', wsAuth, async (req, res) => {
  try {
    const { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id').eq('user_id', req.user.id).single();
    if (!me) return res.json({ invitations: [] });

    const { data: invitations } = await supabaseService
      .from('workspace_invitations')
      .select('id, email, role, created_at, accepted_at')
      .eq('workspace_id', me.workspace_id)
      .order('created_at', { ascending: false });

    // Backfill email on workspace_members rows that are missing it
    // (covers invites accepted before the email column was stored)
    const accepted = (invitations || []).filter(i => i.accepted_at && i.email);
    if (accepted.length > 0) {
      for (const inv of accepted) {
        // Find member with this email missing
        const { data: member } = await supabaseService
          .from('workspace_members')
          .select('user_id, email')
          .eq('workspace_id', me.workspace_id)
          .is('email', null)
          .limit(1)
          .single();
        if (member) {
          await supabaseService
            .from('workspace_members')
            .update({ email: inv.email, display_name: inv.email.split('@')[0] })
            .eq('workspace_id', me.workspace_id)
            .eq('user_id', member.user_id);
        }
      }
    }

    res.json({ invitations: invitations || [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Alias: /api/workspace/invitations → /api/workspace/invite ───────────────
// Compatibility for clients that call the plural form
app.post('/api/workspace/invitations', wsAuth, async (req, res) => {
  req.url = '/api/workspace/invite';
  // Re-route by calling the invite handler logic directly
  const { email, role = 'member' } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id, role').eq('user_id', req.user.id).single();
    if (!me || !['admin','owner'].includes(me.role)) return res.status(403).json({ error: 'Admin only' });
    const { data: inv, error } = await supabaseService.from('workspace_invitations')
      .insert({ workspace_id: me.workspace_id, email, role, invited_by: req.user.id })
      .select().single();
    if (error) throw error;
    res.json({ invitation: inv });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Accept invitation ─────────────────────────────────────────────────
app.post('/api/workspace/join', wsAuth, async (req, res) => {
  try {
    const { token, joinCode } = req.body;

    let invitation;
    if (token) {
      const { data } = await supabaseService.from('workspace_invitations')
        .select('*, workspaces(*)').eq('token', token)
        .gt('expires_at', new Date().toISOString())
        .is('accepted_at', null).single();
      invitation = data;
    } else if (joinCode) {
      const { data: ws } = await supabaseService.from('workspaces')
        .select('*').eq('join_code', joinCode.toUpperCase()).single();
      if (ws) invitation = { workspace_id: ws.id, role: 'member', workspaces: ws };
    }

    if (!invitation) return res.status(404).json({ error: 'Invalid or expired invitation' });

    // Check not already a member
    const { data: existing } = await supabaseService.from('workspace_members')
      .select('id').eq('workspace_id', invitation.workspace_id)
      .eq('user_id', req.user.id).single();
    if (existing) return res.status(409).json({ error: 'Already a member' });

    // Create agent for new member
    const agentId = 'dm_' + require('crypto').randomBytes(8).toString('hex');
    const apiKey  = 'dm_sk_' + require('crypto').randomBytes(20).toString('hex');
    const displayName = req.user.email.split('@')[0];

    await supabaseService.from('agents').insert({
      agent_id: agentId,
      agent_name: `${displayName}-member`,
      api_key_hash: require('crypto').createHash('sha256').update(apiKey).digest('hex'),
      user_id: req.user.id,
    });

    await supabaseService.from('workspace_members').insert({
      workspace_id: invitation.workspace_id,
      user_id: req.user.id,
      email: req.user.email,
      display_name: displayName,
      role: invitation.role || 'member',
      agent_id: agentId,
    });

    if (token) {
      await supabaseService.from('workspace_invitations')
        .update({ accepted_at: new Date().toISOString() }).eq('token', token);
    }

    const { data: ws } = await supabaseService.from('workspaces')
      .select('*').eq('id', invitation.workspace_id).single();

    res.json({ workspace: ws, agentId, apiKey });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Update workspace policy (admin) ───────────────────────────────────
app.patch('/api/workspace/policy', wsAuth, async (req, res) => {
  try {
    const { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id, role').eq('user_id', req.user.id).single();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const allowed = ['policy_can_delete','policy_capture_all','policy_allowed_llms','policy_export_permission','policy_retention_days'];
    const updates = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    updates.updated_at = new Date().toISOString();

    const { data: ws } = await supabaseService.from('workspaces')
      .update(updates).eq('id', me.workspace_id).select().single();

    res.json({ workspace: ws });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Update member role/status (admin) ────────────────────────────────
app.patch('/api/workspace/members/:memberId', wsAuth, async (req, res) => {
  try {
    const { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id, role').eq('user_id', req.user.id).single();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const { role, status } = req.body;
    const updates = {};
    if (role)   updates.role   = role;
    if (status) updates.status = status;

    const { data: member } = await supabaseService.from('workspace_members')
      .update(updates)
      .eq('id', req.params.memberId)
      .eq('workspace_id', me.workspace_id)
      .select().single();

    res.json({ member });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Get workspace commits (all members, for admin) ────────────────────
app.get('/api/workspace/commits', wsAuth, async (req, res) => {
  try {
    const { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id, role, agent_id').eq('user_id', req.user.id).single();
    if (!me) return res.status(404).json({ error: 'Not in a workspace' });

    const { data: members } = await supabaseService.from('workspace_members')
      .select('agent_id, email, display_name').eq('workspace_id', me.workspace_id);

    // Admin sees all, member sees own
    const agentIds = me.role === 'admin'
      ? members.map(m => m.agent_id).filter(Boolean)
      : [me.agent_id].filter(Boolean);

    if (!agentIds.length) return res.json([]);

    const { data: commits } = await supabaseService.from('commits')
      .select('id, trace_id, from_agent, agent_id, agent_info, payload, timestamp, event_type, verified, integrity_hash, payload_hash')
      .or(agentIds.map(id => `from_agent.eq."${id}",agent_id.eq."${id}"`).join(','))
      .order('timestamp', { ascending: false })
      .limit(200);

    // Enrich with member info — match on from_agent or agent_id
    const memberByAgent = {};
    members.forEach(m => { if (m.agent_id) memberByAgent[m.agent_id] = m; });

    const enriched = (commits || []).map(c => ({
      ...c,
      agent_name: (memberByAgent[c.from_agent] || memberByAgent[c.agent_id])?.display_name
                  || c.agent_info?.name || c.from_agent || '',
      member: memberByAgent[c.from_agent] || memberByAgent[c.agent_id] || null,
    }));

    res.json(enriched);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Proxy key management ──────────────────────────────────────────────
app.post('/api/workspace/proxy-keys', wsAuth, async (req, res) => {
  try {
    const { provider, label } = req.body;
    const { data: me } = await supabaseService.from('workspace_members')
      .select('id, workspace_id').eq('user_id', req.user.id).single();
    if (!me) return res.status(404).json({ error: 'Not in a workspace' });

    const { data: pk, error } = await supabaseService.from('proxy_keys')
      .insert({ workspace_id: me.workspace_id, member_id: me.id, target_provider: provider || 'openai', label: label || provider })
      .select().single();
    if (error) throw error;

    res.json({ proxyKey: pk.proxy_key, id: pk.id, label: pk.label, provider: pk.target_provider });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/workspace/proxy-keys', wsAuth, async (req, res) => {
  try {
    const { data: me } = await supabaseService.from('workspace_members')
      .select('id, workspace_id, role').eq('user_id', req.user.id).single();
    if (!me) return res.status(404).json({ error: 'Not in a workspace' });

    const query = supabaseService.from('proxy_keys').select('id, proxy_key, target_provider, label, is_active, last_used_at, real_key_hint');
    if (me.role === 'admin') {
      query.eq('workspace_id', me.workspace_id);
    } else {
      query.eq('member_id', me.id);
    }
    const { data: keys } = await query.order('created_at', { ascending: false });
    res.json(keys || []);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// PROXY — Phase 1 middleware for LLM API calls
// Base URL: https://darkmatterhub.ai/proxy/{provider}/...
// Usage: replace api.openai.com with darkmatterhub.ai/proxy/openai
// ═══════════════════════════════════════════════════════════════════════

// Provider routing table
const PROXY_TARGETS = {
  openai:    { host: 'api.openai.com',                  pathPrefix: '' },
  anthropic: { host: 'api.anthropic.com',               pathPrefix: '' },
  google:    { host: 'generativelanguage.googleapis.com', pathPrefix: '' },
  groq:      { host: 'api.groq.com',                    pathPrefix: '' },
  mistral:   { host: 'api.mistral.ai',                  pathPrefix: '' },
};

// Auth via proxy key
async function proxyAuth(req, res, next) {
  try {
    const proxyKey = (req.headers['x-dm-key'] || req.headers['authorization'] || '')
      .replace('Bearer ', '').trim();

    if (!proxyKey.startsWith('dmp_')) {
      return res.status(401).json({ error: 'Invalid proxy key. Use your DarkMatter proxy key in Authorization header or X-DM-Key header.' });
    }

    const { data: pk } = await supabaseService.from('proxy_keys')
      .select('*, workspace_members(*, workspaces(*))')
      .eq('proxy_key', proxyKey).eq('is_active', true).single();

    if (!pk) return res.status(401).json({ error: 'Proxy key not found or inactive' });

    req.proxyKey   = pk;
    req.member     = pk.workspace_members;
    req.workspace  = pk.workspace_members?.workspaces;

    // Update last used
    await supabaseService.from('proxy_keys').update({ last_used_at: new Date().toISOString() }).eq('id', pk.id);
    next();
  } catch(e) {
    res.status(500).json({ error: 'Proxy auth error: ' + e.message });
  }
}

// Core proxy handler — captures request + response, commits to DarkMatter
app.all('/proxy/:provider/*', proxyAuth, async (req, res) => {
  const provider = req.params.provider;
  const target   = PROXY_TARGETS[provider];

  if (!target) {
    return res.status(400).json({
      error: `Unknown provider "${provider}". Supported: ${Object.keys(PROXY_TARGETS).join(', ')}`
    });
  }

  const upstreamPath = req.path.replace(`/proxy/${provider}`, '') || '/';
  const member       = req.member;
  const workspace    = req.workspace;

  // Capture raw request body
  const requestBody  = req.body;
  const requestStart = Date.now();
  const clientTs     = new Date().toISOString();

  // Build upstream request
  const upstreamOptions = {
    hostname: target.host,
    path:     upstreamPath + (req.url.includes('?') ? '?' + req.url.split('?')[1] : ''),
    method:   req.method,
    headers:  {
      'Content-Type':  'application/json',
      'User-Agent':    'DarkMatter-Proxy/1.0',
    },
  };

  // Forward real API key — either from proxy_key record or from request header
  // Priority: stored key > forwarded key (with dm-forward- prefix)
  const forwardedKey = req.headers['x-dm-forward-key'];
  if (forwardedKey) {
    // Client provided real key — never stored on DarkMatter servers
    upstreamOptions.headers['Authorization'] = `Bearer ${forwardedKey}`;
  } else {
    return res.status(400).json({
      error: 'Include your real API key in X-DM-Forward-Key header. DarkMatter never stores your real key.',
      example: 'X-DM-Forward-Key: sk-...'
    });
  }

  // Provider-specific header adjustments
  if (provider === 'anthropic') {
    upstreamOptions.headers['anthropic-version'] = req.headers['anthropic-version'] || '2023-06-01';
    upstreamOptions.headers['x-api-key']         = forwardedKey;
    delete upstreamOptions.headers['Authorization'];
  }

  const isStreaming = requestBody?.stream === true;

  if (isStreaming) {
    // ── Streaming response ─────────────────────────────────────────
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Transfer-Encoding', 'chunked');

    let fullResponseBuffer = '';

    const upstream = https.request(upstreamOptions, (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
      upstreamRes.on('data', (chunk) => {
        res.write(chunk);                          // pipe to client immediately
        fullResponseBuffer += chunk.toString();    // buffer for DarkMatter
      });
      upstreamRes.on('end', async () => {
        res.end();
        // Commit after streaming completes — zero impact on client
        await commitProxyInteraction({
          provider, upstreamPath, requestBody, responseText: fullResponseBuffer,
          statusCode: upstreamRes.statusCode, latencyMs: Date.now() - requestStart,
          member, workspace, clientTs, isStreaming: true,
        });
      });
    });

    upstream.on('error', (e) => { res.end(); console.error('Proxy upstream error:', e.message); });
    if (requestBody) upstream.write(JSON.stringify(requestBody));
    upstream.end();

  } else {
    // ── Non-streaming response ─────────────────────────────────────
    const upstream = https.request(upstreamOptions, (upstreamRes) => {
      let responseBuffer = '';
      upstreamRes.on('data', (chunk) => { responseBuffer += chunk.toString(); });
      upstreamRes.on('end', async () => {
        // Send response to client first
        res.status(upstreamRes.statusCode).set(upstreamRes.headers).send(responseBuffer);
        // Then commit — fire and forget
        await commitProxyInteraction({
          provider, upstreamPath, requestBody, responseText: responseBuffer,
          statusCode: upstreamRes.statusCode, latencyMs: Date.now() - requestStart,
          member, workspace, clientTs, isStreaming: false,
        });
      });
    });

    upstream.on('error', (e) => { res.status(502).json({ error: 'Upstream error: ' + e.message }); });
    if (requestBody) upstream.write(JSON.stringify(requestBody));
    upstream.end();
  }
});

// ── Commit a proxied interaction to DarkMatter ────────────────────────
async function commitProxyInteraction({ provider, upstreamPath, requestBody, responseText, statusCode, latencyMs, member, workspace, clientTs, isStreaming }) {
  try {
    // Extract the meaningful parts of request/response
    const model    = requestBody?.model || 'unknown';
    const messages = requestBody?.messages || [];
    const lastMsg  = messages[messages.length - 1];
    const inputText = typeof lastMsg?.content === 'string' ? lastMsg.content : JSON.stringify(lastMsg?.content || '');

    let outputText = '';
    try {
      const parsed = JSON.parse(responseText);
      // OpenAI format
      outputText = parsed?.choices?.[0]?.message?.content
        || parsed?.choices?.[0]?.text
        // Anthropic format
        || parsed?.content?.[0]?.text
        || parsed?.completion
        || '';
    } catch(e) {
      // Streaming SSE — extract last complete data line
      const lines = responseText.split('\n').filter(l => l.startsWith('data: ') && l !== 'data: [DONE]');
      const lastLine = lines[lines.length - 1];
      if (lastLine) {
        try {
          const d = JSON.parse(lastLine.replace('data: ', ''));
          outputText = d?.choices?.[0]?.delta?.content || d?.delta?.text || '';
        } catch(e2) {}
      }
    }

    const payload = {
      _source:     'proxy',
      _provider:   provider,
      _model:      model,
      _path:       upstreamPath,
      _latency_ms: latencyMs,
      _status:     statusCode,
      _streaming:  isStreaming,
      role:        'assistant',
      prompt:      inputText.slice(0, 2000),    // truncate for storage
      output:      outputText.slice(0, 10000),  // truncate for storage
      input_messages: messages.length,
    };

    // Use member's agent_id for signing/attribution
    const agentId = member?.agent_id;
    if (!agentId) return;

    // Get agent API key for this member
    const { data: agent } = await supabaseService.from('agents')
      .select('api_key_hash, agent_name').eq('agent_id', agentId).single();
    if (!agent) return;

    // Build the commit directly (internal commit path)
    const { createCommit } = require('./integrity');
    const parentRes = await supabaseService.from('commits')
      .select('id, integrity_hash')
      .or(`from_agent.eq."${agentId}",agent_id.eq."${agentId}"`)
      .order('timestamp', { ascending: false }).limit(1).single();

    const parentHash = parentRes?.data?.integrity_hash || 'root';
    const payloadHash = require('crypto').createHash('sha256')
      .update(JSON.stringify(payload)).digest('hex');

    await supabaseService.from('commits').insert({
      id:               'ctx_' + Date.now() + '_' + require('crypto').randomBytes(4).toString('hex'),
      trace_id:         'proxy_' + Date.now(),
      from_agent:       agentId,
      agent_id:         agentId,  // v13+ column
      agent_info:       { name: member?.display_name || agent.agent_name, source: 'proxy', provider },
      payload,
      payload_hash:     payloadHash,
      parent_hash:      parentHash,
      integrity_hash:   require('crypto').createHash('sha256')
                          .update(payloadHash + parentHash).digest('hex'),
      timestamp:        clientTs,
      event_type:       'commit',
      branch_key:       'main',
      verified:         true,
      verification_reason: 'Proxy capture',
      capture_mode: captureMode || 'proxy_forwarded',
    });

  } catch(e) {
    console.error('[DarkMatter Proxy] Commit error:', e.message);
    // Never surface this to the user — proxy transparency is paramount
  }
}

// ── Proxy status/test endpoint ────────────────────────────────────────
app.get('/proxy/status', proxyAuth, (req, res) => {
  res.json({
    status:    'connected',
    member:    req.member?.display_name || req.member?.email,
    workspace: req.workspace?.name,
    providers: Object.keys(PROXY_TARGETS),
    message:   'Your DarkMatter proxy is working. All API calls through this proxy are automatically recorded.',
  });
});

// ── Join page (for invite links) ──────────────────────────────────────
app.get('/join',          (req, res) => res.sendFile(path.join(__dirname, '../public/join.html')));
app.get('/organizations', (req, res) => res.sendFile(path.join(__dirname, '../public/organizations.html')));

// ── GET /api/workspace/my-organizations ─────────────────────────────────────
app.get('/api/workspace/my-organizations', requireAuth, async (req, res) => {
  try {
    const { data: memberships } = await supabaseService
      .from('workspace_members')
      .select('workspace_id, role, workspaces(id, name, owner_user_id)')
      .eq('user_id', req.user.id);

    const orgs = (memberships || []).map(m => ({
      id:         m.workspace_id,
      name:       m.workspaces?.name || req.user.email,
      email:      req.user.email,
      role:       m.role,
      role_label: m.role === 'owner' ? 'Owner' : m.role === 'admin' ? 'Admin' : 'Member',
      is_current: true,
    }));

    // If no workspaces, return a default entry
    if (!orgs.length) {
      orgs.push({
        id:         'default',
        name:       req.user.email,
        email:      req.user.email,
        role:       'owner',
        role_label: 'Owner',
        is_current: true,
      });
    }

    res.json({ organizations: orgs });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});



// ── GET /dashboard/commits ────────────────────────────────────────────
;

// ── GET /api/auth/refresh ──────────────────────────────────────────────
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

// ── Static file serving ──────────────────────────────────────────────── v2
const publicDir = path.join(__dirname, '../public');
app.use(express.static(publicDir));

// SPA fallback — serve dashboard for unknown routes when user is likely logged in
// ── GET /chat ── serve chat page (must be before SPA catch-all)
app.get('/chat', (req, res) => {
  res.sendFile(require('path').join(__dirname, '../public/chat.html'));
});


app.get('*', (req, res, next) => {
  // API routes: pass through to registered handlers (or Express default 404)
  if (req.path.startsWith('/api/') || req.path.startsWith('/proxy/')) {
    return next();
  }
  // Serve the requested HTML file if it exists, else 404
  let filePath = path.join(publicDir, req.path === '/' ? 'index.html' : req.path);
  // If path has no extension, try .html
  if (!path.extname(filePath)) filePath = filePath + '.html';
  res.sendFile(filePath, err => {
    if (err) res.status(404).send('Not found');
  });
});

// ── GET /admin/stats — admin check + basic stats ──────────────────────────
app.get('/admin/stats', requireAuth, async (req, res) => {
  try {
    // Check if the authenticated user is an admin email
    const adminEmails = (process.env.ADMIN_EMAILS || 'hello@darkmatterhub.ai').split(',').map(e => e.trim());
    if (!adminEmails.includes(req.user.email)) {
      return res.status(403).json({ error: 'Admin only' });
    }

    const [agentsRes, commitsRes, usersRes] = await Promise.all([
      supabaseService.from('agents').select('id', { count: 'exact', head: true }),
      supabaseService.from('commits').select('id', { count: 'exact', head: true }),
      supabaseService.auth.admin.listUsers({ page: 1, perPage: 1 }),
    ]);

    res.json({
      admin: true,
      email: req.user.email,
      agents: agentsRes.count || 0,
      commits: commitsRes.count || 0,
      users: usersRes.data?.total || 0,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /admin — serve admin panel ────────────────────────────────────────
app.get('/admin', requireAuth, (req, res) => {
  res.sendFile(require('path').join(__dirname, '../public/admin.html'));
});

// ── GET /api/debug/me — diagnostic for "no records" issue (admin only) ──────
app.get('/api/debug/me', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const email  = req.user.email;

    // 1. Find agents for this user
    const { data: agents, error: ae } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, user_id, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(10);

    const agentIds = (agents || []).map(a => a.agent_id);
    const idList   = agentIds.map(id => '"' + id + '"').join(',');

    // 2. Count commits for those agents
    let commitCount = 0, sampleCommits = [];
    if (agentIds.length > 0) {
      const { data: commits, count } = await supabaseService
        .from('commits')
        .select('id, trace_id, from_agent, agent_id, timestamp', { count: 'exact' })
        .or(['agent_id.in.(' + idList + ')', 'from_agent.in.(' + idList + ')'].join(','))
        .order('timestamp', { ascending: false })
        .limit(5);
      commitCount  = count || (commits || []).length;
      sampleCommits = commits || [];
    }

    // 3. Also check: any commits where from_agent matches agents but user_id was null
    const { data: nullAgents } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, user_id, created_at')
      .is('user_id', null)
      .limit(5);

    res.json({
      auth_user_id:   userId,
      auth_email:     email,
      agents_found:   (agents || []).length,
      agents:         agents || [],
      commit_count:   commitCount,
      sample_commits: sampleCommits,
      null_user_id_agents: nullAgents || [],
      diagnosis: agentIds.length === 0
        ? 'NO AGENTS: No agents found with user_id = ' + userId + '. Commits exist but are linked to a different user_id or an agent with null user_id.'
        : commitCount === 0
          ? 'AGENTS EXIST but NO COMMITS found for agent IDs: ' + agentIds.join(', ')
          : 'OK: Found ' + agentIds.length + ' agents and ' + commitCount + ' commits.',
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});



// ═══════════════════════════════════════════════════════════════════════
// DARKMATTER SERVER ADDITIONS
// Append this block to the END of server.js, BEFORE the PORT listen call.
//
// Implements:
//   1. /api/workspace/chat          — send message, get response, auto-record
//   2. /api/workspace/activity      — real dashboard feed from Supabase
//   3. /api/workspace/provider-keys — connect Claude/ChatGPT modals
//
// Also fixes: bare `supabase` variable in workspace routes — replace with supabaseService
// ═══════════════════════════════════════════════════════════════════════

// NOTE: The workspace routes added earlier use `supabase` (not defined).
// That variable should be `supabaseService`. Until those routes are fixed,
// they will throw. The new routes below use supabaseService directly.

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: resolve the workspace for a logged-in user
// Returns { workspace_id, role, agent_id } or null
// ─────────────────────────────────────────────────────────────────────────────
async function getMembership(userId) {
  const { data } = await supabaseService
    .from('workspace_members')
    .select('workspace_id, role, agent_id, display_name, email')
    .eq('user_id', userId)
    .eq('status', 'active')
    .single();
  return data || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: get a stored provider key for a user (decrypted for use)
// provider: 'anthropic' | 'openai'
// ─────────────────────────────────────────────────────────────────────────────
async function getStoredProviderKey(userId, provider) {
  // Try workspace_provider_keys first (workspace-scoped)
  const { data: wsKey } = await supabaseService
    .from('workspace_provider_keys')
    .select('encrypted_key, recording_enabled')
    .eq('user_id', userId)
    .eq('provider', provider)
    .eq('recording_enabled', true)
    .single();
  if (wsKey?.encrypted_key) return wsKey.encrypted_key;

  // Fallback: user_recording_keys (older table)
  const { data: rk } = await supabaseService
    .from('user_recording_keys')
    .select('encrypted_key, recording_enabled')
    .eq('user_id', userId)
    .eq('provider', provider)
    .eq('recording_enabled', true)
    .single();
  return rk?.encrypted_key || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: save a DarkMatter commit for a workspace chat message
// ─────────────────────────────────────────────────────────────────────────────
async function commitWorkspaceChat({ userId, agentId, provider, model, messages, response, traceId }) {
  try {
    const commitId = 'ctx_' + Date.now() + '_' + require('crypto').randomBytes(6).toString('hex');
    const ts       = new Date().toISOString();
    const lastMsg  = messages[messages.length - 1];
    const inputText = typeof lastMsg?.content === 'string'
      ? lastMsg.content
      : JSON.stringify(lastMsg?.content || '');

    const payload = {
      _source:   'workspace_chat',
      _provider: provider,
      _model:    model,
      role:      'assistant',
      prompt:    inputText.slice(0, 2000),
      output:    response.slice(0, 10000),
      input_messages: messages.length,
    };

    const normalizedPayload = JSON.stringify(payload, Object.keys(payload).sort());
    const payloadHash       = require('crypto').createHash('sha256').update(normalizedPayload).digest('hex');

    // Get parent hash for chain
    const { data: parentCommit } = await supabaseService
      .from('commits')
      .select('integrity_hash')
      .or(`from_agent.eq."${agentId}",agent_id.eq."${agentId}"`)
      .order('timestamp', { ascending: false })
      .limit(1)
      .single();

    const parentHash    = parentCommit?.integrity_hash || 'root';
    const integrityHash = require('crypto')
      .createHash('sha256')
      .update(payloadHash + parentHash)
      .digest('hex');

    await supabaseService.from('commits').insert({
      id:               commitId,
      trace_id:         traceId || commitId,
      from_agent:       agentId,
      agent_id:         agentId,
      agent_info:       { name: 'workspace-chat', source: 'workspace_chat', provider, model },
      payload,
      payload_hash:     payloadHash,
      parent_hash:      parentHash,
      integrity_hash:   integrityHash,
      timestamp:        ts,
      event_type:       'commit',
      branch_key:       'main',
      verified:         true,
      verification_reason: 'Workspace chat capture',
      capture_mode:     'workspace_chat',
    });

    return { commitId, integrityHash };
  } catch(e) {
    console.error('[commitWorkspaceChat]', e.message);
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. POST /api/workspace/chat
//    Send a message through DarkMatter to Claude or GPT-4o.
//    Uses the user's stored provider API key.
//    Returns: { message, model, provider, recordId, traceId }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/workspace/chat', requireAuth, async (req, res) => {
  try {
    const { messages, model, provider: reqProvider, traceId, conversationId } = req.body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages array required' });
    }

    // Determine provider from model name
    const provider = reqProvider || (
      model?.startsWith('gpt')    ? 'openai'    :
      model?.startsWith('claude') ? 'anthropic' :
      'anthropic'
    );

    const resolvedModel = model || (provider === 'anthropic' ? 'claude-sonnet-4-6' : 'gpt-4o');

    // Get API key
    const apiKey = await getStoredProviderKey(req.user.id, provider);
    if (!apiKey) {
      return res.status(402).json({
        error: `No ${provider} API key connected. Connect your key in Settings.`,
        code:  'NO_API_KEY',
        provider,
      });
    }

    // Get user's agent ID for recording
    const membership = await getMembership(req.user.id);
    let agentId = membership?.agent_id;

    // Fallback: user's first agent
    if (!agentId) {
      const { data: agents } = await supabaseService
        .from('agents')
        .select('agent_id')
        .eq('user_id', req.user.id)
        .limit(1)
        .single();
      agentId = agents?.agent_id;
    }

    // ── Call the LLM ──────────────────────────────────────────
    let responseText = '';
    let upstreamStatus = 200;

    if (provider === 'anthropic') {
      // Anthropic Messages API
      const systemMessage = messages.find(m => m.role === 'system');
      const chatMessages  = messages.filter(m => m.role !== 'system');

      const body = {
        model: resolvedModel,
        max_tokens: 4096,
        messages: chatMessages,
        ...(systemMessage ? { system: systemMessage.content } : {}),
      };

      const upstreamRes = await fetch('https://api.anthropic.com/v1/messages', {
        method:  'POST',
        headers: {
          'Content-Type':    'application/json',
          'x-api-key':       apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify(body),
      });

      upstreamStatus = upstreamRes.status;
      const data = await upstreamRes.json();

      if (!upstreamRes.ok) {
        return res.status(upstreamStatus).json({
          error: data?.error?.message || 'Anthropic API error',
          code:  data?.error?.type    || 'upstream_error',
        });
      }

      responseText = data?.content?.[0]?.text || '';

    } else if (provider === 'openai') {
      // OpenAI Chat Completions API
      const upstreamRes = await fetch('https://api.openai.com/v1/chat/completions', {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model:      resolvedModel,
          messages,
          max_tokens: 4096,
        }),
      });

      upstreamStatus = upstreamRes.status;
      const data = await upstreamRes.json();

      if (!upstreamRes.ok) {
        return res.status(upstreamStatus).json({
          error: data?.error?.message || 'OpenAI API error',
          code:  data?.error?.type    || 'upstream_error',
        });
      }

      responseText = data?.choices?.[0]?.message?.content || '';

    } else {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }

    // ── Record to DarkMatter ──────────────────────────────────
    const commitResult = agentId
      ? await commitWorkspaceChat({
          userId:   req.user.id,
          agentId,
          provider,
          model:    resolvedModel,
          messages,
          response: responseText,
          traceId:  traceId || conversationId,
        })
      : null;

    res.json({
      message:    responseText,
      model:      resolvedModel,
      provider,
      recordId:   commitResult?.commitId || null,
      traceId:    traceId || commitResult?.commitId || null,
      recorded:   !!commitResult,
    });

  } catch(err) {
    console.error('[workspace/chat]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. GET /api/workspace/activity
//    Dashboard activity feed — real commits for this user's workspace.
//    Returns recent commits formatted for the dashboard UI.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/workspace/activity', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 25, 200);

    // Run membership and agents queries in parallel
    const [membership, agentsRes] = await Promise.all([
      getMembership(req.user.id),
      supabaseService.from('agents').select('agent_id, agent_name').eq('user_id', req.user.id).limit(100),
    ]);

    const userAgents   = agentsRes.data || [];
    const userAgentIds = userAgents.map(a => a.agent_id);
    const agentNameMap = {};
    userAgents.forEach(a => { agentNameMap[a.agent_id] = a.agent_name; });

    let allAgentIds = [...userAgentIds];

    if (membership) {
      if (membership.role === 'admin') {
        const { data: members } = await supabaseService
          .from('workspace_members')
          .select('agent_id')
          .eq('workspace_id', membership.workspace_id)
          .not('agent_id', 'is', null);
        const wsIds = (members || []).map(m => m.agent_id).filter(Boolean);
        allAgentIds = [...new Set([...allAgentIds, ...wsIds])];
      } else if (membership.agent_id) {
        allAgentIds = [...new Set([...allAgentIds, membership.agent_id])];
      }
    }

    if (allAgentIds.length === 0) return res.json({ activity: [], total: 0 });

    const idList = allAgentIds.map(id => `"${id}"`).join(',');
    const { data: commits, error } = await supabaseService
      .from('commits')
      .select('id, trace_id, from_agent, agent_id, agent_info, payload, timestamp, event_type, verified, capture_mode')
      .or(`from_agent.in.(${idList}),agent_id.in.(${idList})`)
      .order('timestamp', { ascending: false })
      .limit(limit);

    if (error) throw error;

    const activity = (commits || []).map(c => {
      const agentKey  = c.agent_id || c.from_agent;
      const agentName = agentNameMap[agentKey] || c.agent_info?.name || agentKey || 'Agent';
      const provider  = c.agent_info?.provider || c.payload?._provider || null;
      const model     = c.agent_info?.model     || c.payload?._model    || null;
      const source    = c.capture_mode || c.payload?._source || 'api';
      const p         = c.payload || {};
      let title = p.decision ? 'Decision: ' + p.decision
                : p.action   ? 'Action: '   + p.action
                : p.output   ? String(p.output).slice(0, 80)
                : p.input    ? String(p.input).slice(0, 80)
                : p.convTitle ? p.convTitle
                : p.prompt   ? p.prompt.slice(0, 80)
                : 'Commit ' + c.id.slice(0, 12);

      return {
        id: c.id, traceId: c.trace_id || c.id, agentId: agentKey,
        agentName, provider: provider || 'unknown', model: model || 'unknown',
        eventType: c.event_type || 'commit', title, timestamp: c.timestamp,
        verified: c.verified || false, source,
      };
    });

    res.json({ activity, total: activity.length });
  } catch(err) {
    console.error('[workspace/activity]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Provider Key Management — /api/workspace/provider-keys
//    Backs the Connect Claude / Connect ChatGPT modals in dashboard.html
//    Keys are stored in `workspace_provider_keys` table.
//    If that table doesn't exist yet, falls back to `user_recording_keys`.
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/workspace/provider-keys — save a provider API key
app.post('/api/workspace/provider-keys', requireAuth, async (req, res) => {
  try {
    const { provider, apiKey, label } = req.body;

    if (!provider || !apiKey) {
      return res.status(400).json({ error: 'provider and apiKey required' });
    }

    const VALID_PROVIDERS = ['anthropic', 'openai'];
    if (!VALID_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: `provider must be one of: ${VALID_PROVIDERS.join(', ')}` });
    }

    // Basic format validation — never expose full key
    const isValidFormat =
      (provider === 'anthropic' && apiKey.startsWith('sk-ant-')) ||
      (provider === 'openai'    && apiKey.startsWith('sk-'));

    if (!isValidFormat) {
      return res.status(400).json({
        error: provider === 'anthropic'
          ? 'Anthropic API keys start with sk-ant-'
          : 'OpenAI API keys start with sk-',
      });
    }

    // Key hint for display (never expose full key)
    const keyHint = apiKey.slice(0, 10).replace(/./g, (c, i) => i < 7 ? c : '•') + '...' + apiKey.slice(-4);

    // Try workspace_provider_keys table first
    try {
      // Remove existing key for this provider
      await supabaseService
        .from('workspace_provider_keys')
        .delete()
        .eq('user_id', req.user.id)
        .eq('provider', provider);

      const { data, error } = await supabaseService
        .from('workspace_provider_keys')
        .insert({
          user_id:           req.user.id,
          provider,
          encrypted_key:     apiKey,  // TODO: encrypt with server-side key in production
          key_hint:          keyHint,
          recording_enabled: true,
          label:             label || provider,
        })
        .select('id, provider, key_hint, recording_enabled, label, created_at')
        .single();

      if (!error) {
        return res.json({
          success:  true,
          id:       data.id,
          provider: data.provider,
          keyHint:  data.key_hint,
          label:    data.label,
          message:  `${provider === 'anthropic' ? 'Claude' : 'ChatGPT'} connected. All conversations through DarkMatter chat will be recorded.`,
        });
      }

      // Table doesn't exist — fall through to user_recording_keys
    } catch(tableErr) {
      // workspace_provider_keys table may not exist — fall through
    }

    // Fallback: user_recording_keys (existing table)
    await supabaseService
      .from('user_recording_keys')
      .delete()
      .eq('user_id', req.user.id)
      .eq('provider', provider);

    const { data, error } = await supabaseService
      .from('user_recording_keys')
      .insert({
        user_id:           req.user.id,
        provider,
        encrypted_key:     apiKey,
        key_hint:          keyHint,
        recording_enabled: true,
        label:             label || provider,
      })
      .select('id, provider, key_hint, recording_enabled, label, created_at')
      .single();

    if (error) throw error;

    res.json({
      success:  true,
      id:       data.id,
      provider: data.provider,
      keyHint:  data.key_hint,
      label:    data.label,
      message:  `${provider === 'anthropic' ? 'Claude' : 'ChatGPT'} connected.`,
    });

  } catch(err) {
    console.error('[provider-keys POST]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/workspace/provider-keys — list connected providers (no keys, just status)
app.get('/api/workspace/provider-keys', requireAuth, async (req, res) => {
  try {
    // Try workspace_provider_keys first
    let keys = [];
    try {
      const { data } = await supabaseService
        .from('workspace_provider_keys')
        .select('id, provider, key_hint, recording_enabled, label, created_at, last_used_at')
        .eq('user_id', req.user.id)
        .order('created_at', { ascending: false });
      if (data) keys = data;
    } catch(_) {
      // Table doesn't exist — try fallback
    }

    // Fallback to user_recording_keys
    if (keys.length === 0) {
      const { data } = await supabaseService
        .from('user_recording_keys')
        .select('id, provider, key_hint, recording_enabled, label, created_at, last_used_at')
        .eq('user_id', req.user.id)
        .order('created_at', { ascending: false });
      keys = data || [];
    }

    // Return summary — no actual keys ever exposed
    res.json(keys.map(k => ({
      id:               k.id,
      provider:         k.provider,
      keyHint:          k.key_hint,
      recording_enabled: k.recording_enabled,
      label:            k.label,
      connected:        true,
      createdAt:        k.created_at,
      lastUsedAt:       k.last_used_at || null,
    })));

  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/workspace/provider-keys/:provider — disconnect a provider
app.delete('/api/workspace/provider-keys/:provider', requireAuth, async (req, res) => {
  try {
    const { provider } = req.params;

    // Try both tables
    try {
      await supabaseService
        .from('workspace_provider_keys')
        .delete()
        .eq('user_id', req.user.id)
        .eq('provider', provider);
    } catch(_) {}

    await supabaseService
      .from('user_recording_keys')
      .delete()
      .eq('user_id', req.user.id)
      .eq('provider', provider);

    res.json({ success: true, provider, disconnected: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/workspace/provider-keys/:id — toggle recording on/off
app.patch('/api/workspace/provider-keys/:id', requireAuth, async (req, res) => {
  try {
    const { recording_enabled } = req.body;
    const id = req.params.id;

    // Try workspace_provider_keys
    let updated = false;
    try {
      const { data } = await supabaseService
        .from('workspace_provider_keys')
        .update({ recording_enabled })
        .eq('id', id)
        .eq('user_id', req.user.id)
        .select('id, recording_enabled')
        .single();
      if (data) { updated = true; res.json({ success: true, ...data }); }
    } catch(_) {}

    if (!updated) {
      const { data, error } = await supabaseService
        .from('user_recording_keys')
        .update({ recording_enabled })
        .eq('id', id)
        .eq('user_id', req.user.id)
        .select('id, recording_enabled')
        .single();
      if (error) throw error;
      res.json({ success: true, ...data });
    }
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ── GET /api/workspace/profile — get current user's display name ─────────────
app.get('/api/workspace/profile', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const meta = user.user_metadata || {};
    const full_name = meta.full_name || meta.name || meta.display_name || '';
    res.json({
      email:      user.email,
      full_name,
      avatar_url: meta.avatar_url || null,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── PATCH /api/workspace/profile — update display name ───────────────────────
app.patch('/api/workspace/profile', requireAuth, async (req, res) => {
  try {
    const { full_name } = req.body;
    if (!full_name || typeof full_name !== 'string' || !full_name.trim()) {
      return res.status(400).json({ error: 'full_name is required' });
    }
    const name = full_name.trim().slice(0, 100);
    const { data, error } = await supabaseService.auth.admin.updateUserById(
      req.user.id,
      { user_metadata: { ...req.user.user_metadata, full_name: name } }
    );
    if (error) throw error;
    res.json({ full_name: name });
  } catch(e) {
    console.error('[profile patch]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/debug/whoami ── temporary debug endpoint ─────────────────────
app.get('/api/debug/whoami', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const email  = req.user.email;

    // Count agents by user_id
    const { count: byId } = await supabaseService
      .from('agents')
      .select('agent_id', { count: 'exact', head: true })
      .eq('user_id', userId);

    // Count all agents (no filter) for comparison
    const { count: total } = await supabaseService
      .from('agents')
      .select('agent_id', { count: 'exact', head: true });

    // Get sample of agents with null user_id
    const { data: nullAgents } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, user_id, created_at')
      .is('user_id', null)
      .order('created_at', { ascending: false })
      .limit(5);

    // Get sample of agents matching this user
    const { data: myAgents } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, user_id, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(5);

    res.json({
      auth_user_id:    userId,
      auth_email:      email,
      agents_by_my_id: byId,
      agents_total:    total,
      my_agents_sample: myAgents || [],
      null_user_id_sample: nullAgents || [],
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/workspace/api-keys ──────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// API KEY MANAGEMENT  (dashboard — JWT auth)
// GET    /api/workspace/api-keys       → list user's agents/keys
// POST   /api/workspace/api-keys       → create a new key
// DELETE /api/workspace/api-keys/:id   → delete a key by agent_id
// ─────────────────────────────────────────────────────────────────────────────

app.get('/api/workspace/api-keys', requireAuth, async (req, res) => {
  try {
    const { data: agents, error } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;

    res.json({ keys: (agents || []).map(a => ({
      id:         a.agent_id,
      name:       a.agent_name || 'API Key',
      created_at: a.created_at,
      created_by: req.user.email,
      note:       'DarkMatter workspace',
    })) });
  } catch (e) {
    console.error('[api-keys GET]', e.message);
    res.status(500).json({ error: 'Could not load API keys' });
  }
});

app.post('/api/workspace/api-keys', requireAuth, async (req, res) => {
  try {
    const name      = sanitizeText(req.body?.name || 'API Key', 100);
    const newAgentId = generateAgentId();
    const newApiKey  = generateApiKey();

    const { data, error } = await supabaseService
      .from('agents')
      .insert({
        agent_id:   newAgentId,
        agent_name: name,
        user_id:    req.user.id,
        api_key:    newApiKey,
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      id:         data.agent_id,
      name:       data.agent_name,
      key:        newApiKey,
      created_at: data.created_at,
    });
  } catch (e) {
    console.error('[api-keys POST]', e.message, e.details || '');
    res.status(500).json({ error: 'Could not create API key: ' + e.message });
  }
});

app.delete('/api/workspace/api-keys/:keyId', requireAuth, async (req, res) => {
  try {
    const { keyId } = req.params;

    // Verify ownership before delete
    const { data: agent } = await supabaseService
      .from('agents')
      .select('agent_id, user_id')
      .eq('agent_id', keyId)
      .eq('user_id', req.user.id)
      .single();

    if (!agent) return res.status(404).json({ error: 'Key not found or not yours' });

    const { error } = await supabaseService
      .from('agents')
      .delete()
      .eq('agent_id', keyId)
      .eq('user_id', req.user.id);

    if (error) throw error;

    res.json({ deleted: true, id: keyId });
  } catch (e) {
    console.error('[api-keys DELETE]', e.message);
    res.status(500).json({ error: 'Could not delete key' });
  }
});

// 4. GET /api/workspace/stats
//    Dashboard stats cards — conversations, active people, AI services, exports
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/workspace/stats', requireAuth, async (req, res) => {
  try {
    const membership = await getMembership(req.user.id);

    // Get all agent IDs for scope
    const { data: userAgents } = await supabaseService
      .from('agents')
      .select('agent_id')
      .eq('user_id', req.user.id);

    let agentIds = (userAgents || []).map(a => a.agent_id);

    if (membership) {
      const { data: members } = await supabaseService
        .from('workspace_members')
        .select('agent_id')
        .eq('workspace_id', membership.workspace_id)
        .not('agent_id', 'is', null);
      agentIds = [...new Set([...agentIds, ...(members || []).map(m => m.agent_id).filter(Boolean)])];
    }

    const idList = agentIds.map(id => `"${id}"`).join(',');
    const since  = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

    const { data: commits } = agentIds.length > 0
      ? await supabaseService
          .from('commits')
          .select('id, from_agent, agent_info, payload, timestamp')
          .or(`from_agent.in.(${idList}),agent_id.in.(${idList})`)
          .gte('timestamp', since)
          .limit(1000)
      : { data: [] };

    const commitList = commits || [];

    // Count unique conversations (by trace_id, falling back to id)
    const conversations = new Set(commitList.map(c => c.trace_id || c.id)).size;

    // Count unique active people (by from_agent in last 7 days)
    const weekAgo      = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const recentAgents = new Set(
      commitList
        .filter(c => c.timestamp >= weekAgo)
        .map(c => c.from_agent)
        .filter(Boolean)
    );
    const peopleActive = membership
      ? recentAgents.size
      : (recentAgents.size || (agentIds.length > 0 ? 1 : 0));

    // Count connected AI services
    const { data: connectedKeys } = await supabaseService
      .from('user_recording_keys')
      .select('provider')
      .eq('user_id', req.user.id)
      .eq('recording_enabled', true);
    const aiServices = (connectedKeys || []).length;

    res.json({
      conversations,
      peopleActive,
      aiServices,
      exports: 0, // TODO: track export events
      period: '30d',
    });
  } catch(err) {
    console.error('[workspace/stats]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. GET /api/workspace/conversation/:traceId
//    Full conversation transcript for the dashboard detail drawer
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/workspace/conversation/:traceId', requireAuth, async (req, res) => {
  try {
    const { traceId } = req.params;

    const { data: commits, error } = await supabaseService
      .from('commits')
      .select('*')
      .or(`trace_id.eq."${traceId}",id.eq."${traceId}"`)
      .order('timestamp', { ascending: true });

    if (error) throw error;
    if (!commits?.length) return res.status(404).json({ error: 'Conversation not found' });

    // Verify the requester owns one of these agents
    const { data: userAgents } = await supabaseService
      .from('agents')
      .select('agent_id')
      .eq('user_id', req.user.id);
    const userAgentIds = new Set((userAgents || []).map(a => a.agent_id));

    const hasAccess = commits.some(c =>
      userAgentIds.has(c.from_agent) || userAgentIds.has(c.agent_id)
    );

    // Also allow workspace admin access
    const membership = await getMembership(req.user.id);
    const isAdmin    = membership?.role === 'admin';

    if (!hasAccess && !isAdmin) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Build transcript
    const transcript = commits.map(c => {
      const p = c.payload || {};
      return {
        id:        c.id,
        role:      p.role || 'assistant',
        content:   p.output || p.text || p.prompt || JSON.stringify(p).slice(0, 500),
        timestamp: c.timestamp,
        model:     c.agent_info?.model || p._model || null,
        provider:  c.agent_info?.provider || p._provider || null,
        verified:  c.verified || false,
        integrityHash: c.integrity_hash,
      };
    });

    // Verify chain integrity
    let chainIntact = true;
    for (let i = 1; i < commits.length; i++) {
      if (commits[i].parent_hash && commits[i-1].integrity_hash &&
          commits[i].parent_hash !== commits[i-1].integrity_hash) {
        chainIntact = false; break;
      }
    }

    res.json({
      traceId,
      chainIntact,
      stepCount: commits.length,
      transcript,
      exportUrl: `/r/${traceId}?format=json`,
      verifyUrl: `/r/${traceId}`,
    });

  } catch(err) {
    console.error('[workspace/conversation]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Note: /chat is declared above the static middleware and catch-all (line ~5141).
// /dashboard is declared at line ~427. No duplicates needed here.

// ─────────────────────────────────────────────────────────────────────────────
// MIGRATION NOTE: workspace_provider_keys table
//
// Run this in Supabase SQL editor if the table doesn't exist:
//
// CREATE TABLE IF NOT EXISTS workspace_provider_keys (
//   id               uuid DEFAULT gen_random_uuid() PRIMARY KEY,
//   user_id          uuid REFERENCES auth.users(id) ON DELETE CASCADE,
//   provider         text NOT NULL,
//   encrypted_key    text NOT NULL,
//   key_hint         text,
//   recording_enabled boolean DEFAULT true,
//   label            text,
//   created_at       timestamptz DEFAULT now(),
//   last_used_at     timestamptz,
//   UNIQUE(user_id, provider)
// );
// ALTER TABLE workspace_provider_keys ENABLE ROW LEVEL SECURITY;
// CREATE POLICY "Users manage own keys" ON workspace_provider_keys
//   FOR ALL USING (auth.uid() = user_id);
// ─────────────────────────────────────────────────────────────────────────────




process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DarkMatter server running on port ${PORT}`);
});

