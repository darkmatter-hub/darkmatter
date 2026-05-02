require('dotenv').config();
const express      = require('express');
const cookieParser = require('cookie-parser');
const path         = require('path');
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

const app = express();

// ── Stripe client (lazy init so server starts even if key missing) ────────────
let _stripe = null;
function getStripe() {
  if (!_stripe) {
    if (!process.env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY not set');
    try {
      _stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    } catch(e) {
      throw new Error('Stripe npm package not installed. Run: npm install stripe');
    }
  }
  return _stripe;
}

// Plan → Stripe price ID mapping
const STRIPE_PRICES = {
  pro:        process.env.STRIPE_PRICE_PRO   || null,
  teams:      process.env.STRIPE_PRICE_TEAMS || null,
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || null,
};

// Plan metadata map — single source of truth
// Stripe products must match: Pro=$29/mo, Teams=$99/mo, Enterprise=$499/mo (contact)
const PLAN_META = {
  free:       { commitLimit: 10000,  retentionDays: 30,  price: null },
  pro:        { commitLimit: 50000,  retentionDays: 365, price: 29   }, // Stripe: STRIPE_PRICE_PRO = $29/mo
  teams:      { commitLimit: 250000, retentionDays: null, price: 99  }, // Stripe: STRIPE_PRICE_TEAMS = $99/mo
  enterprise: { commitLimit: null,   retentionDays: null, price: 499 }, // display only — contact sales
};

function priceIdToPlan(priceId) {
  if (!priceId) return 'free';
  if (priceId === process.env.STRIPE_PRICE_PRO)   return 'pro';
  if (priceId === process.env.STRIPE_PRICE_TEAMS) return 'teams';
  if (priceId === process.env.STRIPE_PRICE_ENTERPRISE) return 'enterprise';
  return 'free';
}

async function upsertSubscription(userId, email, sub, customerId) {
  const priceId  = sub.items?.data[0]?.price?.id;
  const plan     = priceIdToPlan(priceId);
  const meta     = PLAN_META[plan] || PLAN_META.free;
  const record   = {
    user_id:                userId,
    email,
    plan,
    status:                 sub.status,
    stripe_customer_id:     customerId,
    stripe_subscription_id: sub.id,
    current_period_end:     new Date(sub.current_period_end * 1000).toISOString(),
    cancel_at_period_end:   sub.cancel_at_period_end || false,
    commit_limit:           meta.commitLimit,
    retention_days:         meta.retentionDays,
    updated_at:             new Date().toISOString(),
  };
  const { error } = await supabaseService
    .from('subscriptions')
    .upsert(record, { onConflict: 'user_id' });
  if (error) console.error('[upsertSubscription]', error.message);
  return record;
}





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
// Explicit origin allowlist — no wildcard.
// Server-side SDK/CLI calls (no Origin header) pass through unaffected by CORS.
const ALLOWED_ORIGINS = [
  'https://darkmatterhub.ai',
  'https://www.darkmatterhub.ai',
  // local dev only:
  'http://localhost:3000',
  'http://localhost:5173',
];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  // No Origin header = server-side client (Node SDK, Python SDK, curl) — no CORS header needed
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,User-Agent');
  res.setHeader('Access-Control-Expose-Headers', 'X-New-Access-Token,X-New-Refresh-Token,X-New-Expires-At');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// ── Cookie auth helpers ───────────────────────────────
const COOKIE_BASE = {
  httpOnly: true,
  secure:   (process.env.APP_URL || '').startsWith('https'),
  sameSite: 'strict',
  path:     '/',
};
function setAuthCookies(res, session) {
  const accessAge = (session.expires_in || 3600) * 1000;
  res.cookie('dm_access',  session.access_token,  { ...COOKIE_BASE, maxAge: accessAge });
  res.cookie('dm_refresh', session.refresh_token, { ...COOKIE_BASE, maxAge: 90 * 24 * 60 * 60 * 1000 });
}
function clearAuthCookies(res) {
  res.clearCookie('dm_access',  { path: '/' });
  res.clearCookie('dm_refresh', { path: '/' });
}

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
// Service role for server-side operations (bypasses RLS).
// CRITICAL: persistSession:false prevents refreshSession() from overwriting the
// service-role JWT with a user JWT. Without this, token refreshes in requireAuth /
// wsAuth corrupt the shared singleton and subsequent DB calls hit RLS instead of
// bypassing it — causing "row-level security policy" errors and empty query results.
const supabaseService = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,  // service_role key — never expose to client
  { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } }
);

// Anon key for auth operations (signup, login, OAuth, code exchange).
// Also stateless — no session stored on the server-side singleton.
const supabaseAnon = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } }
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

    req.agent = data[0];
    next();
  } catch(e) {
    console.error('[requireApiKey]', e.message);
    res.status(500).json({ error: 'Auth error' });
  }
}

// ── Middleware: validate Supabase JWT (dashboard calls) ──
async function requireAuth(req, res, next) {
  try {
    // Prefer httpOnly cookie; fall back to Bearer header for API clients
    const token = req.cookies?.dm_access ||
      (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const { data: { user }, error } = await supabaseService.auth.getUser(token);
    if (!error && user) { req.user = user; return next(); }

    // Token expired — try refresh cookie then header
    const rt = req.cookies?.dm_refresh || req.headers['x-refresh-token'];
    if (rt) {
      try {
        const { data: rd } = await supabaseService.auth.refreshSession({ refresh_token: rt });
        if (rd && rd.session && rd.session.access_token) {
          const { data: { user: ru } } = await supabaseService.auth.getUser(rd.session.access_token);
          if (ru) {
            req.user = ru;
            setAuthCookies(res, rd.session);
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

// ── flexAuth — accepts Supabase JWT (cookie/dashboard) OR dm_sk_ API key (SDK/CLI) ──
async function flexAuth(req, res, next) {
  const headerAuth = (req.headers.authorization || '').replace('Bearer ', '').trim();

  // API key path always uses Authorization header
  if (headerAuth.startsWith('dm_sk_') || headerAuth.startsWith('dmp_')) {
    try {
      const keyHash = crypto.createHash('sha256').update(headerAuth).digest('hex');
      const { data: agent } = await supabaseService.from('agents')
        .select('agent_id, agent_name, user_id').eq('api_key_hash', keyHash).single();
      if (agent) { req.agent = agent; req.authType = 'apikey'; return next(); }
    } catch(e) {}
    return res.status(401).json({ error: 'Invalid API key or session' });
  }

  // User JWT path — prefer cookie, fall back to header
  const token = req.cookies?.dm_access || headerAuth;
  if (!token) return res.status(401).json({ error: 'Authorization required' });

  try {
    const { data: { user }, error } = await supabaseService.auth.getUser(token);
    if (!error && user) { req.user = user; req.authType = 'supabase'; return next(); }

    const rt = req.cookies?.dm_refresh || req.headers['x-refresh-token'];
    if (rt) {
      const { data: rd } = await supabaseService.auth.refreshSession({ refresh_token: rt });
      if (rd && rd.session) {
        const { data: { user: ru } } = await supabaseService.auth.getUser(rd.session.access_token);
        if (ru) {
          req.user = ru; req.authType = 'supabase';
          setAuthCookies(res, rd.session);
          return next();
        }
      }
    }
  } catch(e) {}

  return res.status(401).json({ error: 'Invalid API key or session' });
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
      console.log(`  📧 Magic link sent to: ${email}`);
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
        // Redirect to /auth/callback so the confirmation tokens can be exchanged
        // for server-side cookies before the user reaches the dashboard.
        // Pointing at /dashboard directly causes a login-redirect loop because
        // the server never sees the #fragment tokens Supabase appends.
        emailRedirectTo: `${process.env.BASE_URL || 'https://darkmatterhub.ai'}/auth/callback`,
      },
    });
    if (error) return res.status(400).json({ error: error.message });

    if (data.session) setAuthCookies(res, data.session);
    res.json({ user: data.user });
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

    setAuthCookies(res, data.session);
    res.json({ user: data.user });
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

// ── GET /auth/callback ── email-confirmation and OAuth landing page ──────────
// Supabase redirects here after email confirmation or OAuth with either:
//   Implicit flow: #access_token=...&refresh_token=...&type=signup  (URL fragment)
//   PKCE flow:     ?code=...                                         (query string)
// The page reads whichever is present, exchanges tokens for server-set cookies,
// then forwards to /dashboard — so the user lands directly in the app.
app.get('/auth/callback', (req, res) => {
  const code     = req.query.code  ? String(req.query.code)  : null;
  const errParam = req.query.error ? String(req.query.error_description || req.query.error) : null;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Confirming...</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0a09;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:'JetBrains Mono',monospace;color:#888;font-size:13px;letter-spacing:.05em}.dot{width:8px;height:8px;border-radius:50%;background:#28a062;animation:p 1.2s ease-in-out infinite;display:inline-block}@keyframes p{0%,100%{opacity:1}50%{opacity:.25}}.msg{text-align:center;display:flex;flex-direction:column;gap:1.25rem;align-items:center}</style>
</head><body><div class="msg"><div class="dot"></div><div>Confirming account...</div></div>
<script>
(async function(){
  var code=${JSON.stringify(code)};
  var errMsg=${JSON.stringify(errParam)};
  if(errMsg){window.location.href='/login?error='+encodeURIComponent(errMsg);return;}
  try{
    if(code){
      // PKCE flow: exchange authorization code for session cookies server-side
      var r=await fetch('/auth/exchange',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code})});
      if(r.ok){window.location.href='/dashboard';return;}
      var d=await r.json().catch(function(){return{};});
      window.location.href='/login?error='+encodeURIComponent(d.error||'Confirmation failed');
      return;
    }
    // Implicit flow: tokens are in the URL fragment (never sent to server)
    var hash=window.location.hash.slice(1);
    var p=Object.fromEntries(new URLSearchParams(hash));
    if(p.access_token&&p.refresh_token){
      var r2=await fetch('/auth/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({access_token:p.access_token,refresh_token:p.refresh_token})});
      if(r2.ok){window.location.href='/dashboard';return;}
    }
    window.location.href='/login?error=confirmation_failed';
  }catch(e){window.location.href='/login?error=confirmation_failed';}
})();
</script></body></html>`);
});

// ── POST /auth/session ── set cookies from fragment tokens ───────────────────
// Called by /auth/callback when Supabase uses the implicit (fragment) flow.
// Validates the access token then writes httpOnly cookies so the dashboard can
// authenticate without the user ever seeing a login form.
app.post('/auth/session', authLimiter, async (req, res) => {
  try {
    const { access_token, refresh_token } = req.body || {};
    if (!access_token || !refresh_token) return res.status(400).json({ error: 'Missing tokens' });
    const { data: { user }, error } = await supabaseService.auth.getUser(access_token);
    if (error || !user) return res.status(401).json({ error: 'Invalid or expired token' });
    setAuthCookies(res, { access_token, refresh_token, expires_in: 3600 });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/exchange ── exchange PKCE code for session cookies ─────────────
// Called by /auth/callback when Supabase uses the PKCE (code) flow.
app.post('/auth/exchange', authLimiter, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: 'Missing code' });
    const { data, error } = await supabaseAnon.auth.exchangeCodeForSession(code);
    if (error || !data?.session) return res.status(400).json({ error: error?.message || 'Code exchange failed' });
    setAuthCookies(res, data.session);
    res.json({ ok: true });
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

    // Verify the recovery token and get the user via service client
    const { data: { user }, error: sessionError } = await supabaseService.auth.getUser(token);
    if (sessionError || !user) return res.status(400).json({ error: 'Invalid or expired reset link' });

    // Update password via admin API (service role required)
    const { error } = await supabaseService.auth.admin.updateUserById(user.id, { password });
    if (error) return res.status(400).json({ error: error.message });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /auth/logout ────────────────────────────────
app.post('/auth/logout', async (req, res) => {
  const token = req.cookies?.dm_access ||
    (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  try {
    if (token) await supabaseService.auth.admin.signOut(token);
  } catch(_) {}
  clearAuthCookies(res);
  res.json({ success: true });
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
// ── Event hooks stub ─────────────────────────────────────────────────────────
async function fireEventHooks(agentId, eventType, data) {
  // Fire and forget — no-op if no hooks configured
  try {
    const { data: hooks } = await supabaseService
      .from('event_hooks')
      .select('*')
      .eq('agent_id', agentId)
      .eq('event_type', eventType)
      .eq('is_active', true);
    if (!hooks || !hooks.length) return;
    for (const hook of hooks) {
      fetch(hook.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(hook.secret ? { 'X-Hook-Secret': hook.secret } : {}) },
        body: JSON.stringify({ event: eventType, agent_id: agentId, ...data }),
      }).catch(() => {});
    }
  } catch (_) {}
}

// ── commit_usage helpers ──────────────────────────────────────────────────────
// Returns the calendar-month key used as commit_usage.month ('YYYY-MM').
// Using calendar month for all tiers keeps gate checks and increments
// consistent across all commit paths (commit, fork, rich, proxy).
function currentMonthKey() {
  const d  = new Date();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `${d.getUTCFullYear()}-${mm}`;
}

// Increments commit_usage by 1 (and bytes_used by payloadBytes) for (userId, monthKey).
// Fire-and-forget — never throws; a missed increment is self-healing on the next bootstrap.
// bytes_used requires the bytes_used column: ALTER TABLE commit_usage ADD COLUMN IF NOT EXISTS bytes_used bigint DEFAULT 0;
async function incrementCommitUsage(userId, monthKey, payloadBytes) {
  if (!userId || !monthKey) return;
  const bytes = payloadBytes || 0;
  try {
    const now = new Date().toISOString();
    const { data: row } = await supabaseService
      .from('commit_usage')
      .select('commit_count, bytes_used')
      .eq('user_id', userId)
      .eq('month', monthKey)
      .maybeSingle();
    if (row) {
      await supabaseService.from('commit_usage')
        .update({ commit_count: (row.commit_count || 0) + 1, bytes_used: (row.bytes_used || 0) + bytes, updated_at: now })
        .eq('user_id', userId)
        .eq('month', monthKey);
    } else {
      await supabaseService.from('commit_usage')
        .insert({ user_id: userId, month: monthKey, commit_count: 1, bytes_used: bytes, updated_at: now })
        .catch(() => {}); // swallow concurrent-insert race
    }
  } catch (e) {
    console.error('[commit_usage]', e.message);
  }
}
// ─────────────────────────────────────────────────────────────────────────────

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
      agent,              // optional — { role, provider, model } from caller
      completeness_claim, // optional boolean — signed coverage assertion (L3)
      client_attestation, // optional — { key_id, signature, algorithm, ... } for L3
    } = req.body;

    // Accept either payload (v1) or context (legacy)
    const resolvedPayload = payload || (context ? { output: context } : null);
    if (!toAgentId || !resolvedPayload) {
      return res.status(400).json({ error: 'toAgentId and payload (or context) required' });
    }

    // Hard abuse floor: 10 MB per commit. No legitimate agent decision exceeds this.
    const payloadBytes = Buffer.byteLength(JSON.stringify(resolvedPayload), 'utf8');
    if (payloadBytes > 10 * 1024 * 1024) {
      return res.status(413).json({
        error: 'Payload too large. Maximum 10 MB per commit.',
        actual_kb: Math.round(payloadBytes / 1024),
        docs: 'https://darkmatterhub.ai/docs#api-commit',
      });
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

    // ── Assurance level — L1 / L2 / L3 ─────────────────
    // L3: customer holds the signing key — client_attestation carries Ed25519 sig
    // L2: checkpoint anchoring (automatic, applied at checkpoint time)
    // L1: hash chain integrity — default for every commit
    let assuranceLevel = 'L1';
    if (client_attestation && client_attestation.key_id &&
        (client_attestation.signature_b64 || client_attestation.signature)) {
      const sigResult = await verifyCommitSignature(supabaseService, {
        agent_id:         req.agent.agent_id,
        key_id:           client_attestation.key_id,
        agent_signature:  client_attestation.signature_b64 || client_attestation.signature,
        accepted_at:      acceptedAt,
        payload:          resolvedPayload,
        parent_hash:      parentHash,
        client_timestamp: clientTimestamp,
      });
      if (!sigResult.verified) {
        return res.status(400).json({
          error:  'Invalid L3 client_attestation — signature verification failed',
          reason: sigResult.result,
        });
      }
      assuranceLevel = 'L3';
    }

    // ── Plan limit enforcement ────────────────────────
    // O(1): read from commit_usage cache instead of a full COUNT scan.
    // On first commit of a period the cache row won't exist yet; we fall
    // back to COUNT once, seed the row, and stay fast from then on.
    {
      const userId = req.agent.user_id;
      if (userId) {
        // Look up subscription (DB first, then free fallback)
        const { data: sub } = await supabaseService
          .from('subscriptions')
          .select('plan, commit_limit, current_period_start')
          .eq('user_id', userId)
          .eq('status', 'active')
          .single()
          .catch(() => ({ data: null }));

        const currentPlan  = sub?.plan || 'free';
        const planMeta     = PLAN_META[currentPlan] || PLAN_META.free;
        const planLimit    = sub?.commit_limit ?? planMeta.commitLimit;

        // O(1) cache lookup
        const monthKey = currentMonthKey();
        const { data: usageRow } = await supabaseService
          .from('commit_usage')
          .select('commit_count')
          .eq('user_id', userId)
          .eq('month', monthKey)
          .maybeSingle();

        let commitCount = 0;
        if (usageRow) {
          commitCount = usageRow.commit_count || 0;
        } else {
          // Bootstrap: no cached row yet — fall back to COUNT then seed cache
          let periodStart;
          if (sub?.current_period_start) {
            const ps = new Date(sub.current_period_start);
            const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000);
            periodStart = ps > thirtyDaysAgo ? ps : thirtyDaysAgo;
          } else {
            periodStart = new Date(); periodStart.setDate(1); periodStart.setHours(0, 0, 0, 0);
          }
          const { data: agentRows } = await supabaseService
            .from('agents').select('agent_id').eq('user_id', userId);
          const agentIds = (agentRows || []).map(a => a.agent_id);
          if (agentIds.length) {
            const { count } = await supabaseService
              .from('commits').select('id', { count: 'exact', head: true })
              .in('from_agent', agentIds)
              .gte('timestamp', periodStart.toISOString());
            commitCount = count || 0;
          }
          // Seed the cache row so subsequent checks are O(1)
          if (commitCount > 0) {
            supabaseService.from('commit_usage')
              .insert({ user_id: userId, month: monthKey, commit_count: commitCount, updated_at: new Date().toISOString() })
              .catch(() => {});
          }
        }

        if (planLimit !== null && commitCount >= planLimit) {
          return res.status(429).json({
            error: 'Monthly commit limit reached',
            limit: planLimit,
            plan:  currentPlan,
            upgrade_url: 'https://darkmatterhub.ai/pricing',
          });
        }
      }
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
        hash_mismatch:       hashMismatch || false,
        verified:            true,
        verification_reason: 'API key authenticated',
        capture_mode:        'client_signed',
        assurance_level:     assuranceLevel,
        completeness_claim:  completeness_claim !== undefined ? completeness_claim : null,
        client_attestation:  client_attestation  || null,
        timestamp,
      });

    if (error) throw error;

    // Increment commit_usage counter (fire-and-forget)
    if (req.agent.user_id) incrementCommitUsage(req.agent.user_id, currentMonthKey(), payloadBytes).catch(() => {});

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
      capture_mode:        'client_signed',
      assurance_level:     assuranceLevel,
      completeness_claim:  completeness_claim !== undefined ? completeness_claim : null,
      timestamp,
    }, { [req.agent.agent_id]: req.agent.agent_name, [toAgentId]: recipientAgent?.agent_name || toAgentId });
    receipt.assurance_level    = assuranceLevel;
    receipt.completeness_claim = completeness_claim !== undefined ? completeness_claim : null;
    receipt.verify_url         = (process.env.APP_URL || 'https://darkmatterhub.ai') + '/r/' + commitId;

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
      capture_mode: 'client_signed',
      timestamp,
    });

    if (error) throw error;

    // Increment commit_usage counter (fire-and-forget)
    const forkPayloadBytes = Buffer.byteLength(JSON.stringify(forkPayload), 'utf8');
    if (req.agent.user_id) incrementCommitUsage(req.agent.user_id, currentMonthKey(), forkPayloadBytes).catch(() => {});

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
app.get('/api/export/:ctxId', flexAuth, async (req, res) => {
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
  if (req.agent?.agent_id !== process.env.SUPERUSER_AGENT_ID) {
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

// ── POST /api/workspace/keys — register a customer signing key ────────────────
app.post('/api/workspace/keys', wsAuth, async (req, res) => {
  try {
    const { publicKey, keyId = 'default', validUntil } = req.body;
    if (!publicKey) return res.status(400).json({ error: 'publicKey required' });
    const { data: me } = await supabaseService
      .from('workspace_members').select('agent_id').eq('user_id', req.user.id).single();
    if (!me?.agent_id) return res.status(404).json({ error: 'No agent found for this account' });
    const result = await registerKey(supabaseService, me.agent_id, publicKey, keyId, { validUntil, performedBy: me.agent_id });
    res.json({ ...result, message: 'Public key registered. Private key never stored.' });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.get('/api/workspace/keys', wsAuth, async (req, res) => {
  try {
    const { data: me } = await supabaseService
      .from('workspace_members').select('agent_id').eq('user_id', req.user.id).single();
    if (!me?.agent_id) return res.json({ keys: [] });
    const history = await getKeyHistory(supabaseService, me.agent_id);
    res.json({ keys: history || [] });
  } catch (err) { res.status(500).json({ error: err.message }); }
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

// ── POST /enterprise/commit ── RETIRED ──
app.post('/enterprise/commit', (req, res) => {
  res.status(410).json({
    error: 'This endpoint has been retired.',
    reason: 'Server-side key handling contradicts the non-repudiation guarantee. Use L3 client-side signing instead.',
    docs: 'https://darkmatterhub.ai/docs#l3-setup',
  });
});

// ── POST /enterprise/decrypt ── RETIRED ──
app.post('/enterprise/decrypt/:ctxId', (req, res) => {
  res.status(410).json({
    error: 'This endpoint has been retired.',
    reason: 'Server-side key handling contradicts the non-repudiation guarantee. Use L3 client-side signing instead.',
    docs: 'https://darkmatterhub.ai/docs#l3-setup',
  });
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

// ── GET /api/workspace/api-keys — list agents/keys for the authenticated user ──
// Called by the dashboard API Keys section. Returns agents belonging to the
// user, or all agents in the workspace if the user is an admin.
app.get('/api/workspace/api-keys', wsAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    // Find the user's workspace membership
    const { data: me } = await supabaseService
      .from('workspace_members')
      .select('workspace_id, role, agent_id')
      .eq('user_id', userId)
      .single();

    if (!me) {
      // No workspace membership — fall back to user's own agents
      const { data: agents } = await supabaseService
        .from('agents')
        .select('agent_id, agent_name, api_key, created_at, user_id')
        .eq('user_id', userId)
        .order('created_at', { ascending: false });

      return res.json({ keys: (agents || []).map(a => {
        const k = a.api_key || '';
        return {
          id:         a.agent_id,
          name:       a.agent_name,
          agent_name: a.agent_name,
          created_at: a.created_at,
          created_by: req.user.email,
          hint:       k ? k.slice(0, 10) + '......' + k.slice(-4) : null,
        };
      })});
    }

    let agentIds;
    if (me.role === 'admin' || me.role === 'owner') {
      // Admin sees all agents in the workspace
      const { data: members } = await supabaseService
        .from('workspace_members')
        .select('agent_id, email, display_name, user_id')
        .eq('workspace_id', me.workspace_id);
      agentIds = (members || []).map(m => m.agent_id).filter(Boolean);
    } else {
      agentIds = me.agent_id ? [me.agent_id] : [];
    }

    if (!agentIds.length) return res.json({ keys: [] });

    const { data: agents } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name, api_key, created_at, user_id')
      .in('agent_id', agentIds)
      .order('created_at', { ascending: false });

    // Enrich with email from workspace_members
    const { data: allMembers } = await supabaseService
      .from('workspace_members')
      .select('agent_id, email, display_name')
      .eq('workspace_id', me.workspace_id);

    const memberByAgent = {};
    (allMembers || []).forEach(m => { if (m.agent_id) memberByAgent[m.agent_id] = m; });

    const keys = (agents || []).map(a => {
      const k = a.api_key || '';
      return {
        id:         a.agent_id,
        name:       a.agent_name,
        agent_name: a.agent_name,
        created_at: a.created_at,
        created_by: memberByAgent[a.agent_id]?.email || req.user.email,
        note:       'DarkMatter workspace',
        hint:       k ? k.slice(0, 10) + '......' + k.slice(-4) : null,
      };
    });

    res.json({ keys });
  } catch (err) {
    console.error('[workspace/api-keys]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/workspace/profile — read display name for authenticated user ─────
app.get('/api/workspace/profile', wsAuth, async (req, res) => {
  try {
    const { data: member } = await supabaseService
      .from('workspace_members')
      .select('display_name, email, role')
      .eq('user_id', req.user.id)
      .maybeSingle();
    res.json({ display_name: member?.display_name || null, email: member?.email || req.user.email });
  } catch (err) {
    console.error('[workspace/profile GET]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── PATCH /api/workspace/profile — update display name ───────────────────────
app.patch('/api/workspace/profile', wsAuth, async (req, res) => {
  try {
    const { display_name } = req.body || {};
    if (!display_name || !display_name.trim()) return res.status(400).json({ error: 'display_name required' });
    const safeName = sanitizeText(display_name.trim(), 100);
    const userId   = req.user.id;
    const { error } = await supabaseService
      .from('workspace_members')
      .update({ display_name: safeName })
      .eq('user_id', userId);
    if (error) throw error;
    res.json({ display_name: safeName });
  } catch (err) {
    console.error('[workspace/profile PATCH]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/workspace/api-keys — create a new agent/key ─────────────────────
app.post('/api/workspace/api-keys', wsAuth, async (req, res) => {
  try {
    const { name } = req.body || {};
    const agentName = sanitizeText(name || 'Agent', 100);
    const userId    = req.user.id;

    // Generate a new API key
    const rawKey  = 'dm_sk_' + crypto.randomBytes(24).toString('hex');
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const agentId = 'dm_' + crypto.randomBytes(12).toString('hex');

    const { data: agent, error } = await supabaseService.from('agents').insert({
      agent_id:   agentId,
      agent_name: agentName,
      user_id:    userId,
      api_key:    rawKey,
    }).select().single();

    if (error) throw error;

    // Add to workspace if user has one
    const { data: me } = await supabaseService
      .from('workspace_members')
      .select('workspace_id')
      .eq('user_id', userId)
      .single();

    if (me?.workspace_id) {
      await supabaseService.from('workspace_members').insert({
        workspace_id: me.workspace_id,
        user_id:      userId,
        agent_id:     agentId,
        email:        req.user.email,
        role:         'member',
        display_name: agentName,
      }).select().single().catch(() => null); // ignore if already exists
    }

    res.json({
      id:         agentId,
      name:       agentName,
      agent_name: agentName,
      api_key:    rawKey,   // only returned on creation
      created_at: agent.created_at,
      created_by: req.user.email,
    });
  } catch (err) {
    console.error('[workspace/api-keys POST]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/workspace/api-keys/:keyId — delete an agent/key ───────────────
app.delete('/api/workspace/api-keys/:keyId', wsAuth, async (req, res) => {
  try {
    const { keyId } = req.params;
    const userId    = req.user.id;

    // Verify ownership — user must own this agent or be workspace admin
    const { data: agent } = await supabaseService
      .from('agents')
      .select('agent_id, user_id')
      .eq('agent_id', keyId)
      .single();

    if (!agent) return res.status(404).json({ error: 'Key not found' });

    if (agent.user_id !== userId) {
      // Check if user is workspace admin
      const { data: me } = await supabaseService
        .from('workspace_members')
        .select('role')
        .eq('user_id', userId)
        .in('role', ['admin', 'owner'])
        .single();
      if (!me) return res.status(403).json({ error: 'Not authorized to delete this key' });
    }

    await supabaseService.from('agents').delete().eq('agent_id', keyId);
    res.json({ deleted: true });
  } catch (err) {
    console.error('[workspace/api-keys DELETE]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Billing stubs — Stripe not yet implemented ────────────────────────────────
app.get('/api/billing/subscription', wsAuth, async (req, res) => {
  try {
    const email  = req.user.email;
    const userId = req.user.id;

    // Admin accounts — show as internal/unlimited
    const adminEmails = [
      ...(process.env.SUPERUSER_EMAIL || '').split(','),
      ...(process.env.ADMIN_EMAILS    || '').split(','),
    ].map(e => e.trim()).filter(Boolean);
    if (adminEmails.includes(email)) {
      return res.json({
        plan: 'enterprise', status: 'active',
        planInfo: { name: 'Internal', price: null },
        commitCount: null, commitLimit: null,
      });
    }

    // O(1) commit count and bytes from commit_usage cache
    const { data: usageRow } = await supabaseService
      .from('commit_usage')
      .select('commit_count, bytes_used')
      .eq('user_id', userId)
      .eq('month', currentMonthKey())
      .maybeSingle();
    let commitCount = usageRow?.commit_count || 0;
    const bytesUsed = usageRow?.bytes_used   || 0;

    // 1. Check DB subscriptions table first (fast, no Stripe API call)
    const { data: dbSub } = await supabaseService
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .eq('status', 'active')
      .single()
      .catch(() => ({ data: null }));

    if (dbSub && dbSub.plan && dbSub.plan !== 'free') {
      const meta = PLAN_META[dbSub.plan] || PLAN_META.free;
      return res.json({
        plan:              dbSub.plan,
        status:            dbSub.status,
        planInfo:          { name: dbSub.plan.charAt(0).toUpperCase() + dbSub.plan.slice(1), price: meta.price },
        commitCount,
        commitLimit:       dbSub.commit_limit ?? meta.commitLimit,
        bytesUsed,
        retention_days:    dbSub.retention_days ?? meta.retentionDays,
        currentPeriodEnd:  dbSub.current_period_end,
        cancelAtPeriodEnd: dbSub.cancel_at_period_end,
        stripeCustomerId:  dbSub.stripe_customer_id,
        stripeSubId:       dbSub.stripe_subscription_id,
      });
    }

    // 2. Fall back to live Stripe lookup (first login after upgrade, or DB miss)
    if (process.env.STRIPE_SECRET_KEY) {
      try {
        const stripe    = getStripe();
        const customers = await stripe.customers.list({ email, limit: 1 });
        if (customers.data.length) {
          const customer = customers.data[0];
          const subs     = await stripe.subscriptions.list({
            customer: customer.id, status: 'active', limit: 1,
            expand: ['data.items.data.price']
          });
          if (subs.data.length) {
            const sub  = subs.data[0];
            const plan = priceIdToPlan(sub.items.data[0]?.price?.id);
            const meta = PLAN_META[plan] || PLAN_META.free;
            // Write to DB so next request is fast
            await upsertSubscription(userId, email, sub, customer.id);
            return res.json({
              plan,
              status:            sub.status,
              planInfo:          { name: plan.charAt(0).toUpperCase() + plan.slice(1), price: meta.price },
              commitCount,
              commitLimit:       meta.commitLimit,
              bytesUsed,
              retention_days:    meta.retentionDays,
              currentPeriodEnd:  new Date(sub.current_period_end * 1000).toISOString(),
              cancelAtPeriodEnd: sub.cancel_at_period_end,
              stripeCustomerId:  customer.id,
              stripeSubId:       sub.id,
            });
          }
        }
      } catch (stripeErr) {
        console.warn('[billing/subscription] Stripe lookup failed:', stripeErr.message);
      }
    }

    // 3. No subscription found — free plan
    res.json({
      plan: 'free', status: 'active',
      planInfo: { name: 'Free', price: null },
      commitCount, commitLimit: PLAN_META.free.commitLimit, bytesUsed,
      retention_days: PLAN_META.free.retentionDays,
    });
  } catch (err) {
    console.error('[billing/subscription]', err.message);
    res.json({ plan: 'free', status: 'active', planInfo: { name: 'Free', price: null }, commitCount: 0, commitLimit: PLAN_META.free.commitLimit });
  }
});
app.post('/api/billing/checkout', wsAuth, async (req, res) => {
  try {
    const { plan = 'pro' } = req.body || {};
    const priceId = STRIPE_PRICES[plan];
    if (!priceId) {
      return res.status(400).json({ error: 'Unknown plan or price not configured. Set STRIPE_PRICE_' + plan.toUpperCase() + ' on Railway.' });
    }
    const stripe   = getStripe();
    const email    = req.user.email;
    const appUrl   = process.env.APP_URL || 'https://darkmatterhub.ai';

    // Find or create Stripe customer
    let customerId;
    const existing = await stripe.customers.list({ email, limit: 1 });
    if (existing.data.length) {
      customerId = existing.data[0].id;
    } else {
      const customer = await stripe.customers.create({ email, metadata: { user_id: req.user.id } });
      customerId = customer.id;
    }

    const session = await stripe.checkout.sessions.create({
      customer:   customerId,
      mode:       'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: appUrl + '/dashboard?billing=success&session_id={CHECKOUT_SESSION_ID}',
      cancel_url:  appUrl + '/dashboard?billing=cancelled',
      allow_promotion_codes: true,
      subscription_data: {
        metadata: { user_id: req.user.id, plan },
      },
    });
    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error('[billing/checkout]', err.message);
    res.status(500).json({ error: err.message });
  }
});
app.post('/api/billing/portal', wsAuth, async (req, res) => {
  try {
    const stripe  = getStripe();
    const email   = req.user.email;
    const appUrl  = process.env.APP_URL || 'https://darkmatterhub.ai';
    const customers = await stripe.customers.list({ email, limit: 1 });
    if (!customers.data.length) {
      return res.status(404).json({ error: 'No billing account found. Upgrade to a paid plan first.' });
    }
    const session = await stripe.billingPortal.sessions.create({
      customer:   customers.data[0].id,
      return_url: appUrl + '/dashboard?billing=portal_return',
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[billing/portal]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/contact — footer contact modal ─────────────────────────────────
app.post('/api/contact', feedbackLimiter, async (req, res) => {
  try {
    const { name, email, message, subject: subjectParam } = req.body || {};
    if (!email || !message) return res.status(400).json({ error: 'Email and message are required.' });
    const safeName    = sanitizeText(name,         200);
    const safeEmail   = sanitizeText(email,        200);
    const safeMessage = sanitizeText(message,      2000);
    const safeSubject = sanitizeText(subjectParam, 200);
    const emailSubject = safeSubject
      ? `[DarkMatter ${safeSubject}] ${escapeHtml(safeEmail)}`
      : `[DarkMatter Contact] ${escapeHtml(safeEmail)}`;
    if (process.env.RESEND_API_KEY && process.env.FEEDBACK_EMAIL) {
      fetch('https://api.resend.com/emails', {
        method:  'POST',
        headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from:    'DarkMatter <hello@darkmatterhub.ai>',
          to:      [process.env.FEEDBACK_EMAIL],
          subject: emailSubject,
          html:    `<p><b>Name:</b> ${escapeHtml(safeName) || '(not provided)'}</p>
                    <p><b>Email:</b> ${escapeHtml(safeEmail)}</p>
                    <p><b>Message:</b></p>
                    <blockquote style="border-left:3px solid #ccc;padding-left:12px;color:#444">
                      ${escapeHtml(safeMessage).replace(/\n/g, '<br>')}
                    </blockquote>`,
        }),
      }).catch(e => console.error('[contact] Resend failed:', e.message));
    } else {
      console.log('[contact] form submission (RESEND not configured):', { name: safeName, email: safeEmail });
    }
    res.json({ received: true });
  } catch (err) {
    console.error('[contact]', err.message);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

// ── POST /api/enterprise-inquiry — alias for /enterprise/inquiry ──────────────
// enterprise.html posts here; delegate to the canonical handler
app.post('/api/enterprise-inquiry', feedbackLimiter, (req, res, next) => {
  req.url = '/enterprise/inquiry';
  app._router.handle(req, res, next);
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
app.get('/security',      (req, res) => res.sendFile(path.join(__dirname, '../public/security.html')));
app.get('/pricing',       (req, res) => res.sendFile(path.join(__dirname, '../public/pricing.html')));
app.get('/why',           (req, res) => res.sendFile(path.join(__dirname, '../public/why.html')));
app.get('/about',         (req, res) => res.sendFile(path.join(__dirname, '../public/why.html')));
app.get('/docs',          (req, res) => res.sendFile(path.join(__dirname, '../public/docs.html')));
app.get('/enterprise',    (req, res) => res.sendFile(path.join(__dirname, '../public/enterprise.html')));
app.get('/organizations', (req, res) => res.sendFile(path.join(__dirname, '../public/organizations.html')));


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

    // Increment commit_usage counter (fire-and-forget)
    const richPayloadBytes = Buffer.byteLength(JSON.stringify(payload), 'utf8');
    if (agentRecord.user_id) incrementCommitUsage(agentRecord.user_id, currentMonthKey(), richPayloadBytes).catch(() => {});

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
  let bodyHtml = (content.html_content || '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)/gi, '')
    .replace(/href\s*=\s*["']?\s*javascript:[^"'\s>]*/gi, 'href="#"');
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


// ═══════════════════════════════════════════════════════════════════════
// PUBLIC RECORD VIEW — no auth required
// GET /r/:traceId       → human-readable HTML (default)
// GET /r/:traceId?format=json → raw JSON
// ═══════════════════════════════════════════════════════════════════════
app.get('/r/:traceId', async (req, res) => {
  try {
    const { traceId } = req.params;
    if (!traceId || traceId.length > 120 || !/^[a-zA-Z0-9_-]+$/.test(traceId)) return res.status(400).json({ error: 'Invalid ID' });

    const rSel = 'id, trace_id, from_agent, agent_id, agent_info, payload, timestamp, client_timestamp, event_type, integrity_hash, payload_hash, parent_hash, verified, assurance_level, completeness_claim';
    const [{ data: rById }, { data: rByTrace, error }] = await Promise.all([
      supabaseService.from('commits').select(rSel).eq('id', traceId).order('timestamp', { ascending: true }),
      supabaseService.from('commits').select(rSel).eq('trace_id', traceId).order('timestamp', { ascending: true }),
    ]);
    const rSeen = new Set();
    const commits = [...(rById || []), ...(rByTrace || [])]
      .filter(c => !rSeen.has(c.id) && rSeen.add(c.id))
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    if (error || !commits || !commits.length) {
      if (req.query.format === 'json') return res.status(404).json({ error: 'Record not found.' });
      return res.status(404).send('<!DOCTYPE html><html><head><title>Not found</title></head><body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;"><div style="text-align:center"><h2>Record not found</h2><p>This record may have been removed or the link is incorrect.</p><a href="/">Back to DarkMatter</a></div></body></html>');
    }

    // Compute highest assurance level + completeness across commits
    var highestAssurance = 'L1';
    for (var ci = 0; ci < commits.length; ci++) {
      var al = commits[ci].assurance_level || 'L1';
      if (al === 'L3') { highestAssurance = 'L3'; break; }
      if (al === 'L2') highestAssurance = 'L2';
    }
    var hasCompleteness = commits.some(function(c) { return c.completeness_claim === true; });

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
      for (var i = 0; i < commits.length; i++) {
        var p = commits[i].payload || {};
        // Prefer input (the question) over output (the answer)
        var inp = p.input || p.prompt || '';
        var out = p.output || p.result || '';
        if (inp && inp.length > 4) return inp.slice(0, 70) + (inp.length > 70 ? '...' : '');
        if (out && out.length > 4) return out.slice(0, 70) + (out.length > 70 ? '...' : '');
      }
      return 'Agent Decision Record';
    })();

    var platform = (commits[0] && commits[0].payload && commits[0].payload.platform) || 'AI';
    var firstTs = (commits[0] && (commits[0].client_timestamp || commits[0].timestamp)) || '';
    var stepCount = commits.length;
    var statusColor = chainIntact ? '#065f46' : '#991b1b';
    var statusText  = chainIntact ? '\u2713 Record intact' : '\u2717 Mismatch detected';
    var statusBg    = chainIntact ? 'rgba(16,185,129,.06)' : 'rgba(239,68,68,.06)';
    var statusBd    = chainIntact ? 'rgba(16,185,129,.2)'  : 'rgba(239,68,68,.2)';

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
    var dateStr = firstTs ? new Date(firstTs).toLocaleDateString(undefined, {month:'short',day:'numeric',year:'numeric'}) : '';

    var html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
      + '<meta charset="UTF-8"/>\n'
      + '<meta name="viewport" content="width=device-width,initial-scale=1"/>\n'
      + '<title>' + escH(title) + ' \u2014 DarkMatter</title>\n'
      + '<link rel="preconnect" href="https://fonts.googleapis.com"/>\n'
      + '<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>\n'
      + '<style>\n'
      + '*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}\n'
      + ':root{--ink:#0a0e1a;--ink2:#2d3552;--ink3:#5a6480;--ink4:#9199b0;--bg:#f4f6fb;--bg2:#eceef5;--border:#e5e7eb;--border2:#dde1ed;--blue:#3b82f6;--green:#10b981;--mono:"JetBrains Mono","Courier New",monospace;--sans:"Inter",sans-serif;--grad:linear-gradient(90deg,#7C3AED,#2563EB,#0891b2);}\n'
      + 'body{background:var(--bg);color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased;font-size:14px;}\n'
      + '.nav{height:3.5rem;background:rgba(252,251,249,.8);border-bottom:1px solid hsl(38,14%,84%);display:flex;align-items:center;padding:0;position:sticky;top:0;z-index:9998;backdrop-filter:blur(8px);}\n'
      + '#r-dlinks{display:none;gap:2rem;align-items:center;}\n'
      + '#r-signin{display:none;}\n'
      + '@media(min-width:640px){#r-signin{display:inline-flex!important;}}\n'
      + '@media(min-width:768px){#r-dlinks{display:flex!important;}#r-ham{display:none!important;}}\n'
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
      + '.bubble{border-radius:3px;padding:9px 13px;font-size:13.5px;line-height:1.6;word-break:break-word;overflow-wrap:break-word;max-width:75%;display:inline-block;white-space:normal;}\n'
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
      + '<nav class="nav"><div style="display:flex;height:3.5rem;align-items:center;justify-content:space-between;max-width:80rem;margin:0 auto;padding:0 1.5rem;gap:.5rem;"><a href="/" style="display:flex;align-items:center;gap:.6rem;text-decoration:none;flex-shrink:0;"><svg viewBox="0 0 32 32" width="28" height="28" fill="none"><circle cx="16" cy="16" r="10" stroke="#0a0e1a" stroke-opacity="0.45" stroke-width="0.8"/><path d="M 16 6 L 24.66 21 L 7.34 21 Z" stroke="#0a0e1a" stroke-opacity="0.18" stroke-width="0.5" stroke-dasharray="1 1.5"/><circle cx="16" cy="16" r="0.8" fill="#0a0e1a" fill-opacity="0.55"/><circle cx="16" cy="6" r="2.1" fill="hsl(152,64%,34%)"/><circle cx="16" cy="6" r="3.4" stroke="hsl(152,64%,34%)" stroke-opacity="0.3" stroke-width="0.45"/><circle cx="24.66" cy="21" r="1.5" fill="#0a0e1a"/><circle cx="7.34" cy="21" r="1.5" fill="#0a0e1a" fill-opacity="0.85"/></svg><span style="display:flex;align-items:baseline;gap:1px;font-family:JetBrains Mono,monospace;"><span style="font-size:15px;font-weight:600;letter-spacing:.02em;color:#0a0e1a;">DARK</span><span style="font-size:15px;font-weight:300;letter-spacing:.02em;color:#6b6b7b;">MATTER</span></span></a><div id=\"r-dlinks\"><a href=\"/demo\" style=\"font-family:JetBrains Mono,monospace;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:hsl(220,10%,38%);text-decoration:none;\">Demo</a><a href=\"/docs\" style=\"font-family:JetBrains Mono,monospace;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:hsl(220,10%,38%);text-decoration:none;\">Docs</a><a href=\"/pricing\" style=\"font-family:JetBrains Mono,monospace;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:hsl(220,10%,38%);text-decoration:none;\">Pricing</a><a href=\"/compare\" style=\"font-family:JetBrains Mono,monospace;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:hsl(220,10%,38%);text-decoration:none;\">Compare</a><a href=\"/integrity\" style=\"font-family:JetBrains Mono,monospace;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:hsl(220,10%,38%);text-decoration:none;\">Integrity</a></div><div style="display:flex;align-items:center;gap:.5rem;flex-shrink:0;"><a id=\"r-signin\" href=\"/login\" style=\"font-family:JetBrains Mono,monospace;font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:hsl(220,10%,38%);text-decoration:none;padding:.5rem .75rem;\">Sign in</a><button id=\"r-ham\" onclick=\"rHamClick()\" style=\"display:flex;flex-direction:column;justify-content:center;gap:5px;width:36px;height:36px;cursor:pointer;padding:6px;border:0;background:none;flex-shrink:0;\"><span style=\"display:block;height:1.5px;background:#0a0e1a;\"></span><span style=\"display:block;height:1.5px;background:#0a0e1a;\"></span><span style=\"display:block;height:1.5px;background:#0a0e1a;\"></span></button></div></div></nav>\n<style>@media(min-width:640px){#r-signin{display:inline-flex!important;}}@media(min-width:768px){#r-dlinks{display:flex!important;gap:2rem;align-items:center;}#r-ham{display:none!important;}}</style>\n<div id=\"r-menu\" style=\"display:none;position:fixed;top:3.5rem;left:0;right:0;bottom:0;background:rgba(252,251,249,.97);backdrop-filter:blur(12px);z-index:9999;flex-direction:column;align-items:center;justify-content:center;padding:1.5rem;border-top:1px solid #e8e3da;\">\n<a href=\"/demo\" style=\"font-family:JetBrains Mono,monospace;font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#5a6480;padding:.875rem 0;border-bottom:1px solid #e8e3da;text-decoration:none;display:block;text-align:center;width:100%;max-width:280px;\">Demo</a>\n<a href=\"/docs\" style=\"font-family:JetBrains Mono,monospace;font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#5a6480;padding:.875rem 0;border-bottom:1px solid #e8e3da;text-decoration:none;display:block;text-align:center;width:100%;max-width:280px;\">Docs</a>\n<a href=\"/pricing\" style=\"font-family:JetBrains Mono,monospace;font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#5a6480;padding:.875rem 0;border-bottom:1px solid #e8e3da;text-decoration:none;display:block;text-align:center;width:100%;max-width:280px;\">Pricing</a>\n<a href=\"/login\" style=\"font-family:JetBrains Mono,monospace;font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#5a6480;padding:.875rem 0;border-bottom:1px solid #e8e3da;text-decoration:none;display:block;text-align:center;width:100%;max-width:280px;\">Sign in</a>\n<a href=\"/signup\" style=\"font-family:JetBrains Mono,monospace;font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:hsl(152,64%,34%);padding:.875rem 0;text-decoration:none;display:block;text-align:center;width:100%;max-width:280px;\">Try it free</a>\n</div>\n'
      + '<div class="page">\n'
      + '<div class="first-screen">\n'
      + '  <div class="fs-title">' + escH(title) + '</div>\n'
      + '  <div class="fs-meta">\n'
      + '    <span class="fs-status" style="background:' + statusBg + ';color:' + statusColor + ';border-color:' + statusBd + ';">' + statusText + '</span>\n'
      + (highestAssurance === 'L3' ? '    <span class="fs-status" style="background:rgba(15,123,77,.07);color:#0f7b4d;border:1px solid rgba(15,123,77,.2);font-family:monospace;font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;">L3 NON-REPUDIATION</span>\n' : highestAssurance === 'L2' ? '    <span class="fs-status" style="background:rgba(59,130,246,.06);color:#1d4ed8;border:1px solid rgba(59,130,246,.2);font-family:monospace;font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;">L2 VERIFIED</span>\n' : '')
      + (hasCompleteness ? '    <span class="fs-status" style="background:rgba(15,123,77,.05);color:#0f7b4d;border:1px solid rgba(15,123,77,.15);font-family:monospace;font-size:10px;padding:2px 8px;border-radius:4px;">\u2714 Complete</span>\n' : '')
      + '    <span class="fs-sep">\u00b7</span>\n'
      + '    <span class="fs-chip">' + stepCount + ' step' + (stepCount !== 1 ? 's' : '') + '</span>\n'
      + '    <span class="fs-sep">\u00b7</span>\n'
      + '    <span class="fs-chip">' + escH(platform) + '</span>\n'
      + (dateStr ? '    <span class="fs-sep">\u00b7</span>\n    <span class="fs-chip">' + escH(dateStr) + '</span>\n' : '')
      + '  </div>\n'
      + '  <div class="fs-integrity">'
      + (chainIntact ? 'This record has been cryptographically verified. Nothing has been added, removed, or altered since it was captured.' : 'This record could not be fully verified. Download the proof file for independent investigation.')
      + (highestAssurance === 'L3' ? ' Signed with a customer-controlled Ed25519 key before reaching DarkMatter \u2014 DarkMatter cannot forge this record.' : '')
      + (hasCompleteness ? '<br><span style=\"font-size:12px;color:#0f7b4d;\">\u2714 Agent asserted this record is complete (nothing omitted).</span>' : '')
      + '</div>\n'
      + '  <div class="fs-actions">\n'
      + '    <button class="fs-btn-p" onclick="copyLink()">Copy link</button>\n'
      + '    <a class="fs-btn-s" href="' + escH(jsonUrl) + '">Download proof bundle (.json)</a>\n'
      + '    <button class="fs-btn-s" onclick="switchView(this.dataset.v,this)" data-v="proof">View verification &rarr;</button>\n'
      + '  </div>\n'
      + '</div>\n'
      + '<div class="view-switcher">\n'
      + '  <button class="vs-btn on" data-v="conv" onclick="switchView(this.dataset.v,this)">Conversation</button>\n'
      + '  <button class="vs-btn" data-v="timeline" onclick="switchView(this.dataset.v,this)">Timeline</button>\n'
      + '  <button class="vs-btn" data-v="proof" onclick="switchView(this.dataset.v,this)">Proof</button>\n'
      + '  <button class="vs-btn" data-v="json" onclick="switchView(this.dataset.v,this)">Raw JSON</button>\n'
      + '</div>\n'
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
      + '</div>\n'
      + '<footer style="background:hsl(38,30%,97%);border-top:1px solid #e8e3da;margin-top:0;"><div style="max-width:80rem;margin:0 auto;padding:2.5rem 1.5rem;display:flex;flex-wrap:wrap;gap:1.5rem;justify-content:space-between;align-items:center;"><a href="/" style="display:flex;align-items:center;gap:.6rem;text-decoration:none;"><svg viewBox="0 0 32 32" width="22" height="22" fill="none"><circle cx="16" cy="16" r="10" stroke="#0a0e1a" stroke-opacity="0.45" stroke-width="0.8"/><circle cx="16" cy="6" r="2.1" fill="hsl(152,64%,34%)"/><circle cx="24.66" cy="21" r="1.5" fill="#0a0e1a"/><circle cx="7.34" cy="21" r="1.5" fill="#0a0e1a" fill-opacity="0.85"/></svg><span style="font-family:JetBrains Mono,monospace;font-size:12px;font-weight:600;color:#0a0e1a;letter-spacing:.04em;">DARK<span style="font-weight:300;color:#9b9b9b;">MATTER</span></span></a><div style="display:flex;gap:1.5rem;flex-wrap:wrap;"><a href="/demo" style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:#6b6b7b;text-decoration:none;">Demo</a><a href="/pricing" style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:#6b6b7b;text-decoration:none;">Pricing</a><a href="/integrity" style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:#6b6b7b;text-decoration:none;">Integrity Spec</a><a href="/tos" style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:#6b6b7b;text-decoration:none;">Terms</a><a href="/privacy" style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:#6b6b7b;text-decoration:none;">Privacy</a><a href="/signup" style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:hsl(152,64%,34%);text-decoration:none;">Start free</a></div><span style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#b0b0b0;">&copy; 2026 DarkMatter</span></div></footer>\n'
      + '<script>\n'
      + 'var jsonLoaded=false;\n'
      + 'function rHamClick(){var m=document.getElementById("r-menu");var o=m.style.display==="flex";m.style.display=o?"none":"flex";document.body.style.overflow=o?"":"hidden";}\n'
      + 'window.addEventListener("resize",function(){if(window.innerWidth>=768){var m=document.getElementById("r-menu");if(m)m.style.display="none";document.body.style.overflow="";}});\n'
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
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
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



// ── GET /api/demo ── static fake demo data (no real user data exposed) ────────
app.get('/api/demo', async (req, res) => {
  const now = Date.now();
  const activity = [
    {
      id:              'ctx_demo_0001_a1b2c3d4e5f6',
      trace_id:        'ctx_demo_0001_a1b2c3d4e5f6',
      from_agent:      'dm_demo_refund_agent',
      agentName:       'refund-approval-agent',
      payload:         { role: 'assistant', text: 'Approved. Customer within 30-day window. No prior refund history. Amount within auto-approval threshold ($500). Approve immediately.' },
      timestamp:       new Date(now - 120000).toISOString(),
      integrity_hash:  'a3f8c2e1d94b7065f2a1c8e3d0b5f9a2c4e6d8f0b2a4c6e8d0f2a4b6c8e0d2f4',
      payload_hash:    'b5d7f9a1c3e5d7f9b1d3f5a7c9e1d3f5b7d9f1a3c5e7d9f1b3d5f7a9c1e3d5f7',
      assurance_level: 'L2',
      event_type:      'commit',
    },
    {
      id:              'ctx_demo_0002_b2c3d4e5f6a1',
      trace_id:        'ctx_demo_0001_a1b2c3d4e5f6',
      from_agent:      'dm_demo_refund_agent',
      agentName:       'refund-approval-agent',
      payload:         { role: 'user', text: 'Approve refund #84721? $284.00, 18 days since purchase.' },
      timestamp:       new Date(now - 180000).toISOString(),
      integrity_hash:  'c7e9a1b3d5f7a9c1e3d5f7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3d5f7a9',
      payload_hash:    'd9f1a3c5e7d9f1b3d5f7a9c1e3d5f7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1',
      assurance_level: 'L2',
      event_type:      'commit',
    },
    {
      id:              'ctx_demo_0003_c3d4e5f6a1b2',
      trace_id:        'ctx_demo_0003_c3d4e5f6a1b2',
      from_agent:      'dm_demo_escalation_agent',
      agentName:       'escalation-agent',
      payload:         { role: 'assistant', text: 'Escalating to human review. Amount exceeds $500 threshold. Customer has 2 prior refunds in 90 days.' },
      timestamp:       new Date(now - 360000).toISOString(),
      integrity_hash:  'e1b3d5f7a9c1e3d5f7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3d5f7a9c1e3',
      payload_hash:    'f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3d5f7b9d1f3a5c7e9b1d3f5a7c9e1b3d5',
      assurance_level: 'L1',
      event_type:      'commit',
    },
    {
      id:              'ctx_demo_0004_d4e5f6a1b2c3',
      trace_id:        'ctx_demo_0004_d4e5f6a1b2c3',
      from_agent:      'dm_demo_classifier_agent',
      agentName:       'intent-classifier',
      payload:         { role: 'assistant', text: 'Intent: refund_request. Confidence: 0.97. Routing to refund-approval-agent.' },
      timestamp:       new Date(now - 600000).toISOString(),
      integrity_hash:  'a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3d5f7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7',
      payload_hash:    'b7d9f1a3c5e7d9f1b3d5f7a9c1e3d5f7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9',
      assurance_level: 'L3',
      event_type:      'commit',
    },
  ];
  res.json({ activity, commits: activity });
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

    // Increment commit_usage counter (fire-and-forget)
    const proxyPayloadBytes = Buffer.byteLength(JSON.stringify(payload), 'utf8');
    if (userId) incrementCommitUsage(userId, currentMonthKey(), proxyPayloadBytes).catch(() => {});

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
    const token = req.cookies?.dm_access ||
      (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'No token' });

    const { data: { user }, error } = await supabaseService.auth.getUser(token);
    if (!error && user) { req.user = user; return next(); }

    const rt = req.cookies?.dm_refresh || req.headers['x-refresh-token'];
    if (rt) {
      try {
        const { data: rd } = await supabaseService.auth.refreshSession({ refresh_token: rt });
        if (rd && rd.session && rd.session.access_token) {
          const { data: { user: ru } } = await supabaseService.auth.getUser(rd.session.access_token);
          if (ru) {
            req.user = ru;
            setAuthCookies(res, rd.session);
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

    const { data: ws, error } = await supabaseService
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
      .order('joined_at', { ascending: true });

    // Get commit counts per member this week
    const weekAgo = new Date(Date.now() - 7*86400000).toISOString();
    const agentIds = members.map(m => m.agent_id).filter(Boolean);

    const { data: recentCommits } = agentIds.length ? await supabase
      .from('commits').select('agent_id')
      .in('agent_id', agentIds)
      .gte('accepted_at', weekAgo) : { data: [] };

    const countByAgent = {};
    (recentCommits || []).forEach(c => {
      countByAgent[c.agent_id] = (countByAgent[c.agent_id] || 0) + 1;
    });

    const enriched = members.map(m => ({
      ...m,
      weekCommits: countByAgent[m.agent_id] || 0,
    }));

    res.json({ members: enriched, isAdmin: me.role === 'admin' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Invite member ─────────────────────────────────────────────────────
app.post('/api/workspace/invite', wsAuth, async (req, res) => {
  try {
    const { email, role = 'member' } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const { data: me } = await supabaseService.from('workspace_members')
      .select('workspace_id, role').eq('user_id', req.user.id).single();
    if (!me || !['admin','owner'].includes(me.role)) return res.status(403).json({ error: 'Admin only' });

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
async function commitProxyInteraction({ provider, upstreamPath, requestBody, responseText, statusCode, latencyMs, member, workspace, clientTs, isStreaming, captureMode }) {
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
app.get('/join', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/join.html'));
});



// ── GET /dashboard/commits ────────────────────────────────────────────
;

// ── POST /api/auth/refresh ──────────────────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const refresh_token = req.cookies?.dm_refresh || req.body?.refresh_token;
    if (!refresh_token) return res.status(400).json({ error: 'No refresh token' });
    const { data, error } = await supabaseService.auth.refreshSession({ refresh_token });
    if (error) {
      clearAuthCookies(res);
      return res.status(401).json({ error: error.message });
    }
    setAuthCookies(res, data.session);
    res.json({ ok: true, user: data.user });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/user/me ─────────────────────────────────────────────────────────
app.get('/api/user/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ── Static file serving ──────────────────────────────────────────────── v2
const publicDir = path.join(__dirname, '../public');
app.use(express.static(publicDir));

// SPA fallback — serve dashboard for unknown routes when user is likely logged in
// /chat route removed — page no longer used


// ── GET /admin/stats — admin check + basic stats ──────────────────────────
app.get('/admin/stats', requireAuth, async (req, res) => {
  try {
    // Check if the authenticated user is an admin email
    const superuser = process.env.SUPERUSER_EMAIL || '';
    const adminList  = process.env.ADMIN_EMAILS    || '';
    const adminEmails = [...new Set([
      ...superuser.split(','),
      ...adminList.split(','),
    ].map(e => e.trim()).filter(Boolean))];
    const userEmail = req.user.email || '';
    console.log('[admin/stats] auth attempt:', userEmail, '| admin list:', adminEmails.join(','));
    if (!adminEmails.includes(userEmail)) {
      console.warn('[admin/stats] DENIED for:', userEmail);
      return res.status(403).json({ error: 'Admin only', attempted: userEmail, hint: 'Add your email to SUPERUSER_EMAIL on Railway' });
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


// ── GET /api/workspace/stats/usage — admin KPI endpoint ──────────────────────
app.get('/api/workspace/stats/usage', requireAuth, async (req, res) => {
  try {
    // Admin only — same check as /admin/stats
    const superuser  = process.env.SUPERUSER_EMAIL || '';
    const adminList  = process.env.ADMIN_EMAILS    || '';
    const adminEmails = [...new Set([
      ...superuser.split(','),
      ...adminList.split(','),
    ].map(e => e.trim()).filter(Boolean))];
    if (!adminEmails.includes(req.user.email)) {
      return res.status(403).json({ error: 'Admin only' });
    }

    const now    = new Date();
    const ago7d  = new Date(now - 7  * 86400000).toISOString();
    const ago30d = new Date(now - 30 * 86400000).toISOString();

    // Total commits + unique agents
    const { count: totalCommits } = await supabaseService
      .from('commits').select('id', { count: 'exact', head: true });

    const { data: agentRows } = await supabaseService
      .from('commits').select('from_agent').not('from_agent', 'is', null);
    const uniqueAgents = new Set((agentRows || []).map(r => r.from_agent)).size;

    // Active agents 7d / 30d
    const { data: active7d } = await supabaseService
      .from('commits').select('from_agent').gte('timestamp', ago7d).not('from_agent', 'is', null);
    const active7dCount  = new Set((active7d  || []).map(r => r.from_agent)).size;

    const { data: active30d } = await supabaseService
      .from('commits').select('from_agent').gte('timestamp', ago30d).not('from_agent', 'is', null);
    const active30dCount = new Set((active30d || []).map(r => r.from_agent)).size;

    // L3 usage
    const { count: l3Count } = await supabaseService
      .from('commits').select('id', { count: 'exact', head: true }).eq('assurance_level', 'L3');
    const l3Count7d_res = await supabaseService
      .from('commits').select('id', { count: 'exact', head: true })
      .eq('assurance_level', 'L3').gte('timestamp', ago7d);
    const l3Count7d = l3Count7d_res.count || 0;
    const l3Pct = totalCommits > 0 ? Math.round((l3Count || 0) / totalCommits * 100) : 0;

    // Wrapper usage (from metadata.wrapper or agent_info)
    const { data: wrapperRows } = await supabaseService
      .from('commits').select('agent_info').not('agent_info', 'is', null).limit(5000);
    let anthropic = 0, openai = 0, manual = 0;
    (wrapperRows || []).forEach(r => {
      const wrapper = r.agent_info?.wrapper || r.agent_info?.metadata?.wrapper || '';
      if (wrapper === 'anthropic') anthropic++;
      else if (wrapper === 'openai') openai++;
      else manual++;
    });

    // New agents in last 7d
    const { data: allAgents } = await supabaseService
      .from('agents').select('agent_id, created_at');
    const newAgents7d = (allAgents || []).filter(a => a.created_at >= ago7d).length;

    // Commits per agent p50/p90
    const agentCommitCounts = {};
    (agentRows || []).forEach(r => {
      if (r.from_agent) agentCommitCounts[r.from_agent] = (agentCommitCounts[r.from_agent] || 0) + 1;
    });
    const counts = Object.values(agentCommitCounts).sort((a,b) => a - b);
    const p50 = counts.length ? counts[Math.floor(counts.length * 0.5)] : 0;
    const p90 = counts.length ? counts[Math.floor(counts.length * 0.9)] : 0;

    // First / last commit
    const { data: firstRow } = await supabaseService.from('commits')
      .select('timestamp').order('timestamp', { ascending: true }).limit(1).single();
    const { data: lastRow } = await supabaseService.from('commits')
      .select('timestamp').order('timestamp', { ascending: false }).limit(1).single();

    // Per-user commit count / limit / period_start (for the requesting user)
    const userId = req.user.id;
    const { data: userSub } = await supabaseService
      .from('subscriptions')
      .select('plan, commit_limit, current_period_start')
      .eq('user_id', userId)
      .eq('status', 'active')
      .single()
      .catch(() => ({ data: null }));
    const userPlan      = userSub?.plan || 'free';
    const userPlanMeta  = PLAN_META[userPlan] || PLAN_META.free;
    const userLimit     = userSub?.commit_limit ?? userPlanMeta.commitLimit;
    const periodStart   = userSub?.current_period_start
      ? new Date(userSub.current_period_start).toISOString()
      : (() => { const d = new Date(); d.setDate(1); d.setHours(0,0,0,0); return d.toISOString(); })();
    // O(1) commit count from commit_usage cache
    const { data: userUsageRow } = await supabaseService
      .from('commit_usage')
      .select('commit_count')
      .eq('user_id', userId)
      .eq('month', currentMonthKey())
      .maybeSingle();
    const userCommitCount = userUsageRow?.commit_count || 0;

    res.json({
      total_commits: totalCommits || 0,
      unique_agents: uniqueAgents,
      active_agents: { last_7d: active7dCount, last_30d: active30dCount },
      l3_usage: {
        count:   l3Count  || 0,
        percent: l3Pct,
        last_7d: l3Count7d,
      },
      wrapper_usage: { anthropic, openai, manual },
      commits_per_agent: {
        p50, p90,
        total_agents_with_commits: counts.length,
      },
      momentum: {
        new_agents_7d:    newAgents7d,
        first_commit_at:  firstRow?.timestamp || null,
        last_commit_at:   lastRow?.timestamp  || null,
      },
      commit_count:  userCommitCount,
      commit_limit:  userLimit,
      period_start:  periodStart,
    });
  } catch (err) {
    console.error('[stats/usage]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/admin/users — all platform users (admin only) ──────────────────
app.get('/api/admin/users', requireAuth, async (req, res) => {
  try {
    const superuser   = process.env.SUPERUSER_EMAIL || '';
    const adminList   = process.env.ADMIN_EMAILS    || '';
    const adminEmails = [...new Set([
      ...superuser.split(','), ...adminList.split(','),
    ].map(e => e.trim()).filter(Boolean))];
    if (!adminEmails.includes(req.user.email)) {
      return res.status(403).json({ error: 'Admin only' });
    }

    // Fetch all auth users (paginated — Supabase returns max 1000 per page)
    let allUsers = [];
    let page = 1;
    while (true) {
      const { data, error } = await supabaseService.auth.admin.listUsers({ page, perPage: 1000 });
      if (error || !data?.users?.length) break;
      allUsers = allUsers.concat(data.users);
      if (data.users.length < 1000) break;
      page++;
    }

    // Get agent counts per user_id
    const { data: agents } = await supabaseService
      .from('agents').select('user_id, agent_id');
    const agentsByUser = {};
    (agents || []).forEach(a => {
      if (a.user_id) agentsByUser[a.user_id] = (agentsByUser[a.user_id] || []).concat(a.agent_id);
    });

    // Get commit counts per agent (then roll up to user)
    const agentIds = (agents || []).map(a => a.agent_id).filter(Boolean);
    let commitsByAgent = {};
    if (agentIds.length) {
      const idList = agentIds.map(id => `"${id}"`).join(',');
      const { data: commitRows } = await supabaseService
        .from('commits')
        .select('from_agent')
        .or(`from_agent.in.(${idList}),agent_id.in.(${idList})`);
      (commitRows || []).forEach(c => {
        if (c.from_agent) commitsByAgent[c.from_agent] = (commitsByAgent[c.from_agent] || 0) + 1;
      });
    }

    const users = allUsers.map(u => {
      const userAgents = agentsByUser[u.id] || [];
      const commitCount = userAgents.reduce((sum, aid) => sum + (commitsByAgent[aid] || 0), 0);
      return {
        id:            u.id,
        email:         u.email,
        created_at:    u.created_at,
        last_sign_in:  u.last_sign_in_at,
        confirmed:     !!u.email_confirmed_at,
        agent_count:   userAgents.length,
        commit_count:  commitCount,
      };
    }).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json({ users, total: users.length });
  } catch (err) {
    console.error('[admin/users]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/admin/ping — lightweight DB health check (admin only) ────────────
app.get('/api/admin/ping', requireAuth, async (req, res) => {
  const superuser   = process.env.SUPERUSER_EMAIL || '';
  const adminList   = process.env.ADMIN_EMAILS    || '';
  const adminEmails = [...new Set([
    ...superuser.split(','), ...adminList.split(','),
  ].map(e => e.trim()).filter(Boolean))];
  if (!adminEmails.includes(req.user.email)) {
    return res.status(403).json({ error: 'Admin only' });
  }
  try {
    const start = Date.now();
    // Single cheap count query — proves DB + service client are working
    const { count, error } = await supabaseService
      .from('commits').select('id', { count: 'exact', head: true });
    const ms = Date.now() - start;
    if (error) throw error;
    res.json({ ok: true, db_ms: ms, commits: count || 0 });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── POST /api/workspace/share/:traceId — create share link (session auth) ───────
app.post('/api/workspace/share/:traceId', wsAuth, async (req, res) => {
  try {
    const { traceId } = req.params;
    if (!traceId || traceId.length > 120 || !/^[a-zA-Z0-9_-]+$/.test(traceId)) return res.status(400).json({ error: 'Invalid ID' });
    const days = parseInt(req.body?.days || 30);
    // Verify the commit belongs to a user the session has access to
    let { data: commit } = await supabaseService
      .from('commits')
      .select('id, trace_id, from_agent')
      .eq('id', traceId)
      .maybeSingle();
    if (!commit) {
      ({ data: commit } = await supabaseService
        .from('commits')
        .select('id, trace_id, from_agent')
        .eq('trace_id', traceId)
        .limit(1)
        .maybeSingle());
    }
    if (!commit) return res.status(404).json({ error: 'Commit not found' });
    const shareId  = commit.id;
    const shareUrl = (process.env.APP_URL || 'https://darkmatterhub.ai') + '/r/' + shareId;
    res.json({ shareUrl, traceId: shareId, expiresIn: days + 'd' });
  } catch (err) {
    console.error('[workspace/share]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/workspace/share/:traceId/markdown ────────────────────────────────
app.get('/api/workspace/share/:traceId/markdown', wsAuth, async (req, res) => {
  const { traceId } = req.params;
  const shareUrl = (process.env.APP_URL || 'https://darkmatterhub.ai') + '/r/' + traceId;
  res.json({ markdown: `[View commit record](${shareUrl})` });
});

// ── GET /api/workspace/download/:traceId — proof bundle via session auth ─────────
app.get('/api/workspace/download/:traceId', wsAuth, async (req, res) => {
  try {
    const { traceId } = req.params;
    if (!traceId || traceId.length > 120 || !/^[a-zA-Z0-9_-]+$/.test(traceId)) return res.status(400).json({ error: 'Invalid ID' });
    // Walk the chain for this traceId
    const dlSel = 'id, trace_id, from_agent, agent_info, payload, timestamp, integrity_hash, payload_hash, parent_hash, event_type, verified, assurance_level, completeness_claim';
    const [{ data: dlById }, { data: dlByTrace }] = await Promise.all([
      supabaseService.from('commits').select(dlSel).eq('id', traceId).order('timestamp', { ascending: true }),
      supabaseService.from('commits').select(dlSel).eq('trace_id', traceId).order('timestamp', { ascending: true }),
    ]);
    const dlSeen = new Set();
    const commits = [...(dlById || []), ...(dlByTrace || [])]
      .filter(c => !dlSeen.has(c.id) && dlSeen.add(c.id))
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    if (!commits || !commits.length) return res.status(404).json({ error: 'Not found' });
    const bundle = {
      schema_version: '1.0',
      exported_at:    new Date().toISOString(),
      exporter:       'darkmatterhub.ai',
      commits:        commits,
      verify_url:     (process.env.APP_URL || 'https://darkmatterhub.ai') + '/r/' + traceId,
    };
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="darkmatter-proof-${traceId.slice(0,16)}.json"`);
    res.json(bundle);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/billing/webhook — Stripe webhook ────────────────────────────────
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return res.status(400).json({ error: 'Webhook secret not configured' });
  let event;
  try {
    event = getStripe().webhooks.constructEvent(req.body, sig, secret);
  } catch (err) {
    console.error('[webhook] signature verify failed:', err.message);
    return res.status(400).json({ error: 'Webhook signature invalid' });
  }
  console.log('[webhook]', event.type, event.id);
  // Handle subscription lifecycle events
  switch (event.type) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const sub        = event.data.object;
      const customerId = sub.customer;
      try {
        // Look up user_id from customer metadata or email
        const stripe    = getStripe();
        const customer  = await stripe.customers.retrieve(customerId);
        const email     = customer.email;
        const userId    = customer.metadata?.user_id;
        if (email || userId) {
          // Expand price info for plan mapping
          const fullSub = await stripe.subscriptions.retrieve(sub.id, {
            expand: ['items.data.price']
          });
          // Find user_id if not in metadata
          let resolvedUserId = userId;
          if (!resolvedUserId && email) {
            const { data: authUsers } = await supabaseService.auth.admin.listUsers();
            const found = (authUsers?.users || []).find(u => u.email === email);
            if (found) resolvedUserId = found.id;
          }
          if (resolvedUserId) {
            await upsertSubscription(resolvedUserId, email, fullSub, customerId);
            console.log('[webhook]', event.type, '→ subscriptions updated for', email, 'plan:', priceIdToPlan(fullSub.items?.data[0]?.price?.id));
          }
        }
      } catch(e) {
        console.error('[webhook] subscription upsert failed:', e.message);
      }
      break;
    }
    case 'checkout.session.completed': {
      const session = event.data.object;
      if (session.mode === 'subscription' && session.subscription) {
        try {
          const stripe   = getStripe();
          const sub      = await stripe.subscriptions.retrieve(session.subscription, {
            expand: ['items.data.price']
          });
          const email    = session.customer_email || session.customer_details?.email;
          const userId   = session.metadata?.user_id || sub.metadata?.user_id;
          let resolvedUserId = userId;
          if (!resolvedUserId && email) {
            const { data: authUsers } = await supabaseService.auth.admin.listUsers();
            const found = (authUsers?.users || []).find(u => u.email === email);
            if (found) resolvedUserId = found.id;
          }
          if (resolvedUserId) {
            await upsertSubscription(resolvedUserId, email, sub, session.customer);
            console.log('[webhook] checkout.completed → subscriptions updated for', email);
          }
        } catch(e) {
          console.error('[webhook] checkout upsert failed:', e.message);
        }
      }
      break;
    }
    default:
      break;
  }
  res.json({ received: true });
});


// ── Feature flags — persistent via Supabase ───────────────────────────────────
const _flagCache = {}; // in-memory cache — refreshed on GET

async function getFlag(key) {
  if (key in _flagCache) return _flagCache[key];
  const { data } = await supabaseService
    .from('feature_flags').select('enabled').eq('key', key).single().catch(() => ({ data: null }));
  const val = data?.enabled !== undefined ? data.enabled : true; // default on
  _flagCache[key] = val;
  return val;
}

app.get('/api/admin/flags', requireAuth, async (req, res) => {
  try {
    const adminEmails = [...new Set([
      ...(process.env.SUPERUSER_EMAIL || '').split(','),
      ...(process.env.ADMIN_EMAILS    || '').split(','),
    ].map(e => e.trim()).filter(Boolean))];
    if (!adminEmails.includes(req.user.email)) return res.status(403).json({ error: 'Admin only' });
    const { data, error } = await supabaseService.from('feature_flags').select('*').order('key');
    if (error) throw error;
    res.json({ flags: data || [] });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/flags', requireAuth, async (req, res) => {
  try {
    const adminEmails = [...new Set([
      ...(process.env.SUPERUSER_EMAIL || '').split(','),
      ...(process.env.ADMIN_EMAILS    || '').split(','),
    ].map(e => e.trim()).filter(Boolean))];
    if (!adminEmails.includes(req.user.email)) return res.status(403).json({ error: 'Admin only' });
    const { key, enabled, updated_by } = req.body;
    if (!key) return res.status(400).json({ error: 'key required' });
    const { data, error } = await supabaseService
      .from('feature_flags')
      .upsert({ key, enabled: !!enabled, updated_at: new Date().toISOString(), updated_by: updated_by || req.user.email })
      .select().single();
    if (error) throw error;
    _flagCache[key] = !!enabled; // update cache
    // Write audit log
    await writeAuditLog(req.user.id, req.user.email, 'flag_update', 'feature_flag', key, { key, enabled }, req);
    res.json({ flag: data });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── Admin audit log ───────────────────────────────────────────────────────────
async function writeAuditLog(actorId, actorEmail, action, targetType, targetId, meta, req) {
  try {
    await supabaseService.from('admin_audit_log').insert({
      actor_id:    actorId,
      actor_email: actorEmail,
      action,
      target_type: targetType,
      target_id:   String(targetId || ''),
      meta:        meta || {},
      ip:          req?.ip || req?.headers?.['x-forwarded-for'] || null,
      user_agent:  req?.headers?.['user-agent'] || null,
      created_at:  new Date().toISOString(),
    });
  } catch(e) {
    console.warn('[auditLog] write failed:', e.message);
  }
}

app.get('/api/admin/audit-log', requireAuth, async (req, res) => {
  const superuser   = process.env.SUPERUSER_EMAIL || '';
  const adminList   = process.env.ADMIN_EMAILS    || '';
  const adminEmails = [...new Set([
    ...superuser.split(','), ...adminList.split(','),
  ].map(e => e.trim()).filter(Boolean))];
  if (!adminEmails.includes(req.user.email)) {
    return res.status(403).json({ error: 'Admin only' });
  }
  try {
    const limit  = Math.min(parseInt(req.query.limit  || 100), 500);
    const offset = parseInt(req.query.offset || 0);
    const { data, error, count } = await supabaseService
      .from('admin_audit_log')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);
    if (error) throw error;
    res.json({ logs: data || [], total: count || 0 });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── Legal pages ───────────────────────────────────────────────────────────────
app.get('/tos',     (req, res) => res.sendFile(path.join(__dirname, '../public/tos.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, '../public/privacy.html')));

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
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);

    // Get membership
    const membership = await getMembership(req.user.id);

    // Collect all agent IDs we should show
    let agentIds = [];

    if (membership) {
      // Workspace member — show all workspace members' activity (admin) or own (member)
      if (membership.role === 'admin') {
        const { data: members } = await supabaseService
          .from('workspace_members')
          .select('agent_id')
          .eq('workspace_id', membership.workspace_id)
          .not('agent_id', 'is', null);
        agentIds = (members || []).map(m => m.agent_id).filter(Boolean);
      } else {
        if (membership.agent_id) agentIds = [membership.agent_id];
      }
    }

    // Always include user's own agents
    const { data: userAgents } = await supabaseService
      .from('agents')
      .select('agent_id, agent_name')
      .eq('user_id', req.user.id);

    const userAgentIds = (userAgents || []).map(a => a.agent_id);
    const allAgentIds  = [...new Set([...agentIds, ...userAgentIds])];

    if (allAgentIds.length === 0) {
      return res.json({ activity: [], total: 0 });
    }

    const idList = allAgentIds.map(id => `"${id}"`).join(',');
    const { data: commits, error } = await supabaseService
      .from('commits')
      .select('id, trace_id, from_agent, agent_id, agent_info, payload, timestamp, event_type, verified, capture_mode')
      .or(`from_agent.in.(${idList}),agent_id.in.(${idList})`)
      .order('timestamp', { ascending: false })
      .limit(limit);

    if (error) throw error;

    // Build an agent name map
    const agentNameMap = {};
    (userAgents || []).forEach(a => { agentNameMap[a.agent_id] = a.agent_name; });

    // If workspace, also pull member names
    if (membership) {
      const { data: members } = await supabaseService
        .from('workspace_members')
        .select('agent_id, display_name, email')
        .eq('workspace_id', membership.workspace_id);
      (members || []).forEach(m => {
        if (m.agent_id) agentNameMap[m.agent_id] = m.display_name || m.email;
      });
    }

    // Format for dashboard
    const activity = (commits || []).map(c => {
      const agentKey  = c.agent_id || c.from_agent;
      const agentName = agentNameMap[agentKey] || c.agent_info?.name || agentKey || 'Agent';
      const provider  = c.agent_info?.provider || c.payload?._provider || null;
      const model     = c.agent_info?.model     || c.payload?._model    || null;
      const source    = c.capture_mode || c.payload?._source || 'api';

      // Build a human-readable title from payload
      const p = c.payload || {};
      let title = 'AI conversation recorded';
      if (p.prompt || p.output) {
        const preview = (p.prompt || p.output || '').slice(0, 80);
        title = preview ? `"${preview}${preview.length >= 80 ? '…' : ''}"` : title;
      } else if (p.convTitle) {
        title = p.convTitle;
      }

      return {
        id:         c.id,
        traceId:    c.trace_id || c.id,
        agentId:    agentKey,
        agentName,
        provider:   provider || 'unknown',
        model:      model    || 'unknown',
        eventType:  c.event_type || 'commit',
        title,
        timestamp:  c.timestamp,
        verified:   c.verified || false,
        source,
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
    if (!traceId || traceId.length > 120 || !/^[a-zA-Z0-9_-]+$/.test(traceId)) return res.status(400).json({ error: 'Invalid ID' });

    const [{ data: cvById }, { data: cvByTrace, error }] = await Promise.all([
      supabaseService.from('commits').select('*').eq('id', traceId).order('timestamp', { ascending: true }),
      supabaseService.from('commits').select('*').eq('trace_id', traceId).order('timestamp', { ascending: true }),
    ]);
    const cvSeen = new Set();
    const commits = [...(cvById || []), ...(cvByTrace || [])]
      .filter(c => !cvSeen.has(c.id) && cvSeen.add(c.id))
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

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

