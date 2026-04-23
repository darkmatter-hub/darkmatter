/**
 * DarkMatter Stripe billing — 4 tiers
 * ─────────────────────────────────────
 * Free       $0    500 commits/month   30-day retention
 * Pro        $19   2,000/month         90-day retention + share links
 * Teams      $49   10,000/month        Unlimited retention + audit reports
 * Enterprise $199  Unlimited           All features, unlimited commits + retention
 */
'use strict';

// All plans include every feature. Only commits/month and retention differ.
const ALL_FEATURES = [
  'SHA-256 hash chain (L1)',
  'Bitcoin anchoring (L2)',
  'Share links',
  'Export proof bundles',
  'Verify independently',
  'API access',
  'Dashboard',
];

const PLANS = {
  free: {
    name: 'Free', price: 0,
    commitsPerMonth: 500, retentionDays: 30,
    features: ALL_FEATURES,
  },
  pro: {
    name: 'Pro', price: 19,
    commitsPerMonth: 2000, retentionDays: 90,
    features: ALL_FEATURES,
  },
  teams: {
    name: 'Teams', price: 49,
    commitsPerMonth: 10000, retentionDays: null,
    features: ALL_FEATURES,
  },
  enterprise: {
    name: 'Enterprise', price: 199,
    commitsPerMonth: null, retentionDays: null,
    features: ALL_FEATURES,
  },
};

function getStripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) return null;
  // lazy-require so server starts without stripe installed
  try { return require('stripe')(key); } catch(e) { return null; }
}

function planFromPriceId(priceId) {
  if (!priceId) return 'free';
  if (priceId === process.env.STRIPE_PRICE_PRO)        return 'pro';
  if (priceId === process.env.STRIPE_PRICE_TEAMS)      return 'teams';
  if (priceId === process.env.STRIPE_PRICE_ENTERPRISE) return 'enterprise';
  return 'pro';
}

// ── Mount all billing routes ──────────────────────────────────────────────────
function mountBillingRoutes(app, supabaseService, requireAuth) {
  const express = require('express');

  // Webhook MUST be registered BEFORE express.json() in the caller.
  // We register it here with its own raw-body parser.
  app.post('/api/billing/webhook',
    express.raw({ type: 'application/json' }),
    async (req, res) => {
      const sig    = req.headers['stripe-signature'];
      const secret = process.env.STRIPE_WEBHOOK_SECRET;
      const stripe = getStripe();
      if (!stripe || !secret) return res.sendStatus(200);
      let event;
      try { event = stripe.webhooks.constructEvent(req.body, sig, secret); }
      catch(e) { return res.status(400).send(`Webhook Error: ${e.message}`); }
      try { await handleStripeEvent(event, supabaseService); } catch(e) {
        console.error('[webhook] handler error:', e.message);
      }
      res.sendStatus(200);
    }
  );

  // GET /api/billing/plans — public
  app.get('/api/billing/plans', (req, res) => res.json({ plans: PLANS }));

  // GET /api/billing/subscription — current plan + usage
  app.get('/api/billing/subscription', requireAuth, async (req, res) => {
    try {
      const userId = req.user.id;
      const { data: sub } = await supabaseService
        .from('subscriptions').select('*').eq('user_id', userId).single();
      const month = new Date().toISOString().slice(0, 7);
      const { data: usage } = await supabaseService
        .from('commit_usage').select('commit_count')
        .eq('user_id', userId).eq('month', month).single();

      const plan     = (sub?.status === 'active' || sub?.status === 'trialing') ? (sub?.plan || 'free') : 'free';
      const planInfo = PLANS[plan] || PLANS.free;
      const count    = usage?.commit_count || 0;
      const limit    = planInfo.commitsPerMonth;

      res.json({
        plan, planInfo, status: sub?.status || 'active',
        commitCount: count, commitLimit: limit,
        commitsRemaining: limit ? Math.max(0, limit - count) : null,
        currentPeriodEnd: sub?.current_period_end || null,
        cancelAtPeriodEnd: sub?.cancel_at_period_end || false,
      });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });

  // POST /api/billing/checkout — create Stripe Checkout session
  app.post('/api/billing/checkout', requireAuth, async (req, res) => {
    try {
      const stripe = getStripe();
      if (!stripe) return res.status(503).json({ error: 'Billing not configured. Add STRIPE_SECRET_KEY to Railway env vars.' });

      const { plan } = req.body;
      if (!['pro','teams','enterprise'].includes(plan))
        return res.status(400).json({ error: 'Invalid plan.' });

      const priceEnvMap = { pro: 'STRIPE_PRICE_PRO', teams: 'STRIPE_PRICE_TEAMS', enterprise: 'STRIPE_PRICE_ENTERPRISE' };
      const priceId = process.env[priceEnvMap[plan]];
      if (!priceId) return res.status(503).json({
        error: `${priceEnvMap[plan]} not set in Railway env vars. Create a product in Stripe Dashboard first.`
      });

      const userId  = req.user.id;
      const email   = req.user.email;
      const baseUrl = process.env.APP_URL || 'https://darkmatterhub.ai';

      // Find or create Stripe customer
      const { data: existingSub } = await supabaseService
        .from('subscriptions').select('stripe_customer_id').eq('user_id', userId).single();

      let customerId = existingSub?.stripe_customer_id;
      if (!customerId) {
        const customer = await stripe.customers.create({
          email, metadata: { darkmatter_user_id: userId },
        });
        customerId = customer.id;
      }

      const session = await stripe.checkout.sessions.create({
        customer: customerId, mode: 'subscription',
        payment_method_types: ['card'],
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: `${baseUrl}/dashboard?billing=success&plan=${plan}`,
        cancel_url:  `${baseUrl}/dashboard?billing=canceled`,
        metadata: { darkmatter_user_id: userId, plan },
        subscription_data: { metadata: { darkmatter_user_id: userId, plan } },
      });

      res.json({ url: session.url });
    } catch(e) { console.error('[checkout]', e.message); res.status(500).json({ error: e.message }); }
  });

  // POST /api/billing/portal — Stripe Customer Portal
  app.post('/api/billing/portal', requireAuth, async (req, res) => {
    try {
      const stripe = getStripe();
      if (!stripe) return res.status(503).json({ error: 'Billing not configured.' });
      const { data: sub } = await supabaseService
        .from('subscriptions').select('stripe_customer_id').eq('user_id', req.user.id).single();
      if (!sub?.stripe_customer_id)
        return res.status(400).json({ error: 'No billing account. Subscribe first.' });
      const baseUrl = process.env.APP_URL || 'https://darkmatterhub.ai';
      const session = await stripe.billingPortal.sessions.create({
        customer: sub.stripe_customer_id, return_url: `${baseUrl}/dashboard`,
      });
      res.json({ url: session.url });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });
}

// ── Stripe webhook event handler ──────────────────────────────────────────────
async function handleStripeEvent(event, db) {
  const { type, data } = event;
  console.log('[stripe]', type);

  if (type === 'checkout.session.completed') {
    const s = data.object;
    if (s.mode !== 'subscription') return;
    const userId   = s.metadata?.darkmatter_user_id;
    const plan     = s.metadata?.plan || 'pro';
    if (!userId) return;
    const stripe = getStripe();
    const stripeSub = await stripe.subscriptions.retrieve(s.subscription);
    await db.from('subscriptions').upsert({
      id: s.subscription, user_id: userId,
      stripe_customer_id: s.customer, plan, status: stripeSub.status,
      current_period_start: new Date(stripeSub.current_period_start * 1000).toISOString(),
      current_period_end:   new Date(stripeSub.current_period_end   * 1000).toISOString(),
      stripe_price_id: stripeSub.items.data[0]?.price?.id,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id' });
  }

  if (type === 'customer.subscription.updated') {
    const s = data.object;
    const plan = s.metadata?.plan || planFromPriceId(s.items.data[0]?.price?.id);
    await db.from('subscriptions').upsert({
      id: s.id, stripe_customer_id: s.customer,
      plan: s.cancel_at_period_end ? plan : plan,
      status: s.status,
      current_period_start: new Date(s.current_period_start * 1000).toISOString(),
      current_period_end:   new Date(s.current_period_end   * 1000).toISOString(),
      cancel_at_period_end: s.cancel_at_period_end,
      stripe_price_id: s.items.data[0]?.price?.id,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'id' });
  }

  if (type === 'customer.subscription.deleted') {
    const s = data.object;
    await db.from('subscriptions').upsert({
      id: s.id, stripe_customer_id: s.customer,
      plan: 'free', status: 'canceled', cancel_at_period_end: false,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'id' });
  }

  if (type === 'invoice.payment_failed') {
    await db.from('subscriptions')
      .update({ status: 'past_due', updated_at: new Date().toISOString() })
      .eq('stripe_customer_id', data.object.customer);
  }

  if (type === 'invoice.paid') {
    await db.from('subscriptions')
      .update({ status: 'active', updated_at: new Date().toISOString() })
      .eq('stripe_customer_id', data.object.customer);
  }
}

// ── Commit limit check — call BEFORE writing commit ───────────────────────────
async function checkCommitLimit(userId, db) {
  if (!userId) return { allowed: true, plan: 'free', remaining: null };
  const { data: sub } = await db
    .from('subscriptions').select('plan, status').eq('user_id', userId).single();
  const plan     = (sub?.status === 'active' || sub?.status === 'trialing') ? (sub?.plan || 'free') : 'free';
  const planInfo = PLANS[plan] || PLANS.free;
  if (!planInfo.commitsPerMonth) return { allowed: true, plan, remaining: null };

  const month = new Date().toISOString().slice(0, 7);
  const { data: usage } = await db
    .from('commit_usage').select('commit_count').eq('user_id', userId).eq('month', month).single();
  const count = usage?.commit_count || 0;

  if (count >= planInfo.commitsPerMonth) {
    return {
      allowed: false, plan, remaining: 0, limit: planInfo.commitsPerMonth,
      error: `Monthly commit limit reached (${planInfo.commitsPerMonth} on ${planInfo.name} plan). Upgrade at darkmatterhub.ai/dashboard`,
    };
  }
  return { allowed: true, plan, remaining: planInfo.commitsPerMonth - count };
}

// ── Increment usage counter — call AFTER successful commit write ──────────────
async function incrementCommitUsage(userId, db) {
  if (!userId) return;
  const month = new Date().toISOString().slice(0, 7);
  try {
    const { data: existing } = await db
      .from('commit_usage').select('commit_count').eq('user_id', userId).eq('month', month).single();
    if (existing) {
      await db.from('commit_usage')
        .update({ commit_count: existing.commit_count + 1, updated_at: new Date().toISOString() })
        .eq('user_id', userId).eq('month', month);
    } else {
      await db.from('commit_usage').insert({ user_id: userId, month, commit_count: 1 });
    }
  } catch(e) { console.error('[usage]', e.message); }
}

module.exports = { mountBillingRoutes, checkCommitLimit, incrementCommitUsage, PLANS };
