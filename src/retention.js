/**
 * Retention enforcement.
 *
 * The pricing page has always said free-tier records are deleted after 30 days,
 * and the terms said records are kept permanently, and neither happened: there
 * was no purge anywhere in the codebase, no scheduled job, nothing in
 * migrations. Records were kept indefinitely while users were told otherwise.
 *
 * What this deletes, and what it deliberately does not
 * ----------------------------------------------------
 * It nulls the payload. It does not delete the row.
 *
 * Deleting rows would be the obvious reading of "records are deleted", and it
 * would be wrong. Every record commits to the hash of the one before it, so
 * removing a row from the middle of a chain breaks verification for everything
 * after it. A retention policy that silently invalidates a customer's evidence
 * is worse than no retention policy.
 *
 * Nulling the payload removes the content, which is the part that is personal
 * data and the part a retention promise is actually about, while leaving the
 * hashes that prove the record existed and has not been altered. A verifier
 * then reports payload_hash_verified as null, meaning "cannot check this one",
 * rather than false, meaning "this one is broken". The chain stays intact and
 * the redaction is visible rather than silent.
 *
 * Whose records expire
 * --------------------
 * Retention resolves per agent: the agent's own retention_days if set,
 * otherwise the subscription's, otherwise the plan default. A null retention at
 * any of those levels means keep forever, which is what the paid tiers sell.
 */

'use strict';

// A cap per run, so a misconfiguration cannot empty the table in one pass and
// so a run stays inside a sensible transaction footprint.
const MAX_PER_RUN = 500;

/**
 * Work out how many days each agent's records are kept for.
 * Returns a Map of agent_id -> days, omitting agents that keep records forever.
 */
async function resolveRetention(supabase, planMeta) {
  const { data: agents, error: aErr } = await supabase
    .from('agents')
    .select('agent_id, user_id, retention_days');
  if (aErr) throw new Error('agents lookup failed: ' + aErr.message);

  const userIds = [...new Set((agents || []).map(a => a.user_id).filter(Boolean))];
  const subsByUser = new Map();
  if (userIds.length) {
    const { data: subs } = await supabase
      .from('subscriptions')
      .select('user_id, plan, retention_days')
      .in('user_id', userIds);
    for (const s of subs || []) subsByUser.set(s.user_id, s);
  }

  const out = new Map();
  for (const a of agents || []) {
    let days = a.retention_days;

    if (days === null || days === undefined) {
      const sub = subsByUser.get(a.user_id);
      if (sub) {
        days = sub.retention_days;
        if (days === null || days === undefined) {
          const meta = planMeta[sub.plan];
          days = meta ? meta.retentionDays : undefined;
        }
      } else {
        // No subscription row means the free tier.
        days = planMeta.free ? planMeta.free.retentionDays : 30;
      }
    }

    // null here is a deliberate "keep forever" on the paid tiers, so it is the
    // one case that must not fall through to a default.
    if (typeof days === 'number' && days > 0) out.set(a.agent_id, days);
  }
  return out;
}

/**
 * Redact payloads past their retention window.
 *
 * @param {object} supabase   service-role client
 * @param {object} planMeta   PLAN_META from server.js
 * @param {object} [opts]
 * @param {boolean} [opts.dryRun]  report what would be redacted, change nothing
 * @returns {{redacted:number, scanned:number, dryRun:boolean, byAgent:object}}
 */
async function enforceRetention(supabase, planMeta, opts = {}) {
  const dryRun = !!opts.dryRun;
  const retention = await resolveRetention(supabase, planMeta);
  if (!retention.size) return { redacted: 0, scanned: 0, dryRun, byAgent: {} };

  let redacted = 0, scanned = 0;
  const byAgent = {};

  for (const [agentId, days] of retention) {
    const cutoff = new Date(Date.now() - days * 86400000).toISOString();

    // Only rows that still have a payload. Already-redacted rows must not be
    // counted again, or every run would report work it did not do.
    const { data: expired, error } = await supabase
      .from('commits')
      .select('id')
      .eq('agent_id', agentId)
      .lt('timestamp', cutoff)
      .not('payload', 'is', null)
      .limit(MAX_PER_RUN);

    if (error) {
      console.error('[retention] lookup failed for', agentId, error.message);
      continue;
    }
    if (!expired || !expired.length) continue;

    scanned += expired.length;
    byAgent[agentId] = { days, expired: expired.length };

    if (dryRun) continue;

    const ids = expired.map(r => r.id);
    const { error: upErr } = await supabase
      .from('commits')
      // Hashes, links and log position are left alone on purpose: they are what
      // keeps the chain verifiable once the content is gone.
      .update({ payload: null, context: null, encrypted_payload: null })
      .in('id', ids);

    if (upErr) {
      console.error('[retention] redaction failed for', agentId, upErr.message);
      continue;
    }
    redacted += ids.length;
    byAgent[agentId].redacted = ids.length;
  }

  return { redacted, scanned, dryRun, byAgent };
}

/**
 * Run it on a schedule. Off if RETENTION_DISABLED=true; reports without
 * changing anything if RETENTION_DRY_RUN=true.
 */
function startRetentionScheduler(supabase, planMeta, intervalMs = 6 * 3600 * 1000) {
  if (process.env.RETENTION_DISABLED === 'true') {
    console.log('[retention] disabled by RETENTION_DISABLED');
    return { started: false, reason: 'disabled' };
  }
  const dryRun = process.env.RETENTION_DRY_RUN === 'true';

  const run = async () => {
    try {
      const r = await enforceRetention(supabase, planMeta, { dryRun });
      if (r.scanned) {
        console.log('[retention] %s %d payload(s) past their window across %d agent(s)',
          r.dryRun ? 'would redact' : 'redacted', r.dryRun ? r.scanned : r.redacted,
          Object.keys(r.byAgent).length);
      }
    } catch (e) {
      console.error('[retention] run failed:', e.message);
    }
  };

  setTimeout(run, 30000);              // after boot settles
  const t = setInterval(run, intervalMs);
  if (t.unref) t.unref();
  console.log('[retention] enabled, every %dh%s',
    intervalMs / 3600000, dryRun ? ' (dry run)' : '');
  return { started: true, dryRun };
}

module.exports = { enforceRetention, resolveRetention, startRetentionScheduler, MAX_PER_RUN };
