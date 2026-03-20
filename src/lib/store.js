/**
 * Supabase production store
 * Drop-in replacement for store.js
 *
 * To use: rename this file to store.js (replacing the in-memory version)
 * Requires: npm install @supabase/supabase-js
 * Requires: SUPABASE_URL and SUPABASE_KEY in your environment
 */

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

async function registerAgent({ agentId, agentName, publicKey }) {
  const { data, error } = await supabase
    .from('agents')
    .upsert({ agent_id: agentId, agent_name: agentName, public_key: publicKey })
    .select()
    .single();

  if (error) throw new Error(`registerAgent failed: ${error.message}`);
  return { agentId: data.agent_id, agentName: data.agent_name, publicKey: data.public_key, registeredAt: data.registered_at };
}

async function getAgent(agentId) {
  const { data, error } = await supabase
    .from('agents')
    .select('*')
    .eq('agent_id', agentId)
    .single();

  if (error || !data) return null;
  return { agentId: data.agent_id, agentName: data.agent_name, publicKey: data.public_key, registeredAt: data.registered_at };
}

async function getAllAgents() {
  const { data, error } = await supabase
    .from('agents')
    .select('agent_id, agent_name, registered_at')
    .order('registered_at', { ascending: false });

  if (error) throw new Error(`getAllAgents failed: ${error.message}`);
  return data.map(a => ({ agentId: a.agent_id, agentName: a.agent_name, registeredAt: a.registered_at }));
}

async function saveCommit(signedPackage, verification) {
  const id = `commit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const { data, error } = await supabase
    .from('commits')
    .insert({
      id,
      from_agent:           signedPackage.payload.from,
      to_agent:             signedPackage.payload.to,
      context:              signedPackage.payload.context,
      signature:            signedPackage.signature,
      verified:             verification.valid,
      verification_reason:  verification.reason,
      timestamp:            signedPackage.payload.timestamp,
    })
    .select()
    .single();

  if (error) throw new Error(`saveCommit failed: ${error.message}`);
  return {
    id: data.id,
    from: data.from_agent,
    to: data.to_agent,
    context: data.context,
    timestamp: data.timestamp,
    signature: data.signature,
    verified: data.verified,
    verificationReason: data.verification_reason,
    savedAt: data.saved_at,
  };
}

async function getCommitsForAgent(agentId) {
  const { data, error } = await supabase
    .from('commits')
    .select('*')
    .eq('to_agent', agentId)
    .eq('verified', true)
    .order('timestamp', { ascending: false });

  if (error) throw new Error(`getCommitsForAgent failed: ${error.message}`);
  return data.map(c => ({
    id: c.id, from: c.from_agent, to: c.to_agent,
    context: c.context, timestamp: c.timestamp,
    signature: c.signature, verified: c.verified,
    verificationReason: c.verification_reason,
  }));
}

async function getAllCommits() {
  const { data, error } = await supabase
    .from('commits')
    .select(`
      id, context, signature, verified, verification_reason, timestamp,
      from_agent, to_agent
    `)
    .order('timestamp', { ascending: false })
    .limit(100);

  if (error) throw new Error(`getAllCommits failed: ${error.message}`);
  return data.map(c => ({
    id: c.id, from: c.from_agent, to: c.to_agent,
    context: c.context, timestamp: c.timestamp,
    verified: c.verified, verificationReason: c.verification_reason,
  }));
}

module.exports = { registerAgent, getAgent, getAllAgents, saveCommit, getCommitsForAgent, getAllCommits };
