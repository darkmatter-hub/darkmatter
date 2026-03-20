/**
 * In-memory store — replace with Supabase or Postgres in production
 * This is intentionally simple for the prototype
 */

const agents = new Map();   // agentId → { agentId, agentName, publicKey }
const commits = [];         // array of signed commit records

function registerAgent({ agentId, agentName, publicKey }) {
  agents.set(agentId, { agentId, agentName, publicKey, registeredAt: new Date().toISOString() });
  return agents.get(agentId);
}

function getAgent(agentId) {
  return agents.get(agentId) || null;
}

function getAllAgents() {
  return Array.from(agents.values());
}

function saveCommit(signedPackage, verification) {
  const commit = {
    id: `commit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    from: signedPackage.payload.from,
    to: signedPackage.payload.to,
    context: signedPackage.payload.context,
    timestamp: signedPackage.payload.timestamp,
    signature: signedPackage.signature,
    verified: verification.valid,
    verificationReason: verification.reason,
    savedAt: new Date().toISOString(),
  };
  commits.push(commit);
  return commit;
}

function getCommitsForAgent(agentId) {
  return commits.filter(c => c.to === agentId && c.verified);
}

function getAllCommits() {
  return [...commits].reverse(); // most recent first
}

module.exports = { registerAgent, getAgent, getAllAgents, saveCommit, getCommitsForAgent, getAllCommits };
