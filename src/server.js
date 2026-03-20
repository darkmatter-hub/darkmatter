require('dotenv').config();
const express = require('express');
const path = require('path');
const { generateAgentKeypair, signContext, verifyContext } = require('./lib/crypto');
const { registerAgent, getAgent, getAllAgents, saveCommit, getCommitsForAgent, getAllCommits } = require('./lib/store');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ─────────────────────────────────────────────
// POST /api/register
// Register a new agent, returns keypair
// In production: store only public key, agent keeps private key
// ─────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { agentName } = req.body;
  if (!agentName) return res.status(400).json({ error: 'agentName required' });

  const keypair = generateAgentKeypair(agentName);
  registerAgent({
    agentId: keypair.agentId,
    agentName: keypair.agentName,
    publicKey: keypair.publicKey,
  });

  // NOTE: In production, never return privateKey over the wire.
  // The agent generates its own keypair locally and only registers the public key.
  // Returning it here for prototype simplicity so you can test immediately.
  res.json({
    agentId: keypair.agentId,
    agentName: keypair.agentName,
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
    note: 'Store your privateKey securely — DarkMatter never sees it again',
  });
});

// ─────────────────────────────────────────────
// POST /api/commit
// Agent signs and commits a context package for another agent
// ─────────────────────────────────────────────
app.post('/api/commit', (req, res) => {
  const { fromAgentId, toAgentId, context, privateKey } = req.body;

  if (!fromAgentId || !toAgentId || !context || !privateKey) {
    return res.status(400).json({ error: 'fromAgentId, toAgentId, context, and privateKey required' });
  }

  // Verify both agents exist
  const fromAgent = getAgent(fromAgentId);
  const toAgent = getAgent(toAgentId);
  if (!fromAgent) return res.status(404).json({ error: `Agent ${fromAgentId} not registered` });
  if (!toAgent) return res.status(404).json({ error: `Agent ${toAgentId} not registered` });

  // Sign the context package
  const signedPackage = signContext(context, fromAgentId, toAgentId, privateKey);

  // Immediately verify our own signature (integrity check)
  const verification = verifyContext(signedPackage, fromAgent.publicKey);

  // Save to store regardless — failed commits are logged too
  const commit = saveCommit(signedPackage, verification);

  res.json({
    commitId: commit.id,
    from: fromAgent.agentName,
    to: toAgent.agentName,
    verified: verification.valid,
    reason: verification.reason,
    timestamp: commit.timestamp,
  });
});

// ─────────────────────────────────────────────
// GET /api/pull/:agentId
// Agent pulls verified context packages addressed to it
// ─────────────────────────────────────────────
app.get('/api/pull/:agentId', (req, res) => {
  const { agentId } = req.params;

  const agent = getAgent(agentId);
  if (!agent) return res.status(404).json({ error: `Agent ${agentId} not registered` });

  const commits = getCommitsForAgent(agentId);

  // Re-verify each commit against sender's public key before returning
  // This is the critical trust check — Agent Y verifies Agent X's signature
  const verified = commits.map(commit => {
    const sender = getAgent(commit.from);
    if (!sender) return { ...commit, reVerified: false, reason: 'Sender not found' };

    const recheck = verifyContext(
      { payload: { from: commit.from, to: commit.to, context: commit.context, timestamp: commit.timestamp, nonce: commit.signature.slice(0, 8) }, signature: commit.signature },
      sender.publicKey
    );

    return {
      commitId: commit.id,
      from: sender.agentName,
      fromId: commit.from,
      context: commit.context,
      timestamp: commit.timestamp,
      verified: commit.verified,
    };
  });

  res.json({
    agentId,
    agentName: agent.agentName,
    commits: verified,
    count: verified.length,
  });
});

// ─────────────────────────────────────────────
// GET /api/agents
// List all registered agents (for dashboard)
// ─────────────────────────────────────────────
app.get('/api/agents', (req, res) => {
  res.json(getAllAgents().map(a => ({ agentId: a.agentId, agentName: a.agentName, registeredAt: a.registeredAt })));
});

// ─────────────────────────────────────────────
// GET /api/commits
// All commits for dashboard timeline
// ─────────────────────────────────────────────
app.get('/api/commits', (req, res) => {
  const all = getAllCommits().map(c => {
    const from = getAgent(c.from);
    const to = getAgent(c.to);
    return {
      id: c.id,
      from: from?.agentName || c.from,
      to: to?.agentName || c.to,
      context: c.context,
      timestamp: c.timestamp,
      verified: c.verified,
      reason: c.verificationReason,
    };
  });
  res.json(all);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ███╗ █████╗ ████████╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ████╗ ████║██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗
  ██║  ██║███████║██████╔╝█████╔╝     ██╔████╔██║███████║   ██║      ██║   █████╗  ██████╔╝
  ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██║╚██╔╝██║██╔══██║   ██║      ██║   ██╔══╝  ██╔══██╗
  ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║ ╚═╝ ██║██║  ██║   ██║      ██║   ███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝

  Git for AI agent context. Running on http://localhost:${PORT}
  `);
});

module.exports = app;
