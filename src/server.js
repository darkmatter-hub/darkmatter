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
// ─────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { agentName } = req.body;
    if (!agentName) return res.status(400).json({ error: 'agentName required' });

    const keypair = generateAgentKeypair(agentName);
    await registerAgent({
      agentId: keypair.agentId,
      agentName: keypair.agentName,
      publicKey: keypair.publicKey,
    });

    res.json({
      agentId: keypair.agentId,
      agentName: keypair.agentName,
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey,
      note: 'Store your privateKey securely — DarkMatter never sees it again',
    });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// POST /api/commit
// ─────────────────────────────────────────────
app.post('/api/commit', async (req, res) => {
  try {
    const { fromAgentId, toAgentId, context, privateKey } = req.body;

    if (!fromAgentId || !toAgentId || !context || !privateKey) {
      return res.status(400).json({ error: 'fromAgentId, toAgentId, context, and privateKey required' });
    }

    const fromAgent = await getAgent(fromAgentId);
    const toAgent = await getAgent(toAgentId);
    if (!fromAgent) return res.status(404).json({ error: `Agent ${fromAgentId} not registered` });
    if (!toAgent) return res.status(404).json({ error: `Agent ${toAgentId} not registered` });

    const signedPackage = signContext(context, fromAgentId, toAgentId, privateKey);
    const verification = verifyContext(signedPackage, fromAgent.publicKey);
    const commit = await saveCommit(signedPackage, verification);

    res.json({
      commitId: commit.id,
      from: fromAgent.agentName,
      to: toAgent.agentName,
      verified: verification.valid,
      reason: verification.reason,
      timestamp: commit.timestamp,
    });
  } catch (err) {
    console.error('commit error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /api/pull/:agentId
// ─────────────────────────────────────────────
app.get('/api/pull/:agentId', async (req, res) => {
  try {
    const { agentId } = req.params;

    const agent = await getAgent(agentId);
    if (!agent) return res.status(404).json({ error: `Agent ${agentId} not registered` });

    const commits = await getCommitsForAgent(agentId);

    const results = commits.map(commit => ({
      commitId: commit.id,
      from: commit.from,
      fromId: commit.from,
      context: commit.context,
      timestamp: commit.timestamp,
      verified: commit.verified,
    }));

    res.json({
      agentId,
      agentName: agent.agentName,
      commits: results,
      count: results.length,
    });
  } catch (err) {
    console.error('pull error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /api/agents
// ─────────────────────────────────────────────
app.get('/api/agents', async (req, res) => {
  try {
    const agents = await getAllAgents();
    // Strip names from public endpoint — only expose agentId and registeredAt
    const sanitized = agents.map(a => ({
      agentId: a.agentId,
      registeredAt: a.registeredAt,
    }));
    res.json(sanitized);
  } catch (err) {
    console.error('agents error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /api/commits
// ─────────────────────────────────────────────
app.get('/api/commits', async (req, res) => {
  try {
    const all = await getAllCommits();
    res.json(all);
  } catch (err) {
    console.error('commits error:', err);
    res.status(500).json({ error: err.message });
  }
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
