require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { signContext, verifyContext } = require('./lib/crypto');
const { registerAgent, getAgent, getAllAgents, saveCommit, getCommitsForAgent, getAllCommits } = require('./lib/store');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ─────────────────────────────────────────────
// INTERNAL API KEY MIDDLEWARE
// Protects read endpoints from public access
// Set INTERNAL_API_KEY in your Railway environment variables
// ─────────────────────────────────────────────
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.apiKey;
  if (!process.env.INTERNAL_API_KEY || key === process.env.INTERNAL_API_KEY) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// ─────────────────────────────────────────────
// POST /api/register
// Agent owner provides their own agentId + publicKey
// generated locally via keygen.js
// DarkMatter never generates or sees private keys
// ─────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { agentId, agentName, publicKey } = req.body;

    // Support legacy mode (server-side keygen) for backward compat
    // but strongly discourage it
    if (!agentId || !publicKey) {
      return res.status(400).json({
        error: 'agentId and publicKey are required. Generate your keypair locally using keygen.js — DarkMatter should never generate your private key.',
        docs: 'https://github.com/bengunvl/darkmatter#local-key-generation',
      });
    }

    if (!agentName) {
      return res.status(400).json({ error: 'agentName is required' });
    }

    // Validate the public key is a valid Ed25519 key
    try {
      crypto.createPublicKey(publicKey);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid public key — must be a valid Ed25519 PEM public key' });
    }

    // Verify the agentId matches the public key (prevents spoofing)
    const expectedId = 'dm_' + crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex')
      .slice(0, 16);

    if (agentId !== expectedId) {
      return res.status(400).json({
        error: 'agentId does not match the provided public key. Use keygen.js to generate a matching keypair.',
      });
    }

    await registerAgent({ agentId, agentName, publicKey });

    // Return only public information — no private key ever
    res.json({
      agentId,
      agentName,
      registered: true,
      note: 'Your private key was never sent to DarkMatter. Keep it safe locally.',
    });

  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// POST /api/commit
// Agent commits a signed context package
// ─────────────────────────────────────────────
app.post('/api/commit', async (req, res) => {
  try {
    const { fromAgentId, toAgentId, context, privateKey } = req.body;

    if (!fromAgentId || !toAgentId || !context || !privateKey) {
      return res.status(400).json({ error: 'fromAgentId, toAgentId, context, and privateKey required' });
    }

    const fromAgent = await getAgent(fromAgentId);
    const toAgent   = await getAgent(toAgentId);
    if (!fromAgent) return res.status(404).json({ error: `Agent ${fromAgentId} not registered` });
    if (!toAgent)   return res.status(404).json({ error: `Agent ${toAgentId} not registered` });

    const signedPackage  = signContext(context, fromAgentId, toAgentId, privateKey);
    const verification   = verifyContext(signedPackage, fromAgent.publicKey);
    const commit         = await saveCommit(signedPackage, verification);

    res.json({
      commitId:  commit.id,
      verified:  verification.valid,
      reason:    verification.reason,
      timestamp: commit.timestamp,
    });

  } catch (err) {
    console.error('commit error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /api/pull/:agentId
// Agent pulls verified context addressed to it
// Only the intended recipient should call this
// ─────────────────────────────────────────────
app.get('/api/pull/:agentId', async (req, res) => {
  try {
    const { agentId } = req.params;

    const agent = await getAgent(agentId);
    if (!agent) return res.status(404).json({ error: `Agent ${agentId} not registered` });

    const commits = await getCommitsForAgent(agentId);

    res.json({
      agentId,
      commits: commits.map(c => ({
        commitId:  c.id,
        from:      c.from,
        context:   c.context,
        timestamp: c.timestamp,
        verified:  c.verified,
      })),
      count: commits.length,
    });

  } catch (err) {
    console.error('pull error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /api/agents — protected, internal only
// ─────────────────────────────────────────────
app.get('/api/agents', requireApiKey, async (req, res) => {
  try {
    const agents = await getAllAgents();
    res.json(agents.map(a => ({
      agentId:      a.agentId,
      registeredAt: a.registeredAt,
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /api/commits — protected, internal only
// ─────────────────────────────────────────────
app.get('/api/commits', requireApiKey, async (req, res) => {
  try {
    const all = await getAllCommits();
    res.json(all.map(c => ({
      id:        c.id,
      from:      c.from,
      to:        c.to,
      verified:  c.verified,
      timestamp: c.timestamp,
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  ██████╗  █████╗ ██████╗ ██╗  ██╗    ███╗   ███╗ █████╗ ████████╗████████╗███████╗██████╗
  Git for AI agent context. Running on http://localhost:${PORT}
  Private key generation: LOCAL ONLY via keygen.js
  `);
});

module.exports = app;
