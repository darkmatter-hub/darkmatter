const crypto = require('crypto');

/**
 * Generate a new agent keypair
 * Returns { agentId, publicKey, privateKey }
 */
function generateAgentKeypair(agentName) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const agentId = `dm_${crypto.createHash('sha256')
    .update(publicKey)
    .digest('hex')
    .slice(0, 16)}`;

  return { agentId, agentName, publicKey, privateKey };
}

/**
 * Sign a context package with the agent's private key
 * Returns a signed context object ready to hand off
 */
function signContext(context, fromAgentId, toAgentId, privateKey) {
  const payload = {
    from: fromAgentId,
    to: toAgentId,
    context,
    timestamp: new Date().toISOString(),
    nonce: crypto.randomBytes(16).toString('hex'),
  };

  const payloadString = JSON.stringify(payload);
  const signature = crypto.sign(null, Buffer.from(payloadString), privateKey);

  return {
    payload,
    signature: signature.toString('base64'),
  };
}

/**
 * Verify a signed context package
 * Returns { valid: boolean, reason: string }
 */
function verifyContext(signedPackage, senderPublicKey) {
  try {
    const { payload, signature } = signedPackage;

    // Check timestamp — reject packages older than 5 minutes
    const packageAge = Date.now() - new Date(payload.timestamp).getTime();
    if (packageAge > 5 * 60 * 1000) {
      return { valid: false, reason: 'Package expired — timestamp too old' };
    }

    // Verify cryptographic signature
    const payloadString = JSON.stringify(payload);
    const isValid = crypto.verify(
      null,
      Buffer.from(payloadString),
      senderPublicKey,
      Buffer.from(signature, 'base64')
    );

    if (!isValid) {
      return { valid: false, reason: 'Signature verification failed — context may have been tampered with' };
    }

    return { valid: true, reason: 'Signature verified' };
  } catch (err) {
    return { valid: false, reason: `Verification error: ${err.message}` };
  }
}

module.exports = { generateAgentKeypair, signContext, verifyContext };
