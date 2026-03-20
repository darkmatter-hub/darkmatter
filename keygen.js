#!/usr/bin/env node
/**
 * DarkMatter — Local Key Generator
 * ─────────────────────────────────
 * Generates an Ed25519 keypair entirely on your machine.
 * Your private key never leaves this script.
 * DarkMatter never sees it.
 *
 * Usage:
 *   node keygen.js
 *   node keygen.js --name "my-agent"
 *
 * Output:
 *   my-agent.private.pem  ← KEEP SECRET. Never share, never commit.
 *   my-agent.public.pem   ← Share this with DarkMatter to register.
 *   my-agent.id.txt       ← Your agentId derived from your public key.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Parse --name flag or default
const nameFlag = process.argv.indexOf('--name');
const name = nameFlag !== -1 ? process.argv[nameFlag + 1] : 'agent';
const safeName = name.replace(/[^a-z0-9-_]/gi, '-').toLowerCase();

console.log('\n🌑 DarkMatter — Local Key Generator');
console.log('─'.repeat(44));
console.log(`Generating keypair for: ${name}\n`);

// Generate Ed25519 keypair entirely in local process
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Derive a deterministic agentId from the public key
const agentId = 'dm_' + crypto
  .createHash('sha256')
  .update(publicKey)
  .digest('hex')
  .slice(0, 16);

// Write files
const privateFile = `${safeName}.private.pem`;
const publicFile  = `${safeName}.public.pem`;
const idFile      = `${safeName}.id.txt`;

fs.writeFileSync(privateFile, privateKey, { mode: 0o600 }); // owner read-only
fs.writeFileSync(publicFile,  publicKey);
fs.writeFileSync(idFile, `agentId=${agentId}\nagentName=${name}\npublicKeyFile=${publicFile}\n`);

console.log('✅ Files generated:\n');
console.log(`   ${privateFile}`);
console.log(`   └─ YOUR PRIVATE KEY. Never share. Never commit to git.`);
console.log(`      Add to .gitignore: echo "*.private.pem" >> .gitignore\n`);
console.log(`   ${publicFile}`);
console.log(`   └─ Your public identity. Safe to share.\n`);
console.log(`   ${idFile}`);
console.log(`   └─ Your agentId: ${agentId}\n`);
console.log('─'.repeat(44));
console.log('Next step — register with DarkMatter:\n');
console.log(`   node register.js --name "${name}" --public-key ${publicFile}`);
console.log('');
console.log('Or manually:');
console.log(`   curl -X POST https://darkmatter-production.up.railway.app/api/register \\`);
console.log(`     -H "Content-Type: application/json" \\`);
console.log(`     -d '{ "agentId": "${agentId}", "agentName": "${name}", "publicKey": "<contents of ${publicFile}>" }'`);
console.log('');
