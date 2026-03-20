#!/usr/bin/env node
/**
 * DarkMatter — Agent Registration
 * ─────────────────────────────────
 * Registers your agent with DarkMatter using your locally generated public key.
 * Your private key is never used or sent here.
 *
 * Usage:
 *   node register.js --name "my-agent" --public-key my-agent.public.pem
 *
 * Prerequisites:
 *   Run keygen.js first to generate your keypair locally.
 */

const crypto = require('crypto');
const fs = require('fs');

const BASE_URL = 'https://darkmatter-production.up.railway.app/api';

function getArg(flag) {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : null;
}

async function main() {
  const name = getArg('--name');
  const publicKeyFile = getArg('--public-key');

  if (!name || !publicKeyFile) {
    console.error('\nUsage: node register.js --name "my-agent" --public-key my-agent.public.pem\n');
    process.exit(1);
  }

  if (!fs.existsSync(publicKeyFile)) {
    console.error(`\n❌ Public key file not found: ${publicKeyFile}`);
    console.error('   Run keygen.js first to generate your keypair.\n');
    process.exit(1);
  }

  const publicKey = fs.readFileSync(publicKeyFile, 'utf8');

  // Derive agentId from public key (same as keygen.js)
  const agentId = 'dm_' + crypto
    .createHash('sha256')
    .update(publicKey)
    .digest('hex')
    .slice(0, 16);

  console.log('\n🌑 DarkMatter — Agent Registration');
  console.log('─'.repeat(44));
  console.log(`Agent name:  ${name}`);
  console.log(`Agent ID:    ${agentId}`);
  console.log(`Public key:  ${publicKeyFile}`);
  console.log(`\nRegistering with DarkMatter (your private key is NOT sent)...\n`);

  const res = await fetch(`${BASE_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId, agentName: name, publicKey }),
  });

  const data = await res.json();

  if (data.error) {
    console.error(`❌ Registration failed: ${data.error}\n`);
    process.exit(1);
  }

  console.log(`✅ Agent registered successfully!\n`);
  console.log(`   agentId:   ${data.agentId}`);
  console.log(`   agentName: ${data.agentName}`);
  console.log(`\n─`.repeat(44));
  console.log(`\nYour agent is now on the DarkMatter network.`);
  console.log(`Keep your private key safe — DarkMatter does not have it.\n`);
}

main().catch(console.error);
