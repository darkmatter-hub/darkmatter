#!/usr/bin/env node
/**
 * One-time backfill: encrypt existing plaintext user_recording_keys.encrypted_key rows.
 *
 * Run once after DM_ENCRYPTION_KEY is set in your environment:
 *   DM_ENCRYPTION_KEY=<hex> SUPABASE_URL=<url> SUPABASE_SERVICE_KEY=<key> node scripts/encrypt-recording-keys.js
 *
 * Or if you have a local .env:
 *   node -r dotenv/config scripts/encrypt-recording-keys.js
 *
 * Safe to re-run: already-encrypted rows (iv:tag:data format) are skipped.
 */
'use strict';

require('dotenv').config();

const { createClient }    = require('@supabase/supabase-js');
const { randomBytes, createCipheriv } = require('crypto');

// ── Validate env ──────────────────────────────────────────────────────────────
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const DM_ENCRYPTION_KEY    = process.env.DM_ENCRYPTION_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set.');
  process.exit(1);
}
if (!DM_ENCRYPTION_KEY) {
  console.error('ERROR: DM_ENCRYPTION_KEY must be set.');
  process.exit(1);
}
if (DM_ENCRYPTION_KEY.length !== 64) {
  console.error(`ERROR: DM_ENCRYPTION_KEY must be a 64-char hex string (32 bytes). Got ${DM_ENCRYPTION_KEY.length} chars.`);
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function isAlreadyEncrypted(value) {
  if (!value) return false;
  if (value.startsWith('plain:')) return false; // explicit plaintext marker — needs encrypting
  const parts = value.split(':');
  return parts.length === 3; // iv:tag:data AES-GCM format
}

function encryptValue(plaintext) {
  const key       = Buffer.from(DM_ENCRYPTION_KEY, 'hex');
  const iv        = randomBytes(12);
  const cipher    = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag       = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted.toString('hex');
}

function resolvePlaintext(raw) {
  // Strip the 'plain:' prefix added by the server when DM_ENCRYPTION_KEY was missing
  if (raw && raw.startsWith('plain:')) return raw.slice(6);
  return raw;
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log('Starting user_recording_keys encryption backfill...');
  console.log(`DM_ENCRYPTION_KEY: ${DM_ENCRYPTION_KEY.length} chars (looks valid)`);

  let page       = 0;
  const pageSize = 100;
  let totalRows  = 0;
  let encrypted  = 0;
  let skipped    = 0;
  let errors     = 0;

  while (true) {
    const { data: rows, error } = await supabase
      .from('user_recording_keys')
      .select('id, encrypted_key')
      .range(page * pageSize, (page + 1) * pageSize - 1);

    if (error) {
      console.error('ERROR fetching rows:', error.message);
      process.exit(1);
    }
    if (!rows || rows.length === 0) break;

    totalRows += rows.length;

    for (const row of rows) {
      if (isAlreadyEncrypted(row.encrypted_key)) {
        skipped++;
        continue;
      }

      // Row is plaintext (or has 'plain:' prefix) — encrypt it
      const plaintext = resolvePlaintext(row.encrypted_key);
      if (!plaintext) {
        console.log(`  Row ${row.id}: encrypted_key is null/empty — skipping`);
        skipped++;
        continue;
      }

      const newValue = encryptValue(plaintext);
      const { error: updateError } = await supabase
        .from('user_recording_keys')
        .update({ encrypted_key: newValue })
        .eq('id', row.id);

      if (updateError) {
        console.error(`  ERROR updating row ${row.id}:`, updateError.message);
        errors++;
      } else {
        console.log(`  Row ${row.id}: encrypted (was ${row.encrypted_key.length} chars plaintext)`);
        encrypted++;
      }
    }

    if (rows.length < pageSize) break;
    page++;
  }

  console.log('\n── Backfill complete ────────────────────────────────────');
  console.log(`  Total rows scanned : ${totalRows}`);
  console.log(`  Encrypted          : ${encrypted}`);
  console.log(`  Skipped (already)  : ${skipped}`);
  console.log(`  Errors             : ${errors}`);

  if (errors > 0) {
    console.error('\nSome rows failed to update. Re-run to retry.');
    process.exit(1);
  }
  console.log('\nDone.');
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
