#!/usr/bin/env node
// Usage: node dashboard/scripts/add-user.js <email> [--admin] [--password <pw>]
// Requires DATABASE_URL in environment.

const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const args = process.argv.slice(2);
const email = args.find(a => !a.startsWith('--'))?.toLowerCase().trim();
const isAdmin = args.includes('--admin');
const pwFlag = args.indexOf('--password');
let providedPw = pwFlag !== -1 ? args[pwFlag + 1] : null;

if (!email) {
  console.error('Usage: node add-user.js <email> [--admin] [--password <pw>]');
  process.exit(1);
}

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL not set.');
  process.exit(1);
}

async function main() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1 });

  // If no password provided, generate a secure random password
  let password = providedPw;
  if (!password) {
    password = crypto.randomBytes(12).toString('base64url');
    console.log(`Generated password: ${password}`);
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    await pool.query(
      `INSERT INTO allowed_users (email, added_by, is_admin)
       VALUES ($1, 'cli', $2)
       ON CONFLICT (email) DO UPDATE SET active = TRUE, is_admin = $2`,
      [email, isAdmin]
    );
    await pool.query(
      `INSERT INTO user_credentials (email, password_hash)
       VALUES ($1, $2)
       ON CONFLICT (email) DO UPDATE SET password_hash = $2`,
      [email, hash]
    );
    console.log(`\n✓ User provisioned: ${email}${isAdmin ? ' (admin)' : ''}`);
    console.log(`  Share password securely with the analyst.`);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }

  await pool.end();
}

main();
