import 'dotenv/config';
import crypto from 'node:crypto';
import pg from 'pg';

const { Pool } = pg;
const databaseUrl = process.env.DATABASE_URL;
const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
const auditKey = process.env.AUDIT_HMAC_KEY;

if (!databaseUrl || !email || !auditKey || Buffer.byteLength(auditKey) < 32) {
  throw new Error('Set DATABASE_URL, BOOTSTRAP_ADMIN_EMAIL, and the 32-byte-or-longer AUDIT_HMAC_KEY.');
}

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined
});
const client = await pool.connect();

try {
  await client.query('BEGIN');
  await client.query('LOCK TABLE users IN EXCLUSIVE MODE');
  const existing = await client.query(
    `SELECT 1 FROM users WHERE role = 'super_admin' AND deleted_at IS NULL LIMIT 1`
  );
  if (existing.rowCount) throw new Error('A super administrator already exists; use the admin interface.');

  const candidate = await client.query(
    `SELECT id, email FROM users
     WHERE lower(email) = $1 AND email_verified_at IS NOT NULL AND deleted_at IS NULL
     FOR UPDATE`,
    [email]
  );
  if (!candidate.rowCount) throw new Error('No active, verified account was found for BOOTSTRAP_ADMIN_EMAIL.');

  const user = candidate.rows[0];
  await client.query(
    `UPDATE users SET role = 'super_admin', approved_at = now() WHERE id = $1`,
    [user.id]
  );
  await client.query('LOCK TABLE audit_logs IN EXCLUSIVE MODE');
  const previous = await client.query('SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1');
  const previousHash = previous.rows[0]?.entry_hash || '';
  const createdAt = new Date().toISOString();
  const details = { email: user.email };
  const serialized = JSON.stringify({
    actorId: null,
    action: 'bootstrap.super_admin_created',
    targetType: 'user',
    targetId: user.id,
    details,
    createdAt
  });
  const entryHash = crypto.createHmac('sha256', auditKey).update(previousHash + serialized).digest('hex');
  await client.query(
    `INSERT INTO audit_logs (actor_id, action, target_type, target_id, details, previous_hash, entry_hash, created_at)
     VALUES (NULL, 'bootstrap.super_admin_created', 'user', $1, $2, $3, $4, $5)`,
    [user.id, details, previousHash || null, entryHash, createdAt]
  );
  await client.query('COMMIT');
  console.log(`Created the first super administrator for ${user.email}. The bootstrap operation was audit-logged.`);
} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  client.release();
  await pool.end();
}
