import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import argon2 from 'argon2';
import nodemailer from 'nodemailer';
import QRCode from 'qrcode';
import speakeasy from 'speakeasy';
import { z } from 'zod';

const app = express();
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30_000
});
const root = path.dirname(fileURLToPath(import.meta.url));
const production = process.env.NODE_ENV === 'production';
const sessionCookie = production ? '__Host-harbor_session' : 'harbor_session';
const sessionDurationMs = 8 * 60 * 60 * 1000;
const pepper = process.env.PASSWORD_PEPPER;
const auditKey = process.env.AUDIT_HMAC_KEY;
const totpKeyHex = process.env.TOTP_ENCRYPTION_KEY;
const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
        : undefined
    })
  : null;

if (!process.env.DATABASE_URL || !pepper || !auditKey || !totpKeyHex || !process.env.APP_ORIGIN) {
  throw new Error('Set DATABASE_URL, PASSWORD_PEPPER, AUDIT_HMAC_KEY, TOTP_ENCRYPTION_KEY, and APP_ORIGIN.');
}
if (Buffer.byteLength(pepper) < 32 || Buffer.byteLength(auditKey) < 32 || pepper === auditKey) {
  throw new Error('PASSWORD_PEPPER and AUDIT_HMAC_KEY must be distinct secrets of at least 32 bytes.');
}
if (!/^[\da-f]{64}$/i.test(totpKeyHex)) {
  throw new Error('TOTP_ENCRYPTION_KEY must be 32 bytes represented as 64 hexadecimal characters.');
}
const totpKey = Buffer.from(totpKeyHex, 'hex');
const appOrigin = new URL(process.env.APP_ORIGIN).origin;

app.disable('x-powered-by');
app.set('trust proxy', production ? 1 : false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      fontSrc: ["'self'", 'data:'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(root, 'public'), { maxAge: production ? '1h' : 0 }));
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('origin') !== appOrigin) return fail(res, 403, 'Request origin is not allowed.');
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});
const idSchema = z.string().uuid();
const emailSchema = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const passwordSchema = z.string().min(12).max(128);

function fail(res, status, message) {
  return res.status(status).json({ error: message });
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function codeMac(code) {
  return crypto.createHmac('sha256', pepper).update(code).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(left || '');
  const b = Buffer.from(right || '');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', totpKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString('base64')).join('.');
}

function decrypt(value) {
  const [iv, tag, encrypted] = value.split('.').map((part) => Buffer.from(part, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', totpKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

async function audit(actorId, action, targetType, targetId, details = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('LOCK TABLE audit_logs IN EXCLUSIVE MODE');
    const previous = await client.query(
      'SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1'
    );
    const previousHash = previous.rows[0]?.entry_hash || '';
    const createdAt = new Date().toISOString();
    const serialized = JSON.stringify({ actorId, action, targetType, targetId, details, createdAt });
    const entryHash = crypto.createHmac('sha256', auditKey).update(previousHash + serialized).digest('hex');
    await client.query(
      `INSERT INTO audit_logs (actor_id, action, target_type, target_id, details, previous_hash, entry_hash, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [actorId, action, targetType, targetId, details, previousHash || null, entryHash, createdAt]
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function sendCode(email, code, purpose) {
  if (!mailer) throw new Error('Email delivery is not configured. Set SMTP_HOST and SMTP credentials.');
  await mailer.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: purpose === 'verify_email' ? 'Verify your Harbor Health account' : 'Your Harbor Health sign-in code',
    text: `Your one-time code is ${code}. It expires in 2 minutes. If you did not request this, ignore this message.`
  });
}

async function makeChallenge(user, purpose, method) {
  const token = randomToken();
  const code = method === 'email' ? String(crypto.randomInt(0, 1_000_000)).padStart(6, '0') : null;
  await pool.query(
    `INSERT INTO auth_challenges (token_hash, user_id, purpose, method, code_hmac, expires_at)
     VALUES ($1, $2, $3, $4, $5, now() + interval '2 minutes')`,
    [digest(token), user.id, purpose, method, code ? codeMac(code) : null]
  );
  if (code) await sendCode(user.email, code, purpose);
  return token;
}

async function createSession(user, res) {
  const token = randomToken();
  const csrfToken = randomToken();
  const expiresAt = new Date(Date.now() + sessionDurationMs);
  await pool.query(
    'INSERT INTO sessions (token_hash, csrf_token, user_id, expires_at) VALUES ($1, $2, $3, $4)',
    [digest(token), csrfToken, user.id, expiresAt]
  );
  res.cookie(sessionCookie, token, {
    httpOnly: true,
    secure: production,
    sameSite: 'lax',
    expires: expiresAt,
    path: '/'
  });
  return csrfToken;
}

function readCookies(req) {
  const cookies = Object.create(null);
  for (const part of (req.headers.cookie || '').split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0) {
      const name = part.slice(0, separator).trim();
      try {
        cookies[name] = decodeURIComponent(part.slice(separator + 1).trim());
      } catch {
        return Object.create(null);
      }
    }
  }
  return cookies;
}

async function requireSession(req, res, next) {
  try {
    const token = readCookies(req)[sessionCookie];
    if (!token) return fail(res, 401, 'Please sign in to continue.');
    const result = await pool.query(
      `SELECT s.id AS session_id, s.csrf_token, u.id, u.name, u.email, u.role
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > now() AND u.deleted_at IS NULL`,
      [digest(token)]
    );
    if (!result.rowCount) return fail(res, 401, 'Your session expired. Please sign in again.');
    req.user = result.rows[0];
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) &&
        !safeEqual(req.headers['x-csrf-token'], req.user.csrf_token)) {
      return fail(res, 403, 'Security token is invalid. Refresh the page and try again.');
    }
    next();
  } catch (error) {
    next(error);
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return fail(res, 403, 'You do not have permission to do that.');
    next();
  };
}

function validBody(schema, req, res) {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    fail(res, 400, parsed.error.issues[0]?.message || 'Please check the information you entered.');
    return null;
  }
  return parsed.data;
}

app.get('/api/health', async (_req, res, next) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', service: 'Harbor Health' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const data = validBody(z.object({
      name: z.string().trim().min(2).max(100),
      email: emailSchema,
      password: passwordSchema,
      role: z.enum(['patient', 'doctor'])
    }), req, res);
    if (!data) return;
    if (!mailer) return fail(res, 503, 'Email verification is unavailable until email delivery is configured.');
    const passwordHash = await argon2.hash(`${data.password}${pepper}`, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1
    });
    const created = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, approved_at)
       VALUES ($1, $2, $3, $4, CASE WHEN $4 = 'patient' THEN now() ELSE NULL END)
       RETURNING id, name, email`,
      [data.name, data.email, passwordHash, data.role]
    );
    const user = created.rows[0];
    let challenge;
    try {
      challenge = await makeChallenge(user, 'verify_email', 'email');
    } catch (error) {
      await pool.query('DELETE FROM auth_challenges WHERE user_id = $1', [user.id]);
      await pool.query('DELETE FROM users WHERE id = $1 AND email_verified_at IS NULL', [user.id]);
      throw error;
    }
    await audit(user.id, 'user.register', 'user', user.id, { role: data.role });
    res.status(201).json({
      challenge,
      role: data.role,
      message: data.role === 'doctor'
        ? 'Check your email for a verification code. Doctor accounts are reviewed before sign-in is enabled.'
        : 'Check your email for a verification code. It expires in 2 minutes.'
    });
  } catch (error) {
    if (error.code === '23505') return fail(res, 409, 'An account with that email already exists.');
    next(error);
  }
});

app.post('/api/auth/verify-email', authLimiter, async (req, res, next) => {
  try {
    const data = validBody(z.object({
      challenge: z.string().min(20).max(100),
      code: z.string().regex(/^\d{6}$/)
    }), req, res);
    if (!data) return;
    const result = await pool.query(
      `SELECT c.*, u.id AS uid, u.name, u.email, u.role
       FROM auth_challenges c JOIN users u ON u.id = c.user_id
       WHERE c.token_hash = $1 AND c.purpose = 'verify_email' AND c.method = 'email'
         AND c.expires_at > now() AND c.attempts < 5 AND u.email_verified_at IS NULL`,
      [digest(data.challenge)]
    );
    const challenge = result.rows[0];
    if (!challenge || !safeEqual(challenge.code_hmac, codeMac(data.code))) {
      if (challenge) await pool.query('UPDATE auth_challenges SET attempts = attempts + 1 WHERE id = $1', [challenge.id]);
      return fail(res, 400, 'That code is invalid or has expired. Request a new code.');
    }
    await pool.query('UPDATE users SET email_verified_at = now() WHERE id = $1', [challenge.uid]);
    await pool.query('DELETE FROM auth_challenges WHERE id = $1', [challenge.id]);
    await audit(challenge.uid, 'user.email_verified', 'user', challenge.uid);
    if (challenge.role === 'doctor') {
      res.json({ message: 'Email verified. A hospital administrator must approve your doctor account before you can sign in.' });
      return;
    }
    const csrfToken = await createSession({ id: challenge.uid }, res);
    res.json({ user: { id: challenge.uid, name: challenge.name, email: challenge.email, role: challenge.role }, csrfToken });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/resend-verification', authLimiter, async (req, res, next) => {
  try {
    const data = validBody(z.object({
      challenge: z.string().min(20).max(100)
    }), req, res);
    if (!data) return;
    const result = await pool.query(
      `SELECT c.id AS challenge_id, u.id, u.name, u.email
       FROM auth_challenges c JOIN users u ON u.id = c.user_id
       WHERE c.token_hash = $1 AND c.purpose = 'verify_email' AND u.email_verified_at IS NULL
         AND u.deleted_at IS NULL`,
      [digest(data.challenge)]
    );
    const pending = result.rows[0];
    if (!pending) return fail(res, 400, 'Verification cannot be resent. Please create a new account or sign in.');
    const challenge = await makeChallenge(pending, 'verify_email', 'email');
    await pool.query('DELETE FROM auth_challenges WHERE id = $1', [pending.challenge_id]);
    res.json({ challenge, message: 'A new verification code was sent. It expires in 2 minutes.' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const data = validBody(z.object({
      email: emailSchema,
      password: z.string().min(1).max(128)
    }), req, res);
    if (!data) return;
    const result = await pool.query(
      `SELECT id, name, email, role, password_hash, email_verified_at, approved_at, totp_secret_enc
       FROM users WHERE email = $1 AND deleted_at IS NULL`,
      [data.email]
    );
    const user = result.rows[0];
    const passwordMatches = user && await argon2.verify(user.password_hash, `${data.password}${pepper}`);
    if (!passwordMatches) return fail(res, 401, 'Email or password is incorrect.');
    if (!user.email_verified_at) return fail(res, 403, 'Please verify your email address before signing in.');
    if (user.role === 'doctor' && !user.approved_at) return fail(res, 403, 'Your doctor account is awaiting hospital approval.');
    if (!user.totp_secret_enc && !mailer) return fail(res, 503, 'Email two-factor authentication is not configured.');
    const method = user.totp_secret_enc ? 'totp' : 'email';
    const challenge = await makeChallenge(user, 'login', method);
    res.json({
      challenge,
      method,
      message: method === 'totp' ? 'Enter the current code from your authenticator app.' : 'A sign-in code was sent to your email.'
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/complete-login', authLimiter, async (req, res, next) => {
  try {
    const data = validBody(z.object({
      challenge: z.string().min(20).max(100),
      code: z.string().regex(/^\d{6}$/)
    }), req, res);
    if (!data) return;
    const result = await pool.query(
      `SELECT c.*, u.id AS uid, u.name, u.email, u.role, u.totp_secret_enc
       FROM auth_challenges c JOIN users u ON u.id = c.user_id
       WHERE c.token_hash = $1 AND c.purpose = 'login' AND c.expires_at > now()
         AND c.attempts < 5 AND u.deleted_at IS NULL`,
      [digest(data.challenge)]
    );
    const challenge = result.rows[0];
    let valid = false;
    if (challenge?.method === 'email') {
      valid = safeEqual(challenge.code_hmac, codeMac(data.code));
    } else if (challenge?.method === 'totp' && challenge.totp_secret_enc) {
      valid = speakeasy.totp.verify({
        secret: decrypt(challenge.totp_secret_enc),
        encoding: 'base32',
        token: data.code,
        step: 120,
        window: 0
      });
    }
    if (!valid) {
      if (challenge) await pool.query('UPDATE auth_challenges SET attempts = attempts + 1 WHERE id = $1', [challenge.id]);
      return fail(res, 400, 'That code is invalid or has expired. Sign in again to request a new code.');
    }
    await pool.query('DELETE FROM auth_challenges WHERE id = $1', [challenge.id]);
    const csrfToken = await createSession({ id: challenge.uid }, res);
    await audit(challenge.uid, 'auth.login', 'user', challenge.uid);
    res.json({ user: { id: challenge.uid, name: challenge.name, email: challenge.email, role: challenge.role }, csrfToken });
  } catch (error) {
    next(error);
  }
});

app.get('/api/me', requireSession, (req, res) => {
  res.json({
    user: { id: req.user.id, name: req.user.name, email: req.user.email, role: req.user.role },
    csrfToken: req.user.csrf_token
  });
});

app.post('/api/auth/logout', requireSession, async (req, res, next) => {
  try {
    const token = readCookies(req)[sessionCookie];
    await pool.query('DELETE FROM sessions WHERE token_hash = $1', [digest(token)]);
    res.clearCookie(sessionCookie, { httpOnly: true, secure: production, sameSite: 'lax', path: '/' });
    res.json({ message: 'You are signed out.' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/totp/setup', requireSession, async (req, res, next) => {
  try {
    const secret = speakeasy.generateSecret({ length: 20, name: `Harbor Health (${req.user.email})`, issuer: 'Harbor Health' });
    const uri = `otpauth://totp/${encodeURIComponent(`Harbor Health:${req.user.email}`)}?secret=${secret.base32}&issuer=${encodeURIComponent('Harbor Health')}&algorithm=SHA1&digits=6&period=120`;
    const qrCode = await QRCode.toDataURL(uri, { errorCorrectionLevel: 'M', margin: 2, width: 240 });
    await pool.query(
      `UPDATE users SET totp_pending_secret_enc = $1, totp_pending_expires_at = now() + interval '10 minutes'
       WHERE id = $2`,
      [encrypt(secret.base32), req.user.id]
    );
    await audit(req.user.id, 'auth.totp_setup_started', 'user', req.user.id);
    res.json({ qrCode, expiresInSeconds: 120, message: 'Scan with an authenticator app, then enter its 6-digit code to confirm.' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/totp/confirm', requireSession, async (req, res, next) => {
  try {
    const data = validBody(z.object({ code: z.string().regex(/^\d{6}$/) }), req, res);
    if (!data) return;
    const result = await pool.query(
      `SELECT totp_pending_secret_enc FROM users
       WHERE id = $1 AND totp_pending_expires_at > now()`,
      [req.user.id]
    );
    const encrypted = result.rows[0]?.totp_pending_secret_enc;
    const valid = encrypted && speakeasy.totp.verify({
      secret: decrypt(encrypted), encoding: 'base32', token: data.code, step: 120, window: 0
    });
    if (!valid) return fail(res, 400, 'That code is invalid or has expired. Start setup again.');
    await pool.query(
      `UPDATE users SET totp_secret_enc = totp_pending_secret_enc,
       totp_pending_secret_enc = NULL, totp_pending_expires_at = NULL WHERE id = $1`,
      [req.user.id]
    );
    await audit(req.user.id, 'auth.totp_enabled', 'user', req.user.id);
    res.json({ message: 'Authenticator two-factor authentication is enabled.' });
  } catch (error) {
    next(error);
  }
});

const appointmentInput = z.object({
  doctorId: idSchema,
  startsAt: z.string().datetime(),
  reason: z.string().trim().min(3).max(500)
});

app.get('/api/doctors', async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, name FROM users WHERE role = 'doctor' AND approved_at IS NOT NULL AND deleted_at IS NULL ORDER BY name`
    );
    res.json({ doctors: result.rows });
  } catch (error) {
    next(error);
  }
});

app.get('/api/appointments', requireSession, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.starts_at, a.reason, a.status, p.name AS patient_name, d.name AS doctor_name,
              a.patient_id, a.doctor_id
       FROM appointments a
       JOIN users p ON p.id = a.patient_id
       JOIN users d ON d.id = a.doctor_id
       WHERE a.deleted_at IS NULL
         AND ($1 IN ('admin', 'super_admin') OR a.patient_id = $2 OR a.doctor_id = $2)
       ORDER BY a.starts_at ASC LIMIT 100`,
      [req.user.role, req.user.id]
    );
    res.json({ appointments: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post('/api/appointments', requireSession, async (req, res, next) => {
  try {
    if (req.user.role !== 'patient') return fail(res, 403, 'Only patients can request an appointment.');
    const data = validBody(appointmentInput, req, res);
    if (!data) return;
    const startsAt = new Date(data.startsAt);
    if (startsAt <= new Date()) return fail(res, 400, 'Choose an appointment time in the future.');
    const doctor = await pool.query(
      `SELECT id FROM users
       WHERE id = $1 AND role = 'doctor' AND approved_at IS NOT NULL AND deleted_at IS NULL`,
      [data.doctorId]
    );
    if (!doctor.rowCount) return fail(res, 400, 'Choose an available doctor.');
    const result = await pool.query(
      `INSERT INTO appointments (patient_id, doctor_id, starts_at, reason)
       VALUES ($1, $2, $3, $4) RETURNING id, starts_at, reason, status`,
      [req.user.id, data.doctorId, startsAt, data.reason]
    );
    await audit(req.user.id, 'appointment.requested', 'appointment', result.rows[0].id);
    res.status(201).json({ appointment: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/appointments/:id/status', requireSession, async (req, res, next) => {
  try {
    const id = idSchema.safeParse(req.params.id);
    const data = validBody(z.object({ status: z.enum(['confirmed', 'cancelled', 'completed']) }), req, res);
    if (!id.success) return fail(res, 400, 'Invalid appointment.');
    if (!data) return;
    const result = await pool.query(
      `UPDATE appointments SET status = $1
       WHERE id = $2 AND deleted_at IS NULL
         AND ($3 IN ('admin', 'super_admin') OR doctor_id = $4 OR (patient_id = $4 AND $1 = 'cancelled'))
       RETURNING id`,
      [data.status, id.data, req.user.role, req.user.id]
    );
    if (!result.rowCount) return fail(res, 404, 'Appointment not found or you do not have permission.');
    await audit(req.user.id, `appointment.${data.status}`, 'appointment', id.data);
    res.json({ message: 'Appointment updated.' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/users', requireSession, requireRole('admin', 'super_admin'), async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role, created_at, deleted_at, approved_at
       FROM users ORDER BY created_at DESC LIMIT 500`
    );
    res.json({ users: result.rows });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/admin/users/:id/approve', requireSession, requireRole('admin', 'super_admin'), async (req, res, next) => {
  try {
    const id = idSchema.safeParse(req.params.id);
    if (!id.success) return fail(res, 400, 'Invalid user.');
    const result = await pool.query(
      `UPDATE users SET approved_at = now()
       WHERE id = $1 AND role = 'doctor' AND email_verified_at IS NOT NULL
         AND deleted_at IS NULL AND approved_at IS NULL
       RETURNING id`,
      [id.data]
    );
    if (!result.rowCount) return fail(res, 404, 'Verified doctor account not found or already approved.');
    await audit(req.user.id, 'user.doctor_approved', 'user', id.data);
    res.json({ message: 'Doctor account approved.' });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/admin/users/:id/role', requireSession, requireRole('super_admin'), async (req, res, next) => {
  try {
    const id = idSchema.safeParse(req.params.id);
    const data = validBody(z.object({ role: z.enum(['patient', 'doctor', 'admin', 'super_admin']) }), req, res);
    if (!id.success) return fail(res, 400, 'Invalid user.');
    if (!data) return;
    const result = await pool.query(
      `UPDATE users
       SET role = $1,
           approved_at = CASE WHEN $1 = 'patient' THEN now() WHEN $1 = 'doctor' THEN NULL ELSE approved_at END
       WHERE id = $2 AND id <> $3 AND deleted_at IS NULL RETURNING id`,
      [data.role, id.data, req.user.id]
    );
    if (!result.rowCount) return fail(res, 404, 'User not found.');
    await audit(req.user.id, 'user.role_changed', 'user', id.data, { role: data.role });
    res.json({ message: 'Role updated.' });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/admin/users/:id', requireSession, requireRole('admin', 'super_admin'), async (req, res, next) => {
  try {
    const id = idSchema.safeParse(req.params.id);
    if (!id.success) return fail(res, 400, 'Invalid user.');
    const result = await pool.query(
      `UPDATE users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL
       AND role NOT IN ('admin', 'super_admin') RETURNING id`,
      [id.data]
    );
    if (!result.rowCount) return fail(res, 404, 'User not found or protected staff account.');
    await pool.query('UPDATE sessions SET expires_at = now() WHERE user_id = $1', [id.data]);
    await audit(req.user.id, 'user.soft_deleted', 'user', id.data);
    res.json({ message: 'User was deactivated. Their record remains available for authorized audit.' });
  } catch (error) {
    next(error);
  }
});

app.get('/api/admin/audit', requireSession, requireRole('admin', 'super_admin'), async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, actor_id, action, target_type, target_id, details, created_at
       FROM audit_logs ORDER BY id DESC LIMIT 100`
    );
    await audit(req.user.id, 'audit.viewed', 'audit_log', null);
    res.json({ entries: result.rows });
  } catch (error) {
    next(error);
  }
});

app.use('/api', (_req, res) => fail(res, 404, 'That service endpoint does not exist.'));
app.use((error, _req, res, _next) => {
  console.error('Request failed:', error.message);
  if (res.headersSent) return;
  if (error.code === '23503') return fail(res, 400, 'This record is linked to existing clinical data and cannot be removed.');
  res.status(500).json({ error: 'A server error occurred. Please try again later.' });
});

const server = app.listen(Number(process.env.PORT || 3000), () => {
  console.log(`Harbor Health listening on port ${process.env.PORT || 3000}`);
});
const cleanupTimer = setInterval(async () => {
  try {
    await pool.query('DELETE FROM sessions WHERE expires_at <= now()');
    await pool.query('DELETE FROM auth_challenges WHERE expires_at <= now()');
  } catch (error) {
    console.error('Expired authentication data cleanup failed:', error.message);
  }
}, 15 * 60 * 1000);
cleanupTimer.unref();

async function shutdown() {
  clearInterval(cleanupTimer);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
