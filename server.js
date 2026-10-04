'use strict';

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128; // also bounds bcrypt work; bcrypt only uses the first 72 bytes
const MAX_EMAIL_LENGTH = 254;
const BCRYPT_ROUNDS = 12;
const SESSION_COOKIE = 'sid';
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------
const db = new Database(path.join(__dirname, 'users.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'customer',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

// Prepared statements with ? placeholders: user input is bound as data and is
// never concatenated into SQL. Stock Juice Shop builds its login query with
// string concatenation, which is why  ' OR 1=1--  logs you in as admin there.
const findUserByEmail = db.prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?');
const findUserById = db.prepare('SELECT id, email, role FROM users WHERE id = ?');

// Compared against when the email doesn't exist, so a login for an unknown
// email takes as long as one for a real email (no timing-based user enumeration).
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_ROUNDS);

// ---------------------------------------------------------------------------
// Sessions (in-memory; use a persistent store such as Redis in production)
// ---------------------------------------------------------------------------
const sessions = new Map(); // token -> { userId, expires }

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex'); // 256-bit, unguessable
  sessions.set(token, { userId, expires: Date.now() + SESSION_TTL_MS });
  return token;
}

function getSessionToken(req) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === SESSION_COOKIE) return rest.join('=');
  }
  return null;
}

function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,     // JavaScript (including injected XSS) cannot read it
    secure: true,       // HTTPS only (browsers allow it on http://localhost for dev)
    sameSite: 'strict', // not sent on cross-site requests (CSRF defence)
    path: '/',
    maxAge: SESSION_TTL_MS
  });
}

// Every protected route goes through this. The user is looked up from the
// server-side session, never from anything the client sends (no auth bypass
// via forged headers, body fields, or editing a token's payload).
function requireAuth(req, res, next) {
  const token = getSessionToken(req);
  const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ message: 'Not logged in.' });
  }
  const user = findUserById.get(session.userId);
  if (!user) {
    sessions.delete(token);
    return res.status(401).json({ message: 'Not logged in.' });
  }
  session.expires = Date.now() + SESSION_TTL_MS; // sliding expiry
  req.user = user;
  req.sessionToken = token;
  next();
}

// ---------------------------------------------------------------------------
// Server-side validation (mirrors validateLogin() in public/login.js)
// ---------------------------------------------------------------------------
function validateLogin(email, password) {
  const errors = {};

  // typeof checks reject arrays/objects such as {"email": {"$ne": ""}}.
  if (typeof email !== 'string' || !email.includes('@')) {
    errors.email = 'Email must contain an "@" symbol.';
  } else if (email.length > MAX_EMAIL_LENGTH) {
    errors.email = 'Email is too long.';
  } else if (!/^[^\s@<>"'`]+@[^\s@<>"'`]+\.[^\s@<>"'`]+$/.test(email)) {
    // Also rejects quote and HTML characters used in SQLi/XSS payloads.
    errors.email = 'Please enter a valid email address.';
  }

  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    errors.password = `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  } else if (password.length > MAX_PASSWORD_LENGTH) {
    errors.password = `Password must be at most ${MAX_PASSWORD_LENGTH} characters.`;
  }

  return errors;
}

// Only accept JSON. A cross-site HTML form cannot send application/json
// without a CORS preflight, which this server never approves (CSRF defence).
function requireJson(req, res, next) {
  if (!req.is('application/json')) {
    return res.status(415).json({ message: 'Content-Type must be application/json.' });
  }
  next();
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');

// Security headers, including a strict Content-Security-Policy that only allows
// scripts from our own origin. Even if markup were injected, inline <script> and
// onerror= handlers would not run.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  }
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'login.html' }));

// Brute-force / credential-stuffing protection: 5 failed attempts per IP per
// 15 minutes. Successful logins don't count against the limit.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many failed login attempts. Please try again later.' }
});

app.post('/api/login', loginLimiter, requireJson, async (req, res) => {
  // Read only the two fields we expect; anything else in the body is ignored.
  const body = req.body || {};
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : body.email;
  const password = body.password;

  const errors = validateLogin(email, password);
  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ errors });
  }

  try {
    const user = findUserByEmail.get(email);
    // Always run bcrypt, even for unknown emails, to keep response time constant.
    const passwordOk = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

    if (!user || !passwordOk) {
      // Same message for "no such user" and "wrong password" (no user enumeration).
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // Fresh random token on every login (prevents session fixation).
    const oldToken = getSessionToken(req);
    if (oldToken) sessions.delete(oldToken);
    setSessionCookie(res, createSession(user.id));

    // Never return the password hash; send only what the page needs.
    return res.json({ email: user.email });
  } catch (err) {
    // Log details server-side; never leak stack traces or SQL errors to the client.
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Login failed. Please try again.' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.user.email, role: req.user.role });
});

// No JSON check: logout has no body, and the SameSite=Strict cookie already
// stops cross-site requests from carrying the session.
app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.sessionToken); // invalidate server-side, not just the cookie
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' });
  res.json({ message: 'Logged out.' });
});

// Malformed JSON and other errors: return a generic message, not a stack trace.
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
    return res.status(400).json({ message: 'Invalid request body.' });
  }
  console.error(err);
  res.status(500).json({ message: 'Internal server error.' });
});

// Purge expired sessions every 5 minutes.
setInterval(() => {
  const now = Date.now();
  for (const [token, s] of sessions) if (s.expires < now) sessions.delete(token);
}, 5 * 60 * 1000).unref();

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Login server on http://localhost:${PORT}/login.html`));
}

module.exports = { app, db, validateLogin, BCRYPT_ROUNDS };
