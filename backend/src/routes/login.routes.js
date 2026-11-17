const express = require('express');
const { QueryTypes } = require('sequelize');
const { rateLimit } = require('express-rate-limit');
const { sequelize } = require('../models');
const { policy } = require('../config/passwordPolicy');
const { loginSchema } = require('../validation/loginSchemas');
const validate = require('../middleware/validate');
const { generateSalt, hashPassword, verifyPassword } = require('../utils/crypto');

const router = express.Router();

// Per-IP limit, on top of the per-account lockout below: it slows down an attacker who
// tries one or two passwords against many different accounts (password spraying).
// Successful logins are not counted, so normal users are not affected.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later' },
});

// Used when the username does not exist, so that request still costs one HMAC
// comparison and its response time does not reveal whether the account exists.
const DUMMY_SALT = generateSalt();
const DUMMY_HASH = hashPassword(generateSalt(), DUMMY_SALT);

const INVALID_CREDENTIALS = 'Invalid username or password';
const LOCKOUT_MS = policy.lockoutMinutes * 60 * 1000;

/*
 * ---------------------------------------------------------------------------
 * Database access - SQL injection protection with PARAMETERS
 * ---------------------------------------------------------------------------
 * Every query below is a fixed SQL text with named placeholders ($username, $id ...).
 * The values are passed separately in `bind` and SQLite receives them as bound
 * parameters (a prepared statement). User input is never concatenated into the SQL
 * text, so it can never change the query: "x' OR 1=1--" is just a username that
 * does not exist.
 */

// Same date format Sequelize uses for SQLite, so the models keep reading these columns.
function toSqliteDate(date) {
  return date.toISOString().replace('T', ' ').replace('Z', ' +00:00');
}

async function findUserByUsername(username) {
  const rows = await sequelize.query(
    `SELECT id, username, email, salt, password_hash, failed_login_attempts, locked_until
       FROM users
      WHERE username = $username
      LIMIT 1`,
    { bind: { username }, type: QueryTypes.SELECT },
  );
  if (rows.length === 0) return null;

  const row = rows[0];
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    salt: row.salt,
    passwordHash: row.password_hash,
    failedLoginAttempts: row.failed_login_attempts,
    lockedUntil: row.locked_until ? new Date(row.locked_until) : null,
  };
}

// Atomic "x = x + 1" that also returns the new value (RETURNING), so parallel
// requests cannot slip extra guesses past the limit.
async function incrementFailedAttempts(userId, now) {
  const rows = await sequelize.query(
    `UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1, updated_at = $now
      WHERE id = $id
  RETURNING failed_login_attempts`,
    { bind: { id: userId, now: toSqliteDate(now) }, type: QueryTypes.SELECT },
  );
  return rows[0].failed_login_attempts;
}

async function setLoginState(userId, failedLoginAttempts, lockedUntil, now) {
  await sequelize.query(
    `UPDATE users
        SET failed_login_attempts = $attempts, locked_until = $lockedUntil, updated_at = $now
      WHERE id = $id`,
    {
      bind: {
        id: userId,
        attempts: failedLoginAttempts,
        lockedUntil: lockedUntil ? toSqliteDate(lockedUntil) : null,
        now: toSqliteDate(now),
      },
      type: QueryTypes.UPDATE,
    },
  );
}

async function lockAccount(userId, lockedUntil, now) {
  await sequelize.query(
    'UPDATE users SET locked_until = $lockedUntil, updated_at = $now WHERE id = $id',
    { bind: { id: userId, lockedUntil: toSqliteDate(lockedUntil), now: toSqliteDate(now) }, type: QueryTypes.UPDATE },
  );
}

/*
 * ---------------------------------------------------------------------------
 * Login logic
 * ---------------------------------------------------------------------------
 */

function lockedResponse(res, lockedUntil, now) {
  const minutesLeft = Math.max(1, Math.ceil((lockedUntil.getTime() - now.getTime()) / 60000));
  res.set('Retry-After', String(minutesLeft * 60));
  return res.status(423).json({
    error: `Account is locked after too many failed login attempts. Try again in ${minutesLeft} minute(s).`,
  });
}

/**
 * Counts one failed login for an existing user and locks the account when the
 * policy limit (maxLoginAttempts) is reached. Returns the lock end time, or null.
 */
async function recordFailedAttempt(user, now) {
  // A lock that has already expired starts a fresh count.
  if (user.lockedUntil && user.lockedUntil <= now) {
    await setLoginState(user.id, 0, null, now);
  }

  const attempts = await incrementFailedAttempts(user.id, now);
  if (attempts < policy.maxLoginAttempts) return null;

  const lockedUntil = new Date(now.getTime() + LOCKOUT_MS);
  await lockAccount(user.id, lockedUntil, now);
  return lockedUntil;
}

// POST /api/auth/login  { username, password }
router.post('/login', loginLimiter, validate(loginSchema), async (req, res) => {
  const { username, password } = req.validatedBody;
  const now = new Date();

  const user = await findUserByUsername(username);

  // While the account is locked the password is not even checked, so a locked
  // account gives an attacker no information about whether a guess was right.
  if (user?.lockedUntil && user.lockedUntil > now) {
    return lockedResponse(res, user.lockedUntil, now);
  }

  // Recompute HMAC-SHA256(salt + password) and compare in constant time.
  const passwordMatches = verifyPassword(
    password,
    user ? user.salt : DUMMY_SALT,
    user ? user.passwordHash : DUMMY_HASH,
  );

  if (!user || !passwordMatches) {
    if (user) {
      const lockedUntil = await recordFailedAttempt(user, now);
      if (lockedUntil) return lockedResponse(res, lockedUntil, now);
    }
    // One message for "no such user" and "wrong password" (no user enumeration).
    return res.status(401).json({ error: INVALID_CREDENTIALS });
  }

  // Successful login: the failed-attempt counter starts over.
  if (user.failedLoginAttempts !== 0 || user.lockedUntil !== null) {
    await setLoginState(user.id, 0, null, now);
  }

  // Only explicitly listed, non-secret fields are returned.
  return res.status(200).json({
    message: 'Login successful',
    user: { id: user.id, username: user.username, email: user.email },
  });
});

module.exports = router;
