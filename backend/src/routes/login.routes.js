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

/**
 * Reserves one login attempt BEFORE the password is checked, in a single atomic
 * conditional UPDATE. SQLite runs it as one step, so parallel requests are counted
 * one after another and each gets its own number (1, 2, 3, 4 ...).
 * - The WHERE clause skips a locked account: no row comes back -> returns null.
 * - A lock that has already expired is cleared and the count starts again at 1.
 * The caller only checks the password when the returned number is within the limit,
 * so at most maxLoginAttempts guesses are ever checked, however many arrive at once.
 */
async function reserveAttempt(userId, now) {
  const rows = await sequelize.query(
    `UPDATE users
        SET failed_login_attempts = CASE WHEN locked_until IS NOT NULL AND locked_until <= $now
                                         THEN 1 ELSE failed_login_attempts + 1 END,
            locked_until = CASE WHEN locked_until <= $now THEN NULL ELSE locked_until END,
            updated_at = $now
      WHERE id = $id AND (locked_until IS NULL OR locked_until <= $now)
  RETURNING failed_login_attempts`,
    { bind: { id: userId, now: toSqliteDate(now) }, type: QueryTypes.SELECT },
  );
  return rows.length === 0 ? null : rows[0].failed_login_attempts;
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

// Locks the account unless a parallel request already did; returns the lock end time
// that is actually stored, so every request reports the same time.
async function lockAccount(userId, lockedUntil, now) {
  const rows = await sequelize.query(
    `UPDATE users
        SET locked_until = CASE WHEN locked_until IS NULL OR locked_until <= $now
                                THEN $lockedUntil ELSE locked_until END,
            updated_at = $now
      WHERE id = $id
  RETURNING locked_until`,
    { bind: { id: userId, lockedUntil: toSqliteDate(lockedUntil), now: toSqliteDate(now) }, type: QueryTypes.SELECT },
  );
  return new Date(rows[0].locked_until);
}

// Current lock end time, read fresh (the row read at the start of the request may be stale).
async function readLockedUntil(userId) {
  const rows = await sequelize.query('SELECT locked_until FROM users WHERE id = $id', {
    bind: { id: userId },
    type: QueryTypes.SELECT,
  });
  return rows[0]?.locked_until ? new Date(rows[0].locked_until) : null;
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

// POST /api/auth/login  { username, password }
router.post('/login', loginLimiter, validate(loginSchema), async (req, res) => {
  const { username, password } = req.validatedBody;
  const now = new Date();

  const user = await findUserByUsername(username);

  // Unknown user: still run one HMAC comparison (against a dummy hash) so the
  // response time does not reveal whether the account exists, then fail.
  if (!user) {
    verifyPassword(password, DUMMY_SALT, DUMMY_HASH);
    return res.status(401).json({ error: INVALID_CREDENTIALS });
  }

  // 1) Reserve this attempt atomically BEFORE looking at the password. The decision
  //    below uses this fresh number, never the row read above (which parallel
  //    requests may already have made out of date).
  const attempt = await reserveAttempt(user.id, now);

  // Account is locked: the password is not even checked, so a locked account
  // gives an attacker no information about whether a guess was right.
  if (attempt === null) {
    const lockedUntil = await readLockedUntil(user.id);
    return lockedResponse(res, lockedUntil ?? new Date(now.getTime() + LOCKOUT_MS), now);
  }

  // Over the limit: parallel requests that arrived after the last allowed attempt.
  // Lock (if no request has yet) and refuse without checking the password.
  if (attempt > policy.maxLoginAttempts) {
    const lockedUntil = await lockAccount(user.id, new Date(now.getTime() + LOCKOUT_MS), now);
    return lockedResponse(res, lockedUntil, now);
  }

  // 2) Within the limit: recompute HMAC-SHA256(salt + password), constant-time compare.
  if (!verifyPassword(password, user.salt, user.passwordHash)) {
    // The last allowed attempt failed: lock the account.
    if (attempt === policy.maxLoginAttempts) {
      const lockedUntil = await lockAccount(user.id, new Date(now.getTime() + LOCKOUT_MS), now);
      return lockedResponse(res, lockedUntil, now);
    }
    // One message for "no such user" and "wrong password" (no user enumeration).
    return res.status(401).json({ error: INVALID_CREDENTIALS });
  }

  // 3) Correct password within the limit: the counter starts over. This can only run
  //    for one of the first maxLoginAttempts guesses, so it never undoes a lock that
  //    was earned by guesses over the limit.
  await setLoginState(user.id, 0, null, now);

  // Only explicitly listed, non-secret fields are returned.
  return res.status(200).json({
    message: 'Login successful',
    user: { id: user.id, username: user.username, email: user.email },
  });
});

module.exports = router;
