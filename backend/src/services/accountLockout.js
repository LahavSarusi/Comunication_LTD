const { QueryTypes } = require('sequelize');
const { sequelize } = require('../models');
const { policy } = require('../config/passwordPolicy');
const { generateSalt, hashPassword } = require('../utils/crypto');

// Account lockout shared by every route that checks a user's password (login and
// change password). Both count against the same users.failed_login_attempts /
// users.locked_until columns, so an attacker gets maxLoginAttempts guesses per
// account in total, not per screen.

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
 * Reserves one password attempt BEFORE the password is checked, in a single atomic
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

function lockedResponse(res, lockedUntil, now) {
  const minutesLeft = Math.max(1, Math.ceil((lockedUntil.getTime() - now.getTime()) / 60000));
  res.set('Retry-After', String(minutesLeft * 60));
  return res.status(423).json({
    error: `Account is locked after too many failed attempts. Try again in ${minutesLeft} minute(s).`,
  });
}

/**
 * The lockout steps every password check goes through, in order. Returns either a
 * response that has already been sent (`{ done: true }`) or the verified user.
 *
 * 1. Unknown user: one dummy HMAC comparison, then the generic 401.
 * 2. Reserve the attempt atomically; locked or over the limit -> 423 without
 *    checking the password, so a locked account tells an attacker nothing.
 * 3. Wrong password: the last allowed attempt locks the account (423), earlier
 *    ones get the generic 401.
 * The caller resets the counter once the request succeeds.
 */
async function checkPasswordWithLockout(res, { username, password, now, verify }) {
  const user = await findUserByUsername(username);

  if (!user) {
    verify(password, DUMMY_SALT, DUMMY_HASH);
    res.status(401).json({ error: INVALID_CREDENTIALS });
    return { done: true };
  }

  // The decision below uses this fresh number, never the row read above
  // (which parallel requests may already have made out of date).
  const attempt = await reserveAttempt(user.id, now);

  if (attempt === null) {
    const lockedUntil = await readLockedUntil(user.id);
    lockedResponse(res, lockedUntil ?? new Date(now.getTime() + LOCKOUT_MS), now);
    return { done: true };
  }

  // Parallel requests that arrived after the last allowed attempt.
  if (attempt > policy.maxLoginAttempts) {
    const lockedUntil = await lockAccount(user.id, new Date(now.getTime() + LOCKOUT_MS), now);
    lockedResponse(res, lockedUntil, now);
    return { done: true };
  }

  if (!verify(password, user.salt, user.passwordHash)) {
    if (attempt === policy.maxLoginAttempts) {
      const lockedUntil = await lockAccount(user.id, new Date(now.getTime() + LOCKOUT_MS), now);
      lockedResponse(res, lockedUntil, now);
      return { done: true };
    }
    // One message for "no such user" and "wrong password" (no user enumeration).
    res.status(401).json({ error: INVALID_CREDENTIALS });
    return { done: true };
  }

  return { done: false, user };
}

module.exports = {
  INVALID_CREDENTIALS,
  LOCKOUT_MS,
  toSqliteDate,
  findUserByUsername,
  reserveAttempt,
  setLoginState,
  lockAccount,
  readLockedUntil,
  lockedResponse,
  checkPasswordWithLockout,
};
