const express = require('express');
const { QueryTypes } = require('sequelize');
const { rateLimit } = require('express-rate-limit');
const { sequelize, User, PasswordHistory } = require('../models');
const { policy, publicPolicy } = require('../config/passwordPolicy');
const { registerSchema, changePasswordSchema, RECENTLY_USED_MESSAGE } = require('../validation/userSchemas');
const validate = require('../middleware/validate');
const { generateSalt, hashPassword, verifyPassword } = require('../utils/crypto');
const { checkPasswordWithLockout, setLoginState, toSqliteDate } = require('../services/accountLockout');

const router = express.Router();

// Limits automated mass sign-ups / abuse: 10 attempts per IP per 15 minutes.
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many registration attempts, please try again later' },
});

// GET /api/auth/password-policy - the rules the React form shows and pre-checks.
router.get('/password-policy', (req, res) => {
  res.json(publicPolicy);
});

// POST /api/auth/register  { username, email, password }
router.post('/register', registerLimiter, validate(registerSchema), async (req, res) => {
  const { username, email, password } = req.validatedBody;

  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);

  // One transaction: the user and their first password-history row are saved together or not at all.
  // Only explicitly listed fields are written; a uniqueness clash surfaces as a 409 via the error handler.
  const user = await sequelize.transaction(async (transaction) => {
    const created = await User.create({ username, email, salt, passwordHash }, { transaction });
    await PasswordHistory.create({ userId: created.id, salt, passwordHash }, { transaction });
    return created;
  });

  res.status(201).json({
    message: 'Registration successful',
    user: { id: user.id, username: user.username, email: user.email },
  });
});

// Each attempt is a guess at the current password, so this is limited like registration.
const changePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many password change attempts, please try again later' },
});

// The last historyCount passwords of a user, newest first. Parameterized like the
// lockout queries: the values travel separately from the SQL text.
async function findRecentPasswords(userId) {
  if (policy.historyCount === 0) return [];
  const rows = await sequelize.query(
    `SELECT salt, password_hash
       FROM password_history
      WHERE user_id = $userId
      ORDER BY created_at DESC
      LIMIT $limit`,
    { bind: { userId, limit: policy.historyCount }, type: QueryTypes.SELECT },
  );
  return rows.map((row) => ({ salt: row.salt, passwordHash: row.password_hash }));
}

// POST /api/auth/change-password  { username, currentPassword, newPassword }
router.post('/change-password', changePasswordLimiter, validate(changePasswordSchema), async (req, res) => {
  const { username, currentPassword, newPassword } = req.validatedBody;
  const now = new Date();

  // A wrong current password is a password guess, so it goes through exactly the
  // same lockout as login (services/accountLockout.js) and counts against the same
  // per-account limit: unknown user -> 401 after a dummy HMAC compare; locked or over
  // maxLoginAttempts -> 423 without checking the password; wrong password -> 401, or
  // 423 when it was the last allowed attempt.
  const result = await checkPasswordWithLockout(res, {
    username,
    password: currentPassword,
    now,
    verify: verifyPassword,
  });
  if (result.done) return undefined;
  const { user } = result;

  // Password history: the new password may not match any of the last N stored
  // passwords (policy: historyCount). Each row is checked with its own salt.
  const recent = await findRecentPasswords(user.id);

  // The current password is always included, even when historyCount is 0.
  const candidates = [{ salt: user.salt, passwordHash: user.passwordHash }, ...recent];
  // No early exit: every candidate is compared, whatever the result.
  const reused = candidates
    .map((entry) => verifyPassword(newPassword, entry.salt, entry.passwordHash))
    .some(Boolean);

  if (reused) {
    // The current password was correct, so the failed-attempt counter starts over
    // (as after a successful login); only the choice of new password was rejected.
    await setLoginState(user.id, 0, null, now);
    return res.status(400).json({
      error: 'Validation failed',
      formErrors: [],
      fieldErrors: { newPassword: [RECENTLY_USED_MESSAGE] },
    });
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(newPassword, salt);

  // One transaction: the new credentials, the lockout reset and the history row are
  // saved together or not at all.
  await sequelize.transaction(async (transaction) => {
    await sequelize.query(
      `UPDATE users
          SET salt = $salt, password_hash = $passwordHash,
              failed_login_attempts = 0, locked_until = NULL, updated_at = $now
        WHERE id = $id`,
      {
        bind: { id: user.id, salt, passwordHash, now: toSqliteDate(now) },
        type: QueryTypes.UPDATE,
        transaction,
      },
    );
    await PasswordHistory.create({ userId: user.id, salt, passwordHash }, { transaction });
  });

  return res.status(200).json({ message: 'Password changed successfully' });
});

module.exports = router;
