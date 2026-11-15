const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { sequelize, User, PasswordHistory } = require('../models');
const { policy, publicPolicy } = require('../config/passwordPolicy');
const { registerSchema, changePasswordSchema, RECENTLY_USED_MESSAGE } = require('../validation/userSchemas');
const validate = require('../middleware/validate');
const { generateSalt, hashPassword, verifyPassword } = require('../utils/crypto');

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

// Used when the username does not exist, so that request still costs one HMAC
// comparison and its response time does not reveal whether the account exists.
const DUMMY_SALT = generateSalt();
const DUMMY_HASH = hashPassword(generateSalt(), DUMMY_SALT);

// POST /api/auth/change-password  { username, currentPassword, newPassword }
router.post('/change-password', changePasswordLimiter, validate(changePasswordSchema), async (req, res) => {
  const { username, currentPassword, newPassword } = req.validatedBody;

  // Bound parameter via the ORM. The credentials scope is needed to read salt + hash.
  const user = await User.scope('withCredentials').findOne({ where: { username } });

  const passwordMatches = verifyPassword(
    currentPassword,
    user ? user.salt : DUMMY_SALT,
    user ? user.passwordHash : DUMMY_HASH,
  );

  // One message for "no such user" and "wrong password" (no user enumeration).
  if (!user || !passwordMatches) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Password history: the new password may not match any of the last N stored
  // passwords (policy: historyCount). Each row is checked with its own salt.
  const recent =
    policy.historyCount > 0
      ? await PasswordHistory.findAll({
          where: { userId: user.id },
          order: [['createdAt', 'DESC']],
          limit: policy.historyCount,
        })
      : [];

  // The current password is always included, even when historyCount is 0.
  const candidates = [{ salt: user.salt, passwordHash: user.passwordHash }, ...recent];
  // No early exit: every candidate is compared, whatever the result.
  const reused = candidates
    .map((entry) => verifyPassword(newPassword, entry.salt, entry.passwordHash))
    .some(Boolean);

  if (reused) {
    return res.status(400).json({
      error: 'Validation failed',
      formErrors: [],
      fieldErrors: { newPassword: [RECENTLY_USED_MESSAGE] },
    });
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(newPassword, salt);

  // One transaction: the new credentials and their history row are saved together or not at all.
  await sequelize.transaction(async (transaction) => {
    await user.update({ salt, passwordHash }, { transaction });
    await PasswordHistory.create({ userId: user.id, salt, passwordHash }, { transaction });
  });

  return res.status(200).json({ message: 'Password changed successfully' });
});

module.exports = router;
