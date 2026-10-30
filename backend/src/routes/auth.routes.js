const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { sequelize, User, PasswordHistory } = require('../models');
const { publicPolicy } = require('../config/passwordPolicy');
const { registerSchema } = require('../validation/userSchemas');
const validate = require('../middleware/validate');
const { generateSalt, hashPassword } = require('../utils/crypto');

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

module.exports = router;
