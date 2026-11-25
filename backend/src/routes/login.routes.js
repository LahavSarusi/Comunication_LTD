const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { loginSchema } = require('../validation/loginSchemas');
const validate = require('../middleware/validate');
const { verifyPassword } = require('../utils/crypto');
const { checkPasswordWithLockout, setLoginState } = require('../services/accountLockout');

const router = express.Router();

// Per-IP limit, on top of the per-account lockout: it slows down an attacker who
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

// POST /api/auth/login  { username, password }
// The lockout steps (dummy hash for unknown users, atomic attempt reservation,
// 423 when locked, generic 401) live in services/accountLockout.js, shared with
// change password. All queries there are parameterized.
router.post('/login', loginLimiter, validate(loginSchema), async (req, res) => {
  const { username, password } = req.validatedBody;
  const now = new Date();

  const result = await checkPasswordWithLockout(res, { username, password, now, verify: verifyPassword });
  if (result.done) return undefined;
  const { user } = result;

  // Correct password within the limit: the counter starts over. This can only run
  // for one of the first maxLoginAttempts guesses, so it never undoes a lock that
  // was earned by guesses over the limit.
  await setLoginState(user.id, 0, null, now);

  // Only explicitly listed, non-secret fields are returned.
  return res.status(200).json({
    message: 'Login successful',
    user: { id: user.id, username: user.username, email: user.email },
  });
});

module.exports = router;
