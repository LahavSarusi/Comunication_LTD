const { z } = require('zod');
const { policy } = require('../config/passwordPolicy');

// Allowlist: lowercase letters, digits and underscore only. Anything else - quotes,
// spaces, "--", ";" - is rejected outright instead of being "cleaned".
const USERNAME_PATTERN = /^[a-z0-9_]{3,30}$/;

// Printable ASCII punctuation: ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
const SPECIAL_CHAR_PATTERN = /[!-/:-@[-`{-~]/;

// Only real strings are accepted; objects, arrays and numbers fail here.
function requiredString(label) {
  return z.string({
    error: (issue) => (issue.input === undefined ? `${label} is required` : `${label} must be a text value`),
  });
}

/**
 * Password rules are NOT hardcoded: they come from the administrator-editable
 * file backend/config/password-policy.json (loaded and validated at startup).
 * The password is never trimmed or altered - it is hashed exactly as typed.
 */
function buildPasswordSchema({ minLength, maxLength, complexity, dictionary }) {
  let schema = requiredString('Password')
    .min(minLength, `Password must be at least ${minLength} characters`)
    .max(maxLength, `Password must be at most ${maxLength} characters`);

  if (complexity.uppercase) schema = schema.regex(/[A-Z]/, 'Password must contain an uppercase letter (A-Z)');
  if (complexity.lowercase) schema = schema.regex(/[a-z]/, 'Password must contain a lowercase letter (a-z)');
  if (complexity.digits) schema = schema.regex(/[0-9]/, 'Password must contain a digit (0-9)');
  if (complexity.specialChars) schema = schema.regex(SPECIAL_CHAR_PATTERN, 'Password must contain a special character (e.g. ! @ # $ %)');

  if (dictionary.enabled) {
    schema = schema.refine(
      (password) => {
        const lower = password.toLowerCase();
        return !dictionary.words.some((word) => lower.includes(word));
      },
      'Password contains a common word or pattern and is too easy to guess',
    );
  }

  return schema;
}

// strictObject: unknown keys (e.g. "salt", "passwordHash", "isAdmin") are rejected,
// which blocks mass-assignment. Every field must be a string, which blocks
// operator/type-confusion payloads such as {"username": {"$gt": ""}}.
const registerSchema = z
  .strictObject({
    username: requiredString('Username')
      .trim()
      .toLowerCase()
      .regex(USERNAME_PATTERN, 'Username must be 3-30 characters: letters, digits or underscore'),
    email: requiredString('Email')
      .trim()
      .toLowerCase()
      .max(254, 'Email is too long')
      .pipe(z.email('Invalid email address')),
    password: buildPasswordSchema(policy),
  })
  .superRefine(({ username, password }, ctx) => {
    // Only meaningful once both fields are otherwise usable.
    if (typeof password !== 'string' || !USERNAME_PATTERN.test(username)) return;
    if (password.toLowerCase().includes(username)) {
      ctx.addIssue({ code: 'custom', path: ['password'], message: 'Password must not contain your username' });
    }
  });

module.exports = { registerSchema, buildPasswordSchema, USERNAME_PATTERN };
