const { z } = require('zod');
const { policy } = require('../config/passwordPolicy');
const { USERNAME_PATTERN } = require('./userSchemas');

// Only real strings are accepted; objects, arrays and numbers fail here.
function requiredString(label) {
  return z.string({
    error: (issue) => (issue.input === undefined ? `${label} is required` : `${label} must be a text value`),
  });
}

// strictObject: unknown keys are rejected. Every field must be a string, which blocks
// operator/type-confusion payloads such as {"username": {"$gt": ""}}.
// The username gets the same allowlist as registration, so input like "x' OR 1=1--"
// is rejected before any database query runs.
// The password is NOT checked against the complexity rules: it only has to match the
// stored hash. It is limited in length (no huge inputs) and never trimmed or altered.
const loginSchema = z.strictObject({
  username: requiredString('Username')
    .trim()
    .toLowerCase()
    .regex(USERNAME_PATTERN, 'Username must be 3-30 characters: letters, digits or underscore'),
  password: requiredString('Password')
    .min(1, 'Password is required')
    .max(policy.maxLength, `Password must be at most ${policy.maxLength} characters`),
});

module.exports = { loginSchema };
