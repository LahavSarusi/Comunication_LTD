const crypto = require('node:crypto');
const { HMAC_SECRET } = require('../config/env');

const SALT_BYTES = 16; // 128-bit random salt -> 32 hex characters
const HMAC_ALGORITHM = 'sha256'; // 256-bit digest -> 64 hex characters

/** Unique, cryptographically secure random salt for a single user (CSPRNG). */
function generateSalt() {
  return crypto.randomBytes(SALT_BYTES).toString('hex');
}

/**
 * HMAC-SHA256(key = server secret from .env, message = salt + password).
 * The salt makes identical passwords produce different hashes; the secret key
 * means a stolen database alone is not enough to brute-force the hashes.
 */
function hashPassword(password, salt) {
  return crypto.createHmac(HMAC_ALGORITHM, HMAC_SECRET).update(salt + password, 'utf8').digest('hex');
}

/**
 * Constant-time comparison (timingSafeEqual) so response timing does not leak
 * how many leading bytes of the hash matched. Prepared for the login stage.
 */
function verifyPassword(password, salt, expectedHash) {
  const actual = Buffer.from(hashPassword(password, salt), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

module.exports = { generateSalt, hashPassword, verifyPassword };
