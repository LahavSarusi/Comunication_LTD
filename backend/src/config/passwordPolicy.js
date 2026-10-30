const fs = require('node:fs');
const path = require('node:path');
const { z } = require('zod');

// Administrator-editable policy file. Changes take effect after a server restart.
const POLICY_FILE = path.resolve(__dirname, '../../config/password-policy.json');

const policySchema = z
  .strictObject({
    minLength: z.int().min(8).max(128),
    maxLength: z.int().min(8).max(1024),
    complexity: z.strictObject({
      uppercase: z.boolean(),
      lowercase: z.boolean(),
      digits: z.boolean(),
      specialChars: z.boolean(),
    }),
    // Number of previous passwords a user may not reuse (enforced by change-password).
    historyCount: z.int().min(0).max(24),
    dictionary: z.strictObject({
      enabled: z.boolean(),
      words: z.array(z.string().trim().toLowerCase().min(3)).max(10000),
    }),
    // Failed logins allowed before the account is locked (enforced by login).
    maxLoginAttempts: z.int().min(1).max(100),
  })
  .refine((policy) => policy.maxLength >= policy.minLength, {
    message: 'maxLength must be greater than or equal to minLength',
    path: ['maxLength'],
  });

function fail(message) {
  console.error(`Invalid password policy (${POLICY_FILE}):\n${message}`);
  process.exit(1);
}

function deepFreeze(value) {
  for (const child of Object.values(value)) {
    if (child && typeof child === 'object') deepFreeze(child);
  }
  return Object.freeze(value);
}

function loadPolicy() {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(POLICY_FILE, 'utf8'));
  } catch (err) {
    return fail(err.message);
  }

  const result = policySchema.safeParse(raw);
  if (!result.success) return fail(z.prettifyError(result.error));

  return deepFreeze(result.data);
}

const policy = loadPolicy();

// Only what the browser needs to show and pre-check the rules. The dictionary and
// login-attempt limit stay server-side so they are not handed to attackers.
const publicPolicy = deepFreeze({
  minLength: policy.minLength,
  maxLength: policy.maxLength,
  complexity: { ...policy.complexity },
});

module.exports = { policy, publicPolicy };
