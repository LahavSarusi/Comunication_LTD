const path = require('node:path');
const dotenv = require('dotenv');
const { z } = require('zod');

// Load backend/.env no matter which directory the process was started from.
dotenv.config({ path: path.resolve(__dirname, '../../.env'), quiet: true });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  HOST: z.string().min(1).default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  // Normalized to a bare origin ("http://host:port") because CORS compares it exactly.
  CORS_ORIGIN: z.url({ protocol: /^https?$/ }).transform((value) => new URL(value).origin),
  DB_STORAGE: z.string().min(1).default('./data/database.sqlite'),
  HMAC_SECRET: z
    .string({ error: 'HMAC_SECRET is missing - see backend/.env.example' })
    .min(32, 'HMAC_SECRET must be at least 32 characters - see backend/.env.example'),
});

const result = envSchema.safeParse(process.env);

// Fail fast: never start the server with a missing or weak secret.
if (!result.success) {
  console.error(`Invalid environment configuration (backend/.env):\n${z.prettifyError(result.error)}`);
  process.exit(1);
}

module.exports = Object.freeze(result.data);
