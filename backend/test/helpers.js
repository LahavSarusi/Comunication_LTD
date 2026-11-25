// Shared setup for the API tests. Each test file runs in its own process (node --test),
// so each gets its own temporary SQLite file and its own random HMAC secret: the real
// backend/data/database.sqlite and the secret in backend/.env are never touched.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { after } = require('node:test');

const SRC_DIR = path.resolve(__dirname, '../src');
// A password that meets the policy in config/password-policy.json.
const DEFAULT_PASSWORD = 'Gr8t!Horizon#77';
const DB_FILE = path.join(os.tmpdir(), `communication-ltd-test-${process.pid}-${Date.now()}.sqlite`);

// Set before anything under src/ is loaded. dotenv never overrides existing variables.
process.env.NODE_ENV = 'test';
process.env.DB_STORAGE = DB_FILE;
process.env.HMAC_SECRET = crypto.randomBytes(32).toString('hex');
process.env.CORS_ORIGIN = 'http://localhost:5173';

after(() => {
  fs.rmSync(DB_FILE, { force: true });
});

/**
 * Starts a fresh copy of the API on a random port. The rate limiters keep their
 * counters in module memory, so each group of tests loads its own copy of src/
 * and gets its own budget of 10 requests per limiter.
 */
async function startApi() {
  for (const file of Object.keys(require.cache)) {
    if (file.startsWith(SRC_DIR)) delete require.cache[file];
  }
  const models = require('../src/models');
  const app = require('../src/app');
  await models.sequelize.sync();

  const server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  const base = `http://127.0.0.1:${server.address().port}/api/auth`;

  async function post(route, body, rawBody) {
    const response = await fetch(`${base}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: rawBody ?? JSON.stringify(body),
    });
    const text = await response.text();
    return { status: response.status, headers: response.headers, text, body: text ? JSON.parse(text) : null };
  }

  // Lockout state straight from the database (the model's default scope hides it).
  async function lockState(username) {
    const user = await models.User.scope('withCredentials').findOne({ where: { username } });
    return {
      failedLoginAttempts: user.failedLoginAttempts,
      lockedUntil: user.lockedUntil ? new Date(user.lockedUntil) : null,
      passwordHash: user.passwordHash,
    };
  }

  return {
    models,
    lockState,
    register: (username, password = DEFAULT_PASSWORD) => post('/register', { username, email: `${username}@example.com`, password }),
    login: (username, password) => post('/login', { username, password }),
    change: (body) => post('/change-password', body),
    changeRaw: (rawBody) => post('/change-password', null, rawBody),
    async stop() {
      await new Promise((resolve) => server.close(resolve));
      await models.sequelize.close();
    },
  };
}

module.exports = { startApi, DEFAULT_PASSWORD };
