// Account lockout on POST /api/auth/change-password. The lockout is shared with login
// (src/services/accountLockout.js), so both routes count against one per-account limit.
// Run with:  npm --prefix backend test
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApi, DEFAULT_PASSWORD } = require('./helpers');

const { policy } = require('../src/config/passwordPolicy');

const P0 = DEFAULT_PASSWORD;
const P1 = 'Blue-Kettle_42x!';
const P2 = 'Winter*Maple9Road';
const WRONG = 'Wrong!Pass#1234';

describe('change password: account lockout (shared with login)', () => {
  let api;
  before(async () => {
    api = await startApi();
    assert.equal(policy.maxLoginAttempts, 3, 'these tests are written for maxLoginAttempts = 3');
    assert.equal((await api.register('gina_lock')).status, 201);
  });
  after(() => api.stop());

  const wrong = () => api.change({ username: 'gina_lock', currentPassword: WRONG, newPassword: P1 });

  test(`${policy.maxLoginAttempts} wrong current passwords lock the account (401, 401, 423)`, async () => {
    assert.equal((await wrong()).status, 401);
    assert.equal((await wrong()).status, 401);

    const locking = await wrong();
    assert.equal(locking.status, 423);
    assert.match(locking.body.error, /Account is locked after too many failed attempts/);
    assert.equal(locking.headers.get('retry-after'), String(policy.lockoutMinutes * 60));

    const state = await api.lockState('gina_lock');
    assert.equal(state.failedLoginAttempts, policy.maxLoginAttempts);
    const minutesAhead = (state.lockedUntil.getTime() - Date.now()) / 60000;
    assert.ok(minutesAhead > policy.lockoutMinutes - 1 && minutesAhead <= policy.lockoutMinutes);
  });

  test('while locked, even the correct current password is refused and nothing changes', async () => {
    const beforeTry = await api.lockState('gina_lock');
    const res = await api.change({ username: 'gina_lock', currentPassword: P0, newPassword: P1 });
    assert.equal(res.status, 423);
    assert.ok(!res.text.includes(P0) && !res.text.includes(P1), 'passwords must not be echoed');
    const afterTry = await api.lockState('gina_lock');
    assert.equal(afterTry.passwordHash, beforeTry.passwordHash);
    assert.equal(afterTry.lockedUntil.getTime(), beforeTry.lockedUntil.getTime());
  });

  test('the lock is shared: login with the correct password is refused too', async () => {
    assert.equal((await api.login('gina_lock', P0)).status, 423);
  });

  test('after the lock expires, the correct current password works and the counter resets', async () => {
    // Move the lock into the past instead of waiting lockoutMinutes.
    await api.models.sequelize.query('UPDATE users SET locked_until = $past WHERE username = $username', {
      bind: { past: '2000-01-01 00:00:00.000 +00:00', username: 'gina_lock' },
    });
    const res = await api.change({ username: 'gina_lock', currentPassword: P0, newPassword: P1 });
    assert.equal(res.status, 200);
    const state = await api.lockState('gina_lock');
    assert.equal(state.failedLoginAttempts, 0);
    assert.equal(state.lockedUntil, null);
  });
});

describe('change password: lockout counter reset', () => {
  let api;
  before(async () => {
    api = await startApi();
    assert.equal((await api.register('hank_reset')).status, 201);
  });
  after(() => api.stop());

  const wrong = () => api.change({ username: 'hank_reset', currentPassword: WRONG, newPassword: P2 });

  test('a successful change before the limit resets failedLoginAttempts to 0', async () => {
    assert.equal((await wrong()).status, 401);
    assert.equal((await wrong()).status, 401);
    assert.equal((await api.lockState('hank_reset')).failedLoginAttempts, 2);

    const ok = await api.change({ username: 'hank_reset', currentPassword: P0, newPassword: P1 });
    assert.equal(ok.status, 200);
    const state = await api.lockState('hank_reset');
    assert.equal(state.failedLoginAttempts, 0);
    assert.equal(state.lockedUntil, null);

    // Two more wrong passwords are 401 again, not a lock: the count really started over.
    assert.equal((await wrong()).status, 401);
    assert.equal((await wrong()).status, 401);
  });

  test('a correct current password resets the counter even when the new password is refused', async () => {
    assert.equal((await api.lockState('hank_reset')).failedLoginAttempts, 2);
    const reused = await api.change({ username: 'hank_reset', currentPassword: P1, newPassword: P0 });
    assert.equal(reused.status, 400);
    assert.match(reused.body.fieldErrors.newPassword.join(' '), /used recently/);
    assert.equal((await api.lockState('hank_reset')).failedLoginAttempts, 0);
  });
});

describe('change password: parallel guesses cannot pass the limit', () => {
  let api;
  before(async () => {
    api = await startApi();
    assert.equal((await api.register('ivy_parallel')).status, 201);
  });
  after(() => api.stop());

  test('8 wrong current passwords at once: at most maxLoginAttempts - 1 are 401, the rest 423', async () => {
    const requests = Array.from({ length: 8 }, (_, i) =>
      api.change({ username: 'ivy_parallel', currentPassword: `Wrong!Pass#${i}x`, newPassword: P1 }),
    );
    const statuses = (await Promise.all(requests)).map((res) => res.status);
    assert.ok(statuses.every((status) => status === 401 || status === 423), statuses.join(','));
    assert.ok(statuses.filter((status) => status === 401).length <= policy.maxLoginAttempts - 1, statuses.join(','));

    const state = await api.lockState('ivy_parallel');
    assert.ok(state.lockedUntil && state.lockedUntil.getTime() > Date.now());
  });
});
