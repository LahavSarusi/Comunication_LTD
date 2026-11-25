// End-to-end tests for POST /api/auth/change-password.
// Run with:  npm --prefix backend test      (Node's built-in test runner, no extra packages)
// Setup (temporary database, own HMAC secret, fresh API per group) is in ./helpers.js.
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApi, DEFAULT_PASSWORD } = require('./helpers');

const { policy } = require('../src/config/passwordPolicy');

const P0 = DEFAULT_PASSWORD;
const P1 = 'Blue-Kettle_42x!';
const P2 = 'Winter*Maple9Road';
const P3 = 'Copper&Lantern31z';
const P4 = 'Orbit$Velvet58Kite';
const WRONG = 'Wrong!Pass#1234';

describe('change password: success and credentials', () => {
  let api;
  before(async () => {
    api = await startApi();
  });
  after(() => api.stop());

  test('valid current password and compliant new password -> 200, stored as a new salt + hash', async () => {
    assert.equal((await api.register('alice_ok')).status, 201);
    const before = await api.models.User.scope('withCredentials').findOne({ where: { username: 'alice_ok' } });

    const res = await api.change({ username: 'alice_ok', currentPassword: P0, newPassword: P1 });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { message: 'Password changed successfully' });

    const afterChange = await api.models.User.scope('withCredentials').findOne({ where: { username: 'alice_ok' } });
    assert.notEqual(afterChange.salt, before.salt);
    assert.notEqual(afterChange.passwordHash, before.passwordHash);
    assert.match(afterChange.passwordHash, /^[0-9a-f]{64}$/);
    assert.equal(await api.models.PasswordHistory.count({ where: { userId: afterChange.id } }), 2);
  });

  test('the old password stops working and the new one works', async () => {
    const withOld = await api.change({ username: 'alice_ok', currentPassword: P0, newPassword: P2 });
    assert.equal(withOld.status, 401);
    const withNew = await api.change({ username: 'alice_ok', currentPassword: P1, newPassword: P2 });
    assert.equal(withNew.status, 200);
  });

  test('username is normalized (case and surrounding spaces)', async () => {
    const res = await api.change({ username: '  ALICE_OK ', currentPassword: P2, newPassword: P3 });
    assert.equal(res.status, 200);
  });

  test('wrong current password and unknown user get the same 401', async () => {
    const wrong = await api.change({ username: 'alice_ok', currentPassword: 'Wrong!Pass#1234', newPassword: P4 });
    const unknown = await api.change({ username: 'nobody_here', currentPassword: P0, newPassword: P4 });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.deepEqual(wrong.body, { error: 'Invalid username or password' });
    assert.deepEqual(unknown.body, wrong.body);
  });
});

describe('change password: history', () => {
  let api;
  before(async () => {
    api = await startApi();
  });
  after(() => api.stop());

  const reusedBody = (res) => res.body.fieldErrors.newPassword.join(' ');

  test(`cannot reuse the current password or any of the last ${policy.historyCount} passwords`, async () => {
    assert.equal(policy.historyCount, 3, 'this test is written for historyCount = 3');
    assert.equal((await api.register('bob_hist')).status, 201);
    const change = (currentPassword, newPassword) => api.change({ username: 'bob_hist', currentPassword, newPassword });

    assert.equal((await change(P0, P1)).status, 200);

    const backToFirst = await change(P1, P0);
    assert.equal(backToFirst.status, 400);
    assert.match(reusedBody(backToFirst), /used recently/);

    const sameAsCurrent = await change(P1, P1);
    assert.equal(sameAsCurrent.status, 400);
    assert.match(reusedBody(sameAsCurrent), /used recently/);

    assert.equal((await change(P1, P2)).status, 200);
    assert.equal((await change(P2, P3)).status, 200);

    // History is now P0, P1, P2, P3. The last three are P1, P2, P3.
    assert.equal((await change(P3, P1)).status, 400);
    assert.equal((await change(P3, P2)).status, 400);

    // P0 is the fourth most recent password, so it is allowed again.
    assert.equal((await change(P3, P0)).status, 200);
  });

  test('a rejected change leaves the password and the history untouched', async () => {
    const user = await api.models.User.findOne({ where: { username: 'bob_hist' } });
    assert.equal(await api.models.PasswordHistory.count({ where: { userId: user.id } }), 5);
    assert.equal((await api.change({ username: 'bob_hist', currentPassword: P0, newPassword: P4 })).status, 200);
  });
});

describe('change password: weak new passwords', () => {
  let api;
  before(async () => {
    api = await startApi();
    assert.equal((await api.register('carol_weak')).status, 201);
  });
  after(() => api.stop());

  const cases = [
    ['too short', 'Ab1!xyz'],
    ['no uppercase letter', 'lowercase-only1!'],
    ['no lowercase letter', 'UPPERCASE-ONLY1!'],
    ['no digit', 'NoDigits-Here!!'],
    ['no special character', 'NoSpecials12345'],
    ['dictionary word', 'MyPassword#2026'],
    ['contains the username', 'Xx!Carol_Weak-99'],
    ['longer than maxLength', `Aa1!${'x'.repeat(policy.maxLength)}`],
  ];

  for (const [name, newPassword] of cases) {
    test(`${name} -> 400, nothing echoed back`, async () => {
      const res = await api.change({ username: 'carol_weak', currentPassword: P0, newPassword });
      assert.equal(res.status, 400);
      assert.ok(res.body.fieldErrors.newPassword.length > 0);
      assert.ok(!res.text.includes(newPassword), 'the response must not contain the submitted password');
      assert.ok(!res.text.includes(P0), 'the response must not contain the current password');
    });
  }

  test('the password was not changed by any of them', async () => {
    assert.equal((await api.change({ username: 'carol_weak', currentPassword: P0, newPassword: P1 })).status, 200);
  });
});

describe('change password: injection and malformed input', () => {
  let api;
  before(async () => {
    api = await startApi();
    assert.equal((await api.register('dave_inj')).status, 201);
  });
  after(() => api.stop());

  test('SQL injection in username -> 400 (allowlist)', async () => {
    // Each group has a budget of 10 requests (the rate limit); this group uses exactly 10.
    for (const username of ["' OR 1=1--", 'x"; DROP TABLE users;--']) {
      const res = await api.change({ username, currentPassword: P0, newPassword: P1 });
      assert.equal(res.status, 400);
      assert.ok(res.body.fieldErrors.username.length > 0);
    }
  });

  test('SQL injection in currentPassword is plain data -> 401, password unchanged', async () => {
    const res = await api.change({ username: 'dave_inj', currentPassword: "' OR '1'='1' --", newPassword: P1 });
    assert.equal(res.status, 401);
  });

  test('XSS payload in username -> 400 and is not reflected', async () => {
    const payload = '<script>alert(1)</script>';
    const res = await api.change({ username: payload, currentPassword: P0, newPassword: P1 });
    assert.equal(res.status, 400);
    assert.ok(!res.text.includes('<script>'));
  });

  test('operator objects instead of strings -> 400', async () => {
    for (const field of ['username', 'currentPassword', 'newPassword']) {
      const body = { username: 'dave_inj', currentPassword: P0, newPassword: P1, [field]: { $gt: '' } };
      const res = await api.change(body);
      assert.equal(res.status, 400, `${field} as an object`);
      assert.match(res.body.fieldErrors[field].join(' '), /must be a text value/);
    }
  });

  test('unknown keys (mass assignment) and missing fields -> 400', async () => {
    const extra = await api.change({ username: 'dave_inj', currentPassword: P0, newPassword: P1, salt: '00' });
    assert.equal(extra.status, 400);
    const missing = await api.change({ username: 'dave_inj' });
    assert.equal(missing.status, 400);
  });

  test('malformed JSON -> 400 generic message', async () => {
    const res = await api.changeRaw('{"username": "dave_inj",');
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'Invalid request body' });
  });

  test('the users table survived and the original password still works', async () => {
    assert.ok((await api.models.User.count()) >= 1);
    assert.equal((await api.change({ username: 'dave_inj', currentPassword: P0, newPassword: P1 })).status, 200);
  });
});

describe('change password: rate limit', () => {
  let api;
  before(async () => {
    api = await startApi();
  });
  after(() => api.stop());

  test('the 11th attempt within the window -> 429', async () => {
    const attempt = () => api.change({ username: 'nobody_here', currentPassword: P0, newPassword: P1 });
    for (let i = 0; i < 10; i += 1) assert.equal((await attempt()).status, 401);
    const blocked = await attempt();
    assert.equal(blocked.status, 429);
    assert.deepEqual(blocked.body, { error: 'Too many password change attempts, please try again later' });
  });
});
