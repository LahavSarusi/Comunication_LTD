// Regression tests for POST /api/auth/login, whose lockout code lives in
// src/services/accountLockout.js (shared with change password).
// Run with:  npm --prefix backend test
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApi, DEFAULT_PASSWORD } = require('./helpers');

const { policy } = require('../src/config/passwordPolicy');

const WRONG = 'Wrong!Pass#1234';

describe('login: credentials and lockout', () => {
  let api;
  before(async () => {
    api = await startApi();
    assert.equal(policy.maxLoginAttempts, 3, 'these tests are written for maxLoginAttempts = 3');
    assert.equal((await api.register('lena_login')).status, 201);
    assert.equal((await api.register('omar_login')).status, 201);
  });
  after(() => api.stop());

  test('correct password -> 200 with only id, username and email', async () => {
    const res = await api.login('LENA_LOGIN', DEFAULT_PASSWORD);
    assert.equal(res.status, 200);
    assert.deepEqual(Object.keys(res.body.user).sort(), ['email', 'id', 'username']);
  });

  test('unknown user and wrong password get the same 401', async () => {
    const unknown = await api.login('nobody_here', DEFAULT_PASSWORD);
    const wrong = await api.login('omar_login', WRONG);
    assert.equal(unknown.status, 401);
    assert.equal(wrong.status, 401);
    assert.deepEqual(unknown.body, wrong.body);
  });

  test('a correct login after a failure resets the counter', async () => {
    assert.equal((await api.lockState('omar_login')).failedLoginAttempts, 1);
    assert.equal((await api.login('omar_login', DEFAULT_PASSWORD)).status, 200);
    assert.equal((await api.lockState('omar_login')).failedLoginAttempts, 0);
  });

  test('wrong passwords lock the account (401, 401, 423) and the correct one is then refused', async () => {
    assert.equal((await api.login('lena_login', WRONG)).status, 401);
    assert.equal((await api.login('lena_login', WRONG)).status, 401);
    const locking = await api.login('lena_login', WRONG);
    assert.equal(locking.status, 423);
    assert.ok(locking.headers.get('retry-after'));
    assert.equal((await api.login('lena_login', DEFAULT_PASSWORD)).status, 423);
  });
});
