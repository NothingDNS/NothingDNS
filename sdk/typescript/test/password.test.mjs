/**
 * Contract tests for issue #18 (POST /api/v1/auth/password and
 * PUT /api/v1/auth/users/{username}) and the per-name cache flush
 * (POST /api/v1/cache/flush?name=).
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { NothingDNSClient, NothingDNSValidationError, isBadRequest, isConflict } from '../dist/index.js';
import { PASSWORD, ROTATED_TOKEN, TOKEN, createMockServer } from './mock-server.mjs';

const mock = await createMockServer();

after(async () => {
  await mock.close();
});

function authedClient() {
  const client = new NothingDNSClient({ baseUrl: mock.baseUrl, timeoutMs: 5000 });
  client.setToken(TOKEN);
  return client;
}

describe('password and user updates', () => {
  it('changePassword() switches to the rotated token', async () => {
    const client = authedClient();
    const session = await client.auth.changePassword(PASSWORD, 'new-password-1');
    assert.equal(session.token, ROTATED_TOKEN);
    assert.equal(client.token, ROTATED_TOKEN);
    assert.equal(mock.last.method, 'POST');
    assert.equal(mock.last.path, '/api/v1/auth/password');
    assert.deepEqual(mock.last.body, { old_password: PASSWORD, new_password: 'new-password-1' });

    const wrong = await client.auth.changePassword('wrong', 'new-password-2').catch((e) => e);
    assert.equal(isBadRequest(wrong), true);
    assert.equal(client.token, ROTATED_TOKEN, 'token kept after a failure');
  });

  it('updateUser() sends only the given fields', async () => {
    const client = authedClient();
    const user = await client.auth.updateUser('ops', { role: 'admin' });
    assert.equal(user.role, 'admin');
    assert.equal(mock.last.method, 'PUT');
    assert.equal(mock.last.path, '/api/v1/auth/users/ops');
    assert.deepEqual(mock.last.body, { role: 'admin' });

    const conflict = await client.auth.updateUser('root', { password: 'reset-pass-123' }).catch((e) => e);
    assert.equal(isConflict(conflict), true);

    const before = mock.requests.length;
    const empty = await client.auth.updateUser('ops', {}).catch((e) => e);
    assert.ok(empty instanceof NothingDNSValidationError);
    const badRole = await client.auth.updateUser('ops', { role: 'root' }).catch((e) => e);
    assert.ok(badRole instanceof NothingDNSValidationError);
    assert.equal(mock.requests.length, before, 'no request sent');
  });

  it('cache.flushName() sends ?name=', async () => {
    const client = authedClient();
    await client.cache.flushName('www.example.com').catch(() => {});
    assert.equal(mock.last.method, 'POST');
    assert.equal(mock.last.path, '/api/v1/cache/flush?name=www.example.com');

    const before = mock.requests.length;
    const empty = await client.cache.flushName('').catch((e) => e);
    assert.ok(empty instanceof NothingDNSValidationError);
    assert.equal(mock.requests.length, before, 'no request sent');
  });
});
