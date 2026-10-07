/**
 * Contract tests for the API surface changed in phase 2 (F554): the
 * config_defined flag on GET /api/v1/auth/users, single-record delete
 * (DELETE /zones/{zone}/records with data, 404 when nothing matches) and the
 * 400/409 answers the server gives for refused input.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import {
  NothingDNSApiError,
  NothingDNSClient,
  NothingDNSValidationError,
  isBadRequest,
  isConflict,
  isNotFound,
} from '../dist/index.js';
import { TOKEN, createMockServer } from './mock-server.mjs';

const mock = await createMockServer();
const client = new NothingDNSClient({ baseUrl: mock.baseUrl, timeoutMs: 5000 });
client.setToken(TOKEN);

after(async () => {
  await mock.close();
});

describe('phase-2 API contract', () => {
  it('listUsers() decodes config_defined', async () => {
    const users = await client.auth.listUsers();
    assert.equal(users.length, 2);
    assert.equal(users[0].configDefined, true);
    assert.equal(users[1].configDefined, false);
  });

  it('deleteRecord() sends data and maps a miss to 404', async () => {
    const message = await client.zones.deleteRecord('example.com', 'api', 'A', '192.0.2.9');
    assert.equal(message, 'records deleted');
    assert.equal(mock.last.method, 'DELETE');
    assert.equal(mock.last.path, '/api/v1/zones/example.com/records');
    assert.deepEqual(mock.last.body, { name: 'api', type: 'A', data: '192.0.2.9' });

    const miss = await client.zones.deleteRecord('example.com', 'api', 'A', '192.0.2.250').catch((e) => e);
    assert.equal(isNotFound(miss), true);

    const before = mock.requests.length;
    const blank = await client.zones.deleteRecord('example.com', 'api', 'A', '  ').catch((e) => e);
    assert.ok(blank instanceof NothingDNSValidationError, 'blank data would widen to the whole RRset');
    assert.equal(mock.requests.length, before, 'no request sent for blank data');
  });

  it('409 maps to isConflict, 400 to isBadRequest', async () => {
    const conflict = await client.auth.deleteUser('root').catch((e) => e);
    assert.ok(conflict instanceof NothingDNSApiError);
    assert.equal(conflict.statusCode, 409);
    assert.equal(conflict.message, 'user is defined in the config file; change it there');
    assert.equal(isConflict(conflict), true);
    assert.equal(isBadRequest(conflict), false);

    const bad = await client.upstreams.add('9.9.9.9').catch((e) => e);
    assert.equal(bad.statusCode, 400);
    assert.equal(isBadRequest(bad), true);
    assert.equal(isConflict(bad), false);

    assert.equal(isConflict(new Error('nope')), false);
    assert.equal(isBadRequest(undefined), false);
  });
});
