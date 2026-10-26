/**
 * Contract tests for issue #19 (GET/PUT /api/v1/zones/{zone}/soa and SOA
 * timers on POST /api/v1/zones).
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { NothingDNSClient, NothingDNSValidationError, isBadRequest } from '../dist/index.js';
import { TOKEN, createMockServer } from './mock-server.mjs';

const mock = await createMockServer();

after(async () => {
  await mock.close();
});

function authedClient() {
  const client = new NothingDNSClient({ baseUrl: mock.baseUrl, timeoutMs: 5000 });
  client.setToken(TOKEN);
  return client;
}

describe('SOA edits', () => {
  it('getSOA() and updateSOA() send only the given fields', async () => {
    const client = authedClient();
    const soa = await client.zones.getSOA('example.com');
    assert.equal(soa.ttl, 3600);
    assert.equal(mock.last.path, '/api/v1/zones/example.com/soa');

    const updated = await client.zones.updateSOA('example.com', { rname: 'dns@example.com', minimum: 60 });
    assert.equal(updated.serial, 8);
    assert.equal(updated.rname, 'dns.example.com.');
    assert.equal(updated.minimum, 60);
    assert.equal(mock.last.method, 'PUT');
    assert.equal(mock.last.path, '/api/v1/zones/example.com/soa');
    assert.deepEqual(mock.last.body, { rname: 'dns@example.com', minimum: 60 });

    const refused = await client.zones.updateSOA('example.com', { retry: 3600 }).catch((e) => e);
    assert.equal(isBadRequest(refused), true);

    const before = mock.requests.length;
    await assert.rejects(client.zones.updateSOA('example.com', {}), NothingDNSValidationError);
    assert.equal(mock.requests.length, before, 'no request sent');
  });

  it('create() sends the SOA timers', async () => {
    const client = authedClient();
    await client.zones.create('new.example', ['ns1.new.example'], { refresh: 7200, minimum: 300 }).catch(() => {});
    assert.deepEqual(mock.last.body, {
      name: 'new.example', nameservers: ['ns1.new.example'], refresh: 7200, minimum: 300,
    });
  });
});
