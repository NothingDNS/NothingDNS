/**
 * Error translation and predicate-helper tests.
 *
 * Exercises the 401/403/404/429 mappings, the predicate helpers, the ack
 * message parsing and connection failures against the in-process mock API.
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { after, describe, it } from 'node:test';

import {
  NothingDNSApiError,
  NothingDNSClient,
  NothingDNSConnectionError,
  NothingDNSValidationError,
  isForbidden,
  isNotFound,
  isRateLimited,
  isUnauthorized,
} from '../dist/index.js';
import { PASSWORD, TOKEN, createMockServer } from './mock-server.mjs';

const mock = await createMockServer();
const client = new NothingDNSClient({ baseUrl: mock.baseUrl, timeoutMs: 5000 });

after(async () => {
  await mock.close();
});

describe('status predicates', () => {
  it('401 maps to isUnauthorized with the server message', async () => {
    const error = await client.auth.login('admin', 'wrong').catch((e) => e);

    assert.ok(error instanceof NothingDNSApiError);
    assert.equal(error.statusCode, 401);
    assert.equal(error.message, 'invalid credentials');
    assert.deepEqual(error.payload, { error: 'invalid credentials' });
    assert.equal(isUnauthorized(error), true);
    assert.equal(isForbidden(error), false);
  });

  it('403 maps to isForbidden', async () => {
    client.setToken(TOKEN);
    const error = await client.dnssec.keys().catch((e) => e);

    assert.equal(error.statusCode, 403);
    assert.equal(isForbidden(error), true);
  });

  it('429 maps to isRateLimited', async () => {
    const error = await client.cache.flush().catch((e) => e);

    assert.equal(error.statusCode, 429);
    assert.equal(isRateLimited(error), true);
  });

  it('404 maps to isNotFound', async () => {
    const error = await client.zones.get('missing.com').catch((e) => e);

    assert.equal(isNotFound(error), true);
    assert.ok(error.message.includes('missing.com'));
  });

  it('predicates reject non-API errors', () => {
    assert.equal(isNotFound(new Error('nope')), false);
    assert.equal(isUnauthorized(null), false);
    assert.equal(isForbidden(404), false);
    assert.equal(isRateLimited(undefined), false);
  });
});

describe('error shapes', () => {
  it('stringifies as "NothingDNS API error <code>: <message>"', () => {
    const error = new NothingDNSApiError(409, 'zone already exists');

    assert.match(String(error), /409/);
    assert.match(String(error), /zone already exists/);
  });

  it('local validation failures raise NothingDNSValidationError', async () => {
    await assert.rejects(client.acl.set([]), NothingDNSValidationError);
    await assert.rejects(client.config.setLogging('loud'), NothingDNSValidationError);
  });
});

describe('acknowledgement parsing', () => {
  it('expectJson:false endpoints surface the server message', async () => {
    client.setToken(TOKEN);

    // acl.set and upstreams.add hit 200 {"message": …} ack endpoints on the mock.
    assert.equal(
      await client.acl.set([{ name: 'a', networks: ['0.0.0.0/0'], action: 'allow' }]),
      'acl updated',
    );
    assert.equal(await client.upstreams.add('1.1.1.1:53'), 'upstream added');
  });

  it('login still rejects bad passwords', async () => {
    await assert.rejects(
      client.auth.login('admin', `${PASSWORD}-wrong`),
      (error) => isUnauthorized(error) && error.message === 'invalid credentials',
    );
  });
});

describe('connection failures', () => {
  it('unreachable servers raise NothingDNSConnectionError', async () => {
    // Bind a port, note it, then release it so connections are refused.
    const probe = net.createServer();
    await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const deadPort = probe.address().port;
    await new Promise((resolve) => probe.close(resolve));

    const dead = new NothingDNSClient({ baseUrl: `http://127.0.0.1:${deadPort}`, timeoutMs: 2000 });

    await assert.rejects(dead.health(), (error) => {
      assert.ok(error instanceof NothingDNSConnectionError);
      assert.match(error.message, /Could not reach NothingDNS/);
      return true;
    });
  });
});
