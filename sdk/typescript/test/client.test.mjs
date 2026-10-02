/**
 * Behavioural tests for the NothingDNSClient against an in-process mock API.
 *
 * Mirrors the request-level contract: paths, methods, query strings, JSON
 * bodies, bearer-auth propagation and camelCase/snake_case model mapping.
 * Runs against the built `dist/` output (`npm test` builds first via pretest).
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import {
  NothingDNSClient,
  NothingDNSValidationError,
  isNotFound,
} from '../dist/index.js';
import { PASSWORD, SERVICE_TOKEN, TOKEN, USERNAME, createMockServer } from './mock-server.mjs';

const mock = await createMockServer();
const client = new NothingDNSClient({ baseUrl: mock.baseUrl, timeoutMs: 5000 });

after(async () => {
  await mock.close();
});

describe('health and authentication', () => {
  it('health() needs no authentication', async () => {
    const health = await client.health();
    assert.equal(health.status, 'healthy');
    assert.equal(mock.last.auth, undefined);
  });

  it('login() stores the token; the next request carries it', async () => {
    const session = await client.auth.login(USERNAME, PASSWORD);

    assert.equal(session.role, 'admin');
    assert.equal(session.expires, '2026-10-02T12:00:00Z');
    assert.equal(client.token, TOKEN);
    // The login request itself must not carry a token; the next one must.
    assert.equal(mock.last.auth, undefined);
    await client.status();
    assert.equal(mock.last.auth, `Bearer ${TOKEN}`);
  });

  it('login(storeToken: false) keeps the token off the client', async () => {
    // A fresh client: storeToken:false never clears a previously stored token.
    const fresh = new NothingDNSClient({ baseUrl: mock.baseUrl, timeoutMs: 5000 });

    const session = await fresh.auth.login(USERNAME, PASSWORD, { storeToken: false });

    assert.equal(session.token, TOKEN);
    assert.equal(fresh.token, null);
  });

  it('setToken() is used for subsequent requests', async () => {
    client.setToken(SERVICE_TOKEN);
    await client.status();
    assert.equal(mock.last.auth, `Bearer ${SERVICE_TOKEN}`);
  });

  it('logout() parses the acknowledgement message', async () => {
    assert.equal(await client.auth.logout(), 'logged out');
  });
});

describe('status models', () => {
  it('decodes nested snake_case into camelCase', async () => {
    const status = await client.status();

    assert.equal(status.version, '1.2.17');
    assert.equal(status.cache.hitRatio, 0.9);
    assert.equal(status.cluster.enabled, false);
    assert.equal(status.cluster.nodeId, 'n1');
  });
});

describe('zones and records', () => {
  it('list() decodes zones', async () => {
    const zones = await client.zones.list();

    assert.equal(zones.total, 1);
    assert.equal(zones.truncated, false);
    assert.equal(zones.zones[0].name, 'example.com');
    assert.equal(zones.zones[0].serial, 7);
  });

  it('record CRUD sends contract bodies and methods', async () => {
    const records = await client.zones.listRecords('example.com');
    assert.equal(records.records[0].data, '192.0.2.1');
    assert.equal(records.records[0].class, 'IN');

    await client.zones.addRecord('example.com', 'api', 'A', '192.0.2.9', { ttl: 60 });
    assert.equal(mock.last.method, 'POST');
    assert.equal(mock.last.path, '/api/v1/zones/example.com/records');
    assert.deepEqual(mock.last.body, { name: 'api', type: 'A', data: '192.0.2.9', ttl: 60 });

    await client.zones.replaceRecord('example.com', 'api', 'A', '192.0.2.9', '192.0.2.10');
    assert.equal(mock.last.method, 'PUT');
    assert.equal(mock.last.body.old_data, '192.0.2.9');

    await client.zones.deleteRecords('example.com', 'api', 'A');
    assert.equal(mock.last.method, 'DELETE');
    assert.deepEqual(mock.last.body, { name: 'api', type: 'A' });
  });

  it('export() returns the raw zone-file text', async () => {
    client.setToken(TOKEN);
    const text = await client.zones.export('example.com');
    assert.ok(text.startsWith('$ORIGIN example.com.'));
  });

  it('ptrBulk() keeps the wire camelCase keys and decodes the preview', async () => {
    const preview = await client.zones.ptrBulk(
      '2.0.192.in-addr.arpa',
      '192.0.2.0/24',
      'host-{ip}.example.com',
    );

    assert.equal(preview.preview, true);
    assert.equal(preview.willAdd, 256);
    assert.equal(preview.changes[0].data, 'host-192-0-2-1.example.com');
    assert.equal(mock.last.body.addA, false);
    assert.equal(mock.last.body.preview, true);
  });

  it('transfers() decodes slave zones', async () => {
    const slaves = await client.zones.transfers();

    assert.equal(slaves[0].zone, 'sub.example.com');
    assert.equal(slaves[0].status, 'synced');
    assert.equal(slaves[0].records, 12);
  });
});

describe('acl', () => {
  it('round-trips rules and the recursion list', async () => {
    const acl = await client.acl.get();
    assert.equal(acl.rules[0].action, 'allow');
    assert.deepEqual(acl.rules[0].networks, ['10.0.0.0/8']);
    assert.equal(acl.allowRecursion.allowAll, false);
    assert.equal(acl.persistent, true);

    await client.acl.set([...acl.rules, { name: 'vpn', networks: ['10.1.0.0/16'], action: 'deny' }]);
    assert.deepEqual(mock.last.body.rules.at(-1), {
      name: 'vpn',
      networks: ['10.1.0.0/16'],
      action: 'deny',
    });

    const recursion = await client.acl.setRecursion(['10.0.0.0/8']);
    assert.deepEqual(recursion.networks, ['10.0.0.0/8']);
  });
});

describe('configuration', () => {
  it('partial updates drop undefined fields and parse the message', async () => {
    const message = await client.config.setLogging('debug');

    assert.equal(message, 'log level updated');
    assert.equal(mock.last.method, 'PUT');
    assert.deepEqual(mock.last.body, { level: 'debug' });

    await client.config.setCache({ size: 5000, serveStale: true });
    assert.deepEqual(mock.last.body, { size: 5000, serve_stale: true });

    await client.config.setResolution({ recursive: true, edns0BufferSize: 1232 });
    assert.equal(mock.last.body.edns0_buffer_size, 1232);
  });
});

describe('dashboard and metrics', () => {
  it('dashboard events keep their camelCase wire names', async () => {
    const events = await client.dashboard.queries();

    assert.equal(events[0].clientIp, '10.0.0.5');
    assert.equal(events[0].countryCode, 'NL');
    assert.equal(events[0].cached, true);
  });

  it('queryLog() sends params and maps snake_case payload', async () => {
    const page = await client.metrics.queryLog({ limit: 50, q: 'example' });

    assert.equal(mock.last.path, '/api/v1/queries?limit=50&q=example');
    assert.equal(page.queries[0].clientIp, '10.0.0.5');
    assert.equal(page.total, 1);
  });
});

describe('upstreams', () => {
  it('lists latency and adds servers', async () => {
    const pool = await client.upstreams.list();
    assert.equal(pool.servers[0].latencyMs, 12.5);

    await client.upstreams.add('1.1.1.1:53');
    assert.deepEqual(mock.last.body, { action: 'add', server: '1.1.1.1:53' });
  });
});

describe('local validation', () => {
  const cases = [
    ['empty acl list', () => client.acl.set([])],
    ['unknown log level', () => client.config.setLogging('loud')],
    ['blocklist without a source', () => client.blocklists.add({})],
    [
      'blocklist with both sources',
      () => client.blocklists.add({ file: 'a.hosts', url: 'https://example.invalid/hosts' }),
    ],
    ['unknown role', () => client.auth.createUser('ops', 'pw-op-1', 'root')],
    ['unknown rpz action', () => client.rpz.addRule('ads.example.com', 'DENY')],
    ['zone without nameservers', () => client.zones.create('example.com', [])],
  ];

  for (const [name, call] of cases) {
    it(`rejects ${name} before sending anything`, async () => {
      await assert.rejects(call, NothingDNSValidationError);
      assert.equal(mock.requests.length > 0, true); // mock alive
      const countBefore = mock.requests.length;
      await call().catch(() => {});
      assert.equal(mock.requests.length, countBefore); // nothing was sent
    });
  }
});

describe('request mechanics', () => {
  it('escapes path segments', async () => {
    await assert.rejects(client.zones.get('weird zone/name'), isNotFound);
    assert.ok(mock.last.path.includes('%20'));
    assert.ok(mock.last.path.includes('%2F'));
  });

  it('normalises a trailing slash in the base URL', async () => {
    const client2 = new NothingDNSClient({ baseUrl: `${mock.baseUrl}/`, timeoutMs: 5000 });

    assert.equal(client2.baseUrl, mock.baseUrl);
    assert.equal((await client2.health()).status, 'healthy');
  });
});
