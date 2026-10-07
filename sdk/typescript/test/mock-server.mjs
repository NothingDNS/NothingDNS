/**
 * In-process mock NothingDNS API for the SDK test suite.
 *
 * Implements the response shapes of the real management API contract
 * (NothingDNS 1.2.17) for the endpoints the suite exercises, and records every
 * request so tests can assert on methods, paths, bodies and headers.
 */
import http from 'node:http';

export const USERNAME = 'admin';
export const PASSWORD = 'correct';
export const TOKEN = 'tok-123';
export const SERVICE_TOKEN = `${TOKEN}-service`;

const ZONE_FILE = '$ORIGIN example.com.\n@ IN SOA ns1 hostmaster 7 3600 600 86400 300\n';

/** Create and start a mock server; `await createMockServer()` then `await mock.close()`. */
export async function createMockServer() {
  /** @type {Array<{method: string, path: string, body: any, auth: string | undefined}>} */
  const requests = [];

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString();
      const body = raw ? JSON.parse(raw) : undefined;
      const path = req.url ?? '/';
      const route = path.split('?')[0];
      requests.push({ method: req.method, path, body, auth: req.headers.authorization });

      const json = (code, payload) => {
        const out = JSON.stringify(payload);
        res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(out) });
        res.end(out);
      };
      const text = (code, payload) => {
        res.writeHead(code, { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(payload) });
        res.end(payload);
      };

      switch (route) {
        case '/health':
        case '/readyz':
        case '/livez':
          return json(200, { status: 'healthy', timestamp: '2026-10-02T11:00:00Z' });
        case '/api/v1/auth/login':
          if (body.password !== PASSWORD) return json(401, { error: 'invalid credentials' });
          return json(200, { token: TOKEN, username: USERNAME, role: 'admin', expires: '2026-10-02T12:00:00Z' });
        case '/api/v1/auth/logout':
          return json(200, { message: 'logged out' });
        case '/api/v1/status':
          return json(200, {
            status: 'running', timestamp: 't', version: '1.2.17',
            cache: { size: 3, capacity: 100, hits: 9, misses: 1, hit_ratio: 0.9 },
            cluster: { enabled: false, node_id: 'n1', node_count: 1, alive_count: 1, healthy: true },
          });
        case '/api/v1/zones':
          return json(200, { zones: [{ name: 'example.com', serial: 7, records: 3 }], total: 1, truncated: false });
        case '/api/v1/zones/example.com/records':
          if (req.method === 'GET') {
            return json(200, {
              records: [{ name: 'www', type: 'A', ttl: 300, class: 'IN', data: '192.0.2.1' }],
              total: 1, truncated: false,
            });
          }
          if (req.method === 'POST') return json(201, { message: 'record added' });
          if (req.method === 'PUT') return json(200, { message: 'record replaced' });
          // Single-record delete (F419): 404 when no record carries the data.
          if (body?.data === '192.0.2.250') return json(404, { error: 'record not found: api A 192.0.2.250' });
          return json(200, { message: 'records deleted' });
        case '/api/v1/zones/example.com/export':
          return text(200, ZONE_FILE);
        case '/api/v1/zones/missing.com':
          return json(404, { error: 'Zone missing.com not found' });
        case '/api/v1/zones/2.0.192.in-addr.arpa/ptr-bulk':
          return json(200, {
            preview: true, total: 256, willAdd: 256, willAddA: 0, willSkip: 0, willOverride: 0,
            changes: [{ name: '1', type: 'PTR', ttl: 300, data: 'host-192-0-2-1.example.com', action: 'add' }],
          });
        case '/api/v1/acl':
          if (req.method === 'GET') {
            return json(200, {
              rules: [{ name: 'office', networks: ['10.0.0.0/8'], action: 'allow', types: ['A'], redirect: '' }],
              allow_recursion: { allow_all: false, networks: ['10.0.0.0/8'] },
              persistent: true, policy_file: '/var/lib/nothingdns/access_policy.json',
            });
          }
          return json(200, { message: 'acl updated' });
        case '/api/v1/acl/recursion':
          return json(200, { allow_all: false, networks: ['10.0.0.0/8'] });
        case '/api/v1/config/logging':
          return json(200, { message: 'log level updated' });
        default:
          break;
      }

      if (route.startsWith('/api/v1/config/')) return json(200, { message: 'config updated' });

      switch (route) {
        case '/api/dashboard/queries':
          return json(200, [{
            timestamp: 't', clientIp: '10.0.0.5', countryCode: 'NL', domain: 'example.com',
            queryType: 'A', responseCode: 'NOERROR', answers: ['192.0.2.1'],
            duration: 1, cached: true, blocked: false, protocol: 'udp',
          }]);
        case '/api/v1/queries':
          return json(200, {
            queries: [{
              timestamp: 't', client_ip: '10.0.0.5', domain: 'example.com', query_type: 'A',
              response_code: 'NOERROR', answers: ['192.0.2.1'], duration_ms: 1,
              cached: true, blocked: false, protocol: 'udp',
            }],
            total: 1, offset: 0, limit: 50,
          });
        case '/api/v1/auth/users':
          return json(200, [
            { username: 'root', role: 'admin', created_at: '2026-10-01T00:00:00Z', config_defined: true },
            { username: 'ops', role: 'operator', created_at: '2026-10-02T00:00:00Z', config_defined: false },
          ]);
        case '/api/v1/auth/users/root':
          return json(409, { error: 'user is defined in the config file; change it there' });
        case '/api/v1/upstreams':
          if (req.method === 'PUT' && !String(body?.server ?? '').includes(':')) {
            return json(400, { error: 'server must be host:port' });
          }
          if (req.method === 'GET') {
            return json(200, {
              upstreams: [{ address: '9.9.9.9:53', healthy: true, queries: 5, failed: 0, failovers: 0 }],
              servers: [{ address: '9.9.9.9:53', healthy: true, latency_ms: 12.5 }],
            });
          }
          return json(200, { message: 'upstream added' });
        case '/api/v1/zones/transfers':
          return json(200, {
            slave_zones: [{
              zone: 'sub.example.com', masters: '192.0.2.53', serial: 3,
              last_transfer: '2026-10-01T00:00:00Z', status: 'synced', records: 12,
            }],
          });
        case '/api/v1/dnssec/status':
          return json(200, { enabled: true, require_dnssec: false });
        case '/api/v1/dnssec/keys':
          return json(403, { error: 'admin role required' });
        case '/api/v1/cache/flush':
          return json(429, { error: 'rate limited' });
        default:
          return json(404, { error: 'not found' });
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { address, port } = server.address();

  return {
    requests,
    get last() {
      return requests.at(-1);
    },
    baseUrl: `http://${address}:${port}`,
    close() {
      return new Promise((resolve) => server.close(resolve));
    },
  };
}
