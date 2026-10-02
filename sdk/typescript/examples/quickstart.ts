/**
 * NothingDNS SDK quick start.
 *
 * Logs in, checks health, lists zones and their records, and shows a record
 * write (gated behind NDNS_DEMO_WRITE so the default run is read-only).
 *
 * Usage:
 *   export NDNS_URL="http://dns.example.com:8080"
 *   export NDNS_USER="admin"
 *   export NDNS_PASSWORD="..."        # or NDNS_TOKEN for the static token
 *   npx tsx examples/quickstart.ts
 */

import {
  NothingDNSApiError,
  NothingDNSConnectionError,
  NothingDNSClient,
} from '../src/index.js';

async function main(): Promise<void> {
  const client = new NothingDNSClient({
    baseUrl: process.env.NDNS_URL ?? 'http://localhost:8080',
    timeoutMs: 15_000,
  });

  try {
    // 1. Health probe needs no authentication.
    const health = await client.health();
    console.log(`server health: ${health.status} at ${health.timestamp}`);

    // 2. Authenticate. NDNS_TOKEN short-circuits the login round trip.
    const token = process.env.NDNS_TOKEN;
    if (token) {
      client.setToken(token);
      console.log('using the static service token');
    } else {
      const username = process.env.NDNS_USER ?? 'admin';
      const password = process.env.NDNS_PASSWORD;
      if (!password) {
        console.error('set NDNS_PASSWORD (or NDNS_TOKEN) before running');
        process.exitCode = 2;
        return;
      }
      const session = await client.auth.login(username, password);
      console.log(`signed in as ${session.username} (role ${session.role})`);
    }

    // 3. Server status.
    const status = await client.status();
    console.log(`NothingDNS ${status.version} is ${status.status}`);

    // 4. Zones.
    const zones = await client.zones.list();
    console.log(`\n${zones.zones.length} zone(s):`);
    for (const zone of zones.zones) {
      console.log(`  ${zone.name.padEnd(30)} serial=${zone.serial} records=${zone.records}`);
    }

    const first = zones.zones[0];
    if (first) {
      const detail = await client.zones.get(first.name);
      if (detail.soa) {
        console.log(`\nSOA of ${detail.name}: ${detail.soa.mname} serial ${detail.soa.serial}`);
      }

      const records = await client.zones.listRecords(first.name);
      console.log(`\n${records.total} record(s) in ${first.name}:`);
      for (const record of records.records.slice(0, 10)) {
        console.log(`  ${record.name.padEnd(20)} ${record.type.padEnd(6)} ${String(record.ttl).padEnd(7)} ${record.data}`);
      }
      if (records.total > records.records.length) {
        console.log(`  … ${records.total - records.records.length} more (response truncated)`);
      }
    }

    // 5. Cache statistics (operator role and above).
    const cache = await client.cache.stats();
    console.log(
      `\ncache: ${cache.size}/${cache.capacity} entries, ` +
        `hit ratio ${(cache.hitRatio * 100).toFixed(1)}% ` +
        `(${cache.hits} hits / ${cache.misses} misses)`,
    );

    // 6. Optional write example — off by default so the quick start stays read-only.
    if (process.env.NDNS_DEMO_WRITE && first) {
      console.log(`\nadding a TXT record to ${first.name} …`);
      await client.zones.addRecord(first.name, 'sdk-demo', 'TXT', '"added by the NothingDNS SDK"', {
        ttl: 60,
      });
      console.log(`done — remove it again with:
    client.zones.deleteRecords(${JSON.stringify(first.name)}, 'sdk-demo', 'TXT')`);
    }
  } finally {
    // Nothing to close: the SDK holds no sockets beyond the platform fetch pool.
  }
}

main().catch((error: unknown) => {
  if (error instanceof NothingDNSApiError) {
    console.error(`API error ${error.statusCode}: ${error.message}`);
  } else if (error instanceof NothingDNSConnectionError) {
    console.error(`cannot reach NothingDNS: ${error.message}`);
  } else {
    console.error(error);
  }
  process.exitCode = 1;
});
