/**
 * Poll a NothingDNS server and print a compact health line.
 *
 * Usage:
 *   export NDNS_URL="http://dns.example.com:8080"
 *   export NDNS_TOKEN="..."          # operator or admin role
 *   npx tsx examples/monitor.ts --interval 10 --count 12
 */

import {
  NothingDNSApiError,
  NothingDNSClient,
} from '../src/index.js';

function numericFlag(name: string, fallback: number): number {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return fallback;
  const value = Number(process.argv[index + 1]);
  return Number.isFinite(value) ? value : fallback;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function main(): Promise<void> {
  const intervalSec = numericFlag('interval', 10);
  const count = numericFlag('count', 0); // 0 = forever

  const token = process.env.NDNS_TOKEN;
  const username = process.env.NDNS_USER;
  const password = process.env.NDNS_PASSWORD;
  if (!token && !(username && password)) {
    console.error('set NDNS_TOKEN, or NDNS_USER + NDNS_PASSWORD');
    process.exitCode = 2;
    return;
  }

  const client = new NothingDNSClient({
    baseUrl: process.env.NDNS_URL ?? 'http://localhost:8080',
    timeoutMs: 10_000,
  });

  if (token) {
    client.setToken(token);
  } else {
    await client.auth.login(username!, password!);
  }

  let failures = 0;
  for (let poll = 1; count === 0 || poll <= count; poll += 1) {
    try {
      const [stats, cache, cluster] = await Promise.all([
        client.dashboard.stats(),
        client.cache.stats(),
        client.cluster.status(),
      ]);
      const blocked = stats.blockedQueries ? ` blocked=${stats.blockedQueries}` : '';
      const role = cluster.raft?.isLeader ? 'leader' : 'follower';
      console.log(
        `[${String(poll).padStart(4)}] up=${stats.uptime}s ` +
          `qps=${stats.queriesPerSecond.toFixed(1)} ` +
          `cache=${cache.size}/${cache.capacity} hit=${(cache.hitRatio * 100).toFixed(0)}% ` +
          `clients=${stats.activeClients} ` +
          `nodes=${cluster.aliveCount}/${cluster.nodeCount} (${role})${blocked}`,
      );
      failures = 0;
    } catch (error) {
      failures += 1;
      if (error instanceof NothingDNSApiError) {
        console.error(`[${String(poll).padStart(4)}] API error ${error.statusCode}: ${error.message}`);
      } else {
        console.error(`[${String(poll).padStart(4)}] ${String(error)}`);
      }
    }

    if (count === 0 || poll < count) {
      await sleep(intervalSec * 1000);
    }
  }

  if (failures > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
