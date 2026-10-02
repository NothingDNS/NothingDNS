/**
 * Idempotent zone provisioning with NothingDNS.
 *
 * Creates a zone if it is missing and reconciles a desired set of records against
 * what the server already has. Run with `--dry-run` to see the diff without
 * touching the server.
 *
 * Usage:
 *   export NDNS_URL="http://dns.example.com:8080"
 *   export NDNS_USER="admin"
 *   export NDNS_PASSWORD="..."
 *   npx tsx examples/provisionZone.ts example.com \
 *     --nameserver ns1.example.com --nameserver ns2.example.com \
 *     --record "www A 192.0.2.1" \
 *     --record "@ TXT 'v=spf1 mx -all'"
 */

import {
  isNotFound,
  NothingDNSApiError,
  NothingDNSClient,
  type NothingDNSApiError as ApiError,
} from '../src/index.js';

interface DesiredRecord {
  name: string;
  type: string;
  data: string;
  ttl: number;
}

/** Parse `name TYPE data [ttl]` — the data may contain spaces (e.g. TXT). */
function parseRecord(raw: string): DesiredRecord {
  const parts = raw.split(/\s+/, 4);
  if (parts.length < 3) {
    throw new Error(`invalid record ${JSON.stringify(raw)}; expected 'name TYPE data [ttl]'`);
  }
  const [name, type, data, ttl] = parts;
  return {
    name,
    type: type.toUpperCase(),
    data,
    ttl: ttl && /^\d+$/.test(ttl) ? Number(ttl) : 3600,
  };
}

function flag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

function values(name: string): string[] {
  const collected: string[] = [];
  for (let i = 0; i < process.argv.length; i += 1) {
    if (process.argv[i] === `--${name}` && process.argv[i + 1]) {
      collected.push(process.argv[i + 1]);
    }
  }
  return collected;
}

async function main(): Promise<void> {
  const positionals = process.argv.slice(2).filter((arg) => !arg.startsWith('--'));
  const zone = positionals[0];
  if (!zone) {
    console.error("usage: provisionZone.ts <zone> --nameserver NS [--nameserver NS] [--record 'name TYPE data'] [--dry-run]");
    process.exitCode = 2;
    return;
  }

  const nameservers = values('nameserver');
  if (nameservers.length === 0) {
    console.error('at least one --nameserver is required');
    process.exitCode = 2;
    return;
  }

  const desired = values('record').map(parseRecord);
  const dryRun = flag('dry-run');
  const changes: string[] = [];

  const client = new NothingDNSClient({
    baseUrl: process.env.NDNS_URL ?? 'http://localhost:8080',
    timeoutMs: 20_000,
  });

  const token = process.env.NDNS_TOKEN;
  if (token) {
    client.setToken(token);
  } else {
    const password = process.env.NDNS_PASSWORD;
    if (!password) {
      console.error('set NDNS_PASSWORD (or NDNS_TOKEN) before running');
      process.exitCode = 2;
      return;
    }
    await client.auth.login(process.env.NDNS_USER ?? 'admin', password);
  }

  // 1. Make sure the zone exists.
  try {
    const detail = await client.zones.get(zone);
    console.log(`zone ${detail.name} exists (serial ${detail.serial}, ${detail.records} records)`);
  } catch (error) {
    if (!isNotFound(error as ApiError)) throw error;
    console.log(`zone ${zone} does not exist yet`);
    if (dryRun) {
      changes.push(`create zone ${zone}`);
    } else {
      await client.zones.create(zone, nameservers, {
        adminEmail: values('admin-email')[0],
        ttl: Number(values('ttl')[0] ?? 3600),
      });
      console.log(`  created with NS ${nameservers.join(', ')}`);
    }
  }

  if (desired.length === 0) {
    console.log('no records requested');
    return;
  }

  // 2. Reconcile the desired records against the current ones.
  const existing = (await client.zones.listRecords(zone)).records;
  const have = new Set(existing.map((record) => `${record.name}|${record.type}|${record.data}`));

  for (const { name, type, data, ttl } of desired) {
    if (have.has(`${name}|${type}|${data}`)) {
      console.log(`  ok       ${name} ${type} ${data}`);
      continue;
    }
    // A different value for the same (name, type) means "replace".
    const current = existing.find((record) => record.name === name && record.type === type);
    if (current) {
      changes.push(`replace ${name} ${type} ${current.data} -> ${data}`);
      if (!dryRun) {
        await client.zones.replaceRecord(zone, name, type, current.data, data, { ttl });
        console.log(`  replaced ${name} ${type} ${current.data} -> ${data}`);
      }
    } else {
      changes.push(`add ${name} ${type} ${data}`);
      if (!dryRun) {
        await client.zones.addRecord(zone, name, type, data, { ttl });
        console.log(`  added    ${name} ${type} ${data} (ttl ${ttl})`);
      }
    }
  }

  if (dryRun) {
    console.log(`\ndry run — ${changes.length} change(s) would be applied:`);
    for (const change of changes) console.log(`  - ${change}`);
  } else {
    console.log(`\napplied ${changes.length} change(s)`);
  }
}

main().catch((error: unknown) => {
  if (error instanceof NothingDNSApiError) {
    console.error(`API error ${error.statusCode}: ${error.message}`);
  } else {
    console.error(error);
  }
  process.exitCode = 1;
});
