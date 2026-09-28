import { useState } from 'react';
import { ClusterPage } from '@/pages/cluster';
import { Button } from '@/components/ui/button';

const COUNTS = [3, 5, 8, 12];

const SAMPLE_ADDRS = [
  '195.142.135.122',
  '95.130.170.243',
  '185.29.123.82',
  '185.29.120.115',
  '185.81.236.228',
];

function fixture(count: number) {
  const nodes = Array.from({ length: count }, (_, i) => {
    const addr = SAMPLE_ADDRS[i] ?? `10.1.0.${i + 1}`;
    let state = 'alive';
    if (i === 2 && count > 2) state = 'dead';
    else if (i === count - 1 && count > 4) state = 'suspect';
    return {
      id: `node-${i + 1}`,
      addr,
      port: 7946,
      state,
      role: i === 0 ? 'leader' : 'follower',
      region: 'eu-central',
      zone: i % 2 === 0 ? 'a' : 'b',
      weight: i === 0 ? 1 : 0,
      http_addr: `${addr}:8080`,
      version: 1,
    };
  });
  const localId = nodes.some((n) => n.id === 'node-5') ? 'node-5' : nodes[nodes.length - 1].id;
  return {
    nodes,
    status: {
      node_id: localId,
      consensus: 'raft',
      raft: {
        state: 'Follower',
        term: 12,
        commit_index: 480,
        applied_index: 480,
        is_leader: false,
        leader_id: 'node-1',
      },
    },
  };
}

// Dev-only stand-in for the Cluster page so the membership layout can be
// reviewed without a running API. Vite drops this module from production
// builds because App imports it only when import.meta.env.DEV is true.
export function DevClusterPreview() {
  const [count, setCount] = useState(5);
  return (
    <div className="dark min-h-screen bg-background text-foreground">
      <div className="mx-auto max-w-6xl p-6">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <span className="text-sm text-muted-foreground">Preview</span>
          {COUNTS.map((n) => (
            <Button
              key={n}
              type="button"
              size="sm"
              variant={n === count ? 'default' : 'outline'}
              onClick={() => setCount(n)}
            >
              {n} nodes
            </Button>
          ))}
        </div>
        <ClusterPage key={count} preview={fixture(count)} />
      </div>
    </div>
  );
}
