import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ClusterPage } from './cluster';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

const aliveNode = (id: string, addr: string, state = 'alive') => ({
  id, addr, port: 7946, state, region: 'us-east', zone: 'primary',
  weight: id === 'node-1' ? 1 : 0, http_addr: `${addr}:8080`, version: 1,
});

const sampleNodes = {
  nodes: [
    aliveNode('node-1', '10.0.0.1'),
    aliveNode('node-2', '10.0.0.2'),
    aliveNode('node-3', '10.0.0.3', 'dead'),
  ],
};

const sampleStatus = {
  node_id: 'node-1', consensus: 'raft',
  raft: { state: 'Leader', term: 5, commit_index: 100, applied_index: 100, is_leader: true, leader_id: 'node-1' },
};

beforeEach(() => {
  mockFetch.mockReset();
});

describe('ClusterPage', () => {
  it('renders loading skeleton initially', () => {
    mockFetch.mockReturnValue(new Promise(() => {}));
    render(<ClusterPage />);
    expect(screen.getByText('Cluster')).toBeInTheDocument();
  });

  it('renders cluster overview with nodes', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleNodes))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));
    render(<ClusterPage />);

    expect(await screen.findByText('3')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('Yes')).toBeInTheDocument();
    expect(screen.getByText('Quorum OK')).toBeInTheDocument();
  });

  it('ignores stale responses that resolve after a newer load', async () => {
    // load() has two overlapping triggers: the 10s polling interval and the
    // Refresh button. When an older load's response lands after a newer
    // load's, the stale data must NOT overwrite the fresh state — a cluster
    // page showing stale quorum/node data is operationally misleading.
    vi.useFakeTimers();
    try {
      // load1: the nodes request hangs (will resolve STALE later); status OK.
      let resolveStaleNodes!: (value: unknown) => void;
      mockFetch
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              resolveStaleNodes = resolve;
            }),
        )
        .mockImplementationOnce(() => mockJsonResponse(sampleStatus));
      render(<ClusterPage />);

      // 10s tick: the interval fires load2, whose responses are fresh.
      const freshNodes = {
        nodes: [
          aliveNode('node-1', '10.0.0.1'),
          aliveNode('node-2', '10.0.0.2'),
          aliveNode('node-3', '10.0.0.3', 'dead'),
          aliveNode('node-4', '10.0.0.4'),
          aliveNode('node-5', '10.0.0.5'),
        ],
      };
      mockFetch
        .mockImplementationOnce(() => mockJsonResponse(freshNodes))
        .mockImplementationOnce(() => mockJsonResponse(sampleStatus));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10000);
      });
      // Fresh alive-count '4' is unique to the fresh render (stale has 2
      // alive; raft "Term 5" makes '5' ambiguous, so never assert on '5').
      expect(screen.getByText('4')).toBeInTheDocument();

      // The stale load1 response finally lands. It must be ignored.
      resolveStaleNodes(mockJsonResponse(sampleNodes));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      // Stale alive-count '2' must never appear; fresh '4' must survive.
      expect(screen.queryByText('2')).not.toBeInTheDocument();
      expect(screen.getByText('4')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('renders no quorum when not enough alive nodes', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({
        nodes: [aliveNode('n1', '10.0.0.1', 'dead'), aliveNode('n2', '10.0.0.2', 'dead')],
      }))
      .mockResolvedValueOnce(mockJsonResponse(null));
    render(<ClusterPage />);

    expect(await screen.findByText('No Quorum')).toBeInTheDocument();
    expect(screen.getByText('No')).toBeInTheDocument();
  });

  it('renders Raft consensus section', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleNodes))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));
    render(<ClusterPage />);

    expect(await screen.findByText('Raft Consensus')).toBeInTheDocument();
    expect(screen.getAllByText('node-1').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('5')).toBeInTheDocument();
  });

  it('shows no nodes state', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ nodes: [] }))
      .mockResolvedValueOnce(mockJsonResponse(null));
    render(<ClusterPage />);

    expect(await screen.findByText('No nodes in cluster')).toBeInTheDocument();
  });

  it('renders error state when API fails', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'cluster err' }, 500))
      .mockResolvedValueOnce(mockJsonResponse({ error: 'cluster err' }, 500));
    render(<ClusterPage />);

    expect(await screen.findByText('cluster err')).toBeInTheDocument();
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('renders cluster topology section', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleNodes))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));
    render(<ClusterPage />);

    expect(await screen.findByText('Cluster Topology')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
  });

  it('expands node details on click', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse(sampleNodes))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));

    const user = userEvent.setup();
    render(<ClusterPage />);

    // Wait for data to render
    expect(await screen.findByText('Cluster Topology')).toBeInTheDocument();

    // Find and click the expandable button with "node-1" text
    const nodeButton = screen.getAllByRole('button').find(b =>
      b.textContent?.includes('node-1'),
    );
    expect(nodeButton).not.toBeUndefined();
    await user.click(nodeButton!);

    expect(screen.getByText('10.0.0.1:8080')).toBeInTheDocument();
  });

  it('retries loading after error', async () => {
    mockFetch
      .mockResolvedValueOnce(mockJsonResponse({ error: 'fail' }, 500))
      .mockResolvedValueOnce(mockJsonResponse({ error: 'fail' }, 500))
      .mockResolvedValueOnce(mockJsonResponse(sampleNodes))
      .mockResolvedValueOnce(mockJsonResponse(sampleStatus));

    const user = userEvent.setup();
    render(<ClusterPage />);

    expect(await screen.findByText('fail')).toBeInTheDocument();
    await user.click(screen.getByText('Retry'));

    // After retry, node details should appear
    expect(await screen.findByText('Cluster Topology')).toBeInTheDocument();
    expect(screen.getAllByText('node-1').length).toBeGreaterThanOrEqual(1);
  });
});
