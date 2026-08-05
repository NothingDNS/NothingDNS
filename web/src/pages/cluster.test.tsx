import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
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
