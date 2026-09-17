import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ACLPage } from './acl';
import { useAuthStore } from '@/stores/authStore';
import { toast } from 'sonner';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function json(data: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }));
}

const aclData = {
  rules: [{ name: 'block-bad', action: 'deny', networks: ['198.51.100.0/24'] }],
  allow_recursion: { allow_all: false, networks: ['127.0.0.0/8', '192.168.0.0/16'] },
  persistent: true,
  policy_file: '/var/lib/nothingdns/access_policy.json',
};

function putBodies() {
  return mockFetch.mock.calls
    .filter(([, init]) => (init as RequestInit | undefined)?.method === 'PUT')
    .map(([url, init]) => ({ url: String(url), body: JSON.parse(String((init as RequestInit).body)) }));
}

beforeEach(() => {
  mockFetch.mockReset();
  vi.mocked(toast.success).mockReset();
  vi.mocked(toast.error).mockReset();
  useAuthStore.setState({ token: 't', username: 'admin', role: 'admin', isAuthenticated: true });
});

describe('ACLPage', () => {
  it('shows the recursion allow list and the general ACL rules', async () => {
    mockFetch.mockResolvedValueOnce(json(aclData));
    render(<ACLPage />);

    const list = await screen.findByRole('list', { name: 'Recursion allow list' });
    expect(within(list).getByText('127.0.0.0/8')).toBeInTheDocument();
    expect(within(list).getByText('192.168.0.0/16')).toBeInTheDocument();
    expect(screen.getByText('block-bad')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.0/24')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('adds a network with PUT /api/v1/acl/recursion', async () => {
    mockFetch
      .mockResolvedValueOnce(json(aclData))
      .mockResolvedValueOnce(json({ allow_all: false, networks: ['127.0.0.0/8', '192.168.0.0/16', '203.0.113.5/32'] }));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'Recursion allow list' });

    await userEvent.type(screen.getByLabelText('Network to allow recursion'), '203.0.113.5');
    await userEvent.click(screen.getByRole('button', { name: /add$/i }));

    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(putBodies()[0]).toEqual({
      url: '/api/v1/acl/recursion',
      body: { networks: ['127.0.0.0/8', '192.168.0.0/16', '203.0.113.5'] },
    });
    expect(await screen.findByText('203.0.113.5/32')).toBeInTheDocument();
    expect(screen.getByLabelText('Network to allow recursion')).toHaveValue('');
  });

  it('rejects an invalid network without calling the API', async () => {
    mockFetch.mockResolvedValueOnce(json(aclData));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'Recursion allow list' });

    await userEvent.type(screen.getByLabelText('Network to allow recursion'), 'example.com');
    await userEvent.click(screen.getByRole('button', { name: /add$/i }));

    expect(toast.error).toHaveBeenCalled();
    expect(putBodies()).toHaveLength(0);
  });

  it('removes a network', async () => {
    mockFetch
      .mockResolvedValueOnce(json(aclData))
      .mockResolvedValueOnce(json({ allow_all: false, networks: ['127.0.0.0/8'] }));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'Recursion allow list' });

    await userEvent.click(screen.getByRole('button', { name: 'Remove 192.168.0.0/16' }));

    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(putBodies()[0].body).toEqual({ networks: ['127.0.0.0/8'] });
    await waitFor(() => expect(screen.queryByText('192.168.0.0/16')).not.toBeInTheDocument());
  });

  it('asks for confirmation before removing the last network', async () => {
    mockFetch
      .mockResolvedValueOnce(json({ ...aclData, allow_recursion: { allow_all: false, networks: ['127.0.0.0/8'] } }))
      .mockResolvedValueOnce(json({ allow_all: false, networks: [] }));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'Recursion allow list' });

    await userEvent.click(screen.getByRole('button', { name: 'Remove 127.0.0.0/8' }));
    expect(await screen.findByText('Remove the last network?')).toBeInTheDocument();
    expect(putBodies()).toHaveLength(0);

    await userEvent.click(screen.getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(putBodies()[0].body).toEqual({ networks: [] });
    expect(await screen.findByText('No client may use recursion')).toBeInTheDocument();
  });

  it('warns before opening recursion to every client', async () => {
    mockFetch.mockResolvedValueOnce(json(aclData));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'Recursion allow list' });

    await userEvent.type(screen.getByLabelText('Network to allow recursion'), '0.0.0.0/0');
    await userEvent.click(screen.getByRole('button', { name: /add$/i }));

    expect(await screen.findByText('Allow recursion for every client?')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(putBodies()).toHaveLength(0);
  });

  it('is read-only for non-admin users', async () => {
    useAuthStore.setState({ role: 'operator' });
    mockFetch.mockResolvedValueOnce(json(aclData));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'Recursion allow list' });

    expect(screen.queryByLabelText('Network to allow recursion')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /remove/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Add ACL rule' })).not.toBeInTheDocument();
    expect(screen.getByText('Only administrators can change the recursion allow list.')).toBeInTheDocument();
    expect(screen.getByText('Only administrators can change ACL rules.')).toBeInTheDocument();
  });

  it('warns when changes are not persisted', async () => {
    mockFetch.mockResolvedValueOnce(json({ ...aclData, persistent: false, policy_file: '' }));
    render(<ACLPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent('storage.data_dir');
  });

  it('shows the all-clients state', async () => {
    mockFetch.mockResolvedValueOnce(json({ ...aclData, allow_recursion: { allow_all: true, networks: [] } }));
    render(<ACLPage />);
    expect(await screen.findByText('All clients')).toBeInTheDocument();
  });

  it('adds an ACL rule with PUT /api/v1/acl', async () => {
    const after = {
      ...aclData,
      rules: [
        ...aclData.rules,
        { name: 'allow-lan', action: 'allow', networks: ['192.168.0.0/16'] },
      ],
    };
    mockFetch
      .mockResolvedValueOnce(json(aclData))
      .mockResolvedValueOnce(json({ message: 'ACL rules updated' }))
      .mockResolvedValueOnce(json(after));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'ACL rules' });

    await userEvent.type(screen.getByLabelText('Rule name'), 'allow-lan');
    await userEvent.type(screen.getByLabelText('Rule networks'), '192.168.0.0/16');
    await userEvent.click(screen.getByRole('button', { name: /add rule/i }));

    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(putBodies()[0]).toEqual({
      url: '/api/v1/acl',
      body: {
        rules: [
          { name: 'block-bad', action: 'deny', networks: ['198.51.100.0/24'] },
          { name: 'allow-lan', action: 'allow', networks: ['192.168.0.0/16'] },
        ],
      },
    });
    expect(await screen.findByText('allow-lan')).toBeInTheDocument();
  });

  it('asks for confirmation before adding the first ACL rule', async () => {
    const empty = { ...aclData, rules: [] };
    const after = {
      ...empty,
      rules: [{ name: 'allow-lan', action: 'allow', networks: ['10.0.0.0/8'] }],
    };
    mockFetch
      .mockResolvedValueOnce(json(empty))
      .mockResolvedValueOnce(json({ message: 'ACL rules updated' }))
      .mockResolvedValueOnce(json(after));
    render(<ACLPage />);
    await screen.findByText('No ACL rules configured');

    await userEvent.type(screen.getByLabelText('Rule name'), 'allow-lan');
    await userEvent.type(screen.getByLabelText('Rule networks'), '10.0.0.0/8');
    await userEvent.click(screen.getByRole('button', { name: /add rule/i }));

    expect(await screen.findByText('Add the first ACL rule?')).toBeInTheDocument();
    expect(putBodies()).toHaveLength(0);

    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(await screen.findByText('allow-lan')).toBeInTheDocument();
  });

  it('deletes an ACL rule after confirmation', async () => {
    const after = { ...aclData, rules: [] };
    mockFetch
      .mockResolvedValueOnce(json(aclData))
      .mockResolvedValueOnce(json({ message: 'ACL rules updated' }))
      .mockResolvedValueOnce(json(after));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'ACL rules' });

    await userEvent.click(screen.getByRole('button', { name: 'Delete block-bad' }));
    expect(await screen.findByText('Delete rule "block-bad"?')).toBeInTheDocument();
    expect(putBodies()).toHaveLength(0);

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(putBodies()[0].body).toEqual({ rules: [] });
    expect(await screen.findByText('No ACL rules configured')).toBeInTheDocument();
  });

  it('edits an ACL rule', async () => {
    const after = {
      ...aclData,
      rules: [{ name: 'block-bad', action: 'deny', networks: ['198.51.100.0/24', '203.0.113.0/24'] }],
    };
    mockFetch
      .mockResolvedValueOnce(json(aclData))
      .mockResolvedValueOnce(json({ message: 'ACL rules updated' }))
      .mockResolvedValueOnce(json(after));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'ACL rules' });

    await userEvent.click(screen.getByRole('button', { name: 'Edit block-bad' }));
    expect(screen.getByLabelText('Rule networks')).toHaveValue('198.51.100.0/24');
    await userEvent.clear(screen.getByLabelText('Rule networks'));
    await userEvent.type(screen.getByLabelText('Rule networks'), '198.51.100.0/24, 203.0.113.0/24');
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }));

    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(putBodies()[0].body.rules[0].networks).toEqual(['198.51.100.0/24', '203.0.113.0/24']);
    expect(await screen.findByText('203.0.113.0/24')).toBeInTheDocument();
  });

  it('reorders ACL rules', async () => {
    const twoRules = {
      ...aclData,
      rules: [
        { name: 'first', action: 'allow', networks: ['10.0.0.0/8'] },
        { name: 'second', action: 'deny', networks: ['192.0.2.0/24'] },
      ],
    };
    const reordered = {
      ...aclData,
      rules: [
        { name: 'second', action: 'deny', networks: ['192.0.2.0/24'] },
        { name: 'first', action: 'allow', networks: ['10.0.0.0/8'] },
      ],
    };
    mockFetch
      .mockResolvedValueOnce(json(twoRules))
      .mockResolvedValueOnce(json({ message: 'ACL rules updated' }))
      .mockResolvedValueOnce(json(reordered));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'ACL rules' });

    await userEvent.click(screen.getByRole('button', { name: 'Move first down' }));

    await waitFor(() => expect(putBodies()).toHaveLength(1));
    expect(putBodies()[0].body.rules.map((r: { name: string }) => r.name)).toEqual(['second', 'first']);
  });

  it('requires a domain redirect target', async () => {
    mockFetch.mockResolvedValueOnce(json(aclData));
    render(<ACLPage />);
    await screen.findByRole('list', { name: 'ACL rules' });

    await userEvent.type(screen.getByLabelText('Rule name'), 'sinkhole');
    await userEvent.selectOptions(screen.getByLabelText('Rule action'), 'redirect');
    await userEvent.type(screen.getByLabelText('Rule networks'), '10.0.0.0/8');
    await userEvent.type(screen.getByLabelText('Redirect target'), '1.2.3.4');
    await userEvent.click(screen.getByRole('button', { name: /add rule/i }));

    expect(toast.error).toHaveBeenCalled();
    expect(putBodies()).toHaveLength(0);
  });
});
