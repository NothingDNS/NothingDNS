import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { toast } from 'sonner';
import { ZoneEditor } from './index';

// DELETE /api/v1/zones/{z}/records with `data` deletes exactly that one
// record (200) or answers 404 when no record matches; mutations can also be
// refused with 409 (CNAME conflict / duplicate) or 400 (SOA, apex NS).
//
// F434: a failed single delete (e.g. 404, the record was already removed by
// another operator) left the stale row on screen because the list was only
// reloaded on success, and a failed bulk delete dropped the server's reason.
// F435: renaming a record is delete-old + add-new; when the add was refused
// (409 CNAME conflict / duplicate, 400) the old record had already been
// deleted, silently losing it. The old record must be restored.

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function json(data: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json' },
  }));
}

const records = [
  { name: 'a1.example.com.', type: 'A', ttl: 300, class: 'IN', data: '192.0.2.1' },
  { name: 'a1.example.com.', type: 'A', ttl: 300, class: 'IN', data: '192.0.2.2' },
];

type Handler = (body: Record<string, unknown>) => Promise<Response>;
let onDelete: Handler;
let onPost: Handler;

function calls(method: string): Record<string, unknown>[] {
  return mockFetch.mock.calls
    .filter(([, init]) => (init as RequestInit).method === method)
    .map(([, init]) => JSON.parse((init as RequestInit).body as string));
}

beforeEach(() => {
  mockFetch.mockReset();
  vi.mocked(toast.error).mockReset();
  vi.mocked(toast.success).mockReset();
  onDelete = () => json({ message: 'Record deleted' });
  onPost = () => json({ message: 'Record added' }, 201);
  mockFetch.mockImplementation((_url: string, init: RequestInit) => {
    const body = JSON.parse((init.body as string) ?? '{}');
    if (init.method === 'DELETE') return onDelete(body);
    if (init.method === 'POST') return onPost(body);
    return json({});
  });
});

describe('single-record delete', () => {
  it('sends the record data so only that record is deleted (200)', async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn();
    render(<ZoneEditor zoneName="example.com." initialRecords={records} onRefresh={onRefresh} />);
    await user.click(screen.getAllByLabelText('Delete A record a1.example.com.')[1]);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalled());
    expect(calls('DELETE')).toEqual([{ name: 'a1.example.com.', type: 'A', data: '192.0.2.2' }]);
    expect(toast.error).not.toHaveBeenCalled();
  });

  it('F434: surfaces a 404 and reloads the stale list', async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn();
    onDelete = () => json({ error: 'record not found: a1.example.com. A 192.0.2.1' }, 404);
    render(<ZoneEditor zoneName="example.com." initialRecords={records} onRefresh={onRefresh} />);
    await user.click(screen.getAllByLabelText('Delete A record a1.example.com.')[0]);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('record not found: a1.example.com. A 192.0.2.1'));
    await waitFor(() => expect(onRefresh).toHaveBeenCalled());
  });

  it('F434: bulk delete reports the server reason for each failure', async () => {
    const user = userEvent.setup();
    onDelete = (b) => b.data === '192.0.2.1'
      ? json({ error: 'the zone apex NS RRset cannot be deleted; update the NS record instead' }, 400)
      : json({ message: 'Record deleted' });
    render(<ZoneEditor zoneName="example.com." initialRecords={records} onRefresh={() => {}} />);
    await user.click(screen.getByLabelText('Select all visible records'));
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalled());
    const msg = String(vi.mocked(toast.error).mock.calls[0][0]);
    expect(msg).toContain('A a1.example.com.');
    expect(msg).toContain('the zone apex NS RRset cannot be deleted');
  });
});

describe('F435: rename (delete + add) refused by the server', () => {
  it('restores the original record when the add is refused with 409', async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn();
    onPost = (b) => b.name === 'www.example.com.'
      ? json({ error: 'CNAME conflict: www.example.com. already has a CNAME record' }, 409)
      : json({ message: 'Record added' }, 201);
    render(<ZoneEditor zoneName="example.com." initialRecords={records} onRefresh={onRefresh} />);
    await user.click(screen.getAllByLabelText('Edit A record a1.example.com.')[0]);
    const nameInput = screen.getByDisplayValue('a1.example.com.');
    await user.clear(nameInput);
    await user.type(nameInput, 'www.example.com.');
    await user.click(screen.getByRole('button', { name: 'Save Record' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('CNAME conflict');
    expect(calls('DELETE')).toEqual([{ name: 'a1.example.com.', type: 'A', data: '192.0.2.1' }]);
    const posts = calls('POST');
    expect(posts).toHaveLength(2);
    expect(posts[1]).toEqual({ name: 'a1.example.com.', type: 'A', ttl: 300, data: '192.0.2.1' });
    await waitFor(() => expect(onRefresh).toHaveBeenCalled());
  });
});
