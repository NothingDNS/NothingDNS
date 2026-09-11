import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AddRecordDialog, EditRecordDialog } from './record-dialogs';

// TTL 0 is a legitimate DNS value (no caching). Both dialogs parsed the TTL
// with `parseInt(ttl) || 3600`, whose falsy-zero branch silently rewrote an
// explicit 0 to 3600 — an hour of caching the operator asked not to have.

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
});

describe('explicit TTL 0 must survive the save path', () => {
  it('AddRecordDialog sends ttl 0 instead of the 3600 default', async () => {
    const user = userEvent.setup();
    mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }));
    render(
      <AddRecordDialog
        open
        onClose={() => {}}
        zoneName="example.com."
        initialType="A"
        onSaved={() => {}}
      />,
    );

    await user.type(screen.getByLabelText('Name'), 'ttl0.example.com.');
    // The A record's Address input is the dialog's other textbox (TTL is a
    // number input, i.e. a spinbutton role).
    const address = screen
      .getAllByRole('textbox')
      .find((el) => el !== screen.getByLabelText('Name'));
    if (!address) throw new Error('address input not found');
    await user.type(address, '192.0.2.1');
    const ttl = screen.getByLabelText('TTL');
    await user.clear(ttl);
    await user.type(ttl, '0');
    await user.click(screen.getByRole('button', { name: 'Add Record' }));

    await waitForFetch();
    const body = JSON.parse(lastFetchBody());
    expect(body.ttl).toBe(0);
  });

  it('EditRecordDialog onSave receives ttl 0 instead of the 3600 default', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <EditRecordDialog
        open
        record={{ name: 'x.example.com.', type: 'A', ttl: 3600, class: 'IN', data: '192.0.2.1' }}
        onClose={() => {}}
        onSave={onSave}
      />,
    );

    const ttl = screen.getByDisplayValue('3600');
    await user.clear(ttl);
    await user.type(ttl, '0');
    await user.click(screen.getByRole('button', { name: 'Save Record' }));

    await vi.waitFor(() => expect(onSave).toHaveBeenCalled());
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ ttl: 0 }),
    );
  });
});

async function waitForFetch() {
  await vi.waitFor(() => expect(mockFetch).toHaveBeenCalled());
}

function lastFetchBody(): string {
  const call = mockFetch.mock.calls.at(-1);
  return typeof call?.[1]?.body === 'string' ? call[1].body : '';
}
