import { it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ZoneEditor } from './index';

// Bulk-selection visibility guard.
//
// selectedRecords stores REAL row indexes (so filtering can never redirect
// a delete to the wrong row), but it must not silently keep rows that the
// current filter has hidden: the bulk-delete banner kept counting hidden
// rows ("1 selected" with zero visible checkmarks), the select-all
// checkbox reported checked from that same count, and confirming the
// delete destroyed records the operator could no longer see. The guard
// drops filter-hidden rows from the selection.

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const records = [
  { name: 'a1.example.com.', type: 'A', ttl: 300, class: 'IN', data: '192.0.2.1' },
  { name: 'a2.example.com.', type: 'A', ttl: 300, class: 'IN', data: '192.0.2.2' },
  { name: 't1.example.com.', type: 'TXT', ttl: 300, class: 'IN', data: '"hello"' },
];

beforeEach(() => {
  mockFetch.mockReset();
});

it('drops filter-hidden records from the bulk selection', async () => {
  const user = userEvent.setup();
  render(<ZoneEditor zoneName="example.com." initialRecords={records} onRefresh={() => {}} />);

  // Select the first A record while every row is visible.
  await user.click(screen.getByLabelText('Select A record a1.example.com.'));
  expect(screen.getByText('1 selected')).toBeInTheDocument();

  // Filter to TXT: the selected A record is now hidden, and its stale
  // selection must be dropped rather than kept for the bulk action.
  await user.selectOptions(screen.getByLabelText('Filter by record type'), 'TXT');

  expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Select all visible records')).not.toBeChecked();
});

// Falsy-zero guard: the inline TTL edit uses parseInt(v, 10) || r.ttl, so an
// operator typing an explicit 0 (a legitimate DNS TTL — no caching) got the
// record's previous TTL back. The committed PUT must carry ttl 0.
it('preserves an explicit TTL 0 in the inline edit', async () => {
  const user = userEvent.setup();
  render(<ZoneEditor zoneName="example.com." initialRecords={records} onRefresh={() => {}} />);

  await user.click(screen.getByLabelText('Edit TTL for A record a1.example.com.'));
  const input = screen.getByLabelText('TTL for A record a1.example.com.');

  // The operator's edit: 300 → 0, then commit.
  fireEvent.change(input, { target: { value: '0' } });
  fireEvent.keyDown(input, { key: 'Enter' });

  const putCall = mockFetch.mock.calls.find(([, init]) => (init as RequestInit).method === 'PUT');
  expect(putCall, 'expected the inline edit to commit a PUT').toBeDefined();
  const sentBody = JSON.parse((putCall as unknown[])[1].body as string);
  expect(sentBody.ttl).toBe(0);
});

// #19: the SOA row offers "Edit SOA" (opening the page's SOA dialog) instead of
// the record edit/delete actions, which the server refuses for SOA.
it('offers Edit SOA on the SOA row', async () => {
  const user = userEvent.setup();
  const onEditSOA = vi.fn();
  const withSOA = [
    { name: 'example.com.', type: 'SOA', ttl: 3600, class: 'IN', data: 'ns1.example.com. hostmaster.example.com. 1 3600 600 604800 86400' },
    ...records,
  ];
  render(<ZoneEditor zoneName="example.com." initialRecords={withSOA} onRefresh={() => {}} onEditSOA={onEditSOA} />);

  expect(screen.queryByLabelText('Delete SOA record example.com.')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Edit SOA' }));
  expect(onEditSOA).toHaveBeenCalledTimes(1);
});
