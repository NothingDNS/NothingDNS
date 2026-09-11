import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { toast } from 'sonner';
import { api, type DnsRecord } from '@/lib/api';
import { Plus, Pencil, Trash2, Search, X, Check, Network, Database } from 'lucide-react';
import {
  type EditableRecord,
  type RecordEditValue,
  recordTypePalette,
  recordTypeBadgeVariants,
  isReverseIPv4Zone,
} from './record-utils';
import { RecordDataDisplay } from './record-form';
import { AddRecordDialog, EditRecordDialog, BulkPTRDialog } from './record-dialogs';

export type { EditableRecord } from './record-utils';

interface ZoneEditorProps {
  zoneName: string;
  initialRecords: DnsRecord[];
  onRefresh: () => void;
}

export function ZoneEditor({ zoneName, initialRecords, onRefresh }: ZoneEditorProps) {
  const [records, setRecords] = useState<EditableRecord[]>(
    initialRecords.map(r => ({ ...r, selected: false }))
  );
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [addRecordType, setAddRecordType] = useState('A');
  const [showBulkPTR, setShowBulkPTR] = useState(false);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [selectedRecords, setSelectedRecords] = useState<Set<number>>(new Set());
  // Confirmation state for destructive actions (replaces native confirm()).
  const [pendingDelete, setPendingDelete] = useState<EditableRecord | null>(null);
  const [pendingBulkDelete, setPendingBulkDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const canBulkPTR = isReverseIPv4Zone(zoneName);

  // Keep local state in sync when the parent reloads records after a mutation.
  useEffect(() => {
    setRecords(initialRecords.map(r => ({ ...r, selected: false })));
    setSelectedRecords(new Set());
  }, [initialRecords]);

  const updateRecord = useCallback((index: number, field: keyof DnsRecord, value: string | number) => {
    setRecords(prev => {
      const updated = [...prev];
      const rec = updated[index];
      // Snapshot the pre-edit record the first time it's touched, so the
      // update PUT can locate the row on the server by its ORIGINAL data.
      const original = rec.original ?? { name: rec.name, type: rec.type, ttl: rec.ttl, class: rec.class, data: rec.data };
      updated[index] = { ...rec, [field]: value, edited: true, original };
      return updated;
    });
  }, []);

  // saveEdit commits an inline TTL edit. (Names are not inline-editable — the
  // update API locates a record by its name bucket + data, so a rename must go
  // through the dialog's delete+add path, not this in-place update.)
  const saveEdit = useCallback((index: number) => {
    const record = records[index];
    if (!record.edited) return;
    const oldData = record.original?.data ?? record.data;
    api('PUT', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
      name: record.name,
      type: record.type,
      old_data: oldData,
      ttl: record.ttl,
      data: record.data,
    }).then(() => {
      setRecords(prev => prev.map((r, i) => i === index ? { ...r, edited: false, original: undefined } : r));
      toast.success('Record updated');
      onRefresh();
    }).catch(e => {
      toast.error(e instanceof Error ? e.message : 'Failed to update record');
    });
  }, [records, zoneName, onRefresh]);

  const saveStructuredEdit = useCallback(async (index: number, next: RecordEditValue) => {
    const record = records[index];
    if (!record) return;
    const renamed = next.name !== record.name;
    if (renamed) {
      // The update API cannot move a record between name buckets, so a rename
      // is delete-old + add-new. Delete first; only add the new record if the
      // delete succeeded, so a failure can't duplicate the record.
      await api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: record.name,
        type: record.type,
        data: record.data,
      });
      await api('POST', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: next.name,
        type: record.type,
        ttl: next.ttl,
        data: next.data,
      });
    } else {
      await api('PUT', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: next.name,
        type: record.type,
        old_data: record.original?.data ?? record.data,
        ttl: next.ttl,
        data: next.data,
      });
    }
    toast.success('Record updated');
    onRefresh();
    // Errors propagate to the dialog, which surfaces them inline and stays open.
  }, [records, zoneName, onRefresh]);

  const confirmDelete = useCallback(async () => {
    const record = pendingDelete;
    if (!record) return;
    setDeleting(true);
    try {
      await api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: record.name,
        type: record.type,
        data: record.data,
      });
      toast.success(`Deleted ${record.type} ${record.name}`);
      onRefresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : `Failed to delete ${record.type} ${record.name}`);
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  }, [pendingDelete, zoneName, onRefresh]);

  const confirmBulkDelete = useCallback(async () => {
    const selected = records.filter((_, i) => selectedRecords.has(i));
    if (selected.length === 0) { setPendingBulkDelete(false); return; }
    setDeleting(true);
    const failures: string[] = [];
    for (const r of selected) {
      try {
        await api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
          name: r.name, type: r.type, data: r.data,
        });
      } catch {
        failures.push(`${r.type} ${r.name}`);
      }
    }
    if (failures.length > 0) {
      toast.error(`Failed to delete: ${failures.join(', ')}`);
    } else {
      toast.success(`Deleted ${selected.length} record${selected.length === 1 ? '' : 's'}`);
    }
    setDeleting(false);
    setPendingBulkDelete(false);
    setSelectedRecords(new Set());
    onRefresh();
  }, [selectedRecords, records, zoneName, onRefresh]);

  const toggleSelect = useCallback((index: number) => {
    setSelectedRecords(prev => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  // Pair each record with its REAL index before filtering, so selection /
  // edit / delete always target the correct row even when two rows are
  // structurally identical (indexOf would return the first match).
  const visibleRows = useMemo(
    () =>
      records
        .map((record, index) => ({ record, index }))
        .filter(({ record: r }) => {
          const matchesSearch = !search ||
            r.name.toLowerCase().includes(search.toLowerCase()) ||
            r.data.toLowerCase().includes(search.toLowerCase());
          const matchesType = !typeFilter || r.type === typeFilter;
          return matchesSearch && matchesType;
        }),
    [records, search, typeFilter],
  );

  // Selection follows the visible window: filtering can hide rows, and a
  // hidden row must never be deleted by the bulk action the operator sees.
  // Drop selected rows the current filter hides.
  useEffect(() => {
    setSelectedRecords(prev => {
      const visible = new Set(visibleRows.map(({ index }) => index));
      let changed = false;
      const next = new Set<number>();
      for (const i of prev) {
        if (visible.has(i)) next.add(i);
        else changed = true;
      }
      return changed ? next : prev;
    });
  }, [visibleRows]);

  const selectAll = useCallback(() => {
    const visibleIndices = records
      .map((record, index) => ({ record, index }))
      .filter(({ record: r }) => {
        const matchesSearch = !search ||
          r.name.toLowerCase().includes(search.toLowerCase()) ||
          r.data.toLowerCase().includes(search.toLowerCase());
        const matchesType = !typeFilter || r.type === typeFilter;
        return matchesSearch && matchesType;
      })
      .map(({ index }) => index);
    setSelectedRecords(prev =>
      prev.size === visibleIndices.length ? new Set() : new Set(visibleIndices)
    );
  }, [records, search, typeFilter]);

  const types = [...new Set(records.map(r => r.type))].sort();
  const editedCount = records.filter(r => r.edited).length;
  const typeCounts = records.reduce<Record<string, number>>((acc, record) => {
    acc[record.type] = (acc[record.type] || 0) + 1;
    return acc;
  }, {});
  const addressCount = (typeCounts.A || 0) + (typeCounts.AAAA || 0) + (typeCounts.PTR || 0);
  const routingCount = (typeCounts.CNAME || 0) + (typeCounts.MX || 0) + (typeCounts.NS || 0) + (typeCounts.SRV || 0);
  const policyCount = (typeCounts.TXT || 0) + (typeCounts.CAA || 0) + (typeCounts.NAPTR || 0);
  const securityCount = (typeCounts.DNSKEY || 0) + (typeCounts.DS || 0) + (typeCounts.RRSIG || 0) + (typeCounts.NSEC || 0);
  const allVisibleSelected = visibleRows.length > 0 && selectedRecords.size === visibleRows.length;

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Addressing</span>
            <Badge variant="success">{addressCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">A, AAAA, and PTR records</p>
        </div>
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Routing</span>
            <Badge variant="outline">{routingCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">NS, MX, CNAME, and SRV records</p>
        </div>
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Policy</span>
            <Badge variant="secondary">{policyCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">TXT, CAA, and NAPTR records</p>
        </div>
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Security</span>
            <Badge variant="warning">{securityCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">DNSSEC-related records</p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="rounded-lg border bg-surface p-3 shadow-sm">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative min-w-0 flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search records..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-9 pr-9"
              aria-label="Search records"
            />
            {search && (
              <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2" aria-label="Clear search">
                <X className="h-4 w-4 text-muted-foreground hover:text-foreground" />
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="h-10 min-w-[130px] rounded-md border border-input bg-background px-3 text-sm"
              aria-label="Filter by record type"
            >
              <option value="">All Types</option>
              {types.map(t => <option key={t} value={t}>{t}</option>)}
            </select>

            <Button size="sm" onClick={() => { setAddRecordType('A'); setShowAdd(true); }}>
              <Plus className="h-4 w-4" /> Add Record
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                if (canBulkPTR) {
                  setShowBulkPTR(true);
                } else {
                  setAddRecordType('PTR');
                  setShowAdd(true);
                }
              }}
            >
              <Network className="h-4 w-4" /> {canBulkPTR ? 'Bulk PTR' : 'Add PTR'}
            </Button>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          <Badge variant="secondary" className="gap-1"><Database className="h-3.5 w-3.5" /> {visibleRows.length} shown</Badge>
          <Badge variant="outline">{records.length} total</Badge>
          {editedCount > 0 && <Badge variant="warning">{editedCount} edited</Badge>}
          {search && <Badge variant="secondary">Filtered</Badge>}
          <button onClick={selectAll} className="ml-auto hover:text-foreground underline underline-offset-2">
            {allVisibleSelected ? 'Deselect all' : 'Select all'}
          </button>
        </div>

        {selectedRecords.size > 0 && (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-2">
            <Badge variant="secondary">{selectedRecords.size} selected</Badge>
            <Button variant="destructive" size="sm" onClick={() => setPendingBulkDelete(true)}>
              <Trash2 className="h-4 w-4" /> Delete
            </Button>
          </div>
        )}
      </div>

      <div className="rounded-lg border bg-surface p-3 shadow-sm">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-medium">Record type palette</div>
            <div className="text-xs text-muted-foreground">Filter the zone by record family without losing table context.</div>
          </div>
          {typeFilter && (
            <Button variant="ghost" size="sm" onClick={() => setTypeFilter('')}>
              <X className="h-4 w-4" /> Clear
            </Button>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setTypeFilter('')}
            className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${typeFilter === '' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted/50'}`}
          >
            <span className="font-medium">All</span>
            <Badge variant="secondary">{records.length}</Badge>
          </button>
          {recordTypePalette.map(typeName => (
            <button
              key={typeName}
              type="button"
              onClick={() => setTypeFilter(typeName)}
              className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${typeFilter === typeName ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted/50'}`}
            >
              <span className="font-medium">{typeName}</span>
              <Badge variant={recordTypeBadgeVariants[typeName] || 'outline'}>{typeCounts[typeName] || 0}</Badge>
            </button>
          ))}
        </div>
      </div>

      {/* Records Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th scope="col" className="w-10 px-3 py-3">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={selectAll}
                    className="h-4 w-4 rounded border-input"
                    aria-label="Select all visible records"
                  />
                </th>
                <th scope="col" className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Name</th>
                <th scope="col" className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-24">Type</th>
                <th scope="col" className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-24">TTL</th>
                <th scope="col" className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Data</th>
                <th scope="col" className="text-right text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-32">Actions</th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-muted-foreground">
                    {records.length === 0 ? 'No records in this zone' : 'No matching records'}
                  </td>
                </tr>
              ) : visibleRows.map(({ record: r, index: i }) => (
                <tr
                  key={`${r.name}-${r.type}-${r.data}-${i}`}
                  className={`border-b align-top hover:bg-muted/30 transition-colors ${r.edited ? 'bg-warning/5' : ''} ${selectedRecords.has(i) ? 'bg-primary/5' : ''}`}
                >
                  <td className="px-3 py-2">
                    <input
                      type="checkbox"
                      checked={selectedRecords.has(i)}
                      onChange={() => toggleSelect(i)}
                      className="h-4 w-4 rounded border-input"
                      aria-label={`Select ${r.type} record ${r.name}`}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-sm break-all" title={r.name}>{r.name}</span>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={recordTypeBadgeVariants[r.type] || 'outline'}>{r.type}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    {r.type === 'SOA' ? (
                      <span className="font-mono text-sm">{r.ttl}</span>
                    ) : (
                      <InlineEdit
                        value={String(r.ttl)}
                        label={`TTL for ${r.type} record ${r.name}`}
                        onSave={v => {
                          // parseInt('0') is 0 — falsy — so `|| r.ttl` silently reverted an
                          // explicit TTL 0 (no caching) to the record's previous value.
                          const parsed = parseInt(v, 10);
                          updateRecord(i, 'ttl', Number.isNaN(parsed) ? r.ttl : parsed);
                        }}
                        onFinish={() => saveEdit(i)}
                        edited={r.edited}
                        type="number"
                      />
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <RecordDataDisplay type={r.type} data={r.data} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {r.edited && (
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-success" onClick={() => saveEdit(i)} aria-label="Save changes">
                          <Check className="h-4 w-4" />
                        </Button>
                      )}
                      {r.type !== 'SOA' && !r.edited && (
                        <>
                          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setEditingIndex(i)} aria-label={`Edit ${r.type} record ${r.name}`}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" onClick={() => setPendingDelete(r)} aria-label={`Delete ${r.type} record ${r.name}`}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <AddRecordDialog
        open={showAdd}
        onClose={() => setShowAdd(false)}
        zoneName={zoneName}
        initialType={addRecordType}
        onSaved={() => { onRefresh(); setShowAdd(false); }}
      />

      <EditRecordDialog
        open={editingIndex !== null}
        record={editingIndex === null ? null : records[editingIndex] || null}
        onClose={() => setEditingIndex(null)}
        onSave={async (next) => {
          if (editingIndex === null) return;
          await saveStructuredEdit(editingIndex, next);
          setEditingIndex(null);
        }}
      />

      <BulkPTRDialog
        open={showBulkPTR}
        onClose={() => setShowBulkPTR(false)}
        zoneName={zoneName}
        onSaved={() => { onRefresh(); setShowBulkPTR(false); }}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete record"
        description={pendingDelete ? `Delete ${pendingDelete.type} record ${pendingDelete.name}? This cannot be undone.` : ''}
        confirmLabel="Delete"
        destructive
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setPendingDelete(null)}
      />

      <ConfirmDialog
        open={pendingBulkDelete}
        title="Delete selected records"
        description={`Delete ${selectedRecords.size} selected record${selectedRecords.size === 1 ? '' : 's'}? This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        loading={deleting}
        onConfirm={confirmBulkDelete}
        onCancel={() => setPendingBulkDelete(false)}
      />
    </div>
  );
}

function InlineEdit({ value, label, onSave, onFinish, edited, type = 'text' }: {
  value: string;
  label?: string;
  onSave: (v: string) => void;
  onFinish: () => void;
  edited?: boolean;
  type?: string;
}) {
  const [editing, setEditing] = useState(edited || false);
  const [val, setVal] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { setVal(value); }, [value]);
  useEffect(() => { if (editing) inputRef.current?.focus(); }, [editing]);

  if (!editing) {
    return (
      <button
        type="button"
        className="font-mono text-sm cursor-pointer hover:bg-muted px-2 py-1 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        onClick={() => setEditing(true)}
        aria-label={label ? `Edit ${label}` : undefined}
      >
        {value}
      </button>
    );
  }

  return (
    <input
      ref={inputRef}
      type={type}
      value={val}
      aria-label={label}
      onChange={e => { setVal(e.target.value); onSave(e.target.value); }}
      onBlur={onFinish}
      onKeyDown={e => { if (e.key === 'Enter') onFinish(); if (e.key === 'Escape') { setVal(value); setEditing(false); } }}
      className="font-mono text-sm w-full bg-background border border-primary rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-primary"
    />
  );
}
