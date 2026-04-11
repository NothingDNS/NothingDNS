import { useState, useCallback, useRef, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogTitle } from '@/components/ui/dialog';
import { api, type DnsRecord } from '@/lib/api';
import { Plus, Pencil, Trash2, Undo, Redo, GripVertical, Search, X, Check, AlertTriangle, Network } from 'lucide-react';

export interface EditableRecord extends DnsRecord {
  selected?: boolean;
  edited?: boolean;
  original?: DnsRecord;
}

interface ZoneEditorProps {
  zoneName: string;
  initialRecords: DnsRecord[];
  onRefresh: () => void;
}

interface HistoryState {
  records: EditableRecord[];
  description: string;
}

export function ZoneEditor({ zoneName, initialRecords, onRefresh }: ZoneEditorProps) {
  const [records, setRecords] = useState<EditableRecord[]>(
    initialRecords.map(r => ({ ...r, selected: false }))
  );
  const [history, setHistory] = useState<HistoryState[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [showBulkPTR, setShowBulkPTR] = useState(false);
  const [selectedRecords, setSelectedRecords] = useState<Set<number>>(new Set());
  const dragItem = useRef<number | null>(null);
  const dragOverItem = useRef<number | null>(null);

  const saveToHistory = useCallback((desc: string) => {
    const newHistory = history.slice(0, historyIndex + 1);
    newHistory.push({ records: JSON.parse(JSON.stringify(records)), description: desc });
    setHistory(newHistory);
    setHistoryIndex(newHistory.length - 1);
  }, [history, historyIndex, records]);

  const undo = useCallback(() => {
    if (historyIndex > 0) {
      setHistoryIndex(historyIndex - 1);
      setRecords(history[historyIndex - 1].records.map(r => ({ ...r, selected: false })));
    }
  }, [history, historyIndex]);

  const redo = useCallback(() => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(historyIndex + 1);
      setRecords(history[historyIndex + 1].records.map(r => ({ ...r, selected: false })));
    }
  }, [history, historyIndex]);

  const updateRecord = useCallback((index: number, field: keyof DnsRecord, value: string | number) => {
    setRecords(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], [field]: value, edited: true };
      return updated;
    });
  }, []);

  const saveEdit = useCallback((index: number) => {
    const record = records[index];
    if (!record.edited) return;
    saveToHistory(`Edited ${record.name} ${record.type}`);
    api('PUT', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
      name: record.name,
      type: record.type,
      old_data: record.original?.data || record.data,
      ttl: record.ttl,
      data: record.data
    }).then(() => {
      setRecords(prev => prev.map((r, i) => i === index ? { ...r, edited: false } : r));
    }).catch(e => {
      console.error('Failed to save record:', e);
      // Revert the edited flag on failure
      setRecords(prev => prev.map((r, i) => i === index ? { ...r, edited: true } : r));
    });
  }, [records, saveToHistory, zoneName]);

  const deleteRecord = useCallback((record: EditableRecord) => {
    if (!confirm(`Delete ${record.type} ${record.name}?`)) return;
    saveToHistory(`Deleted ${record.name} ${record.type}`);
    // Optimistic delete - remove first, revert on failure
    setRecords(prev => prev.filter(r => !(r.name === record.name && r.type === record.type && r.data === record.data)));
    api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
      name: record.name,
      type: record.type,
      data: record.data
    }).catch(e => {
      console.error('Delete failed:', e);
      // Revert on failure
      setRecords(prev => [record, ...prev]);
      alert(`Failed to delete ${record.type} ${record.name}`);
    });
  }, [saveToHistory, zoneName]);

  const deleteSelected = useCallback(async () => {
    if (selectedRecords.size === 0) return;
    if (!confirm(`Delete ${selectedRecords.size} selected records?`)) return;
    saveToHistory(`Deleted ${selectedRecords.size} records`);
    const selected = records.filter((_, i) => selectedRecords.has(i));
    const failures: string[] = [];
    for (const r of selected) {
      try {
        await api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
          name: r.name, type: r.type, data: r.data
        });
      } catch {
        failures.push(`${r.type} ${r.name}`);
      }
    }
    if (failures.length > 0) {
      alert(`Failed to delete: ${failures.join(', ')}`);
    }
    onRefresh();
    setSelectedRecords(new Set());
  }, [selectedRecords, records, saveToHistory, zoneName, onRefresh]);

  const toggleSelect = useCallback((index: number) => {
    setSelectedRecords(prev => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  const filteredRecords = records.filter(r => {
    const matchesSearch = !search ||
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.data.toLowerCase().includes(search.toLowerCase());
    const matchesType = !typeFilter || r.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const selectAll = useCallback(() => {
    if (selectedRecords.size === filteredRecords.length) {
      setSelectedRecords(new Set());
    } else {
      setSelectedRecords(new Set(filteredRecords.map((_, i) => i)));
    }
  }, [filteredRecords, selectedRecords]);

  const handleDragStart = (index: number) => {
    dragItem.current = index;
  };

  const handleDragEnter = (index: number) => {
    dragOverItem.current = index;
  };

  const handleDragEnd = () => {
    if (dragItem.current === null || dragOverItem.current === null) return;
    if (dragItem.current === dragOverItem.current) return;

    setRecords(prev => {
      const updated = [...prev];
      const [removed] = updated.splice(dragItem.current!, 1);
      updated.splice(dragOverItem.current!, 0, removed);
      return updated;
    });

    dragItem.current = null;
    dragOverItem.current = null;
  };

  const types = [...new Set(records.map(r => r.type))].sort();
  const tc: Record<string, 'success' | 'warning' | 'secondary' | 'default' | 'outline'> = {
    SOA: 'warning', NS: 'secondary', A: 'success', AAAA: 'success',
    CNAME: 'default', MX: 'outline', TXT: 'outline', SRV: 'outline',
    DNSKEY: 'warning', DS: 'warning', RRSIG: 'secondary', NSEC: 'secondary'
  };

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search records..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9"
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2">
              <X className="h-4 w-4 text-muted-foreground hover:text-foreground" />
            </button>
          )}
        </div>

        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          className="h-10 px-3 rounded-md border border-input bg-background text-sm"
        >
          <option value="">All Types</option>
          {types.map(t => <option key={t} value={t}>{t}</option>)}
        </select>

        <div className="flex items-center gap-1 ml-auto">
          <Button variant="outline" size="sm" onClick={undo} disabled={historyIndex <= 0}>
            <Undo className="h-4 w-4" />
          </Button>
          <Button variant="outline" size="sm" onClick={redo} disabled={historyIndex >= history.length - 1}>
            <Redo className="h-4 w-4" />
          </Button>
        </div>

        {selectedRecords.size > 0 && (
          <div className="flex items-center gap-2">
            <Badge variant="secondary">{selectedRecords.size} selected</Badge>
            <Button variant="destructive" size="sm" onClick={deleteSelected}>
              <Trash2 className="h-4 w-4" /> Delete
            </Button>
          </div>
        )}

        <Button size="sm" onClick={() => setShowAdd(true)}>
          <Plus className="h-4 w-4" /> Add Record
        </Button>
        <Button size="sm" variant="outline" onClick={() => setShowBulkPTR(true)}>
          <Network className="h-4 w-4" /> Bulk PTR
        </Button>
      </div>

      {/* Stats */}
      <div className="flex items-center gap-4 text-sm text-muted-foreground">
        <span>{filteredRecords.length} records</span>
        {search && <Badge variant="secondary">Filtered</Badge>}
        <button onClick={selectAll} className="hover:text-foreground underline underline-offset-2">
          {selectedRecords.size === filteredRecords.length ? 'Deselect all' : 'Select all'}
        </button>
      </div>

      {/* Records Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="w-10 px-3 py-3"></th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Name</th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-24">Type</th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-24">TTL</th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Data</th>
                <th className="text-right text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-32">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-muted-foreground">
                    {records.length === 0 ? 'No records in this zone' : 'No matching records'}
                  </td>
                </tr>
              ) : filteredRecords.map((r, i) => (
                <tr
                  key={`${r.name}-${r.type}-${i}`}
                  className={`border-b hover:bg-muted/30 transition-colors cursor-grab active:cursor-grabbing ${r.edited ? 'bg-warning/5' : ''} ${selectedRecords.has(i) ? 'bg-primary/5' : ''}`}
                  draggable
                  onDragStart={() => handleDragStart(i)}
                  onDragEnter={() => handleDragEnter(i)}
                  onDragEnd={handleDragEnd}
                  onDragOver={e => e.preventDefault()}
                >
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={selectedRecords.has(i)}
                        onChange={() => toggleSelect(i)}
                        className="h-4 w-4 rounded border-input"
                      />
                      <GripVertical className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <InlineEdit
                      value={r.name}
                      onSave={v => updateRecord(i, 'name', v)}
                      onFinish={() => saveEdit(i)}
                      edited={r.edited}
                    />
                  </td>
                  <td className="px-4 py-2">
                    <Badge variant={tc[r.type] || 'outline'}>{r.type}</Badge>
                  </td>
                  <td className="px-4 py-2">
                    <InlineEdit
                      value={String(r.ttl)}
                      onSave={v => updateRecord(i, 'ttl', parseInt(v) || 3600)}
                      onFinish={() => saveEdit(i)}
                      edited={r.edited}
                      type="number"
                    />
                  </td>
                  <td className="px-4 py-2">
                    <InlineEdit
                      value={r.data}
                      onSave={v => updateRecord(i, 'data', v)}
                      onFinish={() => saveEdit(i)}
                      edited={r.edited}
                    />
                  </td>
                  <td className="px-4 py-2 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {r.edited && (
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-success" onClick={() => saveEdit(i)}>
                          <Check className="h-4 w-4" />
                        </Button>
                      )}
                      {r.type !== 'SOA' && !r.edited && (
                        <>
                          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => {
                            const newRecords = [...records];
                            const idx = records.indexOf(r);
                            newRecords[idx] = { ...r, edited: true, original: { ...r } };
                            setRecords(newRecords);
                          }}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" onClick={() => deleteRecord(r)}>
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
        onSaved={() => { onRefresh(); setShowAdd(false); saveToHistory('Added record'); }}
      />

      <BulkPTRDialog
        open={showBulkPTR}
        onClose={() => setShowBulkPTR(false)}
        zoneName={zoneName}
        onSaved={() => { onRefresh(); setShowBulkPTR(false); saveToHistory('Added bulk PTR records'); }}
      />
    </div>
  );
}

function InlineEdit({ value, onSave, onFinish, edited, type = 'text' }: {
  value: string;
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
      <span className="font-mono text-sm cursor-pointer hover:bg-muted px-2 py-1 rounded" onClick={() => setEditing(true)}>
        {value}
      </span>
    );
  }

  return (
    <input
      ref={inputRef}
      type={type}
      value={val}
      onChange={e => { setVal(e.target.value); onSave(e.target.value); }}
      onBlur={onFinish}
      onKeyDown={e => { if (e.key === 'Enter') onFinish(); if (e.key === 'Escape') { setVal(value); setEditing(false); } }}
      className="font-mono text-sm w-full bg-background border border-primary rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-primary"
    />
  );
}

function AddRecordDialog({ open, onClose, zoneName, onSaved }: {
  open: boolean;
  onClose: () => void;
  zoneName: string;
  onSaved: () => void;
}) {
  const [name, setName] = useState('');
  const [type, setType] = useState('A');
  const [ttl, setTtl] = useState('3600');
  const [data, setData] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const handleSave = async () => {
    setError('');
    if (!name.trim() || !data.trim()) {
      setError('Name and data are required');
      return;
    }
    setSaving(true);
    try {
      await api('POST', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: name.trim(),
        type,
        ttl: parseInt(ttl) || 3600,
        data: data.trim()
      });
      setName(''); setType('A'); setTtl('3600'); setData('');
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add record');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Add Record</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-sm font-medium mb-1.5 block">Name</label>
            <Input
              placeholder="@ or subdomain"
              value={name}
              onChange={e => setName(e.target.value)}
              autoFocus
            />
          </div>
          <div>
            <label className="text-sm font-medium mb-1.5 block">Type</label>
            <select
              value={type}
              onChange={e => setType(e.target.value)}
              className="h-10 w-full px-3 rounded-md border border-input bg-background text-sm"
            >
              {['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'CAA', 'DNSKEY', 'DS', 'PTR', 'NAPTR'].map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className="text-sm font-medium mb-1.5 block">TTL</label>
          <Input type="number" value={ttl} onChange={e => setTtl(e.target.value)} />
        </div>

        <div>
          <label className="text-sm font-medium mb-1.5 block">Data</label>
          <Input
            placeholder={type === 'A' ? '192.168.1.1' : type === 'AAAA' ? '::1' : type === 'MX' ? '10 mail.example.com.' : type === 'TXT' ? '"v=spf1 mx ~all"' : type === 'SRV' ? '10 60 443 service.example.com' : 'value'}
            value={data}
            onChange={e => setData(e.target.value)}
          />
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Adding...' : 'Add Record'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function BulkPTRDialog({ open, onClose, zoneName, onSaved }: {
  open: boolean;
  onClose: () => void;
  zoneName: string;
  onSaved: () => void;
}) {
  const [cidr, setCidr] = useState('');
  const [pattern, setPattern] = useState('ip-[A]-[B]-[C]-[D].example.com');
  const [override, setOverride] = useState(false);
  const [addA, setAddA] = useState(true);
  const [saving, setSaving] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{
    total: number;
    willAdd: number;
    willAddA: number;
    willSkip: number;
    willOverride: number;
    changes: { ip: string; ptrName: string; aName?: string; action: string; ptrExist: boolean; aExist?: boolean; oldPtr?: string; oldA?: string }[];
  } | null>(null);
  const [result, setResult] = useState<{ added: number; addedA: number; exists: number; existsA: number; skipped: number } | null>(null);

  const handlePreview = async () => {
    setError('');
    if (!cidr.trim()) {
      setError('CIDR is required');
      return;
    }
    if (!pattern.includes('[A]') || !pattern.includes('[B]') ||
        !pattern.includes('[C]') || !pattern.includes('[D]')) {
      setError('Pattern must contain [A], [B], [C], [D] placeholders');
      return;
    }
    setPreviewing(true);
    try {
      const res = await api<typeof preview>(
        'POST',
        `/api/v1/zones/${encodeURIComponent(zoneName)}/ptr-bulk`,
        { cidr: cidr.trim(), pattern: pattern.trim(), override, addA, preview: true }
      );
      setPreview(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to preview');
    } finally {
      setPreviewing(false);
    }
  };

  const handleSave = async () => {
    setError('');
    if (!cidr.trim()) {
      setError('CIDR is required');
      return;
    }
    if (!pattern.includes('[A]') || !pattern.includes('[B]') ||
        !pattern.includes('[C]') || !pattern.includes('[D]')) {
      setError('Pattern must contain [A], [B], [C], [D] placeholders');
      return;
    }
    setSaving(true);
    try {
      const res = await api<{ added: number; addedA: number; exists: number; existsA: number; skipped: number }>(
        'POST',
        `/api/v1/zones/${encodeURIComponent(zoneName)}/ptr-bulk`,
        { cidr: cidr.trim(), pattern: pattern.trim(), override, addA, preview: false }
      );
      setResult(res);
      setPreview(null);
      if (res.added > 0 || res.skipped > 0 || res.addedA > 0) {
        setCidr('');
        onSaved();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add PTR records');
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setPreview(null);
    setResult(null);
    setError('');
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Bulk PTR Records</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        {result && (
          <div className="text-sm bg-success/10 text-success px-3 py-2 rounded-lg space-y-1">
            <div>PTR: +{result.added} / {result.exists} exists / {result.skipped} skipped</div>
            {result.addedA > 0 && <div>A: +{result.addedA} / {result.existsA} exists</div>}
            <button onClick={reset} className="text-xs underline mt-1">Clear</button>
          </div>
        )}

        {!result && preview && (
          <div className="text-sm bg-primary/10 px-3 py-2 rounded-lg">
            <div className="flex justify-between mb-2">
              <span className="text-primary font-medium">Preview: {preview.total} IPs</span>
              <button onClick={() => setPreview(null)} className="text-xs underline">Edit</button>
            </div>
            <div className="grid grid-cols-3 gap-2 text-xs mb-2">
              <div className="text-success">+{preview.willAdd} add</div>
              {preview.willAddA > 0 && <div className="text-success">+{preview.willAddA} A</div>}
              {preview.willSkip > 0 && <div className="text-warning">~{preview.willSkip} skip</div>}
              {preview.willOverride > 0 && <div className="text-destructive">!{preview.willOverride} override</div>}
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1">
              {preview.changes.slice(0, 20).map((ch, i) => (
                <div key={i} className={`text-xs font-mono flex items-center gap-1 ${
                  ch.action === 'skip' ? 'text-warning' : ch.action === 'override' ? 'text-destructive' : 'text-success'
                }`}>
                  <span>{ch.ip}</span>
                  <span>→</span>
                  <span className="truncate">{ch.ptrName}</span>
                  {ch.action === 'skip' && <span className="text-muted-foreground">exists</span>}
                  {ch.action === 'override' && <span className="text-destructive">→ {ch.oldPtr}</span>}
                </div>
              ))}
              {preview.changes.length > 20 && (
                <div className="text-xs text-muted-foreground text-center">
                  +{preview.changes.length - 20} more...
                </div>
              )}
            </div>
          </div>
        )}

        <div>
          <label className="text-sm font-medium mb-1.5 block">CIDR Range</label>
          <Input
            placeholder="192.168.1.0/24"
            value={cidr}
            onChange={e => { setCidr(e.target.value); setPreview(null); }}
            autoFocus
          />
          <p className="text-xs text-muted-foreground mt-1">IPv4 range (max /16)</p>
        </div>

        <div>
          <label className="text-sm font-medium mb-1.5 block">Pattern</label>
          <Input
            placeholder="ip-[A]-[B]-[C]-[D].example.com"
            value={pattern}
            onChange={e => { setPattern(e.target.value); setPreview(null); }}
          />
          <p className="text-xs text-muted-foreground mt-1">Use [A], [B], [C], [D] for IP octets</p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="addA"
            checked={addA}
            onChange={e => { setAddA(e.target.checked); setPreview(null); }}
            className="h-4 w-4 rounded border-input"
          />
          <label htmlFor="addA" className="text-sm">Also add A records (pattern name → IP)</label>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="override"
            checked={override}
            onChange={e => { setOverride(e.target.checked); setPreview(null); }}
            className="h-4 w-4 rounded border-input"
          />
          <label htmlFor="override" className="text-sm">Override existing records</label>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Close</Button>
          {!preview ? (
            <Button variant="outline" onClick={handlePreview} disabled={previewing || !cidr.trim()}>
              {previewing ? 'Preview...' : 'Preview'}
            </Button>
          ) : null}
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Adding...' : preview ? 'Confirm & Add' : 'Add PTR Records'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
