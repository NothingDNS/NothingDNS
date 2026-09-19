import type { ReactNode } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Lock, Save, RotateCcw } from 'lucide-react';

export function SectionHeader({ title, description, icon, badge }: { title: string; description?: string; icon: ReactNode; badge?: string }) {
  return (
    <CardHeader className="pb-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-primary/10 text-primary">{icon}</div>
          <div>
            <CardTitle className="text-base">{title}</CardTitle>
            {description && <CardDescription className="text-xs">{description}</CardDescription>}
          </div>
        </div>
        {badge && <Badge variant="outline">{badge}</Badge>}
      </div>
    </CardHeader>
  );
}

export function SaveBar({ dirty, saving, onSave, onReset }: { dirty: boolean; saving: boolean; onSave: () => void; onReset: () => void }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-muted/20 p-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-2">
        <Badge variant={dirty ? 'warning' : 'secondary'}>{dirty ? 'Unsaved changes' : 'Current'}</Badge>
        <span className="text-xs text-muted-foreground">{dirty ? 'Review and save runtime changes.' : 'No pending runtime changes.'}</span>
      </div>
      <div className="flex items-center justify-end gap-2">
        <Button variant="outline" size="sm" className="min-w-[92px]" onClick={onReset} disabled={!dirty || saving}>
          <RotateCcw className="h-4 w-4 mr-2" /> Reset
        </Button>
        <Button size="sm" className="min-w-[92px]" onClick={onSave} disabled={!dirty || saving}>
          <Save className="h-4 w-4 mr-2" />
          {saving ? 'Saving...' : 'Save'}
        </Button>
      </div>
    </div>
  );
}

export function ReadOnlyNotice({ title }: { title: string }) {
  return (
    <Card className="border-dashed bg-muted/20">
      <CardHeader className="pb-3">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 p-1.5 rounded-md bg-background text-muted-foreground"><Lock className="h-4 w-4" /></div>
          <div className="min-w-0">
            <CardTitle className="text-base">{title}</CardTitle>
            <CardDescription className="text-xs">Live edits persist to runtime_overrides.json (when storage.data_dir is set) and survive reload. Bind addresses, TLS, cluster crypto and similar still require a YAML edit and restart.</CardDescription>
          </div>
        </div>
      </CardHeader>
    </Card>
  );
}

export function KVRow({ label, value, mono }: { label: string; value: string | number | boolean | undefined; mono?: boolean }) {
  if (value === undefined || value === null) return null;
  const displayValue = typeof value === 'boolean' ? (value ? 'Enabled' : 'Disabled') : String(value);
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-border/50 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className={`text-sm font-medium ${mono ? 'font-mono' : ''}`}>{displayValue}</span>
    </div>
  );
}

// Re-export Card/CardContent for convenience in tab components
export { Card, CardContent };
