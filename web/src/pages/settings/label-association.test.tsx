/**
 * Label-association audit for the settings pages and the standalone
 * users / blocklist forms.
 *
 * Companion to components/zone-editor/label-association.test.tsx, which covers
 * CreateZoneDialog, AddRecordDialog and BulkPTRDialog.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM LINT
 * -----------------------------------------
 * eslint-plugin-jsx-a11y's label-has-associated-control rule only matches the
 * lowercase DOM element `<label>`. These pages use the shadcn `<Label>`
 * component (a Radix LabelPrimitive.Root wrapper), which the rule never sees —
 * `npx eslint` exits 0 on every file asserted here despite the gaps below.
 * These tests are therefore the ONLY automated guard for this class of defect.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { CacheSettings } from './cache-settings';
import { LoggingSettings } from './logging-settings';
import { SecuritySettings } from './security-settings';
import { UsersPage } from '../users';
import { BlocklistPage } from '../blocklist';
import type { ServerConfig } from './types';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

vi.mock('@/hooks/useApi', () => ({
  useUpdateCacheConfig: () => ({ mutate: vi.fn(), isPending: false }),
  useUpdateRRLConfig: () => ({ mutate: vi.fn(), isPending: false }),
  useUpdateLoggingConfig: () => ({ mutate: vi.fn(), isPending: false }),
}));

// Every settings component reads its slice with optional chaining and supplies
// a default (`cache?.Size ?? 10000`), so an empty object renders the full form.
const emptyConfig = {} as ServerConfig;
const noopReload = () => Promise.resolve();

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockResolvedValue(jsonResponse({}));
});

/**
 * Structural backstop, mirroring the zone-editor suite.
 *
 * Accepts BOTH valid association forms so it never false-positives on a
 * correct implementation:
 *   - explicit: <label for="x"> + <control id="x">
 *   - implicit: <label><control /></label>
 *
 * Returns the labels that satisfy neither, so callers can assert on the exact
 * set rather than a bare count.
 */
function unassociatedLabels(container: HTMLElement): string[] {
  const orphans: string[] = [];
  for (const label of container.querySelectorAll('label')) {
    const htmlFor = label.getAttribute('for');
    if (htmlFor) {
      if (!container.ownerDocument.getElementById(htmlFor)) {
        orphans.push(`${label.textContent ?? ''} (for="${htmlFor}" -> no such id)`);
      }
      continue;
    }
    if (!label.querySelector('input, textarea, select, button, [role="switch"], [role="combobox"]')) {
      orphans.push(label.textContent ?? '');
    }
  }
  return orphans;
}

/** Controls that carry no accessible name at all (no label, no aria-label). */
function unnamedControls(container: HTMLElement): string[] {
  const unnamed: string[] = [];
  for (const el of container.querySelectorAll('input, textarea, select')) {
    const id = el.getAttribute('id');
    const hasLabel = id
      ? Boolean(container.ownerDocument.querySelector(`label[for="${id}"]`))
      : false;
    const wrapped = el.closest('label') !== null;
    const aria = el.getAttribute('aria-label') ?? el.getAttribute('aria-labelledby');
    if (!hasLabel && !wrapped && !aria) {
      const placeholder = el.getAttribute('placeholder');
      unnamed.push(placeholder ? `[placeholder="${placeholder}"]` : el.tagName.toLowerCase());
    }
  }
  return unnamed;
}

/*
 * ---------------------------------------------------------------------------
 * LABEL ASSOCIATION (all gaps fixed - these pin the fixed state)
 *
 * These components render <Label> as a SIBLING of their control with no
 * htmlFor, so the accessible name is not exposed. The assertions below pin the
 * exact current gap count: fixing a component makes its list shrink and the
 * test fail loudly, prompting the expectation to be tightened to []. Adding a
 * NEW unassociated label also fails. Either direction is caught.
 * ---------------------------------------------------------------------------
 */

describe('CacheSettings label association', () => {
  it('renders its form controls', () => {
    const { container } = render(<CacheSettings config={emptyConfig} onReload={noopReload} />);
    expect(container.querySelectorAll('input').length).toBeGreaterThan(0);
  });

  it('has a known, unchanged set of unassociated labels', () => {
    const { container } = render(<CacheSettings config={emptyConfig} onReload={noopReload} />);
    expect(unassociatedLabels(container)).toEqual([]);
  });

  it('exposes every control via getByLabelText', () => {
    render(<CacheSettings config={emptyConfig} onReload={noopReload} />);
    expect(screen.getByLabelText('Max Size')).toBeInTheDocument();
  });
});

describe('LoggingSettings label association', () => {
  it('has a known, unchanged set of unassociated labels', () => {
    const { container } = render(<LoggingSettings config={emptyConfig} onReload={noopReload} />);
    expect(unassociatedLabels(container)).toEqual([]);
  });
});

describe('SecuritySettings label association', () => {
  it('has a known, unchanged set of unassociated labels', () => {
    const { container } = render(<SecuritySettings config={emptyConfig} onReload={noopReload} />);
    expect(unassociatedLabels(container)).toEqual([]);
  });
});

// UsersPage and BlocklistPage both render `if (loading) return <Skeleton/>`
// until their initial fetch resolves, so the form is absent on first paint.
// Waiting for a control to appear is what the existing users/blocklist suites
// do; asserting synchronously silently measures the skeleton instead.
describe('UsersPage form control naming', () => {
  it('has a known, unchanged set of unnamed controls', async () => {
    // api<UserInfo[]> unwraps to a bare array; the default {} mock makes
    // `users.map` throw and the form never mounts.
    mockFetch.mockResolvedValue(jsonResponse([]));
    const { container } = render(<UsersPage />);
    await waitFor(() => {
      expect(container.querySelector('input')).toBeTruthy();
    });
    // Placeholders are not accessible names: they disappear on input and are
    // inconsistently announced by screen readers.
    expect(unnamedControls(container)).toEqual([]);
  });

  it('has no unassociated <label> elements', async () => {
    mockFetch.mockResolvedValue(jsonResponse([]));
    const { container } = render(<UsersPage />);
    await waitFor(() => {
      expect(container.querySelector('input')).toBeTruthy();
    });
    expect(unassociatedLabels(container)).toEqual([]);
  });
});

describe('BlocklistPage form control naming', () => {
  it('has a known, unchanged set of unnamed controls', async () => {
    const { container } = render(<BlocklistPage />);
    await waitFor(() => {
      expect(container.querySelector('input')).toBeTruthy();
    });
    expect(unnamedControls(container)).toEqual([]);
  });

  it('has no unassociated <label> elements', async () => {
    const { container } = render(<BlocklistPage />);
    await waitFor(() => {
      expect(container.querySelector('input')).toBeTruthy();
    });
    expect(unassociatedLabels(container)).toEqual([]);
  });
});
