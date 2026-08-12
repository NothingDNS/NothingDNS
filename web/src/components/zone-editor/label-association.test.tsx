import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AddRecordDialog, BulkPTRDialog } from './record-dialogs';
import { ZonesPage } from '@/pages/zones';

// Accessibility regression guard (WCAG 1.3.1 / 4.1.2).
//
// Every form control in these dialogs must be reachable by its visible label
// text. getByLabelText only resolves a control when the label is genuinely
// associated with it -- via htmlFor/id, a wrapping <label>, or aria-label.
// A bare <label> sitting next to an <input> looks correct on screen but is
// invisible to assistive technology, and that is exactly the regression this
// file exists to catch.
//
// These assertions deliberately query by the human-readable label string
// rather than by test id or placeholder: a test that passes when the label
// association is broken would defeat the entire purpose.

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const mockNavigate = vi.fn();
vi.mock('react-router', () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

beforeEach(() => {
  mockFetch.mockReset();
  mockNavigate.mockReset();
});

/**
 * Asserts that each label resolves to an actual form control, and that the
 * resolved element is the same node the label points at. getByLabelText throws
 * a descriptive error when the association is missing, which gives a far more
 * useful failure message than a boolean assertion would.
 */
function expectLabelsResolveToControls(labels: string[]) {
  for (const label of labels) {
    const control = screen.getByLabelText(label);
    expect(control).toBeInTheDocument();
    // Guard against a label being associated with a non-interactive element.
    expect(['INPUT', 'TEXTAREA', 'SELECT']).toContain(control.tagName);
  }
}

describe('form label association', () => {
  describe('AddRecordDialog', () => {
    it('exposes every form control via its visible label', () => {
      render(
        <AddRecordDialog
          open
          onClose={vi.fn()}
          zoneName="example.com."
          initialType="A"
          onSaved={vi.fn()}
        />,
      );

      expectLabelsResolveToControls(['Name', 'TTL']);
    });

    it('associates each label with a distinct control', () => {
      render(
        <AddRecordDialog
          open
          onClose={vi.fn()}
          zoneName="example.com."
          initialType="A"
          onSaved={vi.fn()}
        />,
      );

      const name = screen.getByLabelText('Name');
      const ttl = screen.getByLabelText('TTL');
      expect(name).not.toBe(ttl);
    });

    it('keeps labels usable when two instances are mounted at once', () => {
      // useId must produce a unique prefix per instance. If ids ever collide,
      // getAllByLabelText returns controls that point at the same element and
      // this assertion fails.
      render(
        <>
          <AddRecordDialog
            open
            onClose={vi.fn()}
            zoneName="a.example.com."
            initialType="A"
            onSaved={vi.fn()}
          />
          <AddRecordDialog
            open
            onClose={vi.fn()}
            zoneName="b.example.com."
            initialType="A"
            onSaved={vi.fn()}
          />
        </>,
      );

      const names = screen.getAllByLabelText('Name');
      expect(names).toHaveLength(2);
      expect(names[0]).not.toBe(names[1]);
      expect(names[0].id).not.toBe(names[1].id);
      expect(names[0].id).not.toBe('');
    });
  });

  describe('BulkPTRDialog', () => {
    it('exposes every form control via its visible label', () => {
      render(
        <BulkPTRDialog
          open
          onClose={vi.fn()}
          zoneName="10.in-addr.arpa."
          onSaved={vi.fn()}
        />,
      );

      expectLabelsResolveToControls(['CIDR Range', 'Pattern']);
    });

    it('associates each label with a distinct control', () => {
      render(
        <BulkPTRDialog
          open
          onClose={vi.fn()}
          zoneName="10.in-addr.arpa."
          onSaved={vi.fn()}
        />,
      );

      expect(screen.getByLabelText('CIDR Range')).not.toBe(
        screen.getByLabelText('Pattern'),
      );
    });
  });

  describe('CreateZoneDialog', () => {
    // CreateZoneDialog is not exported from pages/zones.tsx, so it is reached
    // through ZonesPage the same way a user reaches it: by clicking "Create
    // Zone". This also proves the association survives the real render path.
    //
    // Queries here use `screen` rather than a scoped container: under jsdom,
    // Radix's DialogContent mounts without resolving role="dialog", so
    // getByRole('dialog') finds nothing even though the content and its
    // labelled controls are fully rendered. Only one dialog is open at a
    // time, so the global label queries are unambiguous regardless.
    async function openCreateZoneDialog() {
      mockFetch.mockResolvedValue(
        mockJsonResponse({
          zones: [{ name: 'example.com.', serial: 2026071501, records: 5 }],
        }),
      );
      const user = userEvent.setup();
      render(<ZonesPage />);

      await waitFor(() => {
        expect(screen.getByText('example.com.')).toBeInTheDocument();
      });

      // Two buttons match /create zone/i: this page-level trigger and the
      // dialog's own submit button. Index 0 is the trigger.
      const [trigger] = screen.getAllByRole('button', { name: /create zone/i });
      await user.click(trigger);
      await screen.findByText('Create New Zone');
    }

    const createZoneLabels = [
      'Zone Name',
      'Default TTL',
      'Admin Email',
      'Nameservers (one per line)',
    ];

    it('exposes every form control via its visible label', async () => {
      await openCreateZoneDialog();

      for (const label of createZoneLabels) {
        const control = screen.getByLabelText(label);
        expect(control).toBeInTheDocument();
        expect(['INPUT', 'TEXTAREA', 'SELECT']).toContain(control.tagName);
      }
    });

    it('associates each label with a distinct control', async () => {
      await openCreateZoneDialog();

      const controls = createZoneLabels.map((label) =>
        screen.getByLabelText(label),
      );
      expect(new Set(controls).size).toBe(createZoneLabels.length);
      expect(new Set(controls.map((c) => c.id)).size).toBe(
        createZoneLabels.length,
      );
    });

    it('associates the nameservers label with the textarea', async () => {
      await openCreateZoneDialog();

      const nameservers = screen.getByLabelText('Nameservers (one per line)');
      expect(nameservers.tagName).toBe('TEXTAREA');
    });
  });

  describe('no unassociated labels remain', () => {
    // Structural backstop: catches a *newly added* label that nobody wrote an
    // explicit assertion for. Every rendered <label> must either carry htmlFor
    // or wrap its control -- an orphan htmlFor pointing at a missing id is
    // just as broken as no htmlFor at all.
    function expectEveryLabelAssociated(container: HTMLElement) {
      const labels = Array.from(container.querySelectorAll('label'));
      expect(labels.length).toBeGreaterThan(0);

      for (const label of labels) {
        const htmlFor = label.getAttribute('for');
        if (htmlFor) {
          const target = container.ownerDocument.getElementById(htmlFor);
          expect(
            target,
            `<label for="${htmlFor}"> points at a non-existent element`,
          ).not.toBeNull();
          continue;
        }
        const wrapped = label.querySelector('input, textarea, select');
        expect(
          wrapped,
          `label "${label.textContent?.trim()}" has no htmlFor and wraps no control`,
        ).not.toBeNull();
      }
    }

    it('holds for AddRecordDialog', () => {
      render(
        <AddRecordDialog
          open
          onClose={vi.fn()}
          zoneName="example.com."
          initialType="A"
          onSaved={vi.fn()}
        />,
      );
      expectEveryLabelAssociated(document.body);
    });

    it('holds for BulkPTRDialog', () => {
      render(
        <BulkPTRDialog
          open
          onClose={vi.fn()}
          zoneName="10.in-addr.arpa."
          onSaved={vi.fn()}
        />,
      );
      expectEveryLabelAssociated(document.body);
    });

    it('holds for CreateZoneDialog', async () => {
      mockFetch.mockResolvedValue(
        mockJsonResponse({
          zones: [{ name: 'example.com.', serial: 2026071501, records: 5 }],
        }),
      );
      const user = userEvent.setup();
      render(<ZonesPage />);

      await waitFor(() => {
        expect(screen.getByText('example.com.')).toBeInTheDocument();
      });
      const [trigger] = screen.getAllByRole('button', { name: /create zone/i });
      await user.click(trigger);
      await screen.findByText('Create New Zone');

      expectEveryLabelAssociated(document.body);
    });
  });
});
