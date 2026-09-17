import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { HistoricalChartsPage, toChronological, toPerIntervalSeries } from './historical-charts';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function json(data: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }));
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe('toPerIntervalSeries', () => {
  it('converts newest-first cumulatives into oldest-to-newest deltas', () => {
    // API order: newest first — totals 300, 200, 100 at t=3,2,1
    const { values, timestamps } = toPerIntervalSeries([300, 200, 100], [3, 2, 1]);
    expect(values).toEqual([100, 100]);
    expect(timestamps).toEqual([2, 3]);
  });

  it('needs at least two samples', () => {
    expect(toPerIntervalSeries([42], [1])).toEqual({ values: [], timestamps: [] });
    expect(toPerIntervalSeries([], [])).toEqual({ values: [], timestamps: [] });
  });

  it('clamps negative deltas from counter resets', () => {
    const { values } = toPerIntervalSeries([50, 200, 100], [3, 2, 1]);
    expect(values).toEqual([100, 0]);
  });
});

describe('toChronological', () => {
  it('reverses newest-first gauges', () => {
    expect(toChronological([30, 20, 10], [3, 2, 1])).toEqual({
      values: [10, 20, 30],
      timestamps: [1, 2, 3],
    });
  });
});

describe('HistoricalChartsPage', () => {
  it('shows empty state when history has no samples', async () => {
    mockFetch.mockResolvedValueOnce(json({
      timestamps: [], queries: [], cache_hits: [], cache_misses: [], latency_ms: [], count: 0,
    }));
    render(<HistoricalChartsPage />);
    expect(await screen.findByText('No historical data available yet')).toBeInTheDocument();
  });

  it('waits for a second sample before drawing per-minute bars', async () => {
    mockFetch.mockResolvedValueOnce(json({
      timestamps: [1000], queries: [10], cache_hits: [5], cache_misses: [5], latency_ms: [12], count: 1,
    }));
    render(<HistoricalChartsPage />);
    expect(await screen.findByText(/Collecting the first samples/)).toBeInTheDocument();
  });

  it('renders visible bar charts once two samples exist', async () => {
    mockFetch.mockResolvedValueOnce(json({
      timestamps: [2000, 1000],
      queries: [250, 100],
      cache_hits: [80, 40],
      cache_misses: [20, 10],
      latency_ms: [15, 12],
      count: 2,
    }));
    render(<HistoricalChartsPage />);

    expect(await screen.findByText('Queries per Minute')).toBeInTheDocument();
    expect(screen.getByText('Cache Hits vs Misses (per minute)')).toBeInTheDocument();
    expect(screen.getByText('Upstream Latency (ms)')).toBeInTheDocument();

    const charts = screen.getAllByRole('img', { name: 'Bar chart' });
    expect(charts.length).toBeGreaterThanOrEqual(3);

    // Bars must have a non-zero computed height style (the prior CSS bug left them at 0).
    await waitFor(() => {
      const bars = charts[0].querySelectorAll('[style*="height"]');
      expect(bars.length).toBeGreaterThan(0);
      const tall = [...bars].some((el) => {
        const h = (el as HTMLElement).style.height;
        return h && h !== '0%' && h !== '0px';
      });
      expect(tall).toBe(true);
    });
  });
});
