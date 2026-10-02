/**
 * Series transforms for the historical charts page. Kept out of
 * `historical-charts.tsx` so that file only exports components and React Fast
 * Refresh can hot-swap it in development (react-refresh/only-export-components).
 */

/**
 * API returns newest-first cumulative counters; charts want oldest→newest per-interval deltas.
 */
export function toPerIntervalSeries(values: number[], timestamps: number[]): { values: number[]; timestamps: number[] } {
  const chronValues = [...values].reverse();
  const chronTs = [...timestamps].reverse();
  if (chronValues.length < 2) {
    return { values: [], timestamps: [] };
  }
  const outValues: number[] = [];
  const outTs: number[] = [];
  for (let i = 1; i < chronValues.length; i++) {
    outValues.push(Math.max(0, chronValues[i] - chronValues[i - 1]));
    outTs.push(chronTs[i] ?? chronTs[i - 1] ?? 0);
  }
  return { values: outValues, timestamps: outTs };
}

/** Latency samples are gauges (not counters): reverse to chronological order only. */
export function toChronological(values: number[], timestamps: number[]): { values: number[]; timestamps: number[] } {
  return {
    values: [...values].reverse(),
    timestamps: [...timestamps].reverse(),
  };
}
