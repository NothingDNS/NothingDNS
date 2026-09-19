import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AboutPage } from './about';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function json(data: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } }));
}

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockResolvedValue(json({ version: '1.2.3' }));
});

describe('AboutPage', () => {
  it('shows API Docs links near the top of the page', async () => {
    render(<AboutPage />);

    expect(await screen.findByRole('link', { name: /API Docs/i })).toHaveAttribute('href', '/api/docs');
    expect(screen.getByRole('link', { name: /OpenAPI JSON/i })).toHaveAttribute('href', '/api/openapi.json');
    expect(screen.getByRole('link', { name: /Open \/api\/docs/i })).toHaveAttribute('href', '/api/docs');
    expect(screen.getByText('REST API')).toBeInTheDocument();
  });
});
