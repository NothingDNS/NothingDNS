import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AdvancedSettings } from './advanced-settings';
import { type ServerConfig } from './types';

// Minimal fixture: only the ODoH block the KEM row reads. The cast mirrors
// label-association.test.tsx's emptyConfig pattern for focused component tests.
const odoHConfig = (kem: number) =>
  ({
    ODoH: { Enabled: true, Bind: ':8481', TargetURL: '', ProxyURL: '', KEM: kem, KDF: 1, AEAD: 1 },
  }) as ServerConfig;

describe('AdvancedSettings ODoH KEM', () => {
  it('falls back to KEM 32 (RFC 9180 X25519) when ODoH.KEM is absent', () => {
    render(<AdvancedSettings config={odoHConfig(0)} />);
    const row = screen.getByText('KEM').closest('div');
    expect(row).toHaveTextContent('32');
    expect(row).not.toHaveTextContent('4');
  });

  it('renders an explicitly configured KEM verbatim', () => {
    render(<AdvancedSettings config={odoHConfig(32)} />);
    const row = screen.getByText('KEM').closest('div');
    expect(row).toHaveTextContent('32');
  });
});
