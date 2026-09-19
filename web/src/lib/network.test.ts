import { describe, it, expect } from 'vitest';
import { isEverywhere, isIPOrCIDR } from './network';

describe('isIPOrCIDR', () => {
  it.each([
    '192.168.1.0/24', '203.0.113.5', '0.0.0.0/0', '10.0.0.0/8',
    '2001:db8::/32', '::1', '::/0', 'fe80::1', '2001:db8:0:0:0:0:0:1', '::ffff:192.0.2.1',
  ])('accepts %s', (v) => {
    expect(isIPOrCIDR(v)).toBe(true);
  });

  it.each([
    '', 'example.com', '192.168.1.256', '192.168.1.0/33', '10.0.0', '01.2.3.4',
    '2001:db8::/129', '2001::db8::1', '1.2.3.4/24/1', 'gggg::1', '1:2:3:4:5:6:7:8:9',
  ])('rejects %s', (v) => {
    expect(isIPOrCIDR(v)).toBe(false);
  });
});

describe('isEverywhere', () => {
  it('detects any-address networks', () => {
    expect(isEverywhere('0.0.0.0/0')).toBe(true);
    expect(isEverywhere('::/0')).toBe(true);
    expect(isEverywhere('10.0.0.0/8')).toBe(false);
  });
});
