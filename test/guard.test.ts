import { describe, expect, it } from 'vitest';
import { isBlockedAddress } from '../src/net/guard';

describe('egress guard', () => {
  it('blocks loopback, private, and link-local IPv4', () => {
    for (const address of [
      '127.0.0.1',
      '10.0.0.5',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254', // cloud metadata
      '100.64.0.1', // CGNAT
      '0.0.0.0',
      '224.0.0.1', // multicast
      '255.255.255.255',
    ]) {
      expect(isBlockedAddress(address), address).toBe(true);
    }
  });

  it('allows ordinary public IPv4', () => {
    for (const address of ['1.1.1.1', '8.8.8.8', '172.32.0.1', '192.167.1.1', '203.0.113.10']) {
      expect(isBlockedAddress(address), address).toBe(false);
    }
  });

  it('blocks loopback, unique-local, and link-local IPv6', () => {
    for (const address of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1']) {
      expect(isBlockedAddress(address), address).toBe(true);
    }
  });

  it('judges IPv4-mapped IPv6 by its IPv4 half', () => {
    expect(isBlockedAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedAddress('::ffff:8.8.8.8')).toBe(false);
  });

  it('blocks anything it cannot parse', () => {
    for (const address of ['999.1.1.1', 'not-an-address', '1.2.3']) {
      expect(isBlockedAddress(address), address).toBe(true);
    }
  });

  it('allows public IPv6', () => {
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false);
  });
});
