import { describe, expect, it } from 'vitest';
import { deriveKey, sha256 } from '../src/ssh/kex';
import { concat, mpintBytes, toHex } from '../src/ssh/wire';

const K = new Uint8Array(32).fill(0x42);
const H = new Uint8Array(32).fill(0x17);
const SESSION_ID = H;

/**
 * RFC 4253 section 7.2 states the derivation directly:
 *   K1 = HASH(K || H || X || session_id)
 *   K2 = HASH(K || H || K1), and so on, with K encoded as an mpint.
 * These tests recompute that by hand rather than trusting the implementation
 * to check itself.
 */
describe('key derivation (RFC 4253 §7.2)', () => {
  it('produces HASH(K || H || X || session_id) for the first block', async () => {
    const expected = await sha256(
      concat(mpintBytes(K), H, new Uint8Array([0x41]), SESSION_ID), // 0x41 = 'A'
    );
    const actual = await deriveKey(K, H, 'A', SESSION_ID, 32);
    expect(toHex(actual)).toBe(toHex(expected));
  });

  it('gives each letter a different key', async () => {
    const keys = await Promise.all(
      (['A', 'B', 'C', 'D', 'E', 'F'] as const).map((letter) =>
        deriveKey(K, H, letter, SESSION_ID, 32),
      ),
    );
    expect(new Set(keys.map(toHex)).size).toBe(6);
  });

  it('truncates rather than pads for the 12-byte GCM IV', async () => {
    const full = await deriveKey(K, H, 'A', SESSION_ID, 32);
    const iv = await deriveKey(K, H, 'A', SESSION_ID, 12);
    expect(iv.length).toBe(12);
    expect(toHex(iv)).toBe(toHex(full.subarray(0, 12)));
  });

  it('extends past one hash block by rehashing K || H || previous', async () => {
    const k1 = await sha256(concat(mpintBytes(K), H, new Uint8Array([0x43]), SESSION_ID));
    const k2 = await sha256(concat(mpintBytes(K), H, k1));
    const expected = concat(k1, k2).subarray(0, 48);
    const actual = await deriveKey(K, H, 'C', SESSION_ID, 48);
    expect(actual.length).toBe(48);
    expect(toHex(actual)).toBe(toHex(expected));
  });

  it('changes completely when the shared secret changes', async () => {
    const other = new Uint8Array(32).fill(0x43);
    const a = await deriveKey(K, H, 'C', SESSION_ID, 32);
    const b = await deriveKey(other, H, 'C', SESSION_ID, 32);
    expect(toHex(a)).not.toBe(toHex(b));
  });
});
