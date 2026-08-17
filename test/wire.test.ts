import { describe, expect, it } from 'vitest';
import { Reader, Writer, mpintBytes, toHex } from '../src/ssh/wire';

describe('wire codecs', () => {
  it('encodes uint32 big-endian', () => {
    expect(toHex(new Writer().uint32(0x01020304).bytes())).toBe('01020304');
    expect(toHex(new Writer().uint32(0).bytes())).toBe('00000000');
    expect(toHex(new Writer().uint32(0xffffffff).bytes())).toBe('ffffffff');
  });

  it('length-prefixes strings', () => {
    expect(toHex(new Writer().string('abc').bytes())).toBe('00000003616263');
    expect(toHex(new Writer().string('').bytes())).toBe('00000000');
  });

  it('encodes booleans as a single byte', () => {
    expect(toHex(new Writer().boolean(true).bytes())).toBe('01');
    expect(toHex(new Writer().boolean(false).bytes())).toBe('00');
  });

  it('joins name-lists with commas', () => {
    expect(toHex(new Writer().nameList([]).bytes())).toBe('00000000');
    expect(new TextDecoder().decode(new Reader(new Writer().nameList(['a', 'b']).bytes()).string())).toBe(
      'a,b',
    );
  });

  // The three unsigned examples given in RFC 4251 section 5.
  it('encodes mpint per RFC 4251', () => {
    expect(toHex(mpintBytes(new Uint8Array([0])))).toBe('00000000');
    expect(toHex(mpintBytes(new Uint8Array([0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7])))).toBe(
      '0000000809a378f9b2e332a7',
    );
    expect(toHex(mpintBytes(new Uint8Array([0x80])))).toBe('000000020080');
  });

  it('strips leading zero bytes from an mpint', () => {
    expect(toHex(mpintBytes(new Uint8Array([0x00, 0x00, 0x01])))).toBe('0000000101');
  });

  it('round-trips a mixed record', () => {
    const bytes = new Writer()
      .byte(21)
      .uint32(7)
      .string('hello')
      .boolean(true)
      .nameList(['x', 'y'])
      .bytes();

    const r = new Reader(bytes);
    expect(r.byte()).toBe(21);
    expect(r.uint32()).toBe(7);
    expect(r.utf8()).toBe('hello');
    expect(r.boolean()).toBe(true);
    expect(r.nameList()).toEqual(['x', 'y']);
    expect(r.remaining).toBe(0);
  });

  it('refuses to read past the end', () => {
    expect(() => new Reader(new Uint8Array([1, 2])).uint32()).toThrow(/past end/);
  });
});
