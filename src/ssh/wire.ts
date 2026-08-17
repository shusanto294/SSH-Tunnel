/**
 * SSH wire-format codecs (RFC 4251 section 5).
 * byte / boolean / uint32 / string / mpint / name-list
 */

export class Writer {
  private chunks: Uint8Array[] = [];
  private len = 0;

  byte(v: number): this {
    return this.raw(new Uint8Array([v & 0xff]));
  }

  boolean(v: boolean): this {
    return this.byte(v ? 1 : 0);
  }

  uint32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, false);
    return this.raw(b);
  }

  /** Length-prefixed byte string. */
  string(v: Uint8Array | string): this {
    const bytes = typeof v === 'string' ? new TextEncoder().encode(v) : v;
    this.uint32(bytes.length);
    return this.raw(bytes);
  }

  /** Comma-joined name-list, sent as a string. */
  nameList(names: readonly string[]): this {
    return this.string(names.join(','));
  }

  /** Unsigned multiple-precision integer: minimal big-endian, 0x00-prefixed if high bit set. */
  mpint(v: Uint8Array): this {
    let i = 0;
    while (i < v.length && v[i] === 0) i++;
    const trimmed = v.subarray(i);
    if (trimmed.length === 0) return this.uint32(0);
    const first = trimmed[0] as number;
    if (first & 0x80) {
      const padded = new Uint8Array(trimmed.length + 1);
      padded.set(trimmed, 1);
      return this.string(padded);
    }
    return this.string(trimmed);
  }

  /** Append bytes with no length prefix. */
  raw(v: Uint8Array): this {
    this.chunks.push(v);
    this.len += v.length;
    return this;
  }

  bytes(): Uint8Array {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

export class Reader {
  private off = 0;

  constructor(private readonly buf: Uint8Array) {}

  get offset(): number {
    return this.off;
  }

  get remaining(): number {
    return this.buf.length - this.off;
  }

  byte(): number {
    if (this.off >= this.buf.length) throw new Error('wire: read past end');
    return this.buf[this.off++] as number;
  }

  boolean(): boolean {
    return this.byte() !== 0;
  }

  uint32(): number {
    const b = this.raw(4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, false);
  }

  string(): Uint8Array {
    return this.raw(this.uint32());
  }

  utf8(): string {
    return new TextDecoder().decode(this.string());
  }

  nameList(): string[] {
    const s = this.utf8();
    return s.length === 0 ? [] : s.split(',');
  }

  raw(n: number): Uint8Array {
    if (this.off + n > this.buf.length) throw new Error('wire: read past end');
    const out = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return out;
  }
}

/** Encode a value the way `mpint` would, but return only the encoded bytes. */
export function mpintBytes(v: Uint8Array): Uint8Array {
  return new Writer().mpint(v).bytes();
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function toHex(v: Uint8Array): string {
  return Array.from(v, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function toBase64(v: Uint8Array): string {
  let s = '';
  for (const b of v) s += String.fromCharCode(b);
  return btoa(s);
}
