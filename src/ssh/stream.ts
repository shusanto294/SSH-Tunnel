/** Buffered reader over the TCP socket's ReadableStream. */
export class ByteStream {
  private buf = new Uint8Array(0);
  private eof = false;

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}

  private async pull(): Promise<void> {
    const { value, done } = await this.reader.read();
    if (done) {
      this.eof = true;
      return;
    }
    if (!value || value.length === 0) return;
    const next = new Uint8Array(this.buf.length + value.length);
    next.set(this.buf, 0);
    next.set(value, this.buf.length);
    this.buf = next;
  }

  async readExact(n: number): Promise<Uint8Array> {
    while (this.buf.length < n) {
      if (this.eof) {
        throw new Error(
          `connection closed after ${this.buf.length} of ${n} expected bytes`,
        );
      }
      await this.pull();
    }
    const out = this.buf.subarray(0, n);
    // Copy so callers can hold on to it past the next pull().
    const copy = new Uint8Array(out);
    this.buf = this.buf.subarray(n);
    return copy;
  }

  /** Read one CRLF- (or LF-) terminated line, returned without the terminator. */
  async readLine(maxLen = 8192): Promise<string> {
    for (;;) {
      const idx = this.buf.indexOf(0x0a);
      if (idx >= 0) {
        let end = idx;
        if (end > 0 && this.buf[end - 1] === 0x0d) end--;
        const line = new TextDecoder().decode(this.buf.subarray(0, end));
        this.buf = this.buf.subarray(idx + 1);
        return line;
      }
      if (this.buf.length > maxLen) throw new Error('line too long');
      if (this.eof) throw new Error('connection closed before end of line');
      await this.pull();
    }
  }

  cancel(): void {
    void this.reader.cancel().catch(() => {});
  }
}
