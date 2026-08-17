/**
 * Binary Packet Protocol (RFC 4253 section 6) with the two states this client
 * needs: cleartext (pre-NEWKEYS) and aes256-gcm@openssh.com.
 *
 * aes256-gcm@openssh.com differs from the generic BPP:
 *   - packet_length is sent in the clear and used as the AEAD additional data
 *   - the encrypted region is padding_length || payload || padding
 *   - a 16-byte tag follows; no separate MAC is computed
 *   - the 12-byte IV is 4 fixed bytes + an 8-byte big-endian invocation counter
 *     that increments once per packet
 */
import { ByteStream } from './stream';
import { concat } from './wire';

const BLOCK = 16;
const TAG_LEN = 16;
const MAX_PACKET = 256 * 1024;

export interface PacketIO {
  send(payload: Uint8Array): Promise<void>;
  receive(): Promise<Uint8Array>;
  /** Switch to aes256-gcm@openssh.com in both directions. */
  enableGcm(keys: GcmKeys): Promise<void>;
  destroy(): void;
}

export interface GcmKeys {
  ivC2S: Uint8Array; // 12 bytes
  ivS2C: Uint8Array; // 12 bytes
  keyC2S: Uint8Array; // 32 bytes
  keyS2C: Uint8Array; // 32 bytes
}

class GcmDirection {
  private counter: bigint;
  private readonly fixed: Uint8Array;

  constructor(
    readonly key: CryptoKey,
    iv: Uint8Array,
  ) {
    this.fixed = iv.subarray(0, 4);
    const view = new DataView(iv.buffer, iv.byteOffset + 4, 8);
    this.counter = view.getBigUint64(0, false);
  }

  /** Current IV; call bump() after each packet. */
  iv(): Uint8Array {
    const out = new Uint8Array(12);
    out.set(this.fixed, 0);
    new DataView(out.buffer).setBigUint64(4, this.counter, false);
    return out;
  }

  bump(): void {
    this.counter = (this.counter + 1n) & 0xffffffffffffffffn;
  }
}

export class Packets implements PacketIO {
  private gcmOut: GcmDirection | null = null;
  private gcmIn: GcmDirection | null = null;
  private zeroed = false;
  /**
   * Sends are serialised through this chain. Two concurrent sends would
   * interleave their frames on the wire and, worse, race for the GCM
   * invocation counter — which would repeat an IV.
   */
  private sendQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly stream: ByteStream,
    private readonly writer: WritableStreamDefaultWriter<Uint8Array>,
  ) {}

  async enableGcm(keys: GcmKeys): Promise<void> {
    const outKey = await crypto.subtle.importKey('raw', keys.keyC2S, 'AES-GCM', false, [
      'encrypt',
    ]);
    const inKey = await crypto.subtle.importKey('raw', keys.keyS2C, 'AES-GCM', false, [
      'decrypt',
    ]);
    this.gcmOut = new GcmDirection(outKey, keys.ivC2S);
    this.gcmIn = new GcmDirection(inKey, keys.ivS2C);
  }

  async send(payload: Uint8Array): Promise<void> {
    const queued = this.sendQueue.then(async () => {
      if (this.zeroed) throw new Error('packet layer destroyed');
      const frame = this.gcmOut ? await this.frameGcm(payload) : this.frameClear(payload);
      await this.writer.write(frame);
    });
    // Keep the chain alive even when this send rejects, so one failure does not
    // permanently poison every later send with the same error.
    this.sendQueue = queued.catch(() => {});
    return queued;
  }

  private frameClear(payload: Uint8Array): Uint8Array {
    // Pre-NEWKEYS: 8-byte alignment over the whole packet including the length.
    let padLen = 8 - ((5 + payload.length) % 8);
    if (padLen < 4) padLen += 8;
    const packetLen = 1 + payload.length + padLen;
    const out = new Uint8Array(4 + packetLen);
    new DataView(out.buffer).setUint32(0, packetLen, false);
    out[4] = padLen;
    out.set(payload, 5);
    crypto.getRandomValues(out.subarray(5 + payload.length));
    return out;
  }

  private async frameGcm(payload: Uint8Array): Promise<Uint8Array> {
    const gcm = this.gcmOut as GcmDirection;
    // The length field is outside the encrypted region, so only
    // padding_length || payload || padding must be block-aligned.
    let padLen = BLOCK - ((1 + payload.length) % BLOCK);
    if (padLen < 4) padLen += BLOCK;
    const packetLen = 1 + payload.length + padLen;

    const plain = new Uint8Array(packetLen);
    plain[0] = padLen;
    plain.set(payload, 1);
    crypto.getRandomValues(plain.subarray(1 + payload.length));

    const aad = new Uint8Array(4);
    new DataView(aad.buffer).setUint32(0, packetLen, false);

    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: gcm.iv(), additionalData: aad, tagLength: TAG_LEN * 8 },
        gcm.key,
        plain,
      ),
    );
    gcm.bump();
    return concat(aad, sealed);
  }

  async receive(): Promise<Uint8Array> {
    if (this.zeroed) throw new Error('packet layer destroyed');
    return this.gcmIn ? this.readGcm() : this.readClear();
  }

  private async readClear(): Promise<Uint8Array> {
    const lenBuf = await this.stream.readExact(4);
    const packetLen = new DataView(lenBuf.buffer, lenBuf.byteOffset, 4).getUint32(0, false);
    if (packetLen < 8 || packetLen > MAX_PACKET) {
      throw new Error(`bad cleartext packet length ${packetLen}`);
    }
    const rest = await this.stream.readExact(packetLen);
    const padLen = rest[0] as number;
    if (padLen + 1 > packetLen) throw new Error('bad padding length');
    return rest.subarray(1, packetLen - padLen);
  }

  private async readGcm(): Promise<Uint8Array> {
    const gcm = this.gcmIn as GcmDirection;
    const aad = await this.stream.readExact(4);
    const packetLen = new DataView(aad.buffer, aad.byteOffset, 4).getUint32(0, false);
    if (packetLen < BLOCK || packetLen % BLOCK !== 0 || packetLen > MAX_PACKET) {
      throw new Error(`bad gcm packet length ${packetLen}`);
    }
    const body = await this.stream.readExact(packetLen + TAG_LEN);
    let plain: Uint8Array;
    try {
      plain = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: gcm.iv(), additionalData: aad, tagLength: TAG_LEN * 8 },
          gcm.key,
          body,
        ),
      );
    } catch (e) {
      throw new Error(`aes256-gcm tag verification failed: ${(e as Error).message}`);
    }
    gcm.bump();
    const padLen = plain[0] as number;
    if (padLen + 1 > plain.length) throw new Error('bad padding length');
    return plain.subarray(1, plain.length - padLen);
  }

  destroy(): void {
    this.zeroed = true;
    this.gcmIn = null;
    this.gcmOut = null;
    this.stream.cancel();
    void this.writer.close().catch(() => {});
  }
}
