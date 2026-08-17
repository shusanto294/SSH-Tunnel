import { describe, expect, it } from 'vitest';
import { Packets, type GcmKeys } from '../src/ssh/packet';
import { ByteStream } from '../src/ssh/stream';
import { toHex } from '../src/ssh/wire';

/**
 * A TransformStream's readable side defaults to a high-water mark of 0, which
 * makes write() block until something reads. Buffering it lets these tests
 * write a frame and inspect it afterwards.
 */
function channel(): TransformStream<Uint8Array, Uint8Array> {
  return new TransformStream<Uint8Array, Uint8Array>(undefined, undefined, {
    highWaterMark: 64,
  });
}

/** A Packets instance whose frames land in a stream the test can read. */
function sender(): { packets: Packets; frames: ReadableStreamDefaultReader<Uint8Array> } {
  const wire = channel();
  const unused = channel();
  const packets = new Packets(
    new ByteStream(unused.readable.getReader()),
    wire.writable.getWriter(),
  );
  return { packets, frames: wire.readable.getReader() };
}

/** Wires a sender's output straight into a receiver's input. */
function pipe(): { send: Packets; receive: Packets } {
  const wire = channel();
  const unused = channel();
  const send = new Packets(new ByteStream(unused.readable.getReader()), wire.writable.getWriter());
  const receive = new Packets(
    new ByteStream(wire.readable.getReader()),
    unused.writable.getWriter(),
  );
  return { send, receive };
}

const keys: GcmKeys = {
  ivC2S: new Uint8Array(12).fill(1),
  ivS2C: new Uint8Array(12).fill(1), // the receiver reads what the sender wrote
  keyC2S: new Uint8Array(32).fill(7),
  keyS2C: new Uint8Array(32).fill(7),
};

describe('binary packet protocol', () => {
  it('round-trips a cleartext packet', async () => {
    const { send, receive } = pipe();
    const payload = new Uint8Array([20, 1, 2, 3, 4, 5]);
    await send.send(payload);
    expect(toHex(await receive.receive())).toBe(toHex(payload));
  });

  it('pads cleartext packets to an 8-byte boundary with at least 4 bytes', async () => {
    const { packets, frames } = sender();
    await packets.send(new Uint8Array([1]));

    const frame = (await frames.read()).value as Uint8Array;
    const length = new DataView(frame.buffer, frame.byteOffset, 4).getUint32(0, false);
    expect((length + 4) % 8).toBe(0);
    expect(frame[4]).toBeGreaterThanOrEqual(4);
  });

  it('round-trips an aes256-gcm packet', async () => {
    const { send, receive } = pipe();
    await send.enableGcm(keys);
    await receive.enableGcm(keys);

    const payload = new Uint8Array(100).map((_, i) => i);
    await send.send(payload);
    expect(toHex(await receive.receive())).toBe(toHex(payload));
  });

  it('round-trips several packets in a row, keeping the counters in step', async () => {
    const { send, receive } = pipe();
    await send.enableGcm(keys);
    await receive.enableGcm(keys);

    for (let i = 0; i < 5; i++) {
      const payload = new Uint8Array(20).fill(i);
      await send.send(payload);
      expect(toHex(await receive.receive())).toBe(toHex(payload));
    }
  });

  it('keeps the encrypted region block-aligned and the length in the clear', async () => {
    const { packets, frames } = sender();
    await packets.enableGcm(keys);
    await packets.send(new Uint8Array([94, 0, 0, 0, 0]));

    const frame = (await frames.read()).value as Uint8Array;
    const length = new DataView(frame.buffer, frame.byteOffset, 4).getUint32(0, false);
    expect(length % 16).toBe(0);
    // 4-byte length in the clear + ciphertext + 16-byte tag
    expect(frame.length).toBe(4 + length + 16);
  });

  it('advances the IV so identical payloads produce different ciphertext', async () => {
    const { packets, frames } = sender();
    await packets.enableGcm(keys);

    const payload = new Uint8Array([94, 1, 2, 3]);
    await packets.send(payload);
    const first = (await frames.read()).value as Uint8Array;
    await packets.send(payload);
    const second = (await frames.read()).value as Uint8Array;

    expect(toHex(first)).not.toBe(toHex(second));
  });

  it('rejects a tampered ciphertext instead of returning garbage', async () => {
    const { packets, frames } = sender();
    await packets.enableGcm(keys);
    await packets.send(new Uint8Array([94, 9, 9, 9]));

    const frame = (await frames.read()).value as Uint8Array;
    frame[8] = (frame[8] as number) ^ 0xff;

    const replay = channel();
    const unused = channel();
    const receiver = new Packets(
      new ByteStream(replay.readable.getReader()),
      unused.writable.getWriter(),
    );
    await receiver.enableGcm(keys);
    await replay.writable.getWriter().write(frame);

    await expect(receiver.receive()).rejects.toThrow(/tag verification failed/);
  });
});
