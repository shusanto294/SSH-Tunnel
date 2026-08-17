/**
 * Interactive SSH client: handshake, userauth, then a pty-backed shell.
 *
 * Built on the transport primitives proven in spike/ — the packet layer, the
 * curve25519 kex, and the wire codecs are the code that actually completed a
 * handshake against a real server, not a rewrite of it.
 *
 * Nothing in this file logs credentials, key material, or channel data.
 */
import { connect } from 'cloudflare:sockets';
import { ALGS, CLIENT_IDENT, MSG } from './constants';
import {
  computeExchangeHash,
  deriveKey,
  generateX25519,
  verifyHostKey,
  x25519SharedSecret,
} from './kex';
import { Packets } from './packet';
import { parseOpenSshEd25519 } from './privatekey';
import { ByteStream } from './stream';
import { Reader, Writer } from './wire';

export type AuthCredential =
  | { method: 'password'; password: string }
  | { method: 'privatekey'; privateKey: string };

export interface ConnectOptions {
  /** Literal address to dial — already vetted by the egress guard. */
  address: string;
  /** What the user typed. Used for messages only. */
  hostname: string;
  port: number;
  username: string;
  credential: AuthCredential;
  /**
   * Required fingerprint. When null, `confirmHostKey` must be supplied and must
   * return true — there is no silent trust-on-first-use.
   */
  pinnedFingerprint: string | null;
  confirmHostKey?: (fingerprint: string) => Promise<boolean>;
  cols: number;
  rows: number;
  term?: string;
  handshakeTimeoutMs?: number;
  onData: (chunk: Uint8Array) => void;
  onExtendedData?: (chunk: Uint8Array) => void;
  onClose: (reason: string) => void;
}

export class HostKeyError extends Error {
  constructor(
    message: string,
    readonly fingerprint: string,
  ) {
    super(message);
    this.name = 'HostKeyError';
  }
}

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

const LOCAL_WINDOW = 2 * 1024 * 1024;
const WINDOW_REFILL_AT = LOCAL_WINDOW / 2;
const MAX_PACKET = 32 * 1024;
const CLIENT_CHANNEL = 0;

export class SshClient {
  private closed = false;
  private remoteWindow = 0;
  private localWindow = LOCAL_WINDOW;
  private remoteChannel = 0;
  private windowWaiters: Array<() => void> = [];

  private constructor(
    private readonly packets: Packets,
    private readonly socket: Socket,
    private readonly options: ConnectOptions,
    readonly fingerprint: string,
  ) {}

  static async connect(options: ConnectOptions): Promise<SshClient> {
    // Sockets may only be opened inside a handler; this is called from the
    // Durable Object's fetch/RPC path, never at module scope.
    const socket = connect(
      { hostname: options.address, port: options.port },
      { allowHalfOpen: false },
    );
    const stream = new ByteStream(
      socket.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>,
    );
    const writer = socket.writable.getWriter();
    const packets = new Packets(stream, writer);

    try {
      const fingerprint = await withTimeout(
        handshake(packets, stream, writer, options),
        options.handshakeTimeoutMs ?? 20_000,
      );
      const client = new SshClient(packets, socket, options, fingerprint);
      await client.openShell();
      void client.pump();
      return client;
    } catch (error) {
      packets.destroy();
      try {
        await socket.close();
      } catch {
        /* already gone */
      }
      throw error;
    }
  }

  private async openShell(): Promise<void> {
    await this.packets.send(
      new Writer()
        .byte(MSG.CHANNEL_OPEN)
        .string('session')
        .uint32(CLIENT_CHANNEL)
        .uint32(LOCAL_WINDOW)
        .uint32(MAX_PACKET)
        .bytes(),
    );

    const confirmation = await this.expect(MSG.CHANNEL_OPEN_CONFIRMATION, MSG.CHANNEL_OPEN_FAILURE);
    const r = new Reader(confirmation);
    r.byte();
    r.uint32();
    this.remoteChannel = r.uint32();
    this.remoteWindow = r.uint32();
    r.uint32(); // remote max packet size

    await this.packets.send(
      new Writer()
        .byte(MSG.CHANNEL_REQUEST)
        .uint32(this.remoteChannel)
        .string('pty-req')
        .boolean(true)
        .string(this.options.term ?? 'xterm-256color')
        .uint32(this.options.cols)
        .uint32(this.options.rows)
        .uint32(0) // width in pixels — the client reports characters only
        .uint32(0)
        .string(new Uint8Array([0])) // empty terminal modes list
        .bytes(),
    );
    await this.expect(MSG.CHANNEL_SUCCESS, MSG.CHANNEL_FAILURE);

    await this.packets.send(
      new Writer()
        .byte(MSG.CHANNEL_REQUEST)
        .uint32(this.remoteChannel)
        .string('shell')
        .boolean(true)
        .bytes(),
    );
    await this.expect(MSG.CHANNEL_SUCCESS, MSG.CHANNEL_FAILURE);
  }

  /** Reads packets until the channel closes or the socket dies. */
  private async pump(): Promise<void> {
    try {
      for (;;) {
        const packet = await this.packets.receive();
        if (this.closed) return;
        const done = await this.dispatch(packet);
        if (done) break;
      }
      this.finish('Session closed.');
    } catch (error) {
      if (!this.closed) this.finish(describe(error));
    }
  }

  /** Returns true when the channel is finished. */
  private async dispatch(packet: Uint8Array): Promise<boolean> {
    const type = packet[0] as number;
    const r = new Reader(packet);
    r.byte();

    switch (type) {
      case MSG.CHANNEL_DATA: {
        r.uint32();
        const data = r.string();
        this.options.onData(data);
        await this.consumeWindow(data.length);
        return false;
      }
      case MSG.CHANNEL_EXTENDED_DATA: {
        r.uint32();
        r.uint32(); // data type code: 1 = stderr
        const data = r.string();
        this.options.onExtendedData?.(data);
        await this.consumeWindow(data.length);
        return false;
      }
      case MSG.CHANNEL_WINDOW_ADJUST: {
        r.uint32();
        this.remoteWindow += r.uint32();
        for (const wake of this.windowWaiters.splice(0)) wake();
        return false;
      }
      case MSG.CHANNEL_EOF:
        return false;
      case MSG.CHANNEL_CLOSE:
        return true;
      case MSG.CHANNEL_REQUEST: {
        // exit-status and exit-signal arrive here just before CHANNEL_CLOSE;
        // the close itself is what ends the session, so nothing to act on.
        r.uint32();
        r.utf8();
        if (r.boolean()) {
          await this.packets.send(
            new Writer().byte(MSG.CHANNEL_FAILURE).uint32(this.remoteChannel).bytes(),
          );
        }
        return false;
      }
      case MSG.GLOBAL_REQUEST:
        await declineGlobalRequest(this.packets, packet);
        return false;
      case MSG.DISCONNECT: {
        const code = r.uint32();
        this.finish(`Server disconnected (code ${code}): ${r.utf8()}`);
        return true;
      }
      case MSG.KEXINIT:
        // Rekeying mid-session is not implemented. With aes256-gcm the default
        // OpenSSH rekey threshold is measured in gigabytes, so a terminal
        // session hits the session time cap long before this.
        this.finish('Server requested a rekey, which is not supported.');
        return true;
      default:
        return false;
    }
  }

  /** Give the server room to keep sending once our advertised window drains. */
  private async consumeWindow(bytes: number): Promise<void> {
    this.localWindow -= bytes;
    if (this.localWindow > WINDOW_REFILL_AT) return;
    const increment = LOCAL_WINDOW - this.localWindow;
    this.localWindow = LOCAL_WINDOW;
    await this.packets.send(
      new Writer()
        .byte(MSG.CHANNEL_WINDOW_ADJUST)
        .uint32(this.remoteChannel)
        .uint32(increment)
        .bytes(),
    );
  }

  /** Keystrokes and pasted text, honouring the server's advertised window. */
  async write(data: Uint8Array): Promise<void> {
    if (this.closed) throw new Error('Session is closed.');
    let offset = 0;
    while (offset < data.length) {
      while (this.remoteWindow === 0 && !this.closed) {
        await new Promise<void>((resolve) => this.windowWaiters.push(resolve));
      }
      if (this.closed) return;
      const size = Math.min(data.length - offset, this.remoteWindow, MAX_PACKET - 64);
      const chunk = data.subarray(offset, offset + size);
      await this.packets.send(
        new Writer()
          .byte(MSG.CHANNEL_DATA)
          .uint32(this.remoteChannel)
          .string(chunk)
          .bytes(),
      );
      this.remoteWindow -= size;
      offset += size;
    }
  }

  async resize(cols: number, rows: number): Promise<void> {
    if (this.closed) return;
    await this.packets.send(
      new Writer()
        .byte(MSG.CHANNEL_REQUEST)
        .uint32(this.remoteChannel)
        .string('window-change')
        .boolean(false)
        .uint32(cols)
        .uint32(rows)
        .uint32(0)
        .uint32(0)
        .bytes(),
    );
  }

  async close(reason = 'Closed by client.'): Promise<void> {
    if (this.closed) return;
    try {
      await this.packets.send(
        new Writer().byte(MSG.CHANNEL_CLOSE).uint32(this.remoteChannel).bytes(),
      );
    } catch {
      /* the socket may already be gone */
    }
    this.finish(reason);
  }

  /** Single teardown path: kill the socket, drop key material, notify once. */
  private finish(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    for (const wake of this.windowWaiters.splice(0)) wake();
    this.packets.destroy();
    void this.socket.close().catch(() => {});
    this.options.onClose(reason);
  }

  private async expect(want: number, failOn?: number): Promise<Uint8Array> {
    for (;;) {
      const packet = await this.packets.receive();
      const type = packet[0] as number;
      if (type === want) return packet;
      if (failOn !== undefined && type === failOn) {
        throw new Error('The server refused the session request.');
      }
      if (type === MSG.DISCONNECT) {
        const r = new Reader(packet);
        r.byte();
        const code = r.uint32();
        throw new Error(`Server disconnected (code ${code}): ${r.utf8()}`);
      }
      if (type === MSG.GLOBAL_REQUEST) {
        await declineGlobalRequest(this.packets, packet);
        continue;
      }
      if (isNoise(type)) continue;
      /**
       * Channel traffic can legitimately arrive before the reply being waited
       * for. A window adjustment is the common case — the server sizes our
       * send window as soon as the channel exists, which is typically before
       * it answers `pty-req`. Hand anything channel-shaped to the normal
       * dispatcher instead of treating the ordering as an error.
       */
      if (isChannelMessage(type)) {
        const finished = await this.dispatch(packet);
        if (finished) throw new Error('The channel closed before the session was ready.');
        continue;
      }
      throw new Error(`Unexpected SSH message ${type}.`);
    }
  }
}

/** Transport setup through to a successful userauth. Returns the fingerprint. */
async function handshake(
  packets: Packets,
  stream: ByteStream,
  writer: WritableStreamDefaultWriter<Uint8Array>,
  options: ConnectOptions,
): Promise<string> {
  await writer.write(new TextEncoder().encode(`${CLIENT_IDENT}\r\n`));

  let serverIdent = '';
  for (let i = 0; i < 32 && !serverIdent; i++) {
    const line = await stream.readLine();
    if (line.startsWith('SSH-')) serverIdent = line;
  }
  if (!serverIdent.startsWith('SSH-2.0-')) {
    throw new Error('The server did not offer SSH-2.0.');
  }

  const clientKexInit = new Writer()
    .byte(MSG.KEXINIT)
    .raw(crypto.getRandomValues(new Uint8Array(16)))
    .nameList(ALGS.kex)
    .nameList(ALGS.hostKey)
    .nameList(ALGS.cipher)
    .nameList(ALGS.cipher)
    .nameList(ALGS.mac)
    .nameList(ALGS.mac)
    .nameList(ALGS.compression)
    .nameList(ALGS.compression)
    .nameList([])
    .nameList([])
    .boolean(false)
    .uint32(0)
    .bytes();
  await packets.send(clientKexInit);

  const serverKexInit = await expectDuringHandshake(packets, MSG.KEXINIT);
  const sr = new Reader(serverKexInit);
  sr.byte();
  sr.raw(16);
  const serverKex = sr.nameList();
  const serverHostKey = sr.nameList();
  const serverCipherC2S = sr.nameList();
  const serverCipherS2C = sr.nameList();

  pick(ALGS.kex, serverKex, 'key exchange');
  pick(ALGS.hostKey, serverHostKey, 'host key');
  pick(ALGS.cipher, serverCipherC2S, 'cipher');
  pick(ALGS.cipher, serverCipherS2C, 'cipher');

  const ephemeral = await generateX25519();
  await packets.send(new Writer().byte(MSG.KEX_ECDH_INIT).string(ephemeral.publicKey).bytes());

  const reply = await expectDuringHandshake(packets, MSG.KEX_ECDH_REPLY);
  const rr = new Reader(reply);
  rr.byte();
  const hostKeyBlob = rr.string();
  const serverEphemeral = rr.string();
  const signatureBlob = rr.string();
  if (serverEphemeral.length !== 32) throw new Error('Malformed key exchange reply.');

  const shared = await x25519SharedSecret(ephemeral.privateKey, serverEphemeral);
  const exchangeHash = await computeExchangeHash({
    clientIdent: CLIENT_IDENT,
    serverIdent,
    clientKexInit,
    serverKexInit,
    hostKeyBlob,
    clientEphemeral: ephemeral.publicKey,
    serverEphemeral,
    sharedSecret: shared,
  });

  const check = await verifyHostKey(hostKeyBlob, signatureBlob, exchangeHash);
  if (!check.signatureValid) {
    throw new HostKeyError('Host key signature verification failed.', check.fingerprint);
  }

  // Fail closed. A pinned fingerprint must match exactly; an unpinned server
  // requires the caller to obtain explicit confirmation from the user.
  if (options.pinnedFingerprint) {
    if (options.pinnedFingerprint !== check.fingerprint) {
      // Either the machine was rebuilt, or something is impersonating it.
      // Both look identical from here, so the connection stops and a human
      // decides.
      throw new HostKeyError(
        `The host key for this server has changed. It now presents ${check.fingerprint}, ` +
          `but ${options.pinnedFingerprint} was saved. This happens after an OS reinstall — ` +
          'but it is also what an impersonated server looks like. Refusing to connect.',
        check.fingerprint,
      );
    }
  } else {
    const confirmed = options.confirmHostKey
      ? await options.confirmHostKey(check.fingerprint)
      : false;
    if (!confirmed) {
      throw new HostKeyError('The host key was not confirmed.', check.fingerprint);
    }
  }

  await packets.send(new Uint8Array([MSG.NEWKEYS]));
  await expectDuringHandshake(packets, MSG.NEWKEYS);

  const sessionId = exchangeHash; // first kex: session_id is H
  await packets.enableGcm({
    ivC2S: await deriveKey(shared, exchangeHash, 'A', sessionId, 12),
    ivS2C: await deriveKey(shared, exchangeHash, 'B', sessionId, 12),
    keyC2S: await deriveKey(shared, exchangeHash, 'C', sessionId, 32),
    keyS2C: await deriveKey(shared, exchangeHash, 'D', sessionId, 32),
  });

  await packets.send(new Writer().byte(MSG.SERVICE_REQUEST).string('ssh-userauth').bytes());
  await expectDuringHandshake(packets, MSG.SERVICE_ACCEPT);

  await authenticate(packets, sessionId, options);
  return check.fingerprint;
}

async function authenticate(
  packets: Packets,
  sessionId: Uint8Array,
  options: ConnectOptions,
): Promise<void> {
  const request =
    options.credential.method === 'password'
      ? new Writer()
          .byte(MSG.USERAUTH_REQUEST)
          .string(options.username)
          .string('ssh-connection')
          .string('password')
          .boolean(false)
          .string(options.credential.password)
          .bytes()
      : await publicKeyRequest(sessionId, options.username, options.credential.privateKey);

  await packets.send(request);

  for (;;) {
    const packet = await packets.receive();
    const type = packet[0] as number;
    if (type === MSG.USERAUTH_SUCCESS) return;
    if (type === MSG.USERAUTH_BANNER) continue;
    if (type === MSG.USERAUTH_FAILURE) {
      const r = new Reader(packet);
      r.byte();
      const methods = r.nameList();
      throw new AuthError(
        `Authentication failed. The server accepts: ${methods.join(', ') || 'nothing offered'}.`,
      );
    }
    if (type === MSG.DISCONNECT) {
      const r = new Reader(packet);
      r.byte();
      r.uint32();
      throw new AuthError(`Server disconnected during authentication: ${r.utf8()}`);
    }
    if (type === MSG.GLOBAL_REQUEST) {
      await declineGlobalRequest(packets, packet);
      continue;
    }
    if (!isNoise(type)) throw new AuthError('Unexpected reply during authentication.');
  }
}

async function publicKeyRequest(
  sessionId: Uint8Array,
  username: string,
  privateKeyText: string,
): Promise<Uint8Array> {
  const key = parseOpenSshEd25519(privateKeyText);

  // The signed blob is the session id followed by the request itself, so a
  // signature cannot be replayed into a different session.
  const signed = new Writer()
    .string(sessionId)
    .byte(MSG.USERAUTH_REQUEST)
    .string(username)
    .string('ssh-connection')
    .string('publickey')
    .boolean(true)
    .string('ssh-ed25519')
    .string(key.publicKeyBlob)
    .bytes();

  const signingKey = await importEd25519Private(key.pkcs8);
  const signature = new Uint8Array(
    await signEd25519(signingKey, signed),
  );

  return new Writer()
    .byte(MSG.USERAUTH_REQUEST)
    .string(username)
    .string('ssh-connection')
    .string('publickey')
    .boolean(true)
    .string('ssh-ed25519')
    .string(key.publicKeyBlob)
    .string(new Writer().string('ssh-ed25519').string(signature).bytes())
    .bytes();
}

/** Older workerd builds only expose the legacy algorithm name. */
async function importEd25519Private(pkcs8: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  } catch {
    return await crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' },
      false,
      ['sign'],
    );
  }
}

async function signEd25519(key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
  try {
    return await crypto.subtle.sign({ name: 'Ed25519' }, key, data);
  } catch {
    return await crypto.subtle.sign({ name: 'NODE-ED25519' }, key, data);
  }
}

async function expectDuringHandshake(packets: Packets, want: number): Promise<Uint8Array> {
  for (;;) {
    const packet = await packets.receive();
    const type = packet[0] as number;
    if (type === want) return packet;
    if (type === MSG.DISCONNECT) {
      const r = new Reader(packet);
      r.byte();
      const code = r.uint32();
      throw new Error(`Server disconnected (code ${code}): ${r.utf8()}`);
    }
    if (type === MSG.GLOBAL_REQUEST) {
      await declineGlobalRequest(packets, packet);
      continue;
    }
    if (!isNoise(type)) throw new Error(`Unexpected SSH message ${type} during handshake.`);
  }
}

/**
 * A global request can arrive at any point once the transport is up. OpenSSH
 * sends `hostkeys-00@openssh.com` the instant authentication succeeds, which
 * lands while the client is waiting for its channel to open.
 *
 * This client implements no global requests, so every one is declined — but it
 * must be declined rather than ignored, because a request with want_reply set
 * leaves the server waiting for an answer.
 */
async function declineGlobalRequest(packets: Packets, packet: Uint8Array): Promise<void> {
  const r = new Reader(packet);
  r.byte();
  r.utf8(); // request name
  if (r.boolean()) await packets.send(new Uint8Array([MSG.REQUEST_FAILURE]));
}

function pick(ours: readonly string[], theirs: readonly string[], what: string): string {
  for (const candidate of ours) if (theirs.includes(candidate)) return candidate;
  throw new Error(`No shared ${what} algorithm with this server.`);
}

/** Message numbers 91–100 are the connection protocol's channel messages. */
function isChannelMessage(type: number): boolean {
  return type >= MSG.CHANNEL_OPEN_CONFIRMATION && type <= MSG.CHANNEL_FAILURE;
}

function isNoise(type: number): boolean {
  return (
    type === MSG.IGNORE ||
    type === MSG.DEBUG ||
    type === MSG.EXT_INFO ||
    type === MSG.UNIMPLEMENTED
  );
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'Connection lost.';
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out after ${ms}ms.`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}
