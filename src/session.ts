/**
 * SshSession — one Durable Object per live terminal.
 *
 * Why hibernation is not used here
 * --------------------------------
 * WebSocket hibernation lets a Durable Object be evicted while its socket stays
 * open, and rehydrate on the next message. That is unusable for this object.
 * A live SSH session is not just a WebSocket: it also holds an outbound TCP
 * socket from `connect()` and, more importantly, cipher state — the AES-GCM
 * keys and the invocation counters for both directions. None of that survives
 * eviction, and none of it can be written to storage without defeating the
 * point of holding credentials in memory only. So this object stays resident
 * for the life of the terminal and is torn down when either side drops.
 *
 * The Worker has already verified the session cookie, confirmed the caller owns
 * the server, decrypted the credential, and vetted the target address. This
 * object performs no database access and no authorization of its own.
 */
import { DurableObject } from 'cloudflare:workers';
import type { Env } from './env';
import type { AuthCredential } from './ssh/connection';
import { AuthError, HostKeyError, SshClient } from './ssh/connection';

export interface SessionParams {
  address: string;
  hostname: string;
  port: number;
  username: string;
  credential: AuthCredential;
  pinnedFingerprint: string | null;
  cols: number;
  rows: number;
}

/** Server-to-client control messages. Terminal output travels as binary frames. */
type ServerMessage =
  | { type: 'status'; state: 'connecting' | 'connected' | 'closed' }
  | { type: 'hostkey'; fingerprint: string }
  | { type: 'hostkey-accepted'; fingerprint: string }
  | { type: 'hostkey-mismatch'; fingerprint: string }
  | { type: 'error'; message: string };

/** Client-to-server control messages. Keystrokes travel as binary frames. */
type ClientMessage =
  | { type: 'resize'; cols: number; rows: number }
  | { type: 'confirm-hostkey'; accept: boolean };

const IDLE_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_SESSION_MS = 60 * 60 * 1000;
const ALARM_INTERVAL_MS = 30 * 1000;

export class SshSession extends DurableObject<Env> {
  private params: SessionParams | null = null;
  private socket: WebSocket | null = null;
  private ssh: SshClient | null = null;
  private startedAt = 0;
  private lastActivity = 0;
  private torndown = false;
  private hostKeyDecision: ((accept: boolean) => void) | null = null;

  /**
   * Called by the Worker over RPC before the upgrade. Connection parameters,
   * including the decrypted credential, arrive as arguments rather than as
   * request headers so they never sit in anything that could be logged.
   */
  async configure(params: SessionParams): Promise<void> {
    if (this.params) throw new Error('This session is already configured.');
    this.params = params;
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Expected a WebSocket upgrade.', { status: 426 });
    }
    if (!this.params) return new Response('Session not configured.', { status: 409 });
    // One Durable Object is exactly one terminal.
    if (this.socket) return new Response('This session is already in use.', { status: 409 });

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    this.socket = server;
    this.startedAt = Date.now();
    this.lastActivity = this.startedAt;

    server.addEventListener('message', (event: MessageEvent) => {
      void this.onMessage(event);
    });
    server.addEventListener('close', () => void this.teardown('Browser disconnected.'));
    server.addEventListener('error', () => void this.teardown('WebSocket error.'));

    await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
    this.send({ type: 'status', state: 'connecting' });
    void this.startSsh();

    return new Response(null, { status: 101, webSocket: client });
  }

  private async startSsh(): Promise<void> {
    const params = this.params as SessionParams;
    try {
      this.ssh = await SshClient.connect({
        address: params.address,
        hostname: params.hostname,
        port: params.port,
        username: params.username,
        credential: params.credential,
        pinnedFingerprint: params.pinnedFingerprint,
        cols: params.cols,
        rows: params.rows,
        confirmHostKey: (fingerprint) => this.askAboutHostKey(fingerprint),
        onData: (chunk) => this.sendBinary(chunk),
        onExtendedData: (chunk) => this.sendBinary(chunk),
        onClose: (reason) => void this.teardown(reason),
      });

      // Credentials are needed only for the handshake. Drop the reference now
      // rather than leaving them reachable for the life of the terminal.
      this.params = { ...params, credential: { method: 'password', password: '' } };

      if (!params.pinnedFingerprint) {
        this.send({ type: 'hostkey-accepted', fingerprint: this.ssh.fingerprint });
      }
      this.send({ type: 'status', state: 'connected' });
    } catch (error) {
      if (error instanceof HostKeyError) {
        // Only a pinned server can mismatch; tell the browser which key was
        // actually presented so it can offer to re-verify it.
        if (params.pinnedFingerprint) {
          this.send({ type: 'hostkey-mismatch', fingerprint: error.fingerprint });
        }
        this.send({ type: 'error', message: error.message });
      } else if (error instanceof AuthError) {
        this.send({ type: 'error', message: error.message });
      } else {
        this.send({
          type: 'error',
          message: error instanceof Error ? error.message : 'Could not connect.',
        });
      }
      await this.teardown('Connection failed.');
    }
  }

  /** Asks the browser to confirm an unpinned host key, and waits for an answer. */
  private askAboutHostKey(fingerprint: string): Promise<boolean> {
    this.send({ type: 'hostkey', fingerprint });
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.hostKeyDecision = null;
        resolve(false);
      }, 120_000);
      this.hostKeyDecision = (accept: boolean) => {
        clearTimeout(timer);
        this.hostKeyDecision = null;
        resolve(accept);
      };
    });
  }

  private async onMessage(event: MessageEvent): Promise<void> {
    this.lastActivity = Date.now();

    // Binary frames are terminal input and go straight through, unparsed.
    if (event.data instanceof ArrayBuffer) {
      await this.ssh?.write(new Uint8Array(event.data)).catch(() => {});
      return;
    }
    if (typeof event.data !== 'string') return;

    let message: ClientMessage;
    try {
      message = JSON.parse(event.data) as ClientMessage;
    } catch {
      return;
    }

    if (message.type === 'resize') {
      const { cols, rows } = message;
      if (Number.isInteger(cols) && Number.isInteger(rows) && cols > 0 && rows > 0) {
        await this.ssh?.resize(Math.min(cols, 500), Math.min(rows, 300)).catch(() => {});
      }
      return;
    }
    if (message.type === 'confirm-hostkey') {
      this.hostKeyDecision?.(message.accept === true);
    }
  }

  override async alarm(): Promise<void> {
    if (this.torndown) return;
    const now = Date.now();
    if (now - this.lastActivity > IDLE_TIMEOUT_MS) {
      this.send({ type: 'error', message: 'Session closed after being idle.' });
      await this.teardown('Idle timeout.');
      return;
    }
    if (now - this.startedAt > MAX_SESSION_MS) {
      this.send({ type: 'error', message: 'Session reached its maximum duration.' });
      await this.teardown('Maximum duration reached.');
      return;
    }
    await this.ctx.storage.setAlarm(now + ALARM_INTERVAL_MS);
  }

  /**
   * Both halves die together. If the browser drops, the TCP socket must not be
   * left open; if the SSH side drops, the browser must not be left waiting.
   */
  private async teardown(reason: string): Promise<void> {
    if (this.torndown) return;
    this.torndown = true;

    this.hostKeyDecision?.(false);
    const ssh = this.ssh;
    this.ssh = null;
    // Null out the parameters, credential included, before anything else.
    this.params = null;
    await ssh?.close(reason).catch(() => {});

    this.send({ type: 'status', state: 'closed' });
    try {
      this.socket?.close(1000, reason.slice(0, 120));
    } catch {
      /* already closing */
    }
    this.socket = null;
    await this.ctx.storage.deleteAlarm().catch(() => {});
  }

  private send(message: ServerMessage): void {
    try {
      this.socket?.send(JSON.stringify(message));
    } catch {
      /* the browser went away */
    }
  }

  private sendBinary(chunk: Uint8Array): void {
    this.lastActivity = Date.now();
    try {
      // Copy out of the packet buffer: send() is asynchronous underneath and
      // the source may be a view into a buffer we are about to reuse.
      this.socket?.send(chunk.slice().buffer);
    } catch {
      /* the browser went away */
    }
  }
}
