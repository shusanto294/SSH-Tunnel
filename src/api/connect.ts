/**
 * Provisions a terminal session and returns a single-use ticket.
 *
 * Two ways in:
 *
 *   { serverId }   use a saved server; the stored credential is decrypted here
 *   { host, ... }  an unsaved, one-off connection
 *
 * The second is the point of this endpoint. Credentials for an unsaved session
 * arrive in this request body, are handed to the Durable Object as RPC
 * arguments, and are never written to D1, to Durable Object storage, or to a
 * log. When the session ends they are gone; there is nothing left to steal
 * later. That makes a one-off connection strictly safer than a saved one, and
 * saving genuinely optional.
 *
 * The ticket is the session object's id. It goes in the WebSocket URL, so it
 * must be safe to appear in a log: it is unguessable, single-use, expires in a
 * minute, and is bound to the account that created it.
 */
import type { Env } from '../env';
import type { AuthContext } from '../auth/context';
import { openSecret } from '../auth/dek';
import { audit } from '../db/audit';
import { getServerWithSecret, touchServer } from '../db/servers';
import { resolveTarget } from '../net/guard';
import { LIMITS, rateLimit } from '../rate-limit';
import type { AuthCredential } from '../ssh/connection';
import type { SessionParams } from '../session';
import { fail, json, port as parsePort, readJson, str } from './http';

interface ConnectBody {
  serverId?: unknown;
  host?: unknown;
  port?: unknown;
  sshUser?: unknown;
  authMethod?: unknown;
  secret?: unknown;
  cols?: unknown;
  rows?: unknown;
}

const MAX_SECRET_BYTES = 16 * 1024;

export async function connect(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  const gate = await rateLimit(env, `session:${auth.userId}`, LIMITS.sessionOpen);
  if (!gate.allowed) {
    return json({ error: 'Too many sessions opened. Try again shortly.' }, 429);
  }

  const body = await readJson<ConnectBody>(request);
  if (!body) return fail(400, 'Expected a JSON body.');

  const cols = clamp(body.cols, 80, 1, 500);
  const rows = clamp(body.rows, 24, 1, 300);

  const resolved = body.serverId
    ? await fromSavedServer(env, auth, body)
    : await fromRequestBody(auth, body);
  if ('error' in resolved) return fail(resolved.status, resolved.error);

  const guard = await resolveTarget(env, resolved.host, resolved.port);
  if (!guard.ok) {
    await audit(env, auth.userId, 'session_refused', guard.reason);
    return fail(403, guard.reason);
  }

  const params: SessionParams = {
    ownerId: auth.userId,
    address: guard.target.address,
    hostname: guard.target.hostname,
    port: guard.target.port,
    username: resolved.username,
    credential: resolved.credential,
    pinnedFingerprint: resolved.pinnedFingerprint,
    cols,
    rows,
  };

  // A fresh object per terminal: sessions are never shared or resumed.
  const id = env.SSH_SESSION.newUniqueId();
  await env.SSH_SESSION.get(id).configure(params);

  if (resolved.serverId) {
    await touchServer(env, auth.userId, resolved.serverId);
    await audit(env, auth.userId, 'session_opened', resolved.label);
  } else {
    // Deliberately records that a session happened, not where to. An unsaved
    // connection leaves no trace of the host or the credential.
    await audit(env, auth.userId, 'session_opened', 'unsaved connection');
  }

  return json({
    ticket: id.toString(),
    /** Shown so the user can tell what they are about to connect to. */
    target: `${resolved.username}@${guard.target.hostname}:${guard.target.port}`,
    pinned: resolved.pinnedFingerprint !== null,
  });
}

interface Resolved {
  host: string;
  port: number;
  username: string;
  credential: AuthCredential;
  pinnedFingerprint: string | null;
  serverId?: string;
  label?: string;
}

type Failure = { error: string; status: number };

async function fromSavedServer(
  env: Env,
  auth: AuthContext,
  body: ConnectBody,
): Promise<Resolved | Failure> {
  if (!auth.dek) return { error: 'Sign in again to open a saved server.', status: 409 };
  const serverId = str(body.serverId, 64);
  if (!serverId) return { error: 'No server specified.', status: 400 };

  // Ownership is enforced in the query: someone else's server is
  // indistinguishable from one that does not exist.
  const server = await getServerWithSecret(env, auth.userId, serverId);
  if (!server) return { error: 'No such server.', status: 404 };

  let secret: string;
  try {
    secret = await openSecret(auth.dek, server.secret);
  } catch {
    return { error: 'Could not decrypt the saved credential.', status: 409 };
  }

  return {
    host: server.host,
    port: server.port,
    username: server.sshUser,
    credential:
      server.authMethod === 'password'
        ? { method: 'password', password: secret }
        : { method: 'privatekey', privateKey: secret },
    pinnedFingerprint: server.hostKeyFingerprint,
    serverId: server.id,
    label: server.label,
  };
}

/** An unsaved connection. Nothing here is persisted anywhere. */
function fromRequestBody(auth: AuthContext, body: ConnectBody): Resolved | Failure {
  const host = str(body.host, 253);
  if (!host) return { error: 'A host is required.', status: 400 };

  const port = parsePort(body.port);
  if (port === null) return { error: 'Port must be between 1 and 65535.', status: 400 };

  const username = str(body.sshUser, 64);
  if (!username) return { error: 'An SSH username is required.', status: 400 };

  if (body.authMethod !== 'password' && body.authMethod !== 'privatekey') {
    return { error: 'Auth method must be "password" or "privatekey".', status: 400 };
  }
  if (typeof body.secret !== 'string' || body.secret.length === 0) {
    return { error: 'A password or private key is required.', status: 400 };
  }
  if (body.secret.length > MAX_SECRET_BYTES) {
    return { error: 'That credential is too large.', status: 400 };
  }

  return {
    host,
    port,
    username,
    credential:
      body.authMethod === 'password'
        ? { method: 'password', password: body.secret }
        : { method: 'privatekey', privateKey: body.secret },
    // Nothing was saved, so nothing is pinned: the fingerprint is shown for
    // confirmation on every unsaved connection.
    pinnedFingerprint: null,
  };
}

function clamp(raw: unknown, fallback: number, min: number, max: number): number {
  const n = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
