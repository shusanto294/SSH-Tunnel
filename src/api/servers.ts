/**
 * Saved-server CRUD.
 *
 * The stored secret — an SSH password or a private key — is encrypted with the
 * caller's DEK before it ever reaches D1, and is never sent back to the browser
 * afterwards. Listing a server tells you its host and its pinned fingerprint,
 * nothing more.
 */
import type { Env } from '../env';
import type { AuthContext } from '../auth/context';
import { sealSecret } from '../auth/dek';
import { audit } from '../db/audit';
import * as db from '../db/servers';
import { isBlockedAddress } from '../net/guard';
import { fail, json, port as parsePort, readJson, str } from './http';

const MAX_SERVERS = 50;
const MAX_SECRET_BYTES = 16 * 1024; // comfortably fits an OpenSSH private key

interface ServerBody {
  label?: unknown;
  host?: unknown;
  port?: unknown;
  sshUser?: unknown;
  authMethod?: unknown;
  secret?: unknown;
  hostKeyFingerprint?: unknown;
}

export async function list(env: Env, auth: AuthContext): Promise<Response> {
  return json({ servers: await db.listServers(env, auth.userId) });
}

export async function get(env: Env, auth: AuthContext, id: string): Promise<Response> {
  const server = await db.getServer(env, auth.userId, id);
  return server ? json({ server }) : fail(404, 'No such server.');
}

export async function create(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  if (!auth.dek) return fail(409, 'Sign in again to save credentials.');

  const body = await readJson<ServerBody>(request);
  if (!body) return fail(400, 'Expected a JSON body.');

  const fields = parseFields(body, true);
  if ('error' in fields) return fail(400, fields.error);

  if ((await db.countServers(env, auth.userId)) >= MAX_SERVERS) {
    return fail(409, `You can save at most ${MAX_SERVERS} servers.`);
  }

  const secret = await sealSecret(auth.dek, fields.secret as string);
  const server = await db.createServer(env, auth.userId, {
    label: fields.label as string,
    host: fields.host as string,
    port: fields.port as number,
    sshUser: fields.sshUser as string,
    authMethod: fields.authMethod as db.AuthMethod,
    secret,
    hostKeyFingerprint: fields.hostKeyFingerprint ?? null,
  });
  await audit(env, auth.userId, 'server_created', server.label);
  return json({ server }, 201);
}

export async function update(
  request: Request,
  env: Env,
  auth: AuthContext,
  id: string,
): Promise<Response> {
  const body = await readJson<ServerBody>(request);
  if (!body) return fail(400, 'Expected a JSON body.');

  const fields = parseFields(body, false);
  if ('error' in fields) return fail(400, fields.error);

  const patch: db.ServerPatch = {};
  if (fields.label !== undefined) patch.label = fields.label;
  if (fields.host !== undefined) patch.host = fields.host;
  if (fields.port !== undefined) patch.port = fields.port;
  if (fields.sshUser !== undefined) patch.sshUser = fields.sshUser;
  if (fields.authMethod !== undefined) patch.authMethod = fields.authMethod;
  if (body.hostKeyFingerprint !== undefined) patch.hostKeyFingerprint = fields.hostKeyFingerprint ?? null;

  if (fields.secret !== undefined) {
    if (!auth.dek) return fail(409, 'Sign in again to change credentials.');
    patch.secret = await sealSecret(auth.dek, fields.secret);
  }

  // Changing where a server points invalidates the pinned key: the fingerprint
  // belonged to the old host, and carrying it over would either fail confusingly
  // or, worse, pin the wrong thing.
  if ((patch.host !== undefined || patch.port !== undefined) && patch.hostKeyFingerprint === undefined) {
    patch.hostKeyFingerprint = null;
  }

  const changed = await db.updateServer(env, auth.userId, id, patch);
  if (!changed) return fail(404, 'No such server.');
  await audit(env, auth.userId, 'server_updated', id);
  const server = await db.getServer(env, auth.userId, id);
  return json({ server });
}

export async function remove(env: Env, auth: AuthContext, id: string): Promise<Response> {
  const deleted = await db.deleteServer(env, auth.userId, id);
  if (!deleted) return fail(404, 'No such server.');
  await audit(env, auth.userId, 'server_deleted', id);
  return json({ ok: true });
}

interface ParsedFields {
  label?: string;
  host?: string;
  port?: number;
  sshUser?: string;
  authMethod?: db.AuthMethod;
  secret?: string;
  hostKeyFingerprint?: string | null;
}

function parseFields(body: ServerBody, required: boolean): ParsedFields | { error: string } {
  const out: ParsedFields = {};

  if (required || body.label !== undefined) {
    const label = str(body.label, 80);
    if (!label) return { error: 'A label is required.' };
    out.label = label;
  }

  if (required || body.host !== undefined) {
    const host = str(body.host, 253);
    if (!host) return { error: 'A host is required.' };
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
      // Literal addresses can be judged now. Hostnames are resolved and checked
      // at connect time, where the answer cannot go stale.
      if (isBlockedAddress(host)) {
        return { error: 'That address is in a range this service refuses to connect to.' };
      }
    }
    out.host = host;
  }

  if (required || body.port !== undefined) {
    const port = parsePort(body.port);
    if (port === null) return { error: 'Port must be between 1 and 65535.' };
    out.port = port;
  }

  if (required || body.sshUser !== undefined) {
    const sshUser = str(body.sshUser, 64);
    if (!sshUser) return { error: 'An SSH username is required.' };
    out.sshUser = sshUser;
  }

  if (required || body.authMethod !== undefined) {
    if (body.authMethod !== 'password' && body.authMethod !== 'privatekey') {
      return { error: 'Auth method must be "password" or "privatekey".' };
    }
    out.authMethod = body.authMethod;
  }

  if (required || body.secret !== undefined) {
    if (typeof body.secret !== 'string' || body.secret.length === 0) {
      return { error: 'A password or private key is required.' };
    }
    if (body.secret.length > MAX_SECRET_BYTES) return { error: 'That credential is too large.' };
    out.secret = body.secret;
  }

  if (body.hostKeyFingerprint !== undefined) {
    if (body.hostKeyFingerprint === null) {
      out.hostKeyFingerprint = null;
    } else {
      const fp = str(body.hostKeyFingerprint, 128);
      if (!fp || !/^SHA256:[A-Za-z0-9+/]+=*$/.test(fp)) {
        return { error: 'Host key fingerprint must look like "SHA256:...".' };
      }
      out.hostKeyFingerprint = fp;
    }
  }

  return out;
}
