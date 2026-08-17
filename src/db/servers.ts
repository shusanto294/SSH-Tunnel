/**
 * Saved servers.
 *
 * Every function here takes a userId and puts it in the WHERE clause. Server
 * ids are unguessable, but that is not an authorization mechanism — ownership
 * is checked on every read and every write.
 */
import type { Env } from '../env';
import type { Sealed } from '../auth/dek';
import { newId, nowSeconds, toBytes } from '../util/encoding';

export type AuthMethod = 'password' | 'privatekey';

/** What the browser is allowed to see. Never includes the secret. */
export interface ServerSummary {
  id: string;
  label: string;
  host: string;
  port: number;
  sshUser: string;
  authMethod: AuthMethod;
  hostKeyFingerprint: string | null;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface ServerWithSecret extends ServerSummary {
  secret: Sealed;
}

interface ServerRow {
  id: string;
  label: string;
  host: string;
  port: number;
  ssh_user: string;
  auth_method: string;
  host_key_fp: string | null;
  created_at: number;
  last_used_at: number | null;
  secret_ct?: unknown;
  secret_iv?: unknown;
}

function summary(row: ServerRow): ServerSummary {
  return {
    id: row.id,
    label: row.label,
    host: row.host,
    port: row.port,
    sshUser: row.ssh_user,
    authMethod: row.auth_method === 'privatekey' ? 'privatekey' : 'password',
    hostKeyFingerprint: row.host_key_fp,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
}

const PUBLIC_COLUMNS = `id, label, host, port, ssh_user, auth_method, host_key_fp,
                        created_at, last_used_at`;

export async function listServers(env: Env, userId: string): Promise<ServerSummary[]> {
  const { results } = await env.DB.prepare(
    `SELECT ${PUBLIC_COLUMNS} FROM servers WHERE user_id = ? ORDER BY label`,
  )
    .bind(userId)
    .all<ServerRow>();
  return results.map(summary);
}

export async function getServer(
  env: Env,
  userId: string,
  id: string,
): Promise<ServerSummary | null> {
  const row = await env.DB.prepare(
    `SELECT ${PUBLIC_COLUMNS} FROM servers WHERE id = ? AND user_id = ?`,
  )
    .bind(id, userId)
    .first<ServerRow>();
  return row ? summary(row) : null;
}

export async function getServerWithSecret(
  env: Env,
  userId: string,
  id: string,
): Promise<ServerWithSecret | null> {
  const row = await env.DB.prepare(
    `SELECT ${PUBLIC_COLUMNS}, secret_ct, secret_iv
     FROM servers WHERE id = ? AND user_id = ?`,
  )
    .bind(id, userId)
    .first<ServerRow>();
  if (!row) return null;
  return {
    ...summary(row),
    secret: { ciphertext: toBytes(row.secret_ct), iv: toBytes(row.secret_iv) },
  };
}

export interface NewServer {
  label: string;
  host: string;
  port: number;
  sshUser: string;
  authMethod: AuthMethod;
  secret: Sealed;
  hostKeyFingerprint: string | null;
}

export async function createServer(
  env: Env,
  userId: string,
  input: NewServer,
): Promise<ServerSummary> {
  const id = newId();
  const createdAt = nowSeconds();
  await env.DB.prepare(
    `INSERT INTO servers (id, user_id, label, host, port, ssh_user, auth_method,
                          secret_ct, secret_iv, host_key_fp, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      userId,
      input.label,
      input.host,
      input.port,
      input.sshUser,
      input.authMethod,
      input.secret.ciphertext,
      input.secret.iv,
      input.hostKeyFingerprint,
      createdAt,
    )
    .run();
  return {
    id,
    label: input.label,
    host: input.host,
    port: input.port,
    sshUser: input.sshUser,
    authMethod: input.authMethod,
    hostKeyFingerprint: input.hostKeyFingerprint,
    createdAt,
    lastUsedAt: null,
  };
}

export interface ServerPatch {
  label?: string;
  host?: string;
  port?: number;
  sshUser?: string;
  authMethod?: AuthMethod;
  secret?: Sealed;
  /** Explicit null clears the pin, forcing re-confirmation on next connect. */
  hostKeyFingerprint?: string | null;
}

export async function updateServer(
  env: Env,
  userId: string,
  id: string,
  patch: ServerPatch,
): Promise<boolean> {
  const sets: string[] = [];
  const values: unknown[] = [];
  const set = (column: string, value: unknown): void => {
    sets.push(`${column} = ?`);
    values.push(value);
  };

  if (patch.label !== undefined) set('label', patch.label);
  if (patch.host !== undefined) set('host', patch.host);
  if (patch.port !== undefined) set('port', patch.port);
  if (patch.sshUser !== undefined) set('ssh_user', patch.sshUser);
  if (patch.authMethod !== undefined) set('auth_method', patch.authMethod);
  if (patch.secret !== undefined) {
    set('secret_ct', patch.secret.ciphertext);
    set('secret_iv', patch.secret.iv);
  }
  if (patch.hostKeyFingerprint !== undefined) set('host_key_fp', patch.hostKeyFingerprint);
  if (sets.length === 0) return true;

  values.push(id, userId);
  const result = await env.DB.prepare(
    `UPDATE servers SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`,
  )
    .bind(...values)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteServer(env: Env, userId: string, id: string): Promise<boolean> {
  const result = await env.DB.prepare('DELETE FROM servers WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function touchServer(env: Env, userId: string, id: string): Promise<void> {
  await env.DB.prepare('UPDATE servers SET last_used_at = ? WHERE id = ? AND user_id = ?')
    .bind(nowSeconds(), id, userId)
    .run();
}

export async function countServers(env: Env, userId: string): Promise<number> {
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM servers WHERE user_id = ?')
    .bind(userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}
