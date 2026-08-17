/**
 * Single-use registration invites. Only SHA-256(code) is stored, so the
 * database never holds a redeemable code.
 */
import type { Env } from '../env';
import { b64urlEncode, nowSeconds, randomBytes, sha256 } from '../util/encoding';

export interface Invite {
  code: string;
  expiresAt: number | null;
}

export async function createInvite(
  env: Env,
  createdBy: string | null,
  ttlSeconds: number | null,
): Promise<Invite> {
  const code = b64urlEncode(randomBytes(18));
  const now = nowSeconds();
  const expiresAt = ttlSeconds === null ? null : now + ttlSeconds;
  await env.DB.prepare(
    'INSERT INTO invites (code_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?)',
  )
    .bind(await sha256(code), createdBy, now, expiresAt)
    .run();
  return { code, expiresAt };
}

/**
 * Atomically claims a code. Returns false for unknown, expired, or already-used
 * codes; the conditional UPDATE is what makes two concurrent registrations
 * unable to share one invite.
 */
export async function redeemInvite(env: Env, code: string, userId: string): Promise<boolean> {
  const now = nowSeconds();
  const result = await env.DB.prepare(
    `UPDATE invites SET used_by = ?, used_at = ?
     WHERE code_hash = ? AND used_by IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
  )
    .bind(userId, now, await sha256(code), now)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function releaseInvite(env: Env, code: string): Promise<void> {
  await env.DB.prepare('UPDATE invites SET used_by = NULL, used_at = NULL WHERE code_hash = ?')
    .bind(await sha256(code))
    .run();
}
