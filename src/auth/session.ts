/**
 * Session cookies.
 *
 * Opaque random tokens, not JWTs: revocation matters far more than
 * statelessness for an app that can open a shell on someone's server. Only
 * SHA-256(token) is stored, so a database leak cannot be replayed as a login.
 *
 * Two cookies are set at login:
 *   st  the session token
 *   dk  the account's unwrapped data encryption key
 *
 * `dk` is what keeps saved SSH secrets out of reach of a database-only
 * compromise: the Worker can decrypt a saved credential only during a request
 * that carries the cookie. Both are HttpOnly, so script on the page cannot read
 * either one.
 */
import type { Env } from '../env';
import { b64urlDecode, b64urlEncode, nowSeconds, randomBytes, sha256 } from '../util/encoding';

export const SESSION_COOKIE = 'st';
export const DEK_COOKIE = 'dk';

const TOKEN_BYTES = 32;
/** Hard lifetime: a session dies at this point no matter how active it is. */
const ABSOLUTE_TTL_SECONDS = 14 * 24 * 60 * 60;
/** Idle lifetime: refreshed on use, so an abandoned session expires sooner. */
const IDLE_TTL_SECONDS = 3 * 24 * 60 * 60;

export interface SessionRecord {
  userId: string;
  expiresAt: number;
}

export async function createSession(env: Env, userId: string): Promise<string> {
  const token = b64urlEncode(randomBytes(TOKEN_BYTES));
  const now = nowSeconds();
  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(await sha256(token), userId, now, now + ABSOLUTE_TTL_SECONDS, now)
    .run();
  return token;
}

/**
 * Resolves a token to its owner, sliding the idle window forward. Returns null
 * for unknown, expired, or idled-out tokens, and deletes them on the way out.
 */
export async function lookupSession(env: Env, token: string): Promise<SessionRecord | null> {
  const hash = await sha256(token);
  const row = await env.DB.prepare(
    `SELECT user_id AS userId, expires_at AS expiresAt, last_seen_at AS lastSeenAt
     FROM sessions WHERE token_hash = ?`,
  )
    .bind(hash)
    .first<{ userId: string; expiresAt: number; lastSeenAt: number }>();
  if (!row) return null;

  const now = nowSeconds();
  if (row.expiresAt <= now || row.lastSeenAt + IDLE_TTL_SECONDS <= now) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(hash).run();
    return null;
  }

  // One write per minute at most, so a chatty terminal does not hammer D1.
  if (now - row.lastSeenAt > 60) {
    await env.DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?')
      .bind(now, hash)
      .run();
  }
  return { userId: row.userId, expiresAt: row.expiresAt };
}

export async function destroySession(env: Env, token: string): Promise<void> {
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
}

/** "Sign out everywhere" — also used after a password change. */
export async function destroyAllSessions(env: Env, userId: string): Promise<void> {
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
}

export function parseCookies(header: string | null): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    out.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
  }
  return out;
}

function serializeCookie(name: string, value: string, maxAgeSeconds: number): string {
  return [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ].join('; ');
}

/** Cookie headers for a freshly authenticated request. */
export function authCookies(token: string, dek: Uint8Array): string[] {
  return [
    serializeCookie(SESSION_COOKIE, token, ABSOLUTE_TTL_SECONDS),
    serializeCookie(DEK_COOKIE, b64urlEncode(dek), ABSOLUTE_TTL_SECONDS),
  ];
}

export function clearedCookies(): string[] {
  return [serializeCookie(SESSION_COOKIE, '', 0), serializeCookie(DEK_COOKIE, '', 0)];
}

export function readDek(cookies: Map<string, string>): Uint8Array | null {
  const raw = cookies.get(DEK_COOKIE);
  if (!raw) return null;
  try {
    const bytes = b64urlDecode(raw);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}
