/** Turning a raw Request into "which user is this, and can they decrypt?". */
import type { Env } from '../env';
import { DEK_COOKIE, SESSION_COOKIE, lookupSession, parseCookies, readDek } from './session';

export interface AuthContext {
  userId: string;
  token: string;
  /** Present only when the request carried the DEK cookie. */
  dek: Uint8Array | null;
}

export async function authenticate(request: Request, env: Env): Promise<AuthContext | null> {
  const cookies = parseCookies(request.headers.get('cookie'));
  const token = cookies.get(SESSION_COOKIE);
  if (!token) return null;
  const session = await lookupSession(env, token);
  if (!session) return null;
  return { userId: session.userId, token, dek: readDek(cookies) };
}

/**
 * Cross-site request forgery check for state-changing requests.
 *
 * Both cookies are SameSite=Lax, which already blocks cross-site POSTs from
 * carrying them, but Lax is a browser behaviour and not something to rely on
 * alone. Same-origin is required explicitly.
 */
export function isSameOrigin(request: Request): boolean {
  const site = request.headers.get('sec-fetch-site');
  if (site) return site === 'same-origin' || site === 'none';

  // Older clients: fall back to comparing Origin against the request URL.
  const origin = request.headers.get('origin');
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export function hasDekCookie(request: Request): boolean {
  return parseCookies(request.headers.get('cookie')).has(DEK_COOKIE);
}
