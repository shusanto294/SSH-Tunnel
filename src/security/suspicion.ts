/**
 * Which responses count as suspicious, and how heavily.
 *
 * Kept as a pure function so the policy is testable and reviewable in one
 * place, rather than scattered as `strike()` calls across handlers.
 *
 * The guiding rule: only score outcomes a legitimate browser session would not
 * normally produce. An anonymous visitor loading the landing page triggers
 * `GET /api/auth/me` and gets a 401 — scoring that would ban ordinary readers,
 * so reads are never scored.
 */
/**
 * How long a key is blocked once it reaches a strike count. Escalating rather
 * than fixed: someone who comes back and keeps failing is far more likely to be
 * a script than a person who forgot their password.
 *
 * Lives here rather than beside the Durable Object so the policy can be tested
 * without a Workers runtime.
 */
export function blockDurationFor(strikes: number): number {
  if (strikes >= 50) return 24 * 60 * 60;
  if (strikes >= 25) return 60 * 60;
  if (strikes >= 10) return 5 * 60;
  return 0;
}

export interface Attempt {
  method: string;
  /** Path with the /api prefix stripped, or "ws" for the socket route. */
  path: string;
  status: number;
}

export function suspicionWeight({ method, path, status }: Attempt): number {
  const verb = method.toUpperCase();

  // Reads are free. Anonymous 401s from session checks are normal traffic.
  if (verb === 'GET' || verb === 'HEAD' || verb === 'OPTIONS') {
    // Except probing for endpoints that do not exist, which no client does.
    return status === 404 && path !== 'ws' ? 1 : 0;
  }

  // Tripping a rate limit is already abnormal; repeating it is the signature
  // of a script that does not read responses.
  if (status === 429) return 5;

  if (path === 'auth/login') {
    // Wrong password. Two people fat-finger a password; nobody does it 10 times.
    return status === 401 ? 2 : 0;
  }

  if (path === 'auth/register') {
    // A rejected invite code or a probe for which addresses are taken.
    if (status === 403 || status === 409) return 3;
    return 0;
  }

  if (path === 'auth/password') return status === 401 ? 3 : 0;

  // Reaching for another account's data, or an endpoint that is not there.
  if (status === 403 || status === 404) return 2;

  // Cross-site request forgery attempts land here.
  if (status === 400 && path === '') return 1;

  return 0;
}

/** Weight for a rejected WebSocket upgrade, where no body is returned. */
export function socketSuspicionWeight(status: number): number {
  if (status === 401) return 1;
  if (status === 403) return 3; // blocked target, or someone else's server
  if (status === 404) return 2;
  if (status === 429) return 5;
  return 0;
}
