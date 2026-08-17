/**
 * Fixed-window rate limiting, one Durable Object per key.
 *
 * D1 would race here: two concurrent login attempts can both read the same
 * count. A DO serialises calls for a given key, which is the property that
 * makes the counter trustworthy.
 */
import { DurableObject } from 'cloudflare:workers';
import type { Env } from './env';

export interface RateVerdict {
  allowed: boolean;
  /** Seconds until the window resets. Only meaningful when blocked. */
  retryAfter: number;
}

interface Window {
  count: number;
  resetAt: number;
}

export class RateLimiter extends DurableObject<Env> {
  /**
   * Counts this hit against the window and says whether it is allowed.
   * Callers pick the limit, so one object class serves login, registration,
   * and session-open with different budgets.
   */
  async hit(limit: number, windowSeconds: number): Promise<RateVerdict> {
    const now = Math.floor(Date.now() / 1000);
    const current = (await this.ctx.storage.get<Window>('w')) ?? { count: 0, resetAt: 0 };

    const window: Window =
      current.resetAt <= now ? { count: 0, resetAt: now + windowSeconds } : current;

    window.count += 1;
    await this.ctx.storage.put('w', window);
    // Let the object evict itself once the window is irrelevant.
    await this.ctx.storage.setAlarm((window.resetAt + 60) * 1000);

    return window.count > limit
      ? { allowed: false, retryAfter: Math.max(1, window.resetAt - now) }
      : { allowed: true, retryAfter: 0 };
  }

  /** Clears the window — called after a success, so a good login is not punished. */
  async reset(): Promise<void> {
    await this.ctx.storage.delete('w');
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

export interface RateLimit {
  limit: number;
  windowSeconds: number;
}

export const LIMITS = {
  login: { limit: 10, windowSeconds: 300 },
  register: { limit: 5, windowSeconds: 3600 },
  sessionOpen: { limit: 30, windowSeconds: 300 },
} as const satisfies Record<string, RateLimit>;

export async function rateLimit(
  env: Env,
  key: string,
  { limit, windowSeconds }: RateLimit,
): Promise<RateVerdict> {
  const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(key));
  return stub.hit(limit, windowSeconds);
}

export async function rateLimitReset(env: Env, key: string): Promise<void> {
  const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(key));
  await stub.reset();
}

/** Coarse client identity for limiting. Spoofable in theory, set by Cloudflare in practice. */
export function clientKey(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'unknown';
}
