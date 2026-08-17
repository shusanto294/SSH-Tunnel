/**
 * Rate limiting and IP reputation, one Durable Object per key.
 *
 * D1 would race here: two concurrent login attempts can both read the same
 * count. A DO serialises calls for a given key, which is the property that
 * makes the counter trustworthy.
 *
 * Two mechanisms share the object:
 *
 *   hit()     a fixed window — "at most N of this action per period"
 *   strike()  a reputation score that decays, and blocks outright once an
 *             address has misbehaved enough times
 *
 * The second is what stops a patient attacker. A fixed window alone lets
 * someone try ten passwords every five minutes forever; strikes accumulate
 * across windows and escalate the block each time.
 */
import { DurableObject } from 'cloudflare:workers';
import type { Env } from './env';
import { blockDurationFor } from './security/suspicion';

export interface RateVerdict {
  allowed: boolean;
  /** Seconds until the window resets. Only meaningful when blocked. */
  retryAfter: number;
}

export interface BlockVerdict {
  blocked: boolean;
  retryAfter: number;
  strikes: number;
}

interface Window {
  count: number;
  resetAt: number;
}

interface Strikes {
  count: number;
  /** Unix seconds until which this key is refused outright. */
  until: number;
  lastAt: number;
}

/** A quiet day wipes the slate, so a shared or recycled address recovers. */
const STRIKE_DECAY_SECONDS = 24 * 60 * 60;

export class RateLimiter extends DurableObject<Env> {
  /**
   * Counts this hit against the window and says whether it is allowed.
   * Callers pick the limit, so one object class serves login, registration,
   * and session-open with different budgets.
   */
  async hit(limit: number, windowSeconds: number): Promise<RateVerdict> {
    const now = seconds();
    const current = (await this.ctx.storage.get<Window>('w')) ?? { count: 0, resetAt: 0 };

    const window: Window =
      current.resetAt <= now ? { count: 0, resetAt: now + windowSeconds } : current;

    window.count += 1;
    await this.ctx.storage.put('w', window);
    await this.scheduleCleanup(window.resetAt);

    return window.count > limit
      ? { allowed: false, retryAfter: Math.max(1, window.resetAt - now) }
      : { allowed: true, retryAfter: 0 };
  }

  /** Records misbehaviour and returns whether the key is now blocked. */
  async strike(weight = 1): Promise<BlockVerdict> {
    const now = seconds();
    const current = (await this.ctx.storage.get<Strikes>('s')) ?? {
      count: 0,
      until: 0,
      lastAt: 0,
    };

    // Decay before adding, so an address that behaved for a day starts fresh.
    if (now - current.lastAt > STRIKE_DECAY_SECONDS) current.count = 0;

    current.count += weight;
    current.lastAt = now;

    const duration = blockDurationFor(current.count);
    // Never shorten an existing block by striking again.
    if (duration > 0) current.until = Math.max(current.until, now + duration);

    await this.ctx.storage.put('s', current);
    await this.scheduleCleanup(Math.max(current.until, now + STRIKE_DECAY_SECONDS));

    return {
      blocked: current.until > now,
      retryAfter: Math.max(0, current.until - now),
      strikes: current.count,
    };
  }

  /** Read-only check, used on the hot path before doing any work. */
  async blockStatus(): Promise<BlockVerdict> {
    const now = seconds();
    const current = await this.ctx.storage.get<Strikes>('s');
    if (!current) return { blocked: false, retryAfter: 0, strikes: 0 };
    return {
      blocked: current.until > now,
      retryAfter: Math.max(0, current.until - now),
      strikes: now - current.lastAt > STRIKE_DECAY_SECONDS ? 0 : current.count,
    };
  }

  /** Clears the window after a success, so a good login is not punished. */
  async reset(): Promise<void> {
    await this.ctx.storage.delete('w');
  }

  /** Forgives strikes. Only for a proven-legitimate action, never a guess. */
  async pardon(): Promise<void> {
    await this.ctx.storage.delete('s');
  }

  private async scheduleCleanup(notBefore: number): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    const target = (notBefore + 60) * 1000;
    if (existing === null || existing < target) await this.ctx.storage.setAlarm(target);
  }

  /**
   * Evict only what has actually expired. Deleting everything here would drop
   * an active block along with a stale window.
   */
  override async alarm(): Promise<void> {
    const now = seconds();
    const window = await this.ctx.storage.get<Window>('w');
    if (window && window.resetAt <= now) await this.ctx.storage.delete('w');

    const strikes = await this.ctx.storage.get<Strikes>('s');
    const stale = strikes && strikes.until <= now && now - strikes.lastAt > STRIKE_DECAY_SECONDS;
    if (stale) await this.ctx.storage.delete('s');

    const remaining = await this.ctx.storage.list({ limit: 1 });
    if (remaining.size > 0) await this.ctx.storage.setAlarm(Date.now() + STRIKE_DECAY_SECONDS * 1000);
  }
}

function seconds(): number {
  return Math.floor(Date.now() / 1000);
}

export interface RateLimit {
  limit: number;
  windowSeconds: number;
}

export const LIMITS = {
  /** Deliberately tight: password guessing is the main threat to this app. */
  login: { limit: 8, windowSeconds: 300 },
  register: { limit: 5, windowSeconds: 3600 },
  sessionOpen: { limit: 30, windowSeconds: 300 },
  /** A ceiling across the whole API, so no single address can hammer it. */
  api: { limit: 240, windowSeconds: 60 },
} as const satisfies Record<string, RateLimit>;

function stub(env: Env, key: string) {
  return env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(key));
}

export async function rateLimit(
  env: Env,
  key: string,
  { limit, windowSeconds }: RateLimit,
): Promise<RateVerdict> {
  return stub(env, key).hit(limit, windowSeconds);
}

export async function rateLimitReset(env: Env, key: string): Promise<void> {
  await stub(env, key).reset();
}

export async function strike(env: Env, key: string, weight: number): Promise<BlockVerdict> {
  return stub(env, key).strike(weight);
}

export async function blockStatus(env: Env, key: string): Promise<BlockVerdict> {
  return stub(env, key).blockStatus();
}

export async function pardon(env: Env, key: string): Promise<void> {
  await stub(env, key).pardon();
}

/** Coarse client identity. Spoofable in theory, set by Cloudflare in practice. */
export function clientKey(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'unknown';
}
