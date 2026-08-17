import type { RateLimiter } from './rate-limit';
import type { SshSession } from './session';

export interface Env {
  DB: D1Database;
  SSH_SESSION: DurableObjectNamespace<SshSession>;
  RATE_LIMITER: DurableObjectNamespace<RateLimiter>;
  ASSETS: Fetcher;

  /** "true" opens registration to anyone. Invite-gated otherwise. */
  OPEN_REGISTRATION?: string;
  /** Optional comma-separated allowlist of connectable hosts. */
  TARGET_ALLOWLIST?: string;
}
