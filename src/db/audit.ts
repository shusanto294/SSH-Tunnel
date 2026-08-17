import type { Env } from '../env';
import { newId, nowSeconds } from '../util/encoding';

export type AuditAction =
  | 'register'
  | 'login'
  | 'login_failed'
  | 'logout'
  | 'password_changed'
  | 'server_created'
  | 'server_updated'
  | 'server_deleted'
  | 'session_opened'
  | 'session_refused';

/**
 * Security-relevant events only, and never any secret material. `detail` is for
 * things like a server label or a refusal reason — not hosts' credentials, not
 * tokens, not fingerprintable key bytes.
 */
export async function audit(
  env: Env,
  userId: string | null,
  action: AuditAction,
  detail?: string,
): Promise<void> {
  await env.DB.prepare('INSERT INTO audit (id, user_id, ts, action, detail) VALUES (?, ?, ?, ?, ?)')
    .bind(newId(), userId, nowSeconds(), action, detail ?? null)
    .run();
}
