/**
 * Invite codes. Only admins can mint them, and the plaintext code is shown
 * exactly once — the database keeps nothing but its hash.
 */
import type { Env } from '../env';
import type { AuthContext } from '../auth/context';
import { createInvite } from '../db/invites';
import { findById } from '../db/users';
import { fail, json, readJson } from './http';

const DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_TTL_SECONDS = 90 * 24 * 60 * 60;

interface InviteBody {
  ttlSeconds?: unknown;
}

export async function create(request: Request, env: Env, auth: AuthContext): Promise<Response> {
  const user = await findById(env, auth.userId);
  if (!user?.isAdmin) return fail(403, 'Only an administrator can create invite codes.');

  const body = (await readJson<InviteBody>(request)) ?? {};
  let ttl: number | null = DEFAULT_TTL_SECONDS;
  if (body.ttlSeconds !== undefined) {
    if (body.ttlSeconds === null) {
      ttl = null;
    } else {
      const n = Number(body.ttlSeconds);
      if (!Number.isInteger(n) || n < 60 || n > MAX_TTL_SECONDS) {
        return fail(400, 'Invite lifetime must be between 60 seconds and 90 days.');
      }
      ttl = n;
    }
  }

  const invite = await createInvite(env, auth.userId, ttl);
  return json({ invite }, 201);
}
