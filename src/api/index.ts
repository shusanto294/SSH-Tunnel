/**
 * API routing.
 *
 * Two invariants hold for everything below:
 *   - any request that changes state must be same-origin
 *   - anything past /api/auth/register and /api/auth/login must be signed in
 */
import type { Env } from '../env';
import { authenticate, isSameOrigin } from '../auth/context';
import * as auth from './auth';
import { countUsers } from '../db/users';
import { fail, json } from './http';
import * as invites from './invites';
import * as servers from './servers';

/**
 * The only thing the sign-up form needs before anyone is signed in: whether an
 * invite code is required. Reveals no account data.
 */
async function config(env: Env): Promise<Response> {
  const open = env.OPEN_REGISTRATION === 'true' || (await countUsers(env)) === 0;
  return json({ openRegistration: open });
}

export async function handleApi(request: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const method = request.method.toUpperCase();

  if (method !== 'GET' && method !== 'HEAD' && !isSameOrigin(request)) {
    return fail(403, 'Cross-site requests are not accepted.');
  }

  // Unauthenticated endpoints.
  if (path === 'config' && method === 'GET') return config(env);
  if (path === 'auth/register' && method === 'POST') return auth.register(request, env);
  if (path === 'auth/login' && method === 'POST') return auth.login(request, env);

  const context = await authenticate(request, env);
  if (!context) return fail(401, 'Not signed in.');

  switch (path) {
    case 'auth/me':
      if (method === 'GET') return auth.me(env, context);
      break;
    case 'auth/logout':
      if (method === 'POST') return auth.logout(env, context);
      break;
    case 'auth/logout-everywhere':
      if (method === 'POST') return auth.logoutEverywhere(env, context);
      break;
    case 'auth/password':
      if (method === 'POST') return auth.changePassword(request, env, context);
      break;
    case 'invites':
      if (method === 'POST') return invites.create(request, env, context);
      break;
    case 'servers':
      if (method === 'GET') return servers.list(env, context);
      if (method === 'POST') return servers.create(request, env, context);
      break;
    default:
      break;
  }

  const server = /^servers\/([A-Za-z0-9_-]{1,64})$/.exec(path);
  if (server) {
    const id = server[1] as string;
    if (method === 'GET') return servers.get(env, context, id);
    if (method === 'PATCH' || method === 'PUT') return servers.update(request, env, context, id);
    if (method === 'DELETE') return servers.remove(env, context, id);
  }

  return fail(404, 'No such endpoint.');
}
