/**
 * SSH Tunnel Worker.
 *
 *   /api/*  account auth and saved-server CRUD
 *   /ws     WebSocket upgrade, routed to a fresh SshSession Durable Object
 *   /*      the Next.js static export
 *
 * The /ws handler is where authorization actually happens: it proves who the
 * caller is, that they own the server they named, and that the target is one
 * this service is willing to dial. The Durable Object trusts what it is handed
 * and checks none of it again.
 */
import { handleApi } from './api';
import { authenticate } from './auth/context';
import { openSecret } from './auth/dek';
import type { Env } from './env';
import { audit } from './db/audit';
import { getServerWithSecret, touchServer } from './db/servers';
import { resolveTarget } from './net/guard';
import { LIMITS, blockStatus, clientKey, rateLimit, strike } from './rate-limit';
import { secure } from './security/headers';
import { socketSuspicionWeight, suspicionWeight } from './security/suspicion';
import type { AuthCredential } from './ssh/connection';
import type { SessionParams } from './session';

export { SshSession } from './session';
export { RateLimiter } from './rate-limit';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const isApi = url.pathname.startsWith('/api/');
    const isSocket = url.pathname === '/ws';

    // Static assets are cheap and carry no authority; skip the reputation
    // lookup for them so the landing page stays fast.
    if (!isApi && !isSocket) return secure(await env.ASSETS.fetch(request));

    const ip = clientKey(request);
    const ipKey = `ip:${ip}`;

    // A blocked address is refused before any work is done — no database
    // query, no password hashing, no socket.
    const blocked = await blockStatus(env, ipKey);
    if (blocked.blocked) return secure(refused(blocked.retryAfter));

    // A ceiling across the whole API. Well above what the UI generates, low
    // enough that a scraper hits it immediately.
    const budget = await rateLimit(env, `api:${ip}`, LIMITS.api);
    if (!budget.allowed) {
      ctx.waitUntil(strike(env, ipKey, 5).then(() => undefined));
      return secure(refused(budget.retryAfter));
    }

    const response = isSocket
      ? await handleWebSocket(request, env, url)
      : await handleApiSafely(request, env, url);

    // Score the outcome. Done after responding rather than before, so the
    // reputation update never delays a legitimate request.
    const weight = isSocket
      ? socketSuspicionWeight(response.status)
      : suspicionWeight({
          method: request.method,
          path: url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, ''),
          status: response.status,
        });
    if (weight > 0) ctx.waitUntil(strike(env, ipKey, weight).then(() => undefined));

    return secure(response);
  },
} satisfies ExportedHandler<Env>;

async function handleApiSafely(request: Request, env: Env, url: URL): Promise<Response> {
  try {
    return await handleApi(request, env, url);
  } catch {
    // An uncaught throw would otherwise become Cloudflare's HTML error page,
    // which the browser client then fails to parse as JSON. The message stays
    // generic: no exception text, no stack.
    return new Response(JSON.stringify({ error: 'Something went wrong. Please try again.' }), {
      status: 500,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    });
  }
}

function refused(retryAfter: number): Response {
  return new Response(
    JSON.stringify({ error: 'Too many requests from this address. Try again later.' }),
    {
      status: 429,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'retry-after': String(Math.max(1, retryAfter)),
        'cache-control': 'no-store',
      },
    },
  );
}

async function handleWebSocket(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
    return new Response('Expected a WebSocket upgrade.', { status: 426 });
  }

  const context = await authenticate(request, env);
  if (!context) return new Response('Not signed in.', { status: 401 });
  if (!context.dek) return new Response('Sign in again to open a session.', { status: 409 });

  const gate = await rateLimit(env, `session:${context.userId}`, LIMITS.sessionOpen);
  if (!gate.allowed) {
    return new Response('Too many sessions opened. Try again shortly.', {
      status: 429,
      headers: { 'retry-after': String(gate.retryAfter) },
    });
  }

  const serverId = url.searchParams.get('server');
  if (!serverId) return new Response('No server specified.', { status: 400 });

  // Ownership is enforced in the query itself: a server belonging to someone
  // else is indistinguishable from one that does not exist.
  const server = await getServerWithSecret(env, context.userId, serverId);
  if (!server) return new Response('No such server.', { status: 404 });

  let credential: AuthCredential;
  try {
    const secret = await openSecret(context.dek, server.secret);
    credential =
      server.authMethod === 'password'
        ? { method: 'password', password: secret }
        : { method: 'privatekey', privateKey: secret };
  } catch {
    // A failed GCM tag means the DEK does not belong to this row.
    return new Response('Could not decrypt the saved credential.', { status: 409 });
  }

  const guard = await resolveTarget(env, server.host, server.port);
  if (!guard.ok) {
    await audit(env, context.userId, 'session_refused', guard.reason);
    return new Response(guard.reason, { status: 403 });
  }

  const params: SessionParams = {
    address: guard.target.address,
    hostname: guard.target.hostname,
    port: guard.target.port,
    username: server.sshUser,
    credential,
    pinnedFingerprint: server.hostKeyFingerprint,
    cols: clamp(url.searchParams.get('cols'), 80, 1, 500),
    rows: clamp(url.searchParams.get('rows'), 24, 1, 300),
  };

  // A fresh object per terminal: sessions are never shared or resumed, and an
  // abandoned one has no name anyone could reconnect to.
  const stub = env.SSH_SESSION.get(env.SSH_SESSION.newUniqueId());
  await stub.configure(params);

  await touchServer(env, context.userId, server.id);
  await audit(env, context.userId, 'session_opened', server.label);

  return stub.fetch(request);
}

function clamp(raw: string | null, fallback: number, min: number, max: number): number {
  const n = raw === null ? NaN : Number(raw);
  if (!Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
