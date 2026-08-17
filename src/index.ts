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
import type { Env } from './env';
import { LIMITS, blockStatus, clientKey, rateLimit, strike } from './rate-limit';
import { secure } from './security/headers';
import { socketSuspicionWeight, suspicionWeight } from './security/suspicion';

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

/**
 * Redeems a ticket issued by POST /api/connect.
 *
 * The session was already provisioned there — target vetted, credential
 * resolved — so nothing sensitive rides in this URL. The ticket names a Durable
 * Object; the object itself verifies the claim belongs to the signed-in account
 * and refuses a second one.
 */
async function handleWebSocket(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
    return new Response('Expected a WebSocket upgrade.', { status: 426 });
  }

  const context = await authenticate(request, env);
  if (!context) return new Response('Not signed in.', { status: 401 });

  const ticket = url.searchParams.get('ticket');
  if (!ticket) return new Response('No session ticket.', { status: 400 });

  let id: DurableObjectId;
  try {
    id = env.SSH_SESSION.idFromString(ticket);
  } catch {
    return new Response('Invalid session ticket.', { status: 400 });
  }

  const stub = env.SSH_SESSION.get(id);
  // Single use, bound to the account that created it, and expired after a
  // minute — so a ticket appearing in a proxy log is worth nothing.
  if (!(await stub.claim(context.userId))) {
    return new Response('That session ticket is not valid.', { status: 403 });
  }

  return stub.fetch(request);
}
