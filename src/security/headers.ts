/**
 * Security headers applied to every response, including static assets.
 *
 * The Content-Security-Policy is the important one: it is what stops injected
 * script from exfiltrating anything, and this app holds SSH credentials, so
 * script injection is the worst realistic outcome short of losing the account.
 *
 * `'unsafe-inline'` is present for scripts and styles and cannot currently be
 * removed: Next's static export inlines its hydration payload, and a nonce
 * cannot be generated at build time for a file served straight from the asset
 * store. `connect-src` and `frame-ancestors` still do real work — an injected
 * script cannot post data to another origin, and the page cannot be framed.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  // The terminal WebSocket is same-origin; nothing else may be contacted.
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  'upgrade-insecure-requests',
].join('; ');

const HEADERS: Record<string, string> = {
  'content-security-policy': CSP,
  // Clickjacking, for browsers predating frame-ancestors.
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  // Never leak a session URL to a third party.
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'geolocation=(), camera=(), microphone=(), payment=(), usb=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
};

/**
 * Returns a copy of the response carrying the headers. A 101 WebSocket
 * response is returned untouched — its headers are part of the handshake and
 * it cannot be reconstructed.
 */
export function secure(response: Response): Response {
  if (response.status === 101) return response;

  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(HEADERS)) headers.set(name, value);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
