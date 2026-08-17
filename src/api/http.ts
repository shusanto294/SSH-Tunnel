/** Small JSON response helpers shared by every API route. */

export function json(data: unknown, status = 200, cookies: string[] = []): Response {
  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

/**
 * Error responses carry a message meant for a human and nothing else. No
 * exception text, no stack, no hint about whether an account exists.
 */
export function fail(status: number, message: string, extra: Record<string, unknown> = {}): Response {
  return json({ error: message, ...extra }, status);
}

export async function readJson<T>(request: Request): Promise<T | null> {
  if (!request.headers.get('content-type')?.includes('application/json')) return null;
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

export function str(value: unknown, max = 256): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > max) return null;
  return trimmed;
}

export function port(value: unknown, fallback = 22): number | null {
  if (value === undefined || value === null) return fallback;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function email(value: unknown): string | null {
  const s = str(value, 254);
  return s && EMAIL.test(s) ? s : null;
}
