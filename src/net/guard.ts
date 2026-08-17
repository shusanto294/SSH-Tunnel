/**
 * Egress guard: keeps this app from becoming an open SSH relay, and keeps it
 * from being pointed at addresses it has no business reaching.
 *
 * Hostnames are resolved here rather than handed straight to `connect()`, and
 * the connection is then made to the address that was actually checked. Doing
 * it the other way round leaves a DNS-rebinding window between the check and
 * the connect.
 */
import type { Env } from '../env';

export interface Target {
  /** The literal address to connect to — already checked. */
  address: string;
  /** What the user typed, kept for display and for the host key record. */
  hostname: string;
  port: number;
}

export type GuardResult =
  | { ok: true; target: Target }
  | { ok: false; reason: string };

export async function resolveTarget(
  env: Env,
  hostname: string,
  port: number,
): Promise<GuardResult> {
  const host = hostname.trim().toLowerCase();
  if (!host || host.length > 253) return { ok: false, reason: 'Invalid hostname.' };
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, reason: 'Invalid port.' };
  }

  const allowlist = parseAllowlist(env.TARGET_ALLOWLIST);
  if (allowlist && !allowlist.has(host)) {
    return { ok: false, reason: 'This deployment only allows connections to approved hosts.' };
  }

  if (isIpLiteral(host)) {
    if (isBlockedAddress(host)) return { ok: false, reason: blockedMessage };
    return { ok: true, target: { address: host, hostname: host, port } };
  }

  if (!/^[a-z0-9.-]+$/.test(host) || host.endsWith('.local')) {
    return { ok: false, reason: 'Invalid hostname.' };
  }

  const addresses = await resolve(host);
  if (addresses.length === 0) return { ok: false, reason: 'Hostname did not resolve.' };
  // Every answer must be acceptable: one bad record is enough to refuse, since
  // which one we would have used is not something to leave to chance.
  for (const address of addresses) {
    if (isBlockedAddress(address)) return { ok: false, reason: blockedMessage };
  }
  return { ok: true, target: { address: addresses[0] as string, hostname: host, port } };
}

const blockedMessage =
  'That address is in a range this service refuses to connect to (loopback, private, or link-local).';

function parseAllowlist(raw: string | undefined): Set<string> | null {
  if (!raw) return null;
  const entries = raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return entries.length > 0 ? new Set(entries) : null;
}

/** DNS over HTTPS. Workers has no resolver API, and fetch is not TCP-restricted. */
async function resolve(host: string): Promise<string[]> {
  const out: string[] = [];
  for (const type of ['A', 'AAAA']) {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
    let response: Response;
    try {
      response = await fetch(url, { headers: { accept: 'application/dns-json' } });
    } catch {
      continue;
    }
    if (!response.ok) continue;
    const body = (await response.json()) as { Answer?: Array<{ type: number; data: string }> };
    for (const answer of body.Answer ?? []) {
      // 1 = A, 28 = AAAA. CNAME chains resolve server-side, so anything else is noise.
      if (answer.type === 1 || answer.type === 28) out.push(answer.data);
    }
  }
  return out;
}

function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

export function isBlockedAddress(address: string): boolean {
  if (address.includes(':')) return isBlockedIpv6(address);
  return isBlockedIpv4(address);
}

function isBlockedIpv4(address: string): boolean {
  const parts = address.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return true;
  }
  const [a, b] = parts as [number, number, number, number];
  if (a === 0) return true; // "this network"
  if (a === 10) return true; // RFC 1918
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a === 192 && b === 0) return true; // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast and reserved
  return false;
  // Cloudflare's own ranges need no entry here: the platform refuses
  // connect() to them regardless.
}

function isBlockedIpv6(address: string): boolean {
  const lower = address.toLowerCase().replace(/^\[|\]$/g, '');
  if (lower === '::' || lower === '::1') return true; // unspecified, loopback
  if (lower.startsWith('fe80') || lower.startsWith('fec0')) return true; // link/site-local
  if (/^f[cd]/.test(lower)) return true; // unique local
  if (lower.startsWith('ff')) return true; // multicast
  // IPv4-mapped (::ffff:a.b.c.d) must be judged by its IPv4 half.
  const mapped = /::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (mapped) return isBlockedIpv4(mapped[1] as string);
  return false;
}
