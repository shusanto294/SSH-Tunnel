/**
 * Password hashing.
 *
 * PBKDF2-HMAC-SHA256 via WebCrypto. Argon2/bcrypt/scrypt are not options here:
 * every JS build of them compiles WebAssembly at runtime, which Workers
 * disallows — the spike hit exactly that wall with `ssh2`.
 */
import { randomBytes, timingSafeEqual } from '../util/encoding';

/** OWASP's 2023 floor for PBKDF2-HMAC-SHA256. Raise over time, never lower. */
export const TARGET_ITERATIONS = 600_000;
/**
 * Workers refuses a single deriveBits call above this, with
 * "Pbkdf2 failed: iteration counts above 100000 are not supported".
 * Note that local miniflare does NOT enforce it — this only shows up in
 * production, so the chaining below is not optional.
 */
const MAX_ITERATIONS_PER_CALL = 100_000;
const SALT_BYTES = 16;
const KEY_BYTES = 32;

export interface PasswordRecord {
  hash: Uint8Array;
  salt: Uint8Array;
  iters: number;
}

async function deriveOnce(
  secret: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey('raw', secret, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * PBKDF2-HMAC-SHA256 with a total iteration count that may exceed what a single
 * WebCrypto call accepts on this runtime.
 *
 * The work is split into chained rounds of at most MAX_ITERATIONS_PER_CALL:
 * each round's output becomes the next round's input secret, with the salt held
 * constant. The total number of HMAC iterations an attacker must perform is
 * unchanged, and the result is fully determined by (password, salt,
 * iterations), so stored verifiers stay reproducible.
 */
export async function pbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  let secret: Uint8Array = new TextEncoder().encode(password);
  let remaining = Math.max(1, iterations);
  let output: Uint8Array = secret;

  while (remaining > 0) {
    const round = Math.min(remaining, MAX_ITERATIONS_PER_CALL);
    output = await deriveOnce(secret, salt, round, lengthBytes);
    secret = output;
    remaining -= round;
  }
  return output;
}

export async function hashPassword(password: string): Promise<PasswordRecord> {
  const salt = randomBytes(SALT_BYTES);
  const hash = await pbkdf2(password, salt, TARGET_ITERATIONS, KEY_BYTES);
  return { hash, salt, iters: TARGET_ITERATIONS };
}

export async function verifyPassword(
  password: string,
  record: PasswordRecord,
): Promise<boolean> {
  const candidate = await pbkdf2(password, record.salt, record.iters, record.hash.length);
  return timingSafeEqual(candidate, record.hash);
}

/** True when this account should be re-hashed at a higher iteration count. */
export function needsRehash(record: PasswordRecord): boolean {
  return record.iters < TARGET_ITERATIONS;
}

export interface PasswordProblem {
  message: string;
}

/**
 * Length is the property that actually matters. Composition rules mostly push
 * people toward predictable substitutions, so this checks size and the most
 * obvious junk only.
 */
export function validatePassword(password: string): PasswordProblem | null {
  if (password.length < 12) return { message: 'Password must be at least 12 characters.' };
  if (password.length > 1024) return { message: 'Password must be at most 1024 characters.' };
  if (/^(.)\1*$/.test(password)) return { message: 'Password must not be a single repeated character.' };
  return null;
}
