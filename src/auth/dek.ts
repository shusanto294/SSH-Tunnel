/**
 * Per-user credential encryption.
 *
 * Each account owns a random 32-byte data encryption key (DEK). Saved SSH
 * secrets are encrypted under it with AES-GCM. The DEK itself is stored only in
 * wrapped form, under a key derived from the user's password with a salt that is
 * separate from the login verifier's salt.
 *
 * Consequences, both deliberate:
 *   - A stolen copy of the database contains no usable SSH credentials.
 *   - A forgotten password makes the saved secrets unrecoverable. The UI has to
 *     say so at registration time.
 */
import { randomBytes } from '../util/encoding';
import { pbkdf2, TARGET_ITERATIONS } from './password';

const DEK_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;

export interface WrappedDek {
  wrapped: Uint8Array;
  iv: Uint8Array;
  salt: Uint8Array;
  iters: number;
}

export interface Sealed {
  ciphertext: Uint8Array;
  iv: Uint8Array;
}

async function kekFrom(password: string, salt: Uint8Array, iters: number): Promise<CryptoKey> {
  const bits = await pbkdf2(password, salt, iters, DEK_BYTES);
  return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** Mint a DEK for a new account and wrap it with the chosen password. */
export async function createDek(password: string): Promise<{ dek: Uint8Array; record: WrappedDek }> {
  const dek = randomBytes(DEK_BYTES);
  const record = await wrapDek(dek, password);
  return { dek, record };
}

export async function wrapDek(dek: Uint8Array, password: string): Promise<WrappedDek> {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const kek = await kekFrom(password, salt, TARGET_ITERATIONS);
  const wrapped = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dek),
  );
  return { wrapped, iv, salt, iters: TARGET_ITERATIONS };
}

/** Returns null when the password is wrong; the GCM tag is the only check needed. */
export async function unwrapDek(password: string, record: WrappedDek): Promise<Uint8Array | null> {
  const kek = await kekFrom(password, record.salt, record.iters);
  try {
    const dek = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.iv },
      kek,
      record.wrapped,
    );
    return new Uint8Array(dek);
  } catch {
    return null;
  }
}

async function dekKey(dek: Uint8Array, usage: Array<'encrypt' | 'decrypt'>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', dek, 'AES-GCM', false, usage);
}

export async function sealSecret(dek: Uint8Array, plaintext: string): Promise<Sealed> {
  const iv = randomBytes(IV_BYTES);
  const key = await dekKey(dek, ['encrypt']);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)),
  );
  return { ciphertext, iv };
}

/** Throws on tag mismatch — a wrong DEK must never yield garbage plaintext. */
export async function openSecret(dek: Uint8Array, sealed: Sealed): Promise<string> {
  const key = await dekKey(dek, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: sealed.iv },
    key,
    sealed.ciphertext,
  );
  return new TextDecoder().decode(plain);
}
