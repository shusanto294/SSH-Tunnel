/**
 * OpenSSH private key parsing, ed25519 only.
 *
 * Passphrase-protected keys are not supported and cannot be: OpenSSH encrypts
 * them with bcrypt_pbkdf, and every JS bcrypt compiles WebAssembly at runtime,
 * which Workers forbids. The UI must say "unencrypted ed25519 key" rather than
 * letting people paste a key that will fail here.
 */
import { Reader, Writer, concat } from './wire';

const MAGIC = 'openssh-key-v1\0';

export interface Ed25519PrivateKey {
  /** Raw 32-byte public key. */
  publicKey: Uint8Array;
  /** SSH-format public key blob: string "ssh-ed25519" || string publicKey. */
  publicKeyBlob: Uint8Array;
  /** The signing key, ready for crypto.subtle.importKey('pkcs8', ...). */
  pkcs8: Uint8Array;
}

export function parseOpenSshEd25519(text: string): Ed25519PrivateKey {
  const body = extractBase64(text);
  const raw = decodeBase64(body);

  const magic = new TextDecoder().decode(raw.subarray(0, MAGIC.length));
  if (magic !== MAGIC) {
    throw new Error('Not an OpenSSH private key. Expected a key beginning "-----BEGIN OPENSSH PRIVATE KEY-----".');
  }

  const r = new Reader(raw.subarray(MAGIC.length));
  const cipherName = r.utf8();
  const kdfName = r.utf8();
  r.string(); // kdf options
  const keyCount = r.uint32();

  if (cipherName !== 'none' || kdfName !== 'none') {
    throw new Error('Passphrase-protected keys are not supported. Provide an unencrypted ed25519 key.');
  }
  if (keyCount !== 1) throw new Error('Expected exactly one key in the file.');

  const publicKeyBlob = r.string();
  const privateSection = r.string();

  const p = new Reader(privateSection);
  const check1 = p.uint32();
  const check2 = p.uint32();
  if (check1 !== check2) throw new Error('Private key checksum mismatch; the file looks corrupt.');

  const keyType = p.utf8();
  if (keyType !== 'ssh-ed25519') {
    throw new Error(`Unsupported key type "${keyType}". Only ssh-ed25519 keys work here.`);
  }

  const publicKey = p.string();
  const privateBlob = p.string();
  if (publicKey.length !== 32 || privateBlob.length !== 64) {
    throw new Error('Malformed ed25519 key material.');
  }
  // OpenSSH stores seed||public in the 64-byte field; PKCS#8 wants the seed.
  const seed = privateBlob.subarray(0, 32);

  return { publicKey, publicKeyBlob, pkcs8: pkcs8FromSeed(seed) };
}

/** Build the public key blob for a raw ed25519 public key. */
export function ed25519PublicKeyBlob(publicKey: Uint8Array): Uint8Array {
  return new Writer().string('ssh-ed25519').string(publicKey).bytes();
}

/**
 * The fixed DER prelude for a PKCS#8 Ed25519 private key (RFC 8410):
 * SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }
 */
const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function pkcs8FromSeed(seed: Uint8Array): Uint8Array {
  return concat(PKCS8_PREFIX, seed);
}

function extractBase64(text: string): string {
  const match = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(
    text,
  );
  if (!match) {
    throw new Error('Could not find an OPENSSH PRIVATE KEY block.');
  }
  return (match[1] as string).replace(/\s+/g, '');
}

function decodeBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
