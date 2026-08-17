/**
 * curve25519-sha256 key exchange (RFC 8731) + ssh-ed25519 host key verification
 * (RFC 8709), built only on primitives Workers WebCrypto already has.
 */
import { Reader, Writer, concat, mpintBytes, toBase64 } from './wire';

export interface EphemeralKey {
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

/** Some workerd builds only expose the legacy name; try both. */
async function importEd25519(raw: Uint8Array): Promise<CryptoKey> {
  const names = ['Ed25519', 'NODE-ED25519'];
  let last: unknown;
  for (const name of names) {
    try {
      return await crypto.subtle.importKey(
        'raw',
        raw,
        name === 'NODE-ED25519' ? { name, namedCurve: 'NODE-ED25519' } : { name },
        false,
        ['verify'],
      );
    } catch (e) {
      last = e;
    }
  }
  throw new Error(`Ed25519 import unsupported in this runtime: ${(last as Error)?.message}`);
}

async function verifyEd25519(
  key: CryptoKey,
  sig: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  try {
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, data);
  } catch {
    return await crypto.subtle.verify({ name: 'NODE-ED25519' }, key, sig, data);
  }
}

export async function generateX25519(): Promise<EphemeralKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer,
  );
  return { publicKey: raw, privateKey: pair.privateKey };
}

export async function x25519SharedSecret(
  ours: CryptoKey,
  theirPublicRaw: Uint8Array,
): Promise<Uint8Array> {
  const peer = await crypto.subtle.importKey('raw', theirPublicRaw, { name: 'X25519' }, false, []);
  // workers-types spells the peer-key field `$public`; the runtime wants
  // `public`, matching the WebCrypto spec. Send the spec name.
  const algorithm = { name: 'X25519', public: peer } as unknown as SubtleCryptoDeriveKeyAlgorithm;
  const bits = await crypto.subtle.deriveBits(algorithm, ours, 256);
  return new Uint8Array(bits);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export interface ExchangeHashInput {
  clientIdent: string; // V_C, no CRLF
  serverIdent: string; // V_S, no CRLF
  clientKexInit: Uint8Array; // I_C, full payload incl. message number
  serverKexInit: Uint8Array; // I_S
  hostKeyBlob: Uint8Array; // K_S
  clientEphemeral: Uint8Array; // Q_C
  serverEphemeral: Uint8Array; // Q_S
  sharedSecret: Uint8Array; // K, raw 32 bytes
}

export async function computeExchangeHash(i: ExchangeHashInput): Promise<Uint8Array> {
  const w = new Writer()
    .string(i.clientIdent)
    .string(i.serverIdent)
    .string(i.clientKexInit)
    .string(i.serverKexInit)
    .string(i.hostKeyBlob)
    .string(i.clientEphemeral)
    .string(i.serverEphemeral)
    .mpint(i.sharedSecret);
  return sha256(w.bytes());
}

export interface HostKeyCheck {
  /** "SHA256:base64" as printed by ssh-keygen -lf, padding stripped. */
  fingerprint: string;
  signatureValid: boolean;
}

export async function verifyHostKey(
  hostKeyBlob: Uint8Array,
  signatureBlob: Uint8Array,
  exchangeHash: Uint8Array,
): Promise<HostKeyCheck> {
  const kr = new Reader(hostKeyBlob);
  const keyType = kr.utf8();
  if (keyType !== 'ssh-ed25519') throw new Error(`unexpected host key type ${keyType}`);
  const pub = kr.string();
  if (pub.length !== 32) throw new Error(`bad ed25519 host key length ${pub.length}`);

  const sr = new Reader(signatureBlob);
  const sigType = sr.utf8();
  if (sigType !== 'ssh-ed25519') throw new Error(`unexpected signature type ${sigType}`);
  const sig = sr.string();
  if (sig.length !== 64) throw new Error(`bad ed25519 signature length ${sig.length}`);

  const key = await importEd25519(pub);
  const ok = await verifyEd25519(key, sig, exchangeHash);
  const fp = toBase64(await sha256(hostKeyBlob)).replace(/=+$/, '');
  return { fingerprint: `SHA256:${fp}`, signatureValid: ok };
}

/**
 * RFC 4253 section 7.2 key derivation:
 *   K1 = HASH(K || H || X || session_id), K2 = HASH(K || H || K1), ...
 * K is the mpint encoding, including its length prefix.
 */
export async function deriveKey(
  sharedSecret: Uint8Array,
  exchangeHash: Uint8Array,
  letter: 'A' | 'B' | 'C' | 'D' | 'E' | 'F',
  sessionId: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const k = mpintBytes(sharedSecret);
  const x = new Uint8Array([letter.charCodeAt(0)]);
  let out = await sha256(concat(k, exchangeHash, x, sessionId));
  while (out.length < length) {
    out = concat(out, await sha256(concat(k, exchangeHash, out)));
  }
  return out.subarray(0, length);
}
