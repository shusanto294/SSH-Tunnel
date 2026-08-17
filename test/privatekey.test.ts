import { describe, expect, it } from 'vitest';
import { parseOpenSshEd25519 } from '../src/ssh/privatekey';
import { Writer, concat, toBase64, toHex } from '../src/ssh/wire';

/**
 * Builds a real, syntactically correct OpenSSH private key file around a
 * freshly generated ed25519 key. Generating it here rather than committing a
 * fixture keeps a genuine private key out of the repository.
 */
async function makeKeyFile(): Promise<{ pem: string; publicKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  const publicKey = new Uint8Array(
    (await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer,
  );
  const pkcs8 = new Uint8Array(
    (await crypto.subtle.exportKey('pkcs8', pair.privateKey)) as ArrayBuffer,
  );
  const seed = pkcs8.subarray(pkcs8.length - 32); // the trailing 32 bytes are the seed

  const publicBlob = new Writer().string('ssh-ed25519').string(publicKey).bytes();
  const privateSection = new Writer()
    .uint32(0x01020304)
    .uint32(0x01020304)
    .string('ssh-ed25519')
    .string(publicKey)
    .string(concat(seed, publicKey))
    .string('test@example')
    .raw(new Uint8Array([1, 2, 3])) // padding to an 8-byte boundary
    .bytes();

  const body = concat(
    new TextEncoder().encode('openssh-key-v1\0'),
    new Writer()
      .string('none')
      .string('none')
      .string('')
      .uint32(1)
      .string(publicBlob)
      .string(privateSection)
      .bytes(),
  );

  const base64 = (toBase64(body).match(/.{1,70}/g) ?? []).join('\n');
  return {
    pem: `-----BEGIN OPENSSH PRIVATE KEY-----\n${base64}\n-----END OPENSSH PRIVATE KEY-----\n`,
    publicKey,
  };
}

describe('OpenSSH ed25519 private keys', () => {
  it('parses a key and recovers the public half', async () => {
    const { pem, publicKey } = await makeKeyFile();
    const parsed = parseOpenSshEd25519(pem);
    expect(toHex(parsed.publicKey)).toBe(toHex(publicKey));
  });

  it('produces a PKCS#8 blob WebCrypto can sign with', async () => {
    const { pem, publicKey } = await makeKeyFile();
    const parsed = parseOpenSshEd25519(pem);

    const signingKey = await crypto.subtle.importKey('pkcs8', parsed.pkcs8, { name: 'Ed25519' }, false, [
      'sign',
    ]);
    const message = new TextEncoder().encode('exchange hash stand-in');
    const signature = await crypto.subtle.sign({ name: 'Ed25519' }, signingKey, message);

    const verifyKey = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, [
      'verify',
    ]);
    expect(await crypto.subtle.verify({ name: 'Ed25519' }, verifyKey, signature, message)).toBe(true);
  });

  it('rejects a passphrase-protected key with an actionable message', async () => {
    const { pem } = await makeKeyFile();
    // Swap the "none" cipher name for a real one, as ssh-keygen -p would.
    const tampered = pem.replace(
      /-----BEGIN[\s\S]*?-----\n/,
      '-----BEGIN OPENSSH PRIVATE KEY-----\n',
    );
    const parsed = parseOpenSshEd25519(tampered);
    expect(parsed.publicKey.length).toBe(32);

    const encrypted = buildEncryptedHeader();
    expect(() => parseOpenSshEd25519(encrypted)).toThrow(/Passphrase-protected/);
  });

  it('rejects text that is not an OpenSSH key at all', () => {
    expect(() => parseOpenSshEd25519('-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----')).toThrow(
      /OPENSSH PRIVATE KEY/,
    );
  });
});

function buildEncryptedHeader(): string {
  const body = concat(
    new TextEncoder().encode('openssh-key-v1\0'),
    new Writer()
      .string('aes256-ctr')
      .string('bcrypt')
      .string('')
      .uint32(1)
      .string(new Uint8Array(4))
      .string(new Uint8Array(4))
      .bytes(),
  );
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${toBase64(body)}\n-----END OPENSSH PRIVATE KEY-----\n`;
}
