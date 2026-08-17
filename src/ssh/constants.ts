/** SSH message numbers used by this client (RFC 4250 section 4.1.2). */
export const MSG = {
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  EXT_INFO: 7,
  KEXINIT: 20,
  NEWKEYS: 21,
  KEX_ECDH_INIT: 30,
  KEX_ECDH_REPLY: 31,
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100,
} as const;

export const CLIENT_IDENT = 'SSH-2.0-SshTunnelSpike_0.1';

/**
 * Deliberately minimal suite. Every primitive here exists in Workers WebCrypto,
 * so no bignum library is needed:
 *   curve25519-sha256      -> X25519 deriveBits + SHA-256
 *   ssh-ed25519            -> Ed25519 verify
 *   aes256-gcm@openssh.com -> AES-GCM (AEAD, so no separate HMAC)
 */
export const ALGS = {
  kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org'],
  hostKey: ['ssh-ed25519'],
  cipher: ['aes256-gcm@openssh.com'],
  // Ignored when an AEAD cipher is negotiated, but some servers dislike an
  // empty list, so advertise something real.
  mac: ['hmac-sha2-256'],
  compression: ['none'],
} as const;
