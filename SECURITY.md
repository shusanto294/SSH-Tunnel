# Security

This project holds SSH credentials and can open a shell on a remote machine. It
deserves more care than a typical web app.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue: use
GitHub's **Report a vulnerability** button under the Security tab, which opens a
private advisory.

Useful things to include: what an attacker can do, the smallest reproduction you
have, and which version or commit you tested.

## What is and is not a secret in this repository

Nothing in this repository is a credential. Specifically:

| Value | Where it lives | Secret? |
| ----- | -------------- | ------- |
| Cloudflare API token | wrangler's config in your home directory | Yes — never in the repo |
| `TARGET_ALLOWLIST` | `wrangler secret put`, encrypted at Cloudflare | Yes — never in the repo |
| `database_id` in `wrangler.toml` | committed | No — an identifier; reading the database still requires authenticating as its owner |
| `OPEN_REGISTRATION` | committed in `[vars]` | No — a public policy switch |
| User passwords, SSH credentials, session tokens | D1, encrypted or hashed | Yes — never leave the database in usable form |

`.wrangler/` holds a local development database that can contain real test
credentials. It is gitignored. Do not remove that entry.

## Design

**Account passwords** are hashed with PBKDF2-HMAC-SHA256 at 600,000 iterations
and a per-account salt. Workers caps a single `deriveBits` call at 100,000
iterations, so the work is split into chained rounds — see
`src/auth/password.ts`. Argon2 and bcrypt are not available: every JavaScript
build of them compiles WebAssembly at runtime, which Workers forbids.

**Sessions** are opaque 32-byte random tokens. Only `SHA-256(token)` is stored,
so a database leak cannot be replayed as a sign-in. Sessions can be revoked
individually or all at once.

**Saved SSH credentials** are encrypted with AES-GCM under a per-user data
encryption key. That key is stored only in wrapped form, under a key derived
from the account password with a separate salt. The unwrapped key lives in an
HttpOnly cookie and is never persisted server-side, so the Worker can decrypt a
credential only while serving a request that carries it.

**Host keys** are pinned after explicit confirmation. A mismatch aborts before
authentication, so a credential is never sent to a server whose key changed.

**Egress** is restricted: loopback, private, CGNAT, link-local (including the
cloud metadata address), and multicast ranges are refused. Hostnames are
resolved and every returned address checked, then the connection is made to the
address that was checked — closing the DNS-rebinding window.

## Known limits

- **A compromised Worker sees everything.** Encryption at rest defends against a
  stolen database copy. It does not defend against whoever controls the
  deployment: they can read the encryption key of every user who signs in
  afterwards. This is inherent to any hosted browser terminal.
- **`OPEN_REGISTRATION="true"` makes your deployment an SSH gateway for anyone
  who finds the URL.** Set it to `"false"` once your accounts exist, and
  consider `TARGET_ALLOWLIST` as well.
- **Rekeying mid-session is not implemented.** Sessions are capped at one hour,
  and the OpenSSH rekey threshold for `aes256-gcm` is measured in gigabytes.
- **Passphrase-protected private keys are unsupported**, because unlocking them
  needs `bcrypt_pbkdf`.

## If you fork this

Change `database_id` in `wrangler.toml` to your own — `wrangler d1 create
ssh-tunnel` prints it. Everything else in the file is safe to keep.
