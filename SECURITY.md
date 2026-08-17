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

## Abuse resistance

**Layered rate limits**, all backed by a Durable Object rather than a database
counter — a counter in D1 can be raced by two concurrent requests, a Durable
Object serialises them.

| Scope | Budget |
| ----- | ------ |
| All API traffic, per address | 240 requests / minute |
| Sign-in, per address | 8 / 5 minutes |
| Sign-in, per account | 8 / 5 minutes |
| Registration, per address | 5 / hour |
| Opening a terminal, per account | 30 / 5 minutes |

The per-account sign-in limit matters as much as the per-address one: without
it, anyone with a proxy pool or a botnet gets unlimited attempts at a single
password by rotating addresses.

**Escalating blocks.** Rate limits alone let a patient attacker try eight
passwords every five minutes indefinitely. Every suspicious outcome also adds
to a reputation score for the address (and, on sign-in, the account):

- 10 strikes → blocked 5 minutes
- 25 strikes → blocked 1 hour
- 50 strikes → blocked 24 hours

Scores decay completely after a quiet day, so a shared or reassigned address
recovers on its own. A successful sign-in clears the account's score outright —
proof it was not an attack on that account.

A wrong password is worth 2, a rejected invite code 3, and tripping a rate limit
5. In practice a password-guessing run is blocked after **5 or 6 attempts**, and
the block covers every API endpoint and the WebSocket, not just sign-in.
Blocked requests are refused before any database query or password hashing
happens, so an attack costs the attacker more than it costs the deployment.

What is deliberately *not* scored: reads. The landing page calls
`GET /api/auth/me` while signed out and receives a 401 on every visit — scoring
that would ban anyone who merely reads the site. The policy lives in one place,
`src/security/suspicion.ts`, and is unit-tested.

**Breached-password rejection.** Registration and password changes check the
password against Have I Been Pwned using the k-anonymity range API: only the
first five characters of its SHA-1 hash are sent, so the password never leaves
the Worker and the service cannot tell which hash was being asked about. Reused
passwords from other sites' breaches are the most common way accounts like these
are taken over, and no iteration count helps once an attacker already has the
password. The check fails open: an outage at that service must not prevent
signing up.

**Security headers** on every response, static pages included:
`Content-Security-Policy` (with `frame-ancestors 'none'` and `connect-src
'self'`, so injected script cannot exfiltrate to another origin),
`Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy: no-referrer`, `Permissions-Policy`, and
`Cross-Origin-Opener-Policy`. Pages are served straight from Cloudflare's asset
store without invoking the Worker, so their copy lives in `web/public/_headers`
— keep it in sync with `src/security/headers.ts`.

Session cookies are `HttpOnly; Secure; SameSite=Strict`, and every
state-changing request must additionally be same-origin.

### Worth enabling in the Cloudflare dashboard

The application defends itself, but these cost nothing and act before a request
reaches it:

- **Bot Fight Mode** (Security → Bots) — challenges obvious automation.
- **A WAF rate-limiting rule** on `/api/auth/*`, as a second ceiling below the
  application's own.
- **Turnstile** on registration, if the deployment is public and attracting
  automated sign-ups.

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
