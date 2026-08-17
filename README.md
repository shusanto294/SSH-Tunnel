# SSH Tunnel

A multi-user, browser-based SSH client that runs entirely on Cloudflare Workers.
People register an account, save their own servers, and open a real terminal to
them over HTTPS on port 443 — useful when outbound port 22 is blocked by the
network you are sitting on.

There is no agent to install on the target server and no SSH library on the
Worker: the SSH-2 transport is implemented directly on WebCrypto.

```
Browser (Next.js static export + xterm.js)
    │  HTTPS / WSS on 443
    ├── /api/*  accounts, saved servers ── D1
    └── /ws     ── Worker verifies the session, decrypts the credential,
                   vets the target, then hands it to a Durable Object
                          │
                   Durable Object "SshSession"  (one per live terminal)
                     ├─ the browser WebSocket
                     ├─ the TCP socket from connect()
                     └─ SSH transport, userauth, and channel layers
                          │
                   your server's sshd
```

## Status

| Layer | State |
| ----- | ----- |
| TCP egress from a Worker | verified against a real server |
| KEXINIT negotiation, curve25519 kex, exchange hash | verified |
| ssh-ed25519 host key verification | verified — fingerprint matches the published key |
| RFC 4253 §7.2 key derivation, `aes256-gcm@openssh.com` both directions | verified |
| Accounts, sessions, per-user credential encryption, tenant isolation | verified end to end |
| WebSocket → Durable Object → SSH handshake pipeline | verified end to end |
| Password authentication against a real server | verified — the server accepted it and moved on |
| **pty-req and shell against a real server** | **not independently verified** |

The last row is the honest one. Everything before it has been observed working
against a real server; the interactive shell has not been confirmed by the
author. `npm run smoke -- --host … --user … --password …` closes it: it opens a
terminal, runs a command, and exits non-zero if the output does not come back.

## Supported algorithms

Deliberately one option per layer, chosen so that every primitive already exists
in Workers WebCrypto and no bignum or WASM library is needed:

| Layer | Algorithm |
| ----- | --------- |
| Key exchange | `curve25519-sha256` |
| Host key | `ssh-ed25519` |
| Cipher | `aes256-gcm@openssh.com` (AEAD, so no separate MAC) |
| Compression | `none` |
| User authentication | password, or unencrypted ed25519 private key |

Servers that cannot offer all of these will be refused with a clear message.
Every OpenSSH release since 6.5 can.

## Hosting your own

### What you need

- **Node.js 20 or newer** and npm.
- **A Cloudflare account on the paid Workers plan.** This is not optional. Signing
  in performs two 600,000-iteration PBKDF2 derivations, which is far beyond the
  free plan's 10 ms CPU limit, and every live terminal holds a Durable Object
  open for the duration of the session.
- A domain on Cloudflare, if you want a custom hostname. A `workers.dev`
  subdomain works without one.

### 1. Install

```bash
git clone https://github.com/shusanto294/SSH-Tunnel.git
cd SSH-Tunnel
npm install
npm --prefix web install
```

### 2. Sign in to Cloudflare

```bash
npx wrangler login
```

Opens a browser to authorise the CLI. Confirm it worked with
`npx wrangler whoami`.

### 3. Create the database

```bash
npx wrangler d1 create ssh-tunnel
```

It prints a `database_id`. Put it in `wrangler.toml`, replacing the one already
there:

```toml
[[d1_databases]]
binding = "DB"
database_name = "ssh-tunnel"
database_id = "paste-your-id-here"
```

The binding name must stay `DB` — that is what the Worker code looks for.
Ignore the snippet Cloudflare prints suggesting `ssh_tunnel`.

### 4. Create the tables

```bash
npm run db:remote     # the deployed database
npm run db:local      # the local one, for `npm run dev`
```

### 5. Build and deploy

```bash
npm run deploy
```

This builds the frontend into `web/out` and pushes the Worker, both Durable
Objects, and the static assets. It prints your URL:

```
https://ssh-tunnel.<your-subdomain>.workers.dev
```

Give it a minute. Cloudflare propagates static assets across its edge
independently of the Worker, so for a short while after any deploy some requests
are served the previous version. It settles on its own.

### 6. Claim the first account

Open `/register` on your new URL and sign up **immediately**.

The first account created becomes the administrator, and by default anyone who
finds the URL can register. Whoever gets there first gets that account.

Choose a strong password: the key that encrypts every saved SSH credential is
derived from it, and losing it means losing those credentials permanently.

### 7. Lock it down

Two settings, both worth considering before this is more than a toy.

**Close registration** once your accounts exist. In `wrangler.toml`:

```toml
[vars]
OPEN_REGISTRATION = "false"
```

Then `npm run deploy`. New accounts now need an invite code, which an
administrator mints from the account page.

**Restrict which hosts it can reach**, so a stolen session cannot be used as a
general-purpose SSH relay:

```bash
npx wrangler secret put TARGET_ALLOWLIST
# then enter: server1.example.com,server2.example.com
```

Without it, any signed-in user can connect to any public address. Private,
loopback, link-local, and multicast ranges are always refused regardless.

### 8. Custom domain, optionally

Cloudflare dashboard → Workers & Pages → `ssh-tunnel` → Settings → Domains &
Routes → **Add custom domain**. The certificate is issued automatically.

## Running locally

```bash
npm run build     # the frontend must be built at least once
npm run dev       # http://127.0.0.1:8787
```

`wrangler dev` uses a local D1 database and local Durable Objects, so nothing
touches your deployed data. Outbound TCP still leaves your machine, which
matters: **many home and office networks block outbound port 22**, which is the
whole reason this project exists. If connections fail locally but work when
deployed, that is why.

One production behaviour local development does not reproduce: Workers refuses
PBKDF2 above 100,000 iterations, and the local runtime does not enforce that
limit. The code splits the work into chained rounds to stay under it — see
`src/auth/password.ts` before changing anything there.

## Updating a deployment

```bash
git pull
npm install && npm --prefix web install   # only if dependencies changed
npm run db:remote                         # only if migrations/ changed
npm run deploy
```

## Troubleshooting

**"The host key does not match the one saved for this server."**
The server's host key changed. After an OS reinstall that is expected: use
**Forget host key** on the server card, then confirm the new fingerprint when it
is shown. If you did *not* rebuild the machine, do not click it — a changed host
key is also what an impersonated server looks like. Remember that a reinstall
also resets the password, so update the saved credential too.

**"Authentication failed. The server accepts: publickey."**
The server has `PasswordAuthentication no`. Either switch the saved server to a
private key, or enable password auth in `/etc/ssh/sshd_config`.

**"No shared key exchange / host key / cipher algorithm with this server."**
The server is older than OpenSSH 6.5 or has been hardened to exclude the
algorithms listed above. This client supports exactly one option per layer by
design.

**Private key rejected.**
Only *unencrypted* ed25519 keys work. Passphrase-protected keys need
`bcrypt_pbkdf`, which requires runtime WebAssembly, and Workers forbids it.
Generate one with `ssh-keygen -t ed25519 -N ""`.

**The page looks stale right after deploying.**
Edge propagation. Wait a minute and hard-refresh.

**Sign-in is slow.**
Deliberate: PBKDF2 at 600,000 iterations takes roughly a second. Lower
`TARGET_ITERATIONS` in `src/auth/password.ts` if you want it faster, and accept
the weaker resistance to offline cracking.

## Contributing

Issues and pull requests are welcome. Run `npm run typecheck` and `npm run test`
before opening one.

Report security problems privately through GitHub's **Report a vulnerability**
button rather than a public issue. See [SECURITY.md](SECURITY.md).

Licensed under the [MIT License](LICENSE).

## Security

This section is the important one. A deployment of this app holds other
people's SSH credentials, which makes its threat model very different from a
personal tool.

### How credentials are stored

Each account gets a random 32-byte **data encryption key** (DEK) at
registration. Saved SSH passwords and private keys are encrypted with AES-GCM
under that DEK before they reach the database.

The DEK itself is never stored in the clear. It is wrapped with a key derived
from the account password by PBKDF2-HMAC-SHA256 (600,000 iterations, its own
salt, separate from the login verifier's salt). At sign-in the DEK is unwrapped
and returned to the browser in an `HttpOnly; Secure; SameSite=Lax` cookie, and
it is never written to server-side storage.

Consequences, all of them intentional:

- **A stolen copy of the D1 database yields no usable SSH credentials.** It
  contains wrapped DEKs and ciphertext, and cracking either means cracking a
  600k-iteration PBKDF2 per account.
- **The Worker can decrypt a credential only while serving a request that
  carries the DEK cookie.** There is no ambient ability to read stored secrets.
- **Forgetting the account password destroys access to the saved credentials.**
  Nobody, operator included, can recover them. The registration page says so.
- Changing a password re-wraps the same DEK, so saved servers survive it.

### What an attacker who compromises the Worker can reach

Being honest about the ceiling: an attacker with code execution in the Worker,
or the ability to deploy to it, can read the DEK cookie of every user who
signs in or makes a request afterwards, and therefore every credential those
users have saved. Encryption at rest limits the damage from a database leak; it
does not protect against a compromised runtime, and nothing in this design
claims otherwise.

The blast radius is every server saved by every account that uses the
deployment after the compromise. Deploy accordingly: keep the Cloudflare
account on hardware keys, keep the deploy path narrow, and use per-user SSH
accounts on the target servers rather than shared root credentials.

### Account authentication

- PBKDF2-HMAC-SHA256, 600,000 iterations, unique 32-byte-derived verifier per
  account, constant-time comparison. Argon2 and bcrypt are unavailable in this
  runtime — every JavaScript build of them compiles WebAssembly at runtime,
  which Workers forbids. The per-account iteration count is stored, so it can be
  raised later and existing accounts re-hash transparently on next sign-in.
- Sessions are opaque 32-byte random tokens. Only `SHA-256(token)` is stored, so
  a database leak cannot be replayed as a sign-in. There are no JWTs:
  revocation matters more than statelessness for an app that opens shells.
- Sessions have both a 14-day absolute lifetime and a 3-day idle lifetime, and
  can be revoked individually or all at once.
- Sign-in, registration, and session-open are rate limited per IP and per
  account by a Durable Object, which — unlike a D1 counter — cannot be raced.
- Failure messages never distinguish "no such account" from "wrong password",
  and the unknown-account path performs the same PBKDF2 work so the response
  time does not answer the question either.
- Every state-changing request must be same-origin.

### Multi-tenancy

Every query that touches user data carries `user_id = ?` from the verified
session. Server ids are unguessable, but that is treated as a nicety rather
than an authorization mechanism: another user's server is a 404, not a 403, and
the check lives in the SQL rather than in a caller's discipline.

### Host keys

A saved server pins its host key fingerprint. On the first connection the
fingerprint is shown in the browser and must be confirmed explicitly; there is
no silent trust-on-first-use. Afterwards, any mismatch aborts the connection
before authentication — the credential is never sent to a server whose key
changed. Editing a server's host or port clears the pin, since the old
fingerprint belonged to a different machine.

### Not an open SSH relay

Before connecting, the target is resolved and every returned address is checked
against loopback, private, CGNAT, link-local (including the cloud metadata
address), and multicast ranges. The connection is then made to the address that
was actually checked, which closes the DNS-rebinding window between check and
connect. Cloudflare's own ranges are refused by the platform itself.

`TARGET_ALLOWLIST` narrows this further to a fixed set of hosts, and
registration can be invite-gated with `OPEN_REGISTRATION="false"`. Shipped as
`"true"`, which means anyone on the internet can create an account and use your
Worker to reach arbitrary hosts — close it once your accounts exist.

### Where credentials deliberately do not go

- Not into logs. There is no `console.log` anywhere in `src/`.
- Not into Durable Object storage or KV — only into the session object's memory,
  and the reference is dropped as soon as the handshake completes.
- Not into error messages. Errors returned to the browser carry a human-readable
  message and nothing else; no stacks, no exception text.
- Not into the URL or request headers. Credentials reach the Durable Object as
  RPC arguments, and reach the API as JSON request bodies.

### Known limitations

- Passphrase-protected private keys are not supported, because OpenSSH encrypts
  them with `bcrypt_pbkdf` and that needs runtime WebAssembly.
- Mid-session rekeying is not implemented. With `aes256-gcm` the OpenSSH rekey
  threshold is measured in gigabytes, and sessions are capped at one hour.
- Sessions do not survive a Durable Object eviction. See the comment at the top
  of `src/session.ts` for why hibernation cannot be used here.

## Operational notes

- **Workers plan:** this needs a paid plan. A single sign-in performs two
  600,000-iteration PBKDF2 derivations, which is far past the free plan's 10 ms
  CPU limit. The SSH transport adds AES-GCM work per packet on top.
- **CPU per keystroke:** one keystroke is one small AES-GCM seal plus one open
  for the echo — microseconds of CPU, but it is *per packet*, and an interactive
  session is chatty. Bulk output (`cat` of a large file) is the expensive case.
- **D1 volume:** a session touches D1 only at open time, plus at most one
  `last_seen_at` write per minute per session. Terminal traffic never touches
  the database.
- **What breaks first under load:** concurrent Durable Objects. Each live
  terminal pins one object with an open TCP socket for the life of the session,
  and neither the socket nor the cipher state can be hibernated.

## Testing

```bash
npm run typecheck
npm run test                       # codecs, key derivation, packet framing, egress guard
npm run smoke -- --host example.com --user me --password '…'
```

The smoke test registers a throwaway account, saves a server, opens a real
terminal, runs a command, and exits non-zero if the output does not come back.

## Layout

```
src/index.ts      Worker fetch handler: /api/*, /ws, static assets
src/session.ts    SshSession Durable Object — one live terminal each
src/ssh/          SSH protocol layer; no Worker imports, unit-testable
src/auth/         password hashing, sessions, per-user credential crypto
src/api/          JSON endpoints
src/net/guard.ts  egress policy
migrations/       D1 schema
web/              Next.js frontend, static export
scripts/          end-to-end smoke test
test/             Vitest unit tests
```
