# SSH Tunnel — Claude Code Prompt Playbook

A phased prompt set for building **SSH Tunnel**, a browser-based SSH client that
runs on Cloudflare Workers, so you can reach your servers over HTTPS/443 when
port 22 is blocked.

It is **multi-user**: people register accounts, save their own servers, and only
ever see their own. Account auth is built into the app (Phase 5), not delegated
to Cloudflare Access.

**Architecture being built:**

```
Browser (Next.js static export + xterm.js)
    │  HTTPS/443
    ├── /api/*  ── account auth, server CRUD ── D1 (users, sessions, servers)
    │
    └── /ws     ── WebSocket
            ▼
Worker fetch handler ── verifies app session cookie ── loads the caller's
    │                   saved server, decrypts its secret ── routes to
    ▼
Durable Object "SshSession"   (one per live terminal, keyed per user+server)
    ├─ holds the browser WebSocket
    ├─ holds the TCP socket from connect()
    └─ runs the SSH transport + auth + channel layer
    ▼
The user's own server's sshd on port 22
```

**Repo layout — everything lives at the repo root, next to this file:**

```
./claude.md          this playbook AND the project rules (see the end of the file)
./wrangler.toml      Worker + Durable Object + D1 bindings
./src/               Worker source
   ├── index.ts      fetch handler + routing
   ├── session.ts    SshSession Durable Object
   ├── ssh/          the SSH protocol layer, ported from the Phase 0 spike
   ├── auth/         account auth: password hashing, sessions, per-user crypto
   └── api/          JSON endpoints for register/login/servers
./migrations/        D1 schema migrations
./web/               Next.js app, static export, its own package.json
./scripts/           end-to-end smoke test
```

There is **no nested `ssh-tunnel/` directory.** The repo root is the project.

The Phase 0 spike directory has been removed now that its working code lives in
`src/ssh/`; its findings are recorded in the Phase 0 result section below.

**Read this before starting:** Phase 0 is a kill-gate. If it fails, skip to the
Pivot section at the bottom. Do not build phases 1–6 on an unproven handshake.

---

## Phase 0 — Feasibility spike (do this first, alone)

Goal: prove an SSH handshake can complete from inside a Worker. Nothing else.

```
I want to test whether a Cloudflare Worker can complete an SSH handshake. This is
a feasibility spike only — do NOT build a UI, do NOT scaffold a full project, and
do NOT mock or stub anything.

Create a minimal Worker in a new directory `spike/`:

1. Use `connect()` from `cloudflare:sockets` to open a TCP connection to
   $TEST_HOST:22. Read the server's identification string (the "SSH-2.0-..."
   banner) and return it in the HTTP response. This proves raw TCP egress works.

2. Then attempt a full handshake and run a single command (`whoami`), trying
   these approaches in order and stopping at the first that works:

   a. The npm `ssh2` package with `nodejs_compat_v2` enabled in wrangler.toml.
      If it fails, report the EXACT error and which Node API is missing.

   b. A hand-rolled handshake using WebCrypto only. Target this minimal cipher
      suite so you avoid needing any bignum library:
        - kex:        curve25519-sha256   (X25519 is available in Workers WebCrypto)
        - host key:   ssh-ed25519         (Ed25519 verify is available)
        - cipher:     aes256-gcm@openssh.com  (AEAD, so no separate HMAC needed)
        - compression: none
      Use password authentication for this spike, not publickey.

Test against a real server. I will give you the host, username, and password —
ask me for them, do not hardcode placeholders and claim success.

Report back honestly with one of: WORKS / PARTIALLY WORKS (say exactly where it
stops) / DOES NOT WORK (say why). If you cannot get past a step, say so plainly
rather than writing code that looks complete. Do not summarize this as a success
if `whoami` did not actually return output from the real server.
```

**Gate:** you must see real output from your real server. A banner alone is not a
pass — that only proves TCP. If Claude Code reports 2a works, you've saved weeks.
If only 2b partially works, expect a long project. If neither, go to Pivot.

### Phase 0 result — recorded 2026-08-17

**2a — npm `ssh2` under `nodejs_compat_v2`: DOES NOT WORK.** Fatal error, after
two shimmable ones:

```
RuntimeError: abort(CompileError: WebAssembly.instantiate():
Wasm code generation disallowed by embedder)
```

ssh2 compiles a bundled Emscripten WASM module at runtime. Workers only permits
statically imported WASM, so this cannot be patched from outside the package.
This rules out most existing Node SSH libraries, not just ssh2.

**2b — hand-rolled on WebCrypto: WORKS through the encrypted transport.**
Verified against the third-party server `ssh.github.com:443`:

```
+556ms server ident: SSH-2.0-feb815a
+558ms negotiated curve25519-sha256 / ssh-ed25519 / aes256-gcm@openssh.com
+842ms host key verified SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
+842ms aes256-gcm@openssh.com active in both directions
```

The fingerprint matches GitHub's published ed25519 host key byte for byte, so
the exchange hash and signature verification are provably correct; and
`SERVICE_ACCEPT` / `USERAUTH_FAILURE` decrypted with valid GCM tags, so RFC 4253
§7.2 key derivation and the AEAD framing are correct in both directions.

**Still unproven:** password authentication and command execution. GitHub offers
`publickey` only, so that run stops at `service-accepted` by design. Closing this
needs one run against a real server that accepts password auth. Until that run
produces real `whoami` output, treat the userauth and channel layers as
unverified.

---

## Phase 1 — Project setup

Only run this once Phase 0 passed.

Note: macOS filesystems are case-insensitive, so `CLAUDE.md` and `claude.md` are
the same file. The rules below live at the end of this file rather than in a
separate one — Claude Code loads it either way.

```
Write the project rules at the repo root before writing any code, containing:

- Project name: SSH Tunnel — a multi-user browser-based SSH client on Cloudflare
  Workers, one Durable Object per live terminal session
- Runtime constraints that must never be violated:
  * TCP sockets cannot be created in global scope — only inside a handler
  * No inbound TCP and no HTTP CONNECT support, so the browser side must be
    WebSocket, never a raw proxy
  * Outbound TCP to Cloudflare IP ranges is blocked
  * Runtime WebAssembly.instantiate() is disallowed — no argon2/bcrypt/scrypt
    WASM builds. Password hashing must use WebCrypto PBKDF2
  * SSH crypto burns CPU per packet, which counts against Workers CPU limits
- Rules for you: TypeScript strict mode; no `any` in the protocol layer or the
  auth layer; never log credentials, session keys, decrypted payloads, password
  hashes, or session tokens; never commit secrets
- Multi-tenancy rule: every D1 query that touches user data must be scoped by
  user_id from the verified session. A query against `servers` without a
  `user_id = ?` predicate is a bug, not a shortcut
- Working approach carried over from spike/: <paste Phase 0 conclusion here>

Then scaffold the project AT THE REPO ROOT — do not create a nested project
directory. Worker name `ssh-tunnel` in wrangler.toml, package name `ssh-tunnel`,
"SSH Tunnel" as the display name in the UI and README. Include:

- wrangler.toml with the compat flags the spike proved necessary, a Durable
  Object binding named SSH_SESSION with its migration block, a D1 binding named
  DB, and Workers static assets pointed at the Next.js static-export output
  (`web/out`) — see Phase 4 for why static export and not an SSR adapter
- TypeScript config for the Worker source in src/
- migrations/ for the D1 schema

Port the working handshake code from spike/src/native/ into src/ssh/ — do not
rewrite it from memory, move the code that actually worked. Leave spike/ in
place, untouched and unimported.
```

---

## Phase 2 — The SSH protocol layer

```
Build out src/ssh/ as a self-contained SSH client transport with no Worker or
Durable Object dependencies, so it stays unit-testable. Implement, in order:

1. Binary Packet Protocol: packet framing, padding, sequence numbers, and the
   encrypt/decrypt path for aes256-gcm@openssh.com
2. Wire type codecs: uint32, string, mpint, name-list, boolean
3. KEXINIT exchange and algorithm negotiation
4. curve25519-sha256 key exchange, computing the exchange hash H and deriving
   the six keys (IVs, encryption keys, integrity keys) per RFC 4253 section 7.2
5. Host key verification against the fingerprint pinned on the saved server
   record — fail closed if it does not match. On the very first connection to a
   server the user must be shown the fingerprint and confirm it explicitly;
   never trust-on-first-use silently
6. ssh-userauth: password first, then publickey with ed25519
7. ssh-connection: open a session channel, request a pty (pty-req) with
   configurable rows/cols, then request a shell
8. Data flow: channel data in/out, window adjust, and window-change for resizes

Write Vitest unit tests for the codecs and for key derivation using the test
vectors in the RFCs. After each numbered item, run the tests and confirm the
handshake still completes against my real server before moving to the next.
```

Run this one **in plan mode first** and read the plan. This is the phase where
scope explodes if you let it.

---

## Phase 3 — Durable Object session

```
Implement the SshSession Durable Object in src/session.ts:

- Accepts a WebSocket upgrade from the Worker and calls acceptWebSocket()
- The Worker has ALREADY verified the session cookie and resolved which user and
  which saved server this is. The DO receives the connection parameters and the
  decrypted credential from the Worker and never reads D1 itself
- Opens the TCP socket to the target host inside the handler, never in global scope
- Bridges bidirectionally: browser WebSocket bytes → SSH channel stdin, SSH
  channel stdout/stderr → browser WebSocket
- Defines a small JSON control protocol on the WebSocket for non-data messages:
  { type: "resize", cols, rows }, { type: "status", state }, { type: "error", message }
  Terminal data itself goes as binary frames, not JSON, to avoid base64 overhead
- Holds credentials in memory for the life of the session only. Never write them
  to Durable Object storage, KV, or logs
- Closes the TCP socket and the WebSocket together — if either side drops, tear
  down both and null out key material
- Enforces an idle timeout via an alarm, and a hard maximum session duration
- Refuses a second WebSocket on an already-connected instance, so one DO is
  exactly one terminal

Explain in comments why hibernation is or is not usable here given that the TCP
socket cannot survive it.
```

---

## Phase 4 — Terminal frontend

```
Build the frontend with Next.js, configured for **static export** — this is not
negotiable, read the constraint before you start:

- Use `output: 'export'` in next.config.js. Do NOT use @opennextjs/cloudflare or
  any SSR adapter. This app needs zero server-side rendering, and putting Next's
  server runtime inside the Worker would compete for script size with the SSH
  crypto code and force me to route /ws around the adapter's handler.
- `next build` emits to `out/`. Point the Workers assets directory at `out/`.
- Configure the Worker to handle /ws and /api/* itself and only fall through to
  static assets for everything else.
- No API routes, no middleware, no next/image optimization — none of that
  survives static export. All server logic lives in the Worker and the DO.

The screens:

- /register and /login — email and password, against the Phase 5 API
- /servers — the signed-in user's saved servers: add, edit, delete, connect.
  Shows each server's pinned host key fingerprint
- /terminal — the xterm.js session for one selected server

The terminal itself:

- xterm.js with the fit addon and the web-links addon, in a client component.
  Import it dynamically with ssr: false — it touches the DOM at module load.
- Connects to /ws via WebSocket, naming the saved server by id — the browser
  never sends the SSH credential over the wire, the Worker looks it up
- Handles resize with a debounced ResizeObserver, sending the control message
- Reconnect banner on drop, with a manual reconnect button — do not auto-retry
  in a loop
- Mobile-usable: the terminal must be readable and typeable on a phone, since
  the point of this is access from anywhere

Design direction: dark terminal aesthetic, monospace throughout, minimal chrome.

Keep the Next app in `web/` as its own package, separate from the Worker source
in `src/`, with a single root script that builds the frontend then deploys.
```

---

## Phase 5 — Accounts, multi-tenancy, and credential storage

This replaces the original single-user Cloudflare Access design. Access gates a
fixed list of identities; it cannot serve people who sign themselves up.

```
Build first-party account authentication in src/auth/ and src/api/. This is the
security core of the app — do not defer any of it.

Password hashing:
- PBKDF2-HMAC-SHA256 via WebCrypto, at least 600,000 iterations, 32-byte random
  salt per user, 32-byte derived key. Argon2/bcrypt/scrypt are NOT options: the
  spike proved runtime WebAssembly is disallowed in Workers
- Store iteration count per user so it can be raised later without invalidating
  existing accounts; re-hash on next successful login when it is below target
- Compare with a constant-time comparison, never ===

Sessions:
- Opaque 32-byte random token, sent as a cookie: HttpOnly, Secure, SameSite=Lax,
  Path=/. Store only SHA-256(token) in D1, never the token itself
- Absolute expiry and idle expiry, rotation on login, server-side revocation, and
  a "sign out everywhere" that deletes every session row for the user
- No JWTs. Revocation matters more than statelessness here

Per-user credential encryption — the point is that the database alone is useless:
- At registration, generate a random 32-byte data encryption key (DEK)
- Derive a key-encryption key from the user's password with a SEPARATE PBKDF2
  salt from the login hash, and store only AES-GCM(KEK, DEK)
- Every saved SSH credential is encrypted with AES-GCM under the user's DEK
- The unwrapped DEK is returned to the browser in a second HttpOnly Secure
  cookie and is never persisted server-side. The Worker therefore holds a user's
  DEK only for the duration of a request that carries it
- Changing a password re-wraps the DEK, so saved servers survive. A forgotten
  password means the saved credentials are unrecoverable by design — say this in
  the UI at registration time, do not silently lose people's data

Registration control:
- Registration is invite-code gated by default: codes are stored hashed, single
  use, with an expiry. An OPEN_REGISTRATION Worker secret can turn the gate off,
  and the README must spell out what that means
- Rate-limit login, registration, and code redemption per IP and per account,
  backed by a Durable Object. Generic failure messages: never reveal whether an
  email exists

Multi-tenancy:
- Every query touching `servers` or `sessions` is scoped by the user_id from the
  verified session. Server ids are random, never sequential — but ownership is
  still checked on every read and write, not just inferred from an unguessable id
- Verify the session on every request including the WebSocket upgrade. Reject
  with 401, and 403 when a signed-in user reaches for another user's row

Egress control — this app must not become an open SSH relay:
- Refuse to connect to private, loopback, link-local, and multicast ranges, and
  to Cloudflare's own ranges. Resolve before deciding, and refuse anything that
  fails to parse
- Support an optional target allowlist via a Worker secret for locked-down
  deployments
- Cap concurrent sessions per user and per account age

Then add a security section to README.md covering: the credential handling
model, what an attacker who compromises the Worker can reach, what a stolen D1
snapshot does and does not reveal, and what happens on password loss.

Finally, review the whole codebase for places credentials or key material could
leak: console.log, error messages returned to the client, tail logs, exception
stacks, and D1 query logging.
```

### D1 schema this phase must create

```sql
users     (id, email UNIQUE, pw_hash, pw_salt, pw_iters,
           dek_wrapped, dek_iv, dek_salt, dek_iters,
           created_at, disabled)
sessions  (token_hash PK, user_id, created_at, expires_at, last_seen_at)
servers   (id PK, user_id, label, host, port, ssh_user, auth_method,
           secret_ct, secret_iv, host_key_fp, created_at, last_used_at)
invites   (code_hash PK, created_by, used_by, expires_at, used_at)
audit     (id PK, user_id, ts, action, detail)   -- never any secret material
```

---

## Phase 6 — Deploy

```
Deploy this to Cloudflare:

1. Confirm wrangler.toml has correct Durable Object migrations, the D1 binding,
   and compat flags
2. Apply D1 migrations to the remote database
3. Set secrets with `wrangler secret put` — never in wrangler.toml
4. Deploy and bind a custom subdomain on my zone
5. Create the first invite code, and walk me through creating my own account
6. Add a smoke-test script that registers a throwaway account, saves a server,
   connects, runs a command, and exits non-zero on failure

Then tell me: which Workers plan this requires and why, what the CPU-time
exposure looks like per keystroke, what D1 read/write volume a busy session
generates, and what will break first under load.
```

---

## Pivot — if Phase 0 fails

Do not force it. This prompt gives you the same browser terminal with a fraction
of the risk:

```
The Workers-native SSH handshake did not work. Build the relay architecture
instead:

- A small Go or Node agent that runs on my server, dials out to the Worker over
  WebSocket, and bridges to localhost:22
- The Worker becomes a pure WebSocket relay plus static host for the xterm.js
  frontend, with no SSH protocol code at all
- The app's own account auth still guards the frontend; each agent authenticates
  to the Worker with a per-user enrollment secret

This is architecturally what Cloudflare Tunnel does. Explain the tradeoffs versus
just running cloudflared, and be honest if cloudflared is the better answer.
```

(Phase 0 passed, so this section is retained only as a fallback if the userauth
leg turns out to be blocked.)

---

## Working notes

- Run Phases 0 and 2 in plan mode and actually read the plans.
- Commit at every gate. The protocol layer is easy to break subtly.
- The spike directory served its purpose and has been deleted. What it proved is
  written down in the Phase 0 result section, and the code that worked lives in
  `src/ssh/`.
- Test against a throwaway VPS, not a production box, until Phase 5 is done.
- If Claude Code says "the handshake is now complete" without showing you real
  output from your real server, it isn't.
- Multi-user changes the threat model: this deployment now holds other people's
  server credentials. Treat every Phase 5 item as required, not optional.

---

# Project rules

Everything above is the build plan. Everything below applies to all work in this
repo, permanently.

## Layout

```
src/index.ts      Worker fetch handler: routes /api/*, /ws, static assets
src/session.ts    SshSession Durable Object — one live terminal each
src/ssh/          SSH protocol layer. No Worker or DO imports; unit-testable
src/auth/         password hashing, session cookies, per-user credential crypto
src/api/          JSON endpoints: register, login, servers CRUD
migrations/       D1 schema
web/              Next.js frontend, static export, its own package.json
scripts/          end-to-end smoke test
test/             Vitest unit tests
```

The repo root *is* the project. Do not create a nested `ssh-tunnel/` directory.

## Runtime constraints — never violate these

- **TCP sockets cannot be created in global scope.** `connect()` from
  `cloudflare:sockets` only works inside a request handler.
- **No inbound TCP and no HTTP CONNECT.** The browser side must be a WebSocket.
  Never a raw proxy.
- **Outbound TCP to Cloudflare's own IP ranges is blocked** by the platform.
- **Runtime `WebAssembly.instantiate()` is disallowed.** Proven during the
  Phase 0 spike: it is what killed the npm `ssh2` approach. No argon2, bcrypt, or scrypt WASM
  builds. Password hashing uses WebCrypto PBKDF2.
- **SSH crypto burns CPU per packet**, and that counts against the Workers CPU
  limit. Keep the per-keystroke path allocation-light.

## Working approach carried over from the Phase 0 spike

The npm `ssh2` package does not work in Workers. The transport is hand-rolled on
WebCrypto with a deliberately minimal suite, verified against a real server:

| Layer       | Algorithm                | Workers primitive       |
| ----------- | ------------------------ | ----------------------- |
| kex         | `curve25519-sha256`      | X25519 `deriveBits`     |
| host key    | `ssh-ed25519`            | Ed25519 `verify`        |
| cipher      | `aes256-gcm@openssh.com` | AES-GCM (AEAD, no HMAC) |
| compression | `none`                   | —                       |

Two runtime quirks worth remembering:

- `@cloudflare/workers-types` spells the ECDH peer-key field `$public`, but the
  runtime wants the spec name `public`. See the cast in `src/ssh/kex.ts`.
- Ed25519 import may need the legacy `NODE-ED25519` algorithm name on older
  runtimes; `src/ssh/kex.ts` tries both.

Verified working as of 2026-08-17: TCP egress, KEXINIT negotiation, X25519 kex,
exchange hash, Ed25519 host key verification, RFC 4253 §7.2 key derivation, and
`aes256-gcm@openssh.com` framing in both directions.

**Not yet verified against a real server: password userauth and channel/exec.**
Do not describe those as working until a real `whoami` round-trips.

## Rules

- TypeScript strict mode. **No `any` in the protocol layer or the auth layer.**
- **Never log** credentials, session keys, decrypted payloads, password hashes,
  session tokens, or DEKs. Not in `console.log`, not in error messages returned
  to the client, not in exception stacks that reach a response.
- Never commit secrets. Everything sensitive goes through `wrangler secret put`.
- **Multi-tenancy rule:** every D1 query touching user data is scoped by the
  `user_id` from the verified session. A query against `servers` with no
  `user_id = ?` predicate is a bug, not a shortcut. Unguessable ids are not an
  authorization mechanism.
- **Fail closed on host keys.** A saved server pins a fingerprint; a mismatch
  aborts the connection. First-time connections require explicit user
  confirmation of the fingerprint — never silent trust-on-first-use.
- **No open relay.** Refuse loopback, private, link-local, and multicast targets,
  plus Cloudflare's ranges.
- Error messages to the client are generic. Detail goes nowhere, not even to
  logs, when it could distinguish "no such account" from "wrong password".

## Commands

```
npm run dev        # wrangler dev with the local D1 database
npm run build      # build the Next.js frontend into web/out
npm run typecheck  # tsc over the Worker source
npm run test       # vitest over src/ssh
npm run deploy     # build the frontend, then wrangler deploy
npm run db:local   # apply migrations to the local D1 database
npm run db:remote  # apply migrations to the deployed D1 database
```
