/**
 * End-to-end smoke test: register (or sign in), save a server, open a terminal
 * over the WebSocket, run a command, and exit non-zero if anything fails.
 *
 * Usage:
 *   node scripts/smoke-test.mjs --base http://127.0.0.1:8790 \
 *        --host example.com --port 22 --user me --password '...' [--command whoami]
 *
 * Credentials come from the command line or the environment and are never
 * written to disk or echoed back.
 */

const args = parseArgs(process.argv.slice(2));
const base = args.base ?? process.env.SSH_TUNNEL_BASE ?? 'http://127.0.0.1:8790';
const account = args.account ?? process.env.SMOKE_EMAIL ?? `smoke-${Date.now()}@example.com`;
const accountPassword = args.accountPassword ?? process.env.SMOKE_PASSWORD ?? randomPassword();
const target = {
  host: args.host ?? process.env.SSH_HOST,
  port: Number(args.port ?? process.env.SSH_PORT ?? 22),
  user: args.user ?? process.env.SSH_USER,
  password: args.password ?? process.env.SSH_PASSWORD,
};
const command = args.command ?? 'whoami';
const inviteCode = args.invite ?? process.env.SMOKE_INVITE;

if (!target.host || !target.user || !target.password) {
  fail('Need --host, --user and --password (or SSH_HOST / SSH_USER / SSH_PASSWORD).');
}

const cookies = new Map();

const registration = await request('POST', '/api/auth/register', {
  email: account,
  password: accountPassword,
  inviteCode,
});
if (registration.status === 409) {
  const login = await request('POST', '/api/auth/login', {
    email: account,
    password: accountPassword,
  });
  if (!login.ok) fail(`Sign in failed: ${login.body.error ?? login.status}`);
  step('signed in');
} else if (!registration.ok) {
  fail(`Registration failed: ${registration.body.error ?? registration.status}`);
} else {
  step('registered');
}

const created = await request('POST', '/api/servers', {
  label: `smoke ${new Date().toISOString()}`,
  host: target.host,
  port: target.port,
  sshUser: target.user,
  authMethod: 'password',
  secret: target.password,
});
if (!created.ok) fail(`Could not save the server: ${created.body.error ?? created.status}`);
const serverId = created.body.server.id;
step(`saved server ${serverId}`);

const output = await runTerminal(serverId);
await request('DELETE', `/api/servers/${serverId}`);

if (!output.includes(target.user)) {
  fail(`Ran "${command}" but the output did not mention ${target.user}. Got: ${trim(output)}`);
}
step(`command output: ${trim(output)}`);
console.log('PASS');

// ---------------------------------------------------------------------------

async function runTerminal(id) {
  const wsBase = base.replace(/^http/, 'ws');
  const socket = new WebSocket(`${wsBase}/ws?server=${encodeURIComponent(id)}&cols=80&rows=24`, {
    headers: { cookie: cookieHeader() },
  });
  socket.binaryType = 'arraybuffer';

  let text = '';
  let sentCommand = false;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error(`Timed out. Received so far: ${trim(text)}`));
    }, 45_000);

    const finish = (value) => {
      clearTimeout(timer);
      try {
        socket.close();
      } catch {}
      resolve(value);
    };

    socket.addEventListener('message', (event) => {
      if (typeof event.data !== 'string') {
        text += new TextDecoder().decode(new Uint8Array(event.data));
        // The shell prompt is the signal that the pty is live.
        if (!sentCommand && /[$#>]\s?$/.test(text)) {
          sentCommand = true;
          text = '';
          socket.send(new TextEncoder().encode(`${command}\n`));
          setTimeout(() => finish(text), 3000);
        }
        return;
      }
      const message = JSON.parse(event.data);
      if (message.type === 'hostkey') {
        step(`host key ${message.fingerprint}`);
        socket.send(JSON.stringify({ type: 'confirm-hostkey', accept: true }));
      } else if (message.type === 'error') {
        clearTimeout(timer);
        reject(new Error(message.message));
      } else if (message.type === 'status') {
        step(`status: ${message.state}`);
      }
    });

    socket.addEventListener('error', () => {
      clearTimeout(timer);
      reject(new Error('WebSocket error.'));
    });
    socket.addEventListener('close', () => {
      if (sentCommand) finish(text);
      else {
        clearTimeout(timer);
        reject(new Error('The session closed before a shell was ready.'));
      }
    });
  });
}

async function request(method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      'sec-fetch-site': 'same-origin',
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(cookies.size ? { cookie: cookieHeader() } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });
  for (const raw of response.headers.getSetCookie?.() ?? []) {
    const [pair] = raw.split(';');
    const eq = pair.indexOf('=');
    if (eq > 0) cookies.set(pair.slice(0, eq), pair.slice(eq + 1));
  }
  const text = await response.text();
  return {
    ok: response.ok,
    status: response.status,
    body: text ? JSON.parse(text) : {},
  };
}

function cookieHeader() {
  return [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, '');
    if (key) out[key] = argv[i + 1];
  }
  return out;
}

function randomPassword() {
  return `smoke-${crypto.randomUUID()}`;
}

function step(message) {
  console.log(`  ${message}`);
}

function trim(text) {
  return text.replace(/\s+/g, ' ').trim().slice(0, 200);
}

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}
