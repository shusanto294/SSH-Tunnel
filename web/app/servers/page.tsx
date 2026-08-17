'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { PageLoading } from '@/components/Loading';
import TopBar from '@/components/TopBar';
import { api, type AuthMethod, type Server, type User } from '@/lib/api';

export default function ServersPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [canDecrypt, setCanDecrypt] = useState(true);
  const [servers, setServers] = useState<Server[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [panel, setPanel] = useState<'quick' | 'save' | null>(null);

  const refresh = useCallback(async () => {
    const list = await api.listServers();
    setServers(list.servers);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const session = await api.me();
        if (cancelled) return;
        if (!session.user) {
          router.replace('/login');
          return;
        }
        setUser(session.user);
        setCanDecrypt(session.canDecrypt);
        await refresh();
      } catch {
        if (!cancelled) router.replace('/login');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router, refresh]);

  /**
   * Provisions the session here, then navigates with only a ticket. Nothing
   * sensitive ends up in the URL or in browser history.
   */
  async function open(server: Server) {
    setError(null);
    try {
      const { ticket } = await api.connect({ serverId: server.id, cols: 80, rows: 24 });
      router.push(`/terminal?ticket=${encodeURIComponent(ticket)}&server=${encodeURIComponent(server.id)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not open that session.');
    }
  }

  // Clearing a pinned host key is deliberately not offered here. It is only
  // ever the right action in response to an actual mismatch, and the terminal
  // offers it there — where the new fingerprint is on screen to judge.
  async function remove(server: Server) {
    if (!confirm(`Delete "${server.label}"? The saved credential is destroyed with it.`)) return;
    try {
      await api.deleteServer(server.id);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not delete that server.');
    }
  }

  if (loading) return <PageLoading label="Loading your servers" />;

  return (
    <>
      <TopBar user={user} />

      <main className="shell">
        {error && <div className="notice error">{error}</div>}

        {!canDecrypt && (
          <div className="notice warn">
            Your encryption key is not loaded in this browser, so saved credentials
            cannot be used. Sign out and sign in again.
          </div>
        )}

        <div className="row" style={{ alignItems: 'baseline', marginBottom: 12 }}>
          <h1 style={{ flex: '1 1 auto' }}>Your servers</h1>
          <button style={{ flex: '0 0 auto' }} onClick={() => setPanel(panel === 'quick' ? null : 'quick')}>
            {panel === 'quick' ? 'Cancel' : 'Quick connect'}
          </button>
          <button
            className="primary"
            style={{ flex: '0 0 auto' }}
            onClick={() => setPanel(panel === 'save' ? null : 'save')}
          >
            {panel === 'save' ? 'Cancel' : 'Add server'}
          </button>
        </div>

        {panel === 'quick' && <QuickConnectForm />}

        {panel === 'save' && (
          <AddServerForm
            onSaved={async () => {
              setPanel(null);
              await refresh();
            }}
          />
        )}

        {servers.length === 0 && panel === null && (
          <p className="muted">No servers saved yet. Add one to get started.</p>
        )}

        {servers.map((server) => (
          <div className="server" key={server.id}>
            <header>
              <strong>{server.label}</strong>
              <span className="muted">
                {server.sshUser}@{server.host}:{server.port}
              </span>
            </header>
            <div className="fp">
              {server.hostKeyFingerprint
                ? `pinned ${server.hostKeyFingerprint}`
                : 'no host key pinned yet — you will be asked to confirm it on first connect'}
            </div>
            <div className="row" style={{ marginTop: 12 }}>
              <button className="primary" onClick={() => open(server)}>
                Connect
              </button>
              <button className="danger" onClick={() => remove(server)}>
                Delete
              </button>
            </div>
          </div>
        ))}

      </main>
    </>
  );
}

/**
 * Attributes that keep browsers and password managers from treating these
 * fields as a login form. Without them, Chrome fills the account's own email
 * and password into the SSH credential fields — which would quietly save the
 * wrong secret against the server.
 *
 * `autoComplete="off"` alone is not enough: Chrome ignores it on inputs it
 * believes are logins, so the password field claims to be a *new* password
 * (which suppresses filling a stored one) and the field names avoid the
 * username/email heuristics. The data-* attributes opt out of 1Password,
 * LastPass, and Dashlane respectively.
 */
const NO_AUTOFILL = {
  'data-1p-ignore': true,
  'data-lpignore': 'true',
  'data-form-type': 'other',
} as const;

/**
 * Decoys. Chrome fills the first username/password pair it finds in a form and
 * ignores `autocomplete="off"` while doing it, so this pair is offered up to
 * absorb the fill. They are off-screen rather than `display: none`, because
 * Chrome skips fields it considers unrenderable — which would send the fill
 * straight back to the real inputs.
 */
const OFFSCREEN: React.CSSProperties = {
  position: 'absolute',
  top: -9999,
  left: -9999,
  width: 1,
  height: 1,
  opacity: 0,
  pointerEvents: 'none',
};

function AutofillDecoys() {
  return (
    <div aria-hidden="true" style={OFFSCREEN}>
      <input type="text" name="username" autoComplete="username" tabIndex={-1} />
      <input type="password" name="password" autoComplete="current-password" tabIndex={-1} />
    </div>
  );
}

/**
 * A field that starts read-only and becomes editable on first focus.
 *
 * Chrome will not autofill a read-only input, and its fill happens at page
 * load — so by the time the field is editable, the moment has passed. Typing
 * is unaffected: focusing is what makes it writable, and that is the same
 * gesture as starting to type.
 */
function useAutofillProof(): { readOnly: boolean; onFocus: () => void } {
  const [readOnly, setReadOnly] = useState(true);
  return { readOnly, onFocus: () => setReadOnly(false) };
}

/**
 * A one-off connection. What is typed here is sent once, used for a single
 * session, and never written to the database — so there is nothing to leak
 * afterwards, and nothing to clean up.
 */
function QuickConnectForm() {
  const router = useRouter();
  const [host, setHost] = useState('');
  const [port, setPort] = useState(22);
  const [sshUser, setSshUser] = useState('root');
  const [authMethod, setAuthMethod] = useState<AuthMethod>('password');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const userGuard = useAutofillProof();
  const secretGuard = useAutofillProof();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { ticket } = await api.connect({
        host,
        port,
        sshUser,
        authMethod,
        secret,
        cols: 80,
        rows: 24,
      });
      // Clear it from React state on the way out; the ticket is all the
      // terminal page needs.
      setSecret('');
      router.push(`/terminal?ticket=${encodeURIComponent(ticket)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not connect.');
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit} autoComplete="off">
      <h2>Quick connect</h2>
      <AutofillDecoys />
      {error && <div className="notice error">{error}</div>}

      <div className="notice info">
        Nothing here is saved. The credential is used for this session only and is
        never written to the database — reconnecting later means typing it again.
      </div>

      <div className="row">
        <div style={{ flex: '3 1 200px' }}>
          <label htmlFor="qc-host">Host</label>
          <input
            id="qc-host"
            name="target-address"
            required
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="example.com or 203.0.113.10"
            {...NO_AUTOFILL}
          />
        </div>
        <div style={{ flex: '1 1 80px' }}>
          <label htmlFor="qc-port">Port</label>
          <input
            id="qc-port"
            type="number"
            min={1}
            max={65535}
            required
            value={port}
            onChange={(e) => setPort(Number(e.target.value))}
          />
        </div>
      </div>

      <label htmlFor="qc-user">SSH username</label>
      <input
        id="qc-user"
        name="target-account"
        required
        autoComplete="off"
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
        value={sshUser}
        onChange={(e) => setSshUser(e.target.value)}
        placeholder="root"
        readOnly={userGuard.readOnly}
        onFocus={userGuard.onFocus}
        {...NO_AUTOFILL}
      />

      <label htmlFor="qc-auth">Authentication</label>
      <select
        id="qc-auth"
        value={authMethod}
        onChange={(e) => setAuthMethod(e.target.value as AuthMethod)}
      >
        <option value="password">Password</option>
        <option value="privatekey">Private key (unencrypted ed25519)</option>
      </select>

      {authMethod === 'password' ? (
        <>
          <label htmlFor="qc-secret">SSH password</label>
          <input
            id="qc-secret"
            name="target-secret"
            type="password"
            autoComplete="new-password"
            required
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            readOnly={secretGuard.readOnly}
            onFocus={secretGuard.onFocus}
            {...NO_AUTOFILL}
          />
        </>
      ) : (
        <>
          <label htmlFor="qc-secret">Private key</label>
          <textarea
            id="qc-secret"
            name="target-secret"
            required
            autoComplete="off"
            spellCheck={false}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
            {...NO_AUTOFILL}
          />
        </>
      )}

      <div style={{ marginTop: 20 }}>
        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Connecting…' : 'Connect without saving'}
        </button>
      </div>
    </form>
  );
}

function AddServerForm({ onSaved }: { onSaved: () => Promise<void> }) {
  const [label, setLabel] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState(22);
  // Overwhelmingly the account people SSH in as on a fresh VPS.
  const [sshUser, setSshUser] = useState('root');
  const [authMethod, setAuthMethod] = useState<AuthMethod>('password');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const userGuard = useAutofillProof();
  const secretGuard = useAutofillProof();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createServer({ label, host, port, sshUser, authMethod, secret });
      setLabel('');
      setHost('');
      setPort(22);
      setSshUser('root');
      setSecret('');
      await onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save that server.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit} autoComplete="off">
      <h2>Add a server</h2>
      <AutofillDecoys />
      {error && <div className="notice error">{error}</div>}

      <label htmlFor="label">Label</label>
      <input
        id="label"
        name="server-label"
        required
        autoComplete="off"
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        placeholder="my vps"
        {...NO_AUTOFILL}
      />

      <div className="row">
        <div style={{ flex: '3 1 200px' }}>
          <label htmlFor="host">Host</label>
          <input
            id="host"
            name="server-address"
            required
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="example.com or 203.0.113.10"
            {...NO_AUTOFILL}
          />
        </div>
        <div style={{ flex: '1 1 80px' }}>
          <label htmlFor="port">Port</label>
          <input
            id="port"
            type="number"
            min={1}
            max={65535}
            required
            value={port}
            onChange={(e) => setPort(Number(e.target.value))}
          />
        </div>
      </div>

      <label htmlFor="sshUser">SSH username</label>
      <input
        id="sshUser"
        name="shell-account"
        required
        autoComplete="off"
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
        value={sshUser}
        onChange={(e) => setSshUser(e.target.value)}
        placeholder="root"
        readOnly={userGuard.readOnly}
        onFocus={userGuard.onFocus}
        {...NO_AUTOFILL}
      />

      <label htmlFor="authMethod">Authentication</label>
      <select
        id="authMethod"
        value={authMethod}
        onChange={(e) => setAuthMethod(e.target.value as AuthMethod)}
      >
        <option value="password">Password</option>
        <option value="privatekey">Private key (unencrypted ed25519)</option>
      </select>

      {authMethod === 'password' ? (
        <>
          <label htmlFor="secret">SSH password</label>
          <input
            id="secret"
            name="shell-secret"
            type="password"
            // "new-password" rather than "off": Chrome ignores "off" on
            // password inputs, but will not fill a stored password into a
            // field claiming to be a new one.
            autoComplete="new-password"
            required
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            readOnly={secretGuard.readOnly}
            onFocus={secretGuard.onFocus}
            {...NO_AUTOFILL}
          />
          <div className="notice info">
            This is the password for <strong>{sshUser || 'the account'}</strong> on the
            server — not your SSH Tunnel password.
          </div>
        </>
      ) : (
        <>
          <label htmlFor="secret">Private key</label>
          <textarea
            id="secret"
            name="shell-secret"
            required
            autoComplete="off"
            spellCheck={false}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
            {...NO_AUTOFILL}
          />
          {/* Passphrase-protected keys need bcrypt_pbkdf, which needs runtime
              WebAssembly — unavailable in Workers. */}
          <div className="notice info">
            The key must be an <strong>unencrypted ed25519</strong> key. Passphrase-protected
            keys are not supported.
          </div>
        </>
      )}

      <div style={{ marginTop: 20 }}>
        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Saving…' : 'Save server'}
        </button>
      </div>
    </form>
  );
}
