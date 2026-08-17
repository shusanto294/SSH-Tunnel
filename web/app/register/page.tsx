'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  /**
   * Null until the server says whether a code is required. Starting undecided
   * rather than "required" keeps the field from flashing into view on every
   * load of an open deployment — which is all of them, unless someone closes
   * registration in wrangler.toml.
   */
  const [needsInvite, setNeedsInvite] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .config()
      .then((c) => {
        if (!cancelled) setNeedsInvite(!c.openRegistration);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (password !== confirm) {
      setError('The two passwords do not match.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.register(email, password, inviteCode || undefined);
      router.replace('/servers');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Registration failed.');
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <h1>
        SSH <span style={{ color: 'var(--accent)' }}>Tunnel</span>
      </h1>
      <p className="muted">Create an account to save and reach your own servers.</p>

      <form className="card" onSubmit={submit}>
        <h2>Register</h2>
        {error && <div className="notice error">{error}</div>}

        {/* Not a disclaimer to bury: the credential encryption key is derived
            from this password, so nobody — including the operator — can recover
            saved credentials without it. */}
        <div className="notice warn">
          Your saved SSH credentials are encrypted with a key derived from this
          password. If you forget it, those credentials cannot be recovered by
          anyone, and you will have to add your servers again.
        </div>

        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <label htmlFor="password">Password (at least 12 characters)</label>
        <input
          id="password"
          type="password"
          autoComplete="new-password"
          minLength={12}
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <label htmlFor="confirm">Confirm password</label>
        <input
          id="confirm"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />

        {needsInvite === true && (
          <>
            <label htmlFor="invite">Invite code</label>
            <input
              id="invite"
              type="text"
              required
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              placeholder="Ask an administrator for a code"
            />
          </>
        )}

        <div style={{ marginTop: 20 }}>
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Creating account…' : 'Create account'}
          </button>
        </div>
      </form>

      <p className="muted">
        Already registered? <Link href="/login">Sign in</Link>.
      </p>
    </main>
  );
}
