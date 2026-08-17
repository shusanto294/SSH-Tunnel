'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(email, password);
      router.replace('/servers');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Sign in failed.');
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <h1>
        SSH <span style={{ color: 'var(--accent)' }}>Tunnel</span>
      </h1>
      <p className="muted">Sign in to reach your servers.</p>

      <form className="card" onSubmit={submit}>
        <h2>Sign in</h2>
        {error && <div className="notice error">{error}</div>}

        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <div style={{ marginTop: 20 }}>
          <button className="primary" type="submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </div>
      </form>

      <p className="muted">
        No account yet? <Link href="/register">Create one</Link>.
      </p>
    </main>
  );
}
