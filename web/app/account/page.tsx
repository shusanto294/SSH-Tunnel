'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { PageLoading } from '@/components/Loading';
import TopBar from '@/components/TopBar';
import { api, type User } from '@/lib/api';

export default function AccountPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

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
      } catch {
        if (!cancelled) router.replace('/login');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  async function signOutEverywhere() {
    if (!confirm('Sign out of every browser and device, including this one?')) return;
    await api.logoutEverywhere().catch(() => {});
    router.replace('/login');
  }

  if (loading) return <PageLoading label="Loading your account" />;

  return (
    <>
      <TopBar user={user} />
      <main className="shell">
        <h1>Account</h1>
        <p className="muted">
          Signed in as {user?.email}
          {user?.isAdmin ? ' · administrator' : ''}
        </p>

        <ChangePasswordForm />

        <div className="card">
          <h2>Sessions</h2>
          <p className="muted">
            Ends every signed-in session for this account, on every device. Use it if
            you think someone else has access.
          </p>
          <button className="danger" onClick={signOutEverywhere}>
            Sign out everywhere
          </button>
        </div>

      </main>
    </>
  );
}

function ChangePasswordForm() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (newPassword !== confirm) {
      setError('The two new passwords do not match.');
      return;
    }
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      await api.changePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirm('');
      setDone(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not change the password.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h2>Change password</h2>
      {error && <div className="notice error">{error}</div>}
      {done && (
        <div className="notice info">
          Password changed. Every other session was signed out.
        </div>
      )}

      {/* The encryption key is re-wrapped with the new password, so saved
          credentials survive — worth saying, since the registration page warns
          that losing the password destroys them. */}
      <div className="notice info">
        Your saved servers keep working: their encryption key is re-wrapped with the
        new password.
      </div>

      <label htmlFor="current">Current password</label>
      <input
        id="current"
        type="password"
        autoComplete="current-password"
        required
        value={currentPassword}
        onChange={(e) => setCurrentPassword(e.target.value)}
      />

      <label htmlFor="next">New password (at least 12 characters)</label>
      <input
        id="next"
        type="password"
        autoComplete="new-password"
        minLength={12}
        required
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
      />

      <label htmlFor="confirm">Confirm new password</label>
      <input
        id="confirm"
        type="password"
        autoComplete="new-password"
        required
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
      />

      <div style={{ marginTop: 20 }}>
        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Changing…' : 'Change password'}
        </button>
      </div>
    </form>
  );
}
