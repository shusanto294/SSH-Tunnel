'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api, type User } from '@/lib/api';

/**
 * The header shown on every signed-in page. It renders immediately, before any
 * data arrives, so navigating swaps only the page content and the chrome stays
 * put.
 *
 * There is no nav menu: the brand goes home, and the email address doubles as
 * the way into account settings.
 */
export default function TopBar({
  user,
  children,
}: {
  user?: User | null;
  /** Page-specific content shown just before the account controls. */
  children?: React.ReactNode;
}) {
  const router = useRouter();

  async function signOut() {
    await api.logout().catch(() => {});
    router.replace('/login');
  }

  return (
    <div className="topbar">
      <Link href="/servers" className="brand" aria-label="SSH Tunnel home">
        SSH <span>Tunnel</span>
      </Link>

      <div className="topbar-right">
        {children}
        {user && (
          <Link href="/account" className="muted email" title="Account settings">
            {user.email}
          </Link>
        )}
        <button onClick={signOut}>Sign out</button>
      </div>
    </div>
  );
}
