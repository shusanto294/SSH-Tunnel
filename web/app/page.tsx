'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Loading } from '@/components/Loading';
import { api } from '@/lib/api';

/** Landing page: send people to their servers, or to sign in. */
export default function Home() {
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;
    api
      .me()
      .then(() => {
        if (!cancelled) router.replace('/servers');
      })
      .catch(() => {
        if (!cancelled) router.replace('/login');
      });
    return () => {
      cancelled = true;
    };
  }, [router]);

  // No header here: this page only decides where to send you, and showing
  // signed-in chrome to someone about to land on /login would be a lie.
  return (
    <main className="shell">
      <Loading />
    </main>
  );
}
