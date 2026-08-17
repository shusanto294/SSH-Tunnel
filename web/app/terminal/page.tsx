'use client';

import { Suspense } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { PageLoading } from '@/components/Loading';
import TopBar from '@/components/TopBar';

// xterm touches the DOM at module load, so it must never be evaluated during
// the build's prerender pass. Its own header comes with it, so the fallback
// carries one too and the chrome does not flicker in and out.
const TerminalView = dynamic(() => import('@/components/TerminalView'), {
  ssr: false,
  loading: () => <PageLoading label="Loading terminal" />,
});

function TerminalPageInner() {
  const params = useSearchParams();
  // The session is provisioned before navigating here, so this page carries a
  // ticket rather than a target — and never a credential.
  const ticket = params.get('ticket');
  const serverId = params.get('server') ?? undefined;

  if (!ticket) {
    return (
      <>
        <TopBar />
        <main className="shell">
          <div className="notice error">
            No session to open. Start one from your servers.
          </div>
          <p>
            <Link href="/servers">Back to servers</Link>
          </p>
        </main>
      </>
    );
  }
  return <TerminalView ticket={ticket} serverId={serverId} />;
}

export default function TerminalPage() {
  // useSearchParams needs a Suspense boundary under static export.
  return (
    <Suspense fallback={<PageLoading label="Loading terminal" />}>
      <TerminalPageInner />
    </Suspense>
  );
}
