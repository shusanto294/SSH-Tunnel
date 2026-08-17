'use client';

import { Suspense } from 'react';
import dynamic from 'next/dynamic';
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
  const serverId = params.get('server');

  if (!serverId) {
    return (
      <>
        <TopBar />
        <main className="shell">
          <div className="notice error">No server was specified.</div>
        </main>
      </>
    );
  }
  return <TerminalView serverId={serverId} />;
}

export default function TerminalPage() {
  // useSearchParams needs a Suspense boundary under static export.
  return (
    <Suspense fallback={<PageLoading label="Loading terminal" />}>
      <TerminalPageInner />
    </Suspense>
  );
}
