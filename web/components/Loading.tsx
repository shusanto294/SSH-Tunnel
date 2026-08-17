'use client';

import TopBar from '@/components/TopBar';

/** A spinner with a label, sized to sit inside a page's content area. */
export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

/**
 * The whole-page loading state. The header renders straight away and only the
 * content area waits, so a page never appears without its chrome.
 */
export function PageLoading({ label }: { label?: string }) {
  return (
    <>
      <TopBar />
      <main className="shell">
        <Loading label={label} />
      </main>
    </>
  );
}
