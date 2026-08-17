import type { Metadata, Viewport } from 'next';
import '@xterm/xterm/css/xterm.css';
import './globals.css';

export const metadata: Metadata = {
  title: 'SSH Tunnel — SSH from your browser, over HTTPS',
  description:
    'A real SSH terminal in your browser, tunnelled over HTTPS on port 443. Reach your ' +
    'servers from networks that block port 22 — no agent, no VPN, nothing to install.',
  openGraph: {
    title: 'SSH Tunnel — SSH from your browser, over HTTPS',
    description:
      'Reach your servers from any network that blocks port 22. A browser SSH client ' +
      'running on Cloudflare Workers.',
    type: 'website',
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  // The terminal sizes itself to the visual viewport; letting the page zoom
  // fights the fit addon on a phone.
  maximumScale: 1,
  themeColor: '#0b0d10',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
