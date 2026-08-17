import type { Metadata, Viewport } from 'next';
import '@xterm/xterm/css/xterm.css';
import './globals.css';

export const metadata: Metadata = {
  title: 'SSH Tunnel',
  description: 'A browser-based SSH client that reaches your servers over HTTPS.',
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
