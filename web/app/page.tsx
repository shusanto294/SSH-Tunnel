'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';

/**
 * The public landing page.
 *
 * Signed-in visitors are not redirected away — they get a link to their servers
 * instead, so the page stays shareable and does not flash past anyone who
 * arrives with a session cookie.
 */
export default function Home() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .me()
      .then((s) => {
        if (!cancelled) setSignedIn(Boolean(s.user));
      })
      .catch(() => {
        if (!cancelled) setSignedIn(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <header className="topbar">
        <Link href="/" className="brand">
          SSH <span>Tunnel</span>
        </Link>
        <div className="topbar-right">
          <a
            href="https://github.com/shusanto294/SSH-Tunnel"
            target="_blank"
            rel="noreferrer"
            className="muted"
          >
            GitHub
          </a>
          {signedIn ? (
            <Link href="/servers">
              <button className="primary">Your servers</button>
            </Link>
          ) : (
            <>
              <Link href="/login" className="muted">
                Sign in
              </Link>
              <Link href="/register">
                <button className="primary">Get started</button>
              </Link>
            </>
          )}
        </div>
      </header>

      <main className="landing">
        <section className="hero">
          <p className="eyebrow">SSH over HTTPS</p>
          <h1>
            Your servers, from any network
            <br />
            that blocks port 22.
          </h1>
          <p className="lede">
            A real SSH terminal in your browser, tunnelled over HTTPS on port 443. Hotel
            Wi-Fi, corporate firewalls, locked-down guest networks — if a web page loads,
            you can reach your server.
          </p>
          <div className="cta">
            {signedIn ? (
              <Link href="/servers">
                <button className="primary big">Open your servers</button>
              </Link>
            ) : (
              <Link href="/register">
                <button className="primary big">Create a free account</button>
              </Link>
            )}
            <a href="#how" className="muted">
              See how it works ↓
            </a>
          </div>
          <p className="fineprint">
            Nothing to install on your server. No agent, no VPN, no browser extension.
          </p>
        </section>

        <section className="problem">
          <h2>The problem</h2>
          <div className="grid">
            <div className="tile">
              <h3>Port 22 is blocked</h3>
              <p>
                Guest Wi-Fi, school networks, and corporate firewalls routinely allow only
                ports 80 and 443. Your SSH client sits there timing out while every website
                loads fine.
              </p>
            </div>
            <div className="tile">
              <h3>You are not on your own machine</h3>
              <p>
                A borrowed laptop, a locked-down work desktop, a tablet. No terminal, no
                keys, no permission to install one — and a server that needs attention now.
              </p>
            </div>
            <div className="tile">
              <h3>The usual fixes are heavy</h3>
              <p>
                A VPN, a jump host, or an agent installed on every box. All of them are
                real infrastructure to run, secure, and remember the password for.
              </p>
            </div>
          </div>
        </section>

        <section id="how" className="how">
          <h2>How it works</h2>
          <p className="lede">
            The SSH protocol itself runs inside a Cloudflare Worker. Your browser speaks
            WebSocket over ordinary HTTPS; the Worker speaks SSH to your server. The
            firewall only ever sees port 443.
          </p>

          <pre className="diagram">{`  Your browser                            Your server
  ┌──────────────┐                        ┌──────────────┐
  │  xterm.js    │                        │    sshd      │
  └──────┬───────┘                        └──────▲───────┘
         │  WebSocket over HTTPS :443            │  SSH :22
         │  (the only port you need)             │
         ▼                                       │
  ┌─────────────────────────────────────────────┴───────┐
  │  Cloudflare Worker + Durable Object                  │
  │  verifies your session, decrypts your credential,    │
  │  runs the SSH transport, bridges the two sides       │
  └──────────────────────────────────────────────────────┘`}</pre>

          <ol className="steps">
            <li>
              <strong>Create an account.</strong> Email and password. Your account password
              also derives the key that encrypts everything you save.
            </li>
            <li>
              <strong>Add a server.</strong> Host, port, username, and either a password or
              an ed25519 private key. It is encrypted before it is stored.
            </li>
            <li>
              <strong>Confirm the host key.</strong> On the first connection you are shown
              the server&rsquo;s fingerprint. Check it, accept it, and it is pinned — any
              future change is refused.
            </li>
            <li>
              <strong>Connect.</strong> A full interactive shell, with a pty, colours, and
              resizing. It works on a phone.
            </li>
          </ol>
        </section>

        <section className="security">
          <h2>How your credentials are handled</h2>
          <div className="grid">
            <div className="tile">
              <h3>Encrypted before storage</h3>
              <p>
                Every saved credential is encrypted with a key belonging to your account
                alone. That key is itself wrapped by your password, so the database holds
                nothing usable on its own.
              </p>
            </div>
            <div className="tile">
              <h3>Only readable while you are here</h3>
              <p>
                Your encryption key lives in a cookie the page&rsquo;s own scripts cannot
                read, and is never stored on the server. A credential can be decrypted only
                during a request you made.
              </p>
            </div>
            <div className="tile">
              <h3>Host keys are pinned</h3>
              <p>
                A server&rsquo;s identity is fixed on first use, after you confirm it. If it
                ever changes, the connection stops before your password is sent.
              </p>
            </div>
          </div>

          {/* Better said plainly here than discovered later. */}
          <div className="honest">
            <h3>What this does not protect against</h3>
            <p>
              Encryption at rest defends against a stolen database copy. It cannot defend
              against whoever runs the deployment: an operator who compromises the Worker
              can read the credentials of anyone who signs in afterwards. That is true of
              every hosted terminal, and it is worth knowing before you paste a root
              password anywhere. If that matters to you,{' '}
              <a
                href="https://github.com/shusanto294/SSH-Tunnel"
                target="_blank"
                rel="noreferrer"
              >
                the source is open
              </a>{' '}
              — run your own copy, and use per-user accounts on your servers rather than
              shared root credentials.
            </p>
          </div>
        </section>

        <section className="specs">
          <h2>What it supports</h2>
          <div className="spec-grid">
            <div>
              <dl>
                <dt>Key exchange</dt>
                <dd>curve25519-sha256</dd>
                <dt>Host keys</dt>
                <dd>ssh-ed25519</dd>
                <dt>Cipher</dt>
                <dd>aes256-gcm@openssh.com</dd>
                <dt>Authentication</dt>
                <dd>password, or unencrypted ed25519 key</dd>
              </dl>
            </div>
            <div className="notes">
              <p>
                One option per layer, on purpose — every one is a modern default that
                OpenSSH has shipped since 6.5, and the short list keeps the crypto small
                enough to run inside a Worker.
              </p>
              <p className="muted">
                Passphrase-protected private keys are not supported: unlocking them needs a
                key-derivation function the runtime cannot provide. Use a password, or an
                unencrypted key generated for this purpose.
              </p>
            </div>
          </div>
        </section>

        <section className="closing">
          <h2>Reach your servers from anywhere</h2>
          <p className="lede">
            Takes about a minute to set up. Add a server, confirm its fingerprint, and
            you have a terminal.
          </p>
          <div className="cta">
            {signedIn ? (
              <Link href="/servers">
                <button className="primary big">Open your servers</button>
              </Link>
            ) : (
              <Link href="/register">
                <button className="primary big">Create a free account</button>
              </Link>
            )}
          </div>
        </section>

        <footer className="site-footer">
          <span className="muted">SSH Tunnel — a browser SSH client on Cloudflare Workers</span>
          <a href="https://github.com/shusanto294/SSH-Tunnel" target="_blank" rel="noreferrer">
            Source on GitHub
          </a>
        </footer>
      </main>
    </>
  );
}
