'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import TopBar from '@/components/TopBar';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { Terminal } from '@xterm/xterm';
import { api } from '@/lib/api';

type Status = 'connecting' | 'connected' | 'closed';

interface ServerMessage {
  type: 'status' | 'hostkey' | 'hostkey-accepted' | 'hostkey-mismatch' | 'error';
  state?: Status;
  fingerprint?: string;
  message?: string;
}

const THEME = {
  background: '#000000',
  foreground: '#d7dee7',
  cursor: '#4ade80',
  selectionBackground: '#264f3a',
};

export default function TerminalView({ serverId }: { serverId: string }) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const socketRef = useRef<WebSocket | null>(null);

  const [status, setStatus] = useState<Status>('connecting');
  const [error, setError] = useState<string | null>(null);
  const [pendingFingerprint, setPendingFingerprint] = useState<string | null>(null);
  const [mismatch, setMismatch] = useState<string | null>(null);
  const [generation, setGeneration] = useState(0);

  const send = useCallback((message: unknown) => {
    const socket = socketRef.current;
    if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
  }, []);

  // One effect owns the terminal and the socket for a given connection
  // attempt. Bumping `generation` tears the whole thing down and rebuilds it,
  // which is what the manual reconnect button does.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const term = new Terminal({
      convertEol: false,
      cursorBlink: true,
      fontFamily:
        "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace",
      fontSize: 13,
      theme: THEME,
      scrollback: 5000,
      // Keeps the on-screen keyboard usable on iOS.
      macOptionIsMeta: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(host);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    setStatus('connecting');
    setError(null);
    setPendingFingerprint(null);
    setMismatch(null);

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/ws?server=${encodeURIComponent(
      serverId,
    )}&cols=${term.cols}&rows=${term.rows}`;
    const socket = new WebSocket(url);
    socket.binaryType = 'arraybuffer';
    socketRef.current = socket;

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const keystrokes = term.onData((data) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(encoder.encode(data));
    });

    socket.addEventListener('message', (event) => {
      // Binary frames are terminal output; text frames are control messages.
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
        return;
      }
      let message: ServerMessage;
      try {
        message = JSON.parse(String(event.data)) as ServerMessage;
      } catch {
        return;
      }

      switch (message.type) {
        case 'status':
          if (message.state) setStatus(message.state);
          break;
        case 'hostkey':
          setPendingFingerprint(message.fingerprint ?? null);
          break;
        case 'hostkey-accepted':
          // Pin it, so any later change in the server's key is refused.
          if (message.fingerprint) {
            void api
              .updateServer(serverId, { hostKeyFingerprint: message.fingerprint })
              .catch(() => {});
          }
          break;
        case 'hostkey-mismatch':
          setMismatch(message.fingerprint ?? null);
          break;
        case 'error':
          setError(message.message ?? 'The session ended with an error.');
          break;
      }
    });

    socket.addEventListener('close', () => setStatus('closed'));
    socket.addEventListener('error', () => setStatus('closed'));

    // Debounced so a drag-resize does not send a message per animation frame.
    let resizeTimer: number | undefined;
    const observer = new ResizeObserver(() => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        try {
          fit.fit();
        } catch {
          /* the element may be detached mid-teardown */
        }
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
        }
      }, 150);
    });
    observer.observe(host);

    return () => {
      window.clearTimeout(resizeTimer);
      observer.disconnect();
      keystrokes.dispose();
      // Closing the socket is what tells the Durable Object to drop the TCP
      // connection; leaving it open would strand a live SSH session.
      socket.close();
      term.dispose();
      socketRef.current = null;
      termRef.current = null;
      fitRef.current = null;
      void decoder;
    };
  }, [serverId, generation]);

  /**
   * Clears the saved pin and reconnects. Deliberately does NOT save the new key
   * on the way through: the reconnect runs the ordinary first-contact flow, so
   * the new fingerprint still has to be looked at and accepted.
   */
  async function forgetHostKey() {
    try {
      await api.updateServer(serverId, { hostKeyFingerprint: null });
      setMismatch(null);
      setError(null);
      setGeneration((n) => n + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not clear the saved host key.');
    }
  }

  function answerHostKey(accept: boolean) {
    send({ type: 'confirm-hostkey', accept });
    setPendingFingerprint(null);
    if (!accept) setError('Host key was not accepted, so the connection was refused.');
  }

  return (
    <div className="terminal-page">
      <TopBar>
        <span className={`status status-${status}`}>{status}</span>
      </TopBar>

      {pendingFingerprint && (
        <div className="banner warn">
          <div>
            First connection to this server. Its host key fingerprint is{' '}
            <strong style={{ wordBreak: 'break-all' }}>{pendingFingerprint}</strong>. Accept it only
            if it matches what your server reports from{' '}
            <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>.
          </div>
          <div className="row" style={{ flex: '0 0 auto' }}>
            <button className="primary" onClick={() => answerHostKey(true)}>
              Accept and pin
            </button>
            <button className="danger" onClick={() => answerHostKey(false)}>
              Refuse
            </button>
          </div>
        </div>
      )}

      {mismatch && (
        <div className="banner error">
          <div>
            The server is presenting a different host key:{' '}
            <strong style={{ wordBreak: 'break-all' }}>{mismatch}</strong>. If you rebuilt or
            reinstalled this machine, that is expected. If you did not, stop — something may be
            impersonating it.
          </div>
          <div className="row" style={{ flex: '0 0 auto' }}>
            <button className="danger" onClick={forgetHostKey}>
              I rebuilt this server — forget the old key
            </button>
          </div>
        </div>
      )}

      {error && !mismatch && <div className="banner error">{error}</div>}

      {status === 'closed' && (
        <div className="banner">
          <span>The session has ended.</span>
          {/* Manual reconnect only — an automatic retry loop against an SSH
              server is a good way to get an IP banned. */}
          <button className="primary" onClick={() => setGeneration((n) => n + 1)}>
            Reconnect
          </button>
        </div>
      )}

      <div className="terminal-host" ref={hostRef} />
    </div>
  );
}
