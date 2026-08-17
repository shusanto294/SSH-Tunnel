/**
 * Thin client for the Worker's API.
 *
 * Authentication rides on HttpOnly cookies, so there is no token to store and
 * nothing here ever touches localStorage. `credentials: 'same-origin'` is what
 * makes the cookies travel.
 */

export interface User {
  id: string;
  email: string;
  isAdmin: boolean;
}

export type AuthMethod = 'password' | 'privatekey';

export interface Server {
  id: string;
  label: string;
  host: string;
  port: number;
  sshUser: string;
  authMethod: AuthMethod;
  hostKeyFingerprint: string | null;
  createdAt: number;
  lastUsedAt: number | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: {
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...init.headers,
    },
  });

  const text = await response.text();
  let body: Record<string, unknown> = {};
  if (text) {
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // An edge error page is HTML, not JSON. Report the status rather than
      // letting a parse error surface as "Unexpected token '<'".
      throw new ApiError(`The server returned an unexpected response (${response.status}).`, response.status);
    }
  }
  if (!response.ok) {
    const message = typeof body.error === 'string' ? body.error : 'Something went wrong.';
    throw new ApiError(message, response.status);
  }
  return body as T;
}

export const api = {
  config() {
    return call<{ openRegistration: boolean }>('config');
  },

  register(email: string, password: string, inviteCode?: string) {
    return call<{ user: User }>('auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, inviteCode }),
    });
  },

  login(email: string, password: string) {
    return call<{ user: User }>('auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  logout() {
    return call<{ ok: true }>('auth/logout', { method: 'POST' });
  },

  logoutEverywhere() {
    return call<{ ok: true }>('auth/logout-everywhere', { method: 'POST' });
  },

  me() {
    return call<{ user: User | null; canDecrypt: boolean }>('auth/me');
  },

  changePassword(currentPassword: string, newPassword: string) {
    return call<{ ok: true }>('auth/password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  },

  listServers() {
    return call<{ servers: Server[] }>('servers');
  },

  createServer(input: {
    label: string;
    host: string;
    port: number;
    sshUser: string;
    authMethod: AuthMethod;
    secret: string;
  }) {
    return call<{ server: Server }>('servers', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  updateServer(id: string, patch: Record<string, unknown>) {
    return call<{ server: Server }>(`servers/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    });
  },

  deleteServer(id: string) {
    return call<{ ok: true }>(`servers/${id}`, { method: 'DELETE' });
  },

  createInvite() {
    return call<{ invite: { code: string; expiresAt: number | null } }>('invites', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  },
};
