/**
 * Account endpoints: register, login, logout, password change.
 *
 * Two habits run through this file. Failure messages never distinguish "no such
 * account" from "wrong password", and the unknown-account path still performs a
 * full PBKDF2 derivation so that response time does not leak the difference.
 */
import type { Env } from '../env';
import type { AuthContext } from '../auth/context';
import { createDek, unwrapDek, wrapDek } from '../auth/dek';
import { hashPassword, needsRehash, pbkdf2, validatePassword, verifyPassword } from '../auth/password';
import {
  authCookies,
  clearedCookies,
  createSession,
  destroyAllSessions,
  destroySession,
} from '../auth/session';
import { audit } from '../db/audit';
import { redeemInvite } from '../db/invites';
import * as users from '../db/users';
import { LIMITS, blockStatus, clientKey, pardon, rateLimit, rateLimitReset, strike } from '../rate-limit';
import { BREACHED_MESSAGE, isBreachedPassword } from '../auth/breach';
import { randomBytes } from '../util/encoding';
import { email as parseEmail, fail, json, readJson, str } from './http';

const GENERIC_LOGIN_FAILURE = 'Email or password is incorrect.';

interface RegisterBody {
  email?: unknown;
  password?: unknown;
  inviteCode?: unknown;
}

export async function register(request: Request, env: Env): Promise<Response> {
  const gate = await rateLimit(env, `register:${clientKey(request)}`, LIMITS.register);
  if (!gate.allowed) return tooMany(gate.retryAfter);

  const body = await readJson<RegisterBody>(request);
  if (!body) return fail(400, 'Expected a JSON body.');

  const address = parseEmail(body.email);
  if (!address) return fail(400, 'Enter a valid email address.');
  if (typeof body.password !== 'string') return fail(400, 'A password is required.');

  const problem = validatePassword(body.password);
  if (problem) return fail(400, problem.message);
  if (await isBreachedPassword(body.password)) return fail(400, BREACHED_MESSAGE);

  // Bootstrap: an empty deployment has nobody who could mint an invite, so the
  // very first account is allowed through and becomes the administrator.
  const isFirstAccount = (await users.countUsers(env)) === 0;
  const open = env.OPEN_REGISTRATION === 'true' || isFirstAccount;
  const inviteCode = str(body.inviteCode, 128);
  if (!open && !inviteCode) return fail(403, 'An invite code is required to register.');

  if (await users.findByEmail(env, address)) {
    // Registration cannot hide that an address is taken, but it can avoid
    // saying so in a way that reads as confirmation of an account's existence.
    return fail(409, 'That email address cannot be used to register.');
  }

  const password = await hashPassword(body.password);
  const { dek, record } = await createDek(body.password);
  const user = await users.createUser(env, address, password, record, isFirstAccount);

  if (!open && inviteCode) {
    // Claimed after the account exists so the code is tied to a real user, and
    // rolled back if the claim loses a race with another registration.
    const claimed = await redeemInvite(env, inviteCode, user.id);
    if (!claimed) {
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
      return fail(403, 'That invite code is not valid.');
    }
  }

  const token = await createSession(env, user.id);
  await audit(env, user.id, 'register');
  return json(
    { user: { id: user.id, email: user.email, isAdmin: user.isAdmin } },
    201,
    authCookies(token, dek),
  );
}

interface LoginBody {
  email?: unknown;
  password?: unknown;
}

export async function login(request: Request, env: Env): Promise<Response> {
  const ipGate = await rateLimit(env, `login:${clientKey(request)}`, LIMITS.login);
  if (!ipGate.allowed) return tooMany(ipGate.retryAfter);

  const body = await readJson<LoginBody>(request);
  if (!body) return fail(400, 'Expected a JSON body.');

  const address = parseEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  if (!address || password.length === 0) return fail(401, GENERIC_LOGIN_FAILURE);

  // Limits keyed on the account as well as the address, so rotating IPs — a
  // botnet, or anyone with a proxy pool — does not buy extra attempts against
  // one person's password.
  const accountKey = `login:acct:${address.toLowerCase()}`;
  const accountLock = await blockStatus(env, accountKey);
  if (accountLock.blocked) return tooMany(accountLock.retryAfter);

  const accountGate = await rateLimit(env, accountKey, LIMITS.login);
  if (!accountGate.allowed) {
    await strike(env, accountKey, 5);
    return tooMany(accountGate.retryAfter);
  }

  const user = await users.findByEmail(env, address);
  if (!user || user.disabled) {
    await burnEquivalentTime(password);
    await strike(env, accountKey, 2);
    await audit(env, null, 'login_failed');
    return fail(401, GENERIC_LOGIN_FAILURE);
  }

  if (!(await verifyPassword(password, user.password))) {
    await strike(env, accountKey, 2);
    await audit(env, user.id, 'login_failed');
    return fail(401, GENERIC_LOGIN_FAILURE);
  }

  const dek = await unwrapDek(password, user.dek);
  if (!dek) {
    // The verifier matched but the wrapped DEK did not open: the row is
    // inconsistent. Refusing is the only safe response.
    return fail(500, 'This account needs attention. Contact the administrator.');
  }

  // Transparently strengthen accounts hashed under an older iteration count.
  if (needsRehash(user.password)) {
    await users.updateCredentials(env, user.id, await hashPassword(password), await wrapDek(dek, password));
  }

  // A correct password proves this was not an attack on this account, so both
  // the window and the accumulated strikes are cleared.
  const token = await createSession(env, user.id);
  await rateLimitReset(env, accountKey);
  await pardon(env, accountKey);
  await audit(env, user.id, 'login');
  return json(
    { user: { id: user.id, email: user.email, isAdmin: user.isAdmin } },
    200,
    authCookies(token, dek),
  );
}

export async function logout(env: Env, auth: AuthContext): Promise<Response> {
  await destroySession(env, auth.token);
  await audit(env, auth.userId, 'logout');
  return json({ ok: true }, 200, clearedCookies());
}

export async function logoutEverywhere(env: Env, auth: AuthContext): Promise<Response> {
  await destroyAllSessions(env, auth.userId);
  await audit(env, auth.userId, 'logout', 'all sessions');
  return json({ ok: true }, 200, clearedCookies());
}

export async function me(env: Env, auth: AuthContext): Promise<Response> {
  const user = await users.findById(env, auth.userId);
  if (!user) return json({ user: null }, 401, clearedCookies());
  return json({
    user: { id: user.id, email: user.email, isAdmin: user.isAdmin },
    /** False when the DEK cookie was lost — saved servers cannot be opened. */
    canDecrypt: auth.dek !== null,
  });
}

interface ChangePasswordBody {
  currentPassword?: unknown;
  newPassword?: unknown;
}

export async function changePassword(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  const body = await readJson<ChangePasswordBody>(request);
  if (!body) return fail(400, 'Expected a JSON body.');
  if (typeof body.currentPassword !== 'string' || typeof body.newPassword !== 'string') {
    return fail(400, 'Both the current and new password are required.');
  }
  const problem = validatePassword(body.newPassword);
  if (problem) return fail(400, problem.message);
  if (await isBreachedPassword(body.newPassword)) return fail(400, BREACHED_MESSAGE);

  const user = await users.findById(env, auth.userId);
  if (!user) return fail(401, 'Not signed in.');
  if (!(await verifyPassword(body.currentPassword, user.password))) {
    return fail(401, 'Current password is incorrect.');
  }

  // Re-wrapping the same DEK is what keeps saved servers readable across a
  // password change. Rotating the DEK instead would orphan every secret.
  const dek = await unwrapDek(body.currentPassword, user.dek);
  if (!dek) return fail(500, 'This account needs attention. Contact the administrator.');

  await users.updateCredentials(
    env,
    user.id,
    await hashPassword(body.newPassword),
    await wrapDek(dek, body.newPassword),
  );
  await destroyAllSessions(env, user.id);
  const token = await createSession(env, user.id);
  await audit(env, user.id, 'password_changed');
  return json({ ok: true }, 200, authCookies(token, dek));
}

function tooMany(retryAfter: number): Response {
  return new Response(JSON.stringify({ error: 'Too many attempts. Try again shortly.' }), {
    status: 429,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'retry-after': String(retryAfter),
      'cache-control': 'no-store',
    },
  });
}

/**
 * Spend roughly the same CPU on an unknown address as a real verification
 * would, so timing does not answer "is this person registered here?".
 */
async function burnEquivalentTime(password: string): Promise<void> {
  const record = await hashPassword('');
  await pbkdf2(password, record.salt.length > 0 ? record.salt : randomBytes(16), record.iters, 32);
}
