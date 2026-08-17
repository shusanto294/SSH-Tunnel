import type { Env } from '../env';
import type { WrappedDek } from '../auth/dek';
import type { PasswordRecord } from '../auth/password';
import { newId, nowSeconds, toBytes } from '../util/encoding';

export interface User {
  id: string;
  email: string;
  disabled: boolean;
  isAdmin: boolean;
  password: PasswordRecord;
  dek: WrappedDek;
}

interface UserRow {
  id: string;
  email: string;
  disabled: number;
  is_admin: number;
  pw_hash: unknown;
  pw_salt: unknown;
  pw_iters: number;
  dek_wrapped: unknown;
  dek_iv: unknown;
  dek_salt: unknown;
  dek_iters: number;
}

const SELECT = `SELECT id, email, disabled, is_admin, pw_hash, pw_salt, pw_iters,
                       dek_wrapped, dek_iv, dek_salt, dek_iters
                FROM users`;

function hydrate(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    disabled: row.disabled !== 0,
    isAdmin: row.is_admin !== 0,
    password: {
      hash: toBytes(row.pw_hash),
      salt: toBytes(row.pw_salt),
      iters: row.pw_iters,
    },
    dek: {
      wrapped: toBytes(row.dek_wrapped),
      iv: toBytes(row.dek_iv),
      salt: toBytes(row.dek_salt),
      iters: row.dek_iters,
    },
  };
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function findByEmail(env: Env, email: string): Promise<User | null> {
  const row = await env.DB.prepare(`${SELECT} WHERE email_lower = ?`)
    .bind(normalizeEmail(email))
    .first<UserRow>();
  return row ? hydrate(row) : null;
}

export async function findById(env: Env, id: string): Promise<User | null> {
  const row = await env.DB.prepare(`${SELECT} WHERE id = ?`).bind(id).first<UserRow>();
  return row ? hydrate(row) : null;
}

export async function countUsers(env: Env): Promise<number> {
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first<{ n: number }>();
  return row?.n ?? 0;
}

export async function createUser(
  env: Env,
  email: string,
  password: PasswordRecord,
  dek: WrappedDek,
  isAdmin: boolean,
): Promise<User> {
  const id = newId();
  await env.DB.prepare(
    `INSERT INTO users (id, email, email_lower, pw_hash, pw_salt, pw_iters,
                        dek_wrapped, dek_iv, dek_salt, dek_iters, created_at,
                        disabled, is_admin)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
  )
    .bind(
      id,
      email.trim(),
      normalizeEmail(email),
      password.hash,
      password.salt,
      password.iters,
      dek.wrapped,
      dek.iv,
      dek.salt,
      dek.iters,
      nowSeconds(),
      isAdmin ? 1 : 0,
    )
    .run();
  return { id, email: email.trim(), disabled: false, isAdmin, password, dek };
}

/** Used both on password change and on transparent re-hash at a higher cost. */
export async function updateCredentials(
  env: Env,
  userId: string,
  password: PasswordRecord,
  dek: WrappedDek,
): Promise<void> {
  await env.DB.prepare(
    `UPDATE users SET pw_hash = ?, pw_salt = ?, pw_iters = ?,
                      dek_wrapped = ?, dek_iv = ?, dek_salt = ?, dek_iters = ?
     WHERE id = ?`,
  )
    .bind(
      password.hash,
      password.salt,
      password.iters,
      dek.wrapped,
      dek.iv,
      dek.salt,
      dek.iters,
      userId,
    )
    .run();
}
