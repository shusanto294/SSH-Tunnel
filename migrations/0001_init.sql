-- SSH Tunnel initial schema.
--
-- Credential model: a per-user data encryption key (DEK) is wrapped with a key
-- derived from the user's password. Saved SSH secrets are encrypted under the
-- DEK. A stolen copy of this database therefore contains no usable SSH
-- credentials on its own — see the security section of README.md.

CREATE TABLE users (
  id          TEXT    PRIMARY KEY,
  email       TEXT    NOT NULL,
  email_lower TEXT    NOT NULL UNIQUE,
  -- PBKDF2-HMAC-SHA256 login verifier
  pw_hash     BLOB    NOT NULL,
  pw_salt     BLOB    NOT NULL,
  pw_iters    INTEGER NOT NULL,
  -- DEK wrapped with a key derived from the password using a SEPARATE salt
  dek_wrapped BLOB    NOT NULL,
  dek_iv      BLOB    NOT NULL,
  dek_salt    BLOB    NOT NULL,
  dek_iters   INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  disabled    INTEGER NOT NULL DEFAULT 0,
  -- The first account created becomes admin; admins are the only ones who can
  -- mint invite codes.
  is_admin    INTEGER NOT NULL DEFAULT 0
);

-- Only SHA-256(token) is stored; the token itself lives in the client cookie.
CREATE TABLE sessions (
  token_hash   BLOB    PRIMARY KEY,
  user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_expiry_idx ON sessions(expires_at);

CREATE TABLE servers (
  id           TEXT    PRIMARY KEY,
  user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label        TEXT    NOT NULL,
  host         TEXT    NOT NULL,
  port         INTEGER NOT NULL DEFAULT 22,
  ssh_user     TEXT    NOT NULL,
  -- 'password' or 'privatekey'
  auth_method  TEXT    NOT NULL,
  -- AES-GCM under the owner's DEK. Never plaintext, never logged.
  secret_ct    BLOB    NOT NULL,
  secret_iv    BLOB    NOT NULL,
  -- Pinned host key, e.g. "SHA256:...". NULL means the next connection must
  -- present the fingerprint to the user for explicit confirmation.
  host_key_fp  TEXT,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX servers_user_idx ON servers(user_id);

-- Single-use registration invites. Only the hash of the code is stored.
CREATE TABLE invites (
  code_hash  BLOB    PRIMARY KEY,
  created_by TEXT    REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  used_by    TEXT    REFERENCES users(id) ON DELETE SET NULL,
  used_at    INTEGER
);

-- Security-relevant events. Never contains secret material.
CREATE TABLE audit (
  id      TEXT    PRIMARY KEY,
  user_id TEXT    REFERENCES users(id) ON DELETE SET NULL,
  ts      INTEGER NOT NULL,
  action  TEXT    NOT NULL,
  detail  TEXT
);
CREATE INDEX audit_user_idx ON audit(user_id, ts);
