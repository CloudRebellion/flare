package oidcprelink

// Exact relevant Up statements from native migrations001/011/012/016/022.
// Test fixtures never invoke server startup or live migrations.
const fixtureDDL = `-- +goose Up
CREATE TABLE orgs (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'member',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_users_org ON users (org_id);

CREATE TABLE projects (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL,
    platform   TEXT NOT NULL DEFAULT 'other',
    public_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug)
);
CREATE INDEX idx_projects_org ON projects (org_id);

CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    key_prefix   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX idx_api_keys_org ON api_keys (org_id);

-- alexedwards/scs/pgxstore session store table.
CREATE TABLE sessions (
    token  TEXT PRIMARY KEY,
    data   BYTEA NOT NULL,
    expiry TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expiry);


-- +goose Up
-- Append-only audit trail of sensitive actions (who did what, when).
-- actor_user_id is nullable (NULL for API-key actions) and has NO FK to users:
-- the trail must survive the actor being removed.
CREATE TABLE audit_log (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    actor_user_id TEXT,
    action        TEXT NOT NULL,
    target        TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_org ON audit_log (org_id, created_at DESC);


-- +goose Up
-- Per-org OIDC single sign-on config. The client_secret is admin-set and never
-- returned by the API. default_role is the role a just-in-time provisioned user
-- gets on first SSO login.
CREATE TABLE oidc_config (
    org_id        TEXT PRIMARY KEY REFERENCES orgs (id) ON DELETE CASCADE,
    issuer        TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    default_role  TEXT NOT NULL DEFAULT 'member',
    enabled       BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- +goose Up
-- Sessions whose auth_epoch predates this instant are rejected. Bumped on a
-- password reset so an attacker's already-active session is revoked when the
-- legitimate owner recovers the account (the reset-token invalidation alone
-- does not kill a session established before the reset).
ALTER TABLE users ADD COLUMN sessions_valid_from timestamptz NOT NULL DEFAULT now();


-- +goose Up
-- Bind a user to the IdP identity that signed them in.
--
-- Matching an SSO login to an account by EMAIL ALONE means whoever controls the
-- org's IdP config can assert any email and be signed in as that user, including
-- the org owner. Pairing SSO config with owner-only access closes the
-- admin -> owner path; this binding closes the rest: once an account has signed
-- in through a given issuer+subject, only that same issuer+subject can ever
-- match it again, so re-pointing SSO at a different IdP cannot take over
-- existing accounts.
--
-- Empty string = not yet linked. The first SSO sign-in links the account.
ALTER TABLE users ADD COLUMN sso_issuer  TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN sso_subject TEXT NOT NULL DEFAULT '';

-- A given IdP subject maps to at most one account per issuer.
CREATE UNIQUE INDEX idx_users_sso_identity
    ON users (sso_issuer, sso_subject)
    WHERE sso_subject <> '';

`
