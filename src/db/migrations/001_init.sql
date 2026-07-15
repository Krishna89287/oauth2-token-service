CREATE TABLE IF NOT EXISTS clients (
    id                TEXT PRIMARY KEY,
    name              TEXT        NOT NULL,
    -- Null for a public client. A mobile app or a single page app cannot keep a
    -- secret, so it gets none and leans on PKCE instead of pretending otherwise.
    secret_hash       TEXT,
    redirect_uris     TEXT[]      NOT NULL DEFAULT '{}',
    allowed_scopes    TEXT[]      NOT NULL DEFAULT '{}',
    allowed_grants    TEXT[]      NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash             TEXT PRIMARY KEY,
    client_id             TEXT        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    user_id               TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri          TEXT        NOT NULL,
    scope                 TEXT        NOT NULL,
    code_challenge        TEXT        NOT NULL,
    code_challenge_method TEXT        NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    -- An authorization code is single use. Rather than delete it on redemption we
    -- mark it, so that a second attempt is a detectable event and not just a
    -- missing row that looks the same as a typo.
    consumed_at           TIMESTAMPTZ,
    -- The refresh family this code produced, so that a replayed code can revoke
    -- the tokens it already handed out. RFC 6749 4.1.2 asks for this.
    issued_family_id      TEXT
);

CREATE INDEX IF NOT EXISTS authorization_codes_expires_idx ON authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash  TEXT PRIMARY KEY,
    -- Every refresh token minted from one login shares a family id. Rotation
    -- issues a new token in the same family, so if an old one is ever replayed we
    -- can revoke the whole chain rather than just the token that leaked.
    family_id   TEXT        NOT NULL,
    client_id   TEXT        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    user_id     TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scope       TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_idx ON refresh_tokens (expires_at);
