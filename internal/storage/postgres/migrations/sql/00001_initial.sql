-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind = 'email'),
    normalized_value TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, normalized_value),
    UNIQUE (user_id, kind)
);

CREATE TABLE auth_clients (
    id TEXT PRIMARY KEY,
    audience TEXT NOT NULL UNIQUE,
    refresh_cookie_name TEXT NOT NULL UNIQUE,
    allowed_origins TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE verification_challenges (
    id UUID PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES auth_clients(id),
    purpose TEXT NOT NULL CHECK (purpose IN ('register', 'reset')),
    kind TEXT NOT NULL CHECK (kind = 'email'),
    normalized_identifier TEXT NOT NULL,
    identifier_hash BYTEA NOT NULL,
    code_mac BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    source_ip_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX verification_identifier_rate_idx
    ON verification_challenges (client_id, kind, normalized_identifier, created_at DESC);
CREATE INDEX verification_ip_rate_idx
    ON verification_challenges (source_ip_hash, created_at DESC);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES auth_clients(id),
    refresh_token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT NOT NULL DEFAULT '',
    source_ip_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_idx ON sessions (user_id, created_at DESC);
CREATE INDEX sessions_active_idx ON sessions (id, client_id) WHERE revoked_at IS NULL;

CREATE TABLE auth_events (
    id UUID PRIMARY KEY,
    user_id UUID,
    client_id TEXT REFERENCES auth_clients(id),
    session_id UUID,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    identifier_hash BYTEA,
    source_ip_hash BYTEA NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX auth_events_user_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX auth_events_type_idx ON auth_events (event_type, created_at DESC);

INSERT INTO auth_clients (id, audience, refresh_cookie_name, allowed_origins) VALUES
    ('jobpilot', 'jobpilot', 'jp_refresh', ARRAY['http://127.0.0.1:5173', 'http://localhost:5173']),
    ('studyflow', 'studyflow', 'sf_refresh', ARRAY['http://127.0.0.1:5174', 'http://localhost:5174']);

-- +goose Down
DROP TABLE IF EXISTS auth_events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS verification_challenges;
DROP TABLE IF EXISTS auth_clients;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS users;
