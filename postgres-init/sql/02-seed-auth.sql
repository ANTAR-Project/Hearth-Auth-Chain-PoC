CREATE TYPE user_role AS ENUM ('OWNER', 'RESIDENT', 'GUEST');
CREATE TYPE user_status AS ENUM ('ACTIVE', 'SUSPENDED');

-- ── users ────────────────────────────────────────────────────────────────────
-- Matches User.java:
--   @Id UUID, username VARCHAR(32), password_hash TEXT,
--   role user_role, status user_status, must_change_password BOOLEAN,
--   expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ
CREATE TABLE users
(
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username             VARCHAR(32) NOT NULL UNIQUE,
    password_hash        TEXT        NOT NULL,
    role                 user_role   NOT NULL DEFAULT 'RESIDENT',
    status               user_status NOT NULL DEFAULT 'ACTIVE',
    must_change_password BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_username_format CHECK (username ~ '^[a-z0-9_-]{3,32}$')
);

-- ── sessions ─────────────────────────────────────────────────────────────────
-- Matches Session.java:
--   @Id UUID, user_id FK, device_id VARCHAR(64), amr TEXT[],
--   refresh_hash VARCHAR(43), prev_refresh_hash VARCHAR(43),
--   created_at, last_used_at, expires_at, revoked_at, revoked_reason VARCHAR(32)
CREATE TABLE sessions
(
    id                UUID        PRIMARY KEY,
    user_id           UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id         VARCHAR(64),
    amr               TEXT[]      NOT NULL,
    refresh_hash      VARCHAR(43) NOT NULL,
    prev_refresh_hash VARCHAR(43),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    revoked_at        TIMESTAMPTZ,
    revoked_reason    VARCHAR(32)
);

CREATE INDEX idx_sessions_user ON sessions (user_id) WHERE revoked_at IS NULL;

-- ── service_clients ───────────────────────────────────────────────────────────
-- Matches ServiceClient.java:
--   client_id VARCHAR(64), audience VARCHAR(64), secret_hash VARCHAR(255),
--   scope TEXT, enabled BOOLEAN
-- Service principals are NOT users — no FK to users table.
CREATE TABLE service_clients
(
    client_id   VARCHAR(64)  NOT NULL,
    audience    VARCHAR(64)  NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    scope       TEXT         NOT NULL,
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    PRIMARY KEY (client_id, audience)
);

-- ── credentials ──────────────────────────────────────────────────────────────
-- Passkeys (Phase 1b)
CREATE TABLE credentials
(
    credential_id BYTEA       PRIMARY KEY,
    user_id       UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    public_key    BYTEA       NOT NULL,
    sign_count    BIGINT      NOT NULL DEFAULT 0,
    transports    TEXT[],
    label         VARCHAR(64),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Seed: OWNER user ─────────────────────────────────────────────────────────
INSERT INTO users (username, password_hash, role)
VALUES (:'owner_username', :'owner_password_hash', 'OWNER');

-- ── Seed: service clients ─────────────────────────────────────────────────────
-- scope format: {resource}:{verb}:{path-glob}
INSERT INTO service_clients (client_id, audience, secret_hash, scope)
VALUES ('video-service',        'nas-orchestrator', :'video_svc_hash',        'nas:write:raw/** nas:read:raw/**'),
       ('encoding-service',     'nas-orchestrator', :'encoding_svc_hash',     'nas:read:raw/** nas:write:encoded/**'),
       ('streaming-service',    'nas-orchestrator', :'streaming_svc_hash',    'nas:read:encoded/**'),
       ('api-gateway',          'element-registry', :'gateway_svc_hash',      'elements:read'),
       ('notification-service', 'auth-service',     :'notification_svc_hash', 'user:read:profile');
