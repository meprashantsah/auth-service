-- AUTH SERVICE SCHEMA (v1)
-- Identity/credential store + RBAC. User profiles live in the user-service.

CREATE TABLE IF NOT EXISTS users (
    id                 UUID PRIMARY KEY,
    username           VARCHAR(50)  NOT NULL UNIQUE,
    email              VARCHAR(100) NOT NULL UNIQUE,
    password_hash      VARCHAR(255) NOT NULL,
    enabled            BOOLEAN      NOT NULL DEFAULT TRUE,
    account_non_locked BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_attempt     INTEGER      NOT NULL DEFAULT 0,
    lock_time          TIMESTAMP,
    created_at         TIMESTAMP    NOT NULL DEFAULT now(),
    updated_at         TIMESTAMP    NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY,
    name        VARCHAR(50)  NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS permissions (
    id          UUID PRIMARY KEY,
    name        VARCHAR(50)  NOT NULL UNIQUE,
    resource    VARCHAR(50),
    action      VARCHAR(50),
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY,
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    user_id     UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expiry_date TIMESTAMP    NOT NULL,
    revoked     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP    NOT NULL DEFAULT now()
);

-- Seed default role + a base permission (idempotent).
INSERT INTO permissions (id, name, resource, action, description)
VALUES (gen_random_uuid(), 'USER_MANAGE', 'user', 'manage', 'Manage own user profile')
ON CONFLICT (name) DO NOTHING;

INSERT INTO roles (id, name, description)
VALUES (gen_random_uuid(), 'USER', 'Default user role')
ON CONFLICT (name) DO NOTHING;