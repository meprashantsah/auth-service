-- AUTH SERVICE SCHEMA + SEED DATA (v1, fresh install)
-- Identity/credential store + RBAC. User profiles live in the user-service.
--
-- This is the single migration for a new database. Built-in roles and
-- permissions are seeded here with the resource:action naming convention —
-- each permission name matches @PreAuthorize("hasAuthority('<name>')") exactly.

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

-- ---------------------------- BUILT-IN ROLES ----------------------------

INSERT INTO roles (id, name, description)
VALUES (gen_random_uuid(), 'USER',       'Default user role'),
       (gen_random_uuid(), 'ADMIN',      'Platform administrator'),
       (gen_random_uuid(), 'SUPERADMIN', 'Full platform administrator')
ON CONFLICT (name) DO NOTHING;

-- ------------------------- BUILT-IN PERMISSIONS --------------------------

INSERT INTO permissions (id, name, resource, action, description)
VALUES (gen_random_uuid(), 'user:read',         'user',       'read',   'List and view identity users'),
       (gen_random_uuid(), 'user:delete',       'user',       'delete', 'Delete identity users'),
       (gen_random_uuid(), 'role:assign',       'role',       'assign', 'Assign / remove roles on users'),
       (gen_random_uuid(), 'role:read',         'role',       'read',   'List roles'),
       (gen_random_uuid(), 'role:create',       'role',       'create', 'Create roles'),
       (gen_random_uuid(), 'role:delete',       'role',       'delete', 'Delete roles'),
       (gen_random_uuid(), 'permission:read',   'permission', 'read',   'List permissions'),
       (gen_random_uuid(), 'permission:create', 'permission', 'create', 'Create permissions'),
       (gen_random_uuid(), 'permission:delete', 'permission', 'delete', 'Delete permissions')
ON CONFLICT (name) DO NOTHING;

-- Grant every admin permission above to the built-in admin roles. Users with
-- these roles inherit the permissions; custom roles get theirs via the admin UI.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
  ON p.name IN ('user:read', 'user:delete', 'role:assign', 'role:read',
                'role:create', 'role:delete', 'permission:read',
                'permission:create', 'permission:delete')
WHERE r.name IN ('ADMIN', 'SUPERADMIN')
ON CONFLICT DO NOTHING;