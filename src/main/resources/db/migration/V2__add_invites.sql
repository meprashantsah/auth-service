-- Workspace invites: a shareable, single-use link that grants a chosen role
-- when the invited person registers. The token is the bearer secret — role is
-- decided server-side at creation time, so the public register endpoint can no
-- longer trust a client-supplied role set (privilege escalation).
CREATE TABLE IF NOT EXISTS invites (
    id         UUID PRIMARY KEY,
    token      VARCHAR(64)  NOT NULL UNIQUE,
    role_name  VARCHAR(50)  NOT NULL,
    created_by UUID         NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT now(),
    expires_at TIMESTAMP    NOT NULL,
    used_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invites_created_at ON invites (created_at DESC);
