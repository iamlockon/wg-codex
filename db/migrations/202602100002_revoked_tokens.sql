CREATE TABLE revoked_tokens (
    jti TEXT PRIMARY KEY,
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_revoked_tokens_customer_revoked_at
ON revoked_tokens (customer_id, revoked_at DESC);
