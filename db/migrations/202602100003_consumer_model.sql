-- Consumer VPN model additions: subscription entitlements and geo/pool node metadata.

CREATE TABLE plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    max_active_sessions INTEGER NOT NULL CHECK (max_active_sessions > 0),
    max_devices INTEGER NOT NULL CHECK (max_devices > 0),
    allowed_regions TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE customer_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('active', 'trialing', 'past_due', 'canceled')),
    starts_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uniq_customer_active_subscription
ON customer_subscriptions (customer_id)
WHERE status IN ('active', 'trialing');

INSERT INTO plans (code, max_active_sessions, max_devices, allowed_regions)
VALUES
    ('free', 1, 3, NULL),
    ('plus', 1, 7, NULL),
    ('max', 1, 10, NULL)
ON CONFLICT (code) DO NOTHING;

ALTER TABLE vpn_nodes
    ADD COLUMN country_code TEXT NOT NULL DEFAULT 'US',
    ADD COLUMN city_code TEXT,
    ADD COLUMN pool TEXT NOT NULL DEFAULT 'general',
    ADD COLUMN capacity_peers BIGINT NOT NULL DEFAULT 10000;

ALTER TABLE vpn_nodes
    ADD CONSTRAINT chk_vpn_nodes_country_code_len CHECK (char_length(country_code) = 2),
    ADD CONSTRAINT chk_vpn_nodes_capacity_peers CHECK (capacity_peers > 0);

CREATE INDEX idx_vpn_nodes_selection
ON vpn_nodes (region, country_code, city_code, pool, healthy, updated_at);
