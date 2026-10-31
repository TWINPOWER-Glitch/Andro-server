
-- Andro OAuth 2.1 foundation for Claude MCP connections.
--
-- Security model:
-- 1. One authorized Andro owner identity.
-- 2. Public OAuth clients use Authorization Code + PKCE (S256).
-- 3. Authorization codes and tokens are stored as SHA-256 hashes.
-- 4. Only the trusted server-side API may access these tables.
-- 5. No GitHub access token or client secret is stored here.

CREATE TABLE IF NOT EXISTS andro.oauth_authorized_principal (
    singleton boolean PRIMARY KEY DEFAULT true
        CHECK (singleton = true),

    provider text NOT NULL
        CHECK (provider = 'github'),

    provider_user_id text NOT NULL
        CHECK (char_length(provider_user_id) BETWEEN 1 AND 128),

    provider_login text NOT NULL
        CHECK (char_length(provider_login) BETWEEN 1 AND 255),

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The singleton primary key prevents registering a second owner.

CREATE TABLE IF NOT EXISTS andro.oauth_clients (
    client_id text PRIMARY KEY
        CHECK (char_length(client_id) BETWEEN 16 AND 255),

    client_name text NOT NULL
        CHECK (char_length(client_name) BETWEEN 1 AND 255),

    redirect_uris text[] NOT NULL
        CHECK (cardinality(redirect_uris) BETWEEN 1 AND 20),

    grant_types text[] NOT NULL DEFAULT ARRAY['authorization_code']::text[]
        CHECK (
            grant_types <@ ARRAY[
                'authorization_code',
                'refresh_token'
            ]::text[]
        ),

    response_types text[] NOT NULL DEFAULT ARRAY['code']::text[]
        CHECK (response_types <@ ARRAY['code']::text[]),

    token_endpoint_auth_method text NOT NULL DEFAULT 'none'
        CHECK (token_endpoint_auth_method = 'none'),

    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS andro.oauth_authorization_codes (
    code_hash char(64) PRIMARY KEY,

    client_id text NOT NULL
        REFERENCES andro.oauth_clients(client_id)
        ON DELETE CASCADE,

    redirect_uri text NOT NULL,

    code_challenge text NOT NULL
        CHECK (
            char_length(code_challenge) BETWEEN 43 AND 128
        ),

    code_challenge_method text NOT NULL
        CHECK (code_challenge_method = 'S256'),

    scopes text[] NOT NULL DEFAULT ARRAY['mcp:read']::text[]
        CHECK (
            scopes <@ ARRAY['mcp:read', 'mcp:build']::text[]
        ),

    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oauth_authorization_codes_expiry_idx
    ON andro.oauth_authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS andro.oauth_access_tokens (
    token_hash char(64) PRIMARY KEY,

    client_id text NOT NULL
        REFERENCES andro.oauth_clients(client_id)
        ON DELETE CASCADE,

    principal_singleton boolean NOT NULL DEFAULT true
        REFERENCES andro.oauth_authorized_principal(singleton),

    scopes text[] NOT NULL
        CHECK (
            scopes <@ ARRAY['mcp:read', 'mcp:build']::text[]
        ),

    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oauth_access_tokens_expiry_idx
    ON andro.oauth_access_tokens (expires_at);

CREATE TABLE IF NOT EXISTS andro.oauth_refresh_tokens (
    token_hash char(64) PRIMARY KEY,

    token_family_id uuid NOT NULL,

    client_id text NOT NULL
        REFERENCES andro.oauth_clients(client_id)
        ON DELETE CASCADE,

    principal_singleton boolean NOT NULL DEFAULT true
        REFERENCES andro.oauth_authorized_principal(singleton),

    scopes text[] NOT NULL
        CHECK (
            scopes <@ ARRAY['mcp:read', 'mcp:build']::text[]
        ),

    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_family_idx
    ON andro.oauth_refresh_tokens (token_family_id);

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expiry_idx
    ON andro.oauth_refresh_tokens (expires_at);

-- Deny access to browser/client roles.
ALTER TABLE andro.oauth_authorized_principal
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE andro.oauth_clients
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE andro.oauth_authorization_codes
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE andro.oauth_access_tokens
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE andro.oauth_refresh_tokens
    ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON
    andro.oauth_authorized_principal,
    andro.oauth_clients,
    andro.oauth_authorization_codes,
    andro.oauth_access_tokens,
    andro.oauth_refresh_tokens
FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'anon'
    ) THEN
        REVOKE ALL ON
            andro.oauth_authorized_principal,
            andro.oauth_clients,
            andro.oauth_authorization_codes,
            andro.oauth_access_tokens,
            andro.oauth_refresh_tokens
        FROM anon;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'
    ) THEN
        REVOKE ALL ON
            andro.oauth_authorized_principal,
            andro.oauth_clients,
            andro.oauth_authorization_codes,
            andro.oauth_access_tokens,
            andro.oauth_refresh_tokens
        FROM authenticated;
    END IF;
END
$$;
