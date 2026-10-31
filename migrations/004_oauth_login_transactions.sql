-- Andro OAuth 2.1
-- Migration 004: GitHub login and consent transaction storage.
--
-- This migration has ALREADY been applied to the Supabase database.
-- This file is being added to GitHub to keep migration history aligned.
-- Do not execute it again manually.

CREATE TABLE IF NOT EXISTS andro.oauth_login_transactions (
    state_hash CHAR(64) PRIMARY KEY,

    client_id TEXT NOT NULL
        REFERENCES andro.oauth_clients(client_id)
        ON DELETE CASCADE,

    redirect_uri TEXT NOT NULL,
    client_state TEXT NOT NULL,

    code_challenge TEXT NOT NULL,

    scopes TEXT[] NOT NULL
        CHECK (
            scopes <@ ARRAY['mcp:read', 'mcp:build']::TEXT[]
            AND cardinality(scopes) > 0
        ),

    resource TEXT NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,

    github_user_id TEXT,
    github_login TEXT,

    consent_nonce_hash CHAR(64),

    authenticated_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS
    oauth_login_transactions_expiry_idx
ON andro.oauth_login_transactions (expires_at);

ALTER TABLE andro.oauth_login_transactions
    ENABLE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES
ON TABLE andro.oauth_login_transactions
FROM PUBLIC, anon, authenticated;
