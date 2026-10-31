-- Bind every OAuth code and token to the single canonical MCP resource.
-- The server writes and checks this value on every exchange and MCP request.

ALTER TABLE andro.oauth_authorization_codes
  ADD COLUMN IF NOT EXISTS resource text;

ALTER TABLE andro.oauth_access_tokens
  ADD COLUMN IF NOT EXISTS resource text;

ALTER TABLE andro.oauth_refresh_tokens
  ADD COLUMN IF NOT EXISTS resource text;
