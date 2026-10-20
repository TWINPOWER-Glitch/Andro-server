-- Deny all client-role access unless explicit policies are added later.
-- The trusted API/worker must use a server-side database role and/or server-side Supabase secret.
ALTER TABLE andro.build_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE andro.build_logs ENABLE ROW LEVEL SECURITY;
