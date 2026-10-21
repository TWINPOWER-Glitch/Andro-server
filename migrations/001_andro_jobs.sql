-- Andro server-side queue schema. Keep this schema private; API/worker connect with a server-side database role.
CREATE SCHEMA IF NOT EXISTS andro;
REVOKE ALL ON SCHEMA andro FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN REVOKE ALL ON SCHEMA andro FROM anon; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN REVOKE ALL ON SCHEMA andro FROM authenticated; END IF;
END $$;

CREATE TABLE IF NOT EXISTS andro.build_jobs (
  id uuid PRIMARY KEY,
  project_id text NOT NULL,
  repo_url text NOT NULL,
  git_ref text NOT NULL,
  gradle_task text NOT NULL,
  java_version text NOT NULL CHECK (java_version IN ('17')),
  android_platform text NOT NULL CHECK (android_platform IN ('36')),
  status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')) DEFAULT 'queued',
  artifact_url text,
  artifact_path text,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE andro.build_jobs ADD COLUMN IF NOT EXISTS artifact_path text;

CREATE INDEX IF NOT EXISTS build_jobs_queue_idx ON andro.build_jobs (created_at) WHERE status='queued';
CREATE INDEX IF NOT EXISTS build_jobs_project_idx ON andro.build_jobs (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS andro.build_logs (
  id bigserial PRIMARY KEY,
  job_id uuid NOT NULL REFERENCES andro.build_jobs(id) ON DELETE CASCADE,
  line text NOT NULL CHECK (char_length(line) <= 4000),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS build_logs_job_idx ON andro.build_logs (job_id, id);
REVOKE ALL ON ALL TABLES IN SCHEMA andro FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN REVOKE ALL ON ALL TABLES IN SCHEMA andro FROM anon; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN REVOKE ALL ON ALL TABLES IN SCHEMA andro FROM authenticated; END IF;
END $$;

-- After creating a dedicated server role (replace andro_app with your actual role name), grant it:
-- GRANT USAGE ON SCHEMA andro TO andro_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON andro.build_jobs, andro.build_logs TO andro_app;
-- GRANT USAGE, SELECT ON SEQUENCE andro.build_logs_id_seq TO andro_app;

-- Private artifact objects are stored in Supabase Storage; never expose this bucket publicly.

-- Private object bucket for APK/AAB outputs. Only the server-side secret key may write.
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('andro-artifacts', 'andro-artifacts', false, 536870912,
        ARRAY['application/vnd.android.package-archive', 'application/octet-stream'])
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = EXCLUDED.file_size_limit,
  allowed_mime_types = EXCLUDED.allowed_mime_types;