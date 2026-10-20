# Andro Server

Andro is an API/MCP gateway and a separate Android build-worker prototype. The gateway accepts jobs; only a worker's actual Gradle result can mark a job successful.

## Architecture

- `api/index.ts` and `src/index.ts`: Express API + MCP Streamable HTTP endpoint; supports Vercel's Node function runtime and a standalone server.
- `src/store.ts`: PostgreSQL queue, job state, and logs. Uses `FOR UPDATE SKIP LOCKED` for atomic claims.
- `src/worker.ts`: trusted orchestrator. It claims jobs and launches a separate ephemeral Docker container for repository code, with CPU/memory/PID limits, read-only root, no capabilities, no-new-privileges, tmpfs scratch space, and no API/storage secrets in the build container.
- `migrations/001_andro_jobs.sql`: private `andro` schema and private Supabase Storage bucket for artifacts.
- `migrations/002_enable_rls.sql`: enables RLS on both job tables; no client policies are intentionally created, so client roles cannot access rows by default.
- `worker/Dockerfile`: Android SDK Platform 36, Build Tools 36.1.0, Java 17, Git, Docker CLI.

## Required configuration

Copy `.env.example` to `.env` for the API. Use a dedicated Supabase project and its PostgreSQL connection string (prefer the transaction pooler for serverless use; confirm driver compatibility and TLS settings). Set long random, different values for `ANDRO_API_KEY` and `ANDRO_WORKER_TOKEN`. Set `SUPABASE_URL` and a server-side `SUPABASE_SECRET_KEY` (or legacy `SUPABASE_SERVICE_ROLE_KEY`) for private artifact uploads. Never expose database or Supabase secret keys to browser code or build containers.

Migrations `001_andro_jobs` and `002_enable_rls` have been applied to the dedicated Supabase project referenced in this setup. For a fresh project, apply them in numeric order using a database-owner connection. Migration 002 enables RLS without adding client policies by design. The trusted API/worker must use a server-side database role; do not use a publishable key as a database credential. Do not apply these migrations to an unrelated database.

## API

- `GET /health` — API/database health.
- `GET /v1/status` — API-key protected runtime status.
- `POST /v1/builds` — enqueue a public HTTPS Git repository build.
- `GET /v1/builds`, `GET /v1/builds/:id`, `GET /v1/builds/:id/logs` — query jobs.
- `GET /v1/builds/:id/artifact` — returns a 5-minute signed download URL for a completed private APK/AAB.
- `POST /mcp` — MCP Streamable HTTP endpoint; use `Authorization: Bearer <ANDRO_API_KEY>`.

Example build request:

```bash
curl -X POST "$ANDRO_SERVER_URL/v1/builds" \
  -H "Authorization: Bearer $ANDRO_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"repoUrl":"https://github.com/OWNER/ANDROID_APP","ref":"main","task":"assembleDebug"}'
```

## Worker deployment and isolation

Build the image on a dedicated Linux worker VM with Docker Engine available:

```bash
docker build -f worker/Dockerfile -t andro-android-runner:latest .
```

Configure `.env.worker` with `ANDRO_SERVER_URL`, `ANDRO_WORKER_TOKEN`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and the same bucket name. Start the worker using `docker-compose -f docker-compose.worker.yml up -d --build`.

**Security boundary:** the orchestrator uses the host Docker socket, which is effectively host-root access. Keep it on a dedicated, patched VM; do not co-host unrelated workloads. The job container has no Docker socket and receives no Andro or Supabase credentials. Before accepting untrusted public repositories in production, also enforce host/firewall egress rules that block cloud metadata endpoints and internal control-plane networks, enforce storage and job quotas, rotate credentials, and add monitoring. The Docker bridge allows outbound network access so Gradle can download dependencies; a stronger egress proxy/allowlist is recommended.

## Local checks

```bash
npm install
npm run check
npm run build
```

The API alone does not execute Android builds. A build is verified only when the worker claims the job, runs Gradle in the isolated container, reports the actual exit code, and—when an APK/AAB is produced—uploads it to private Storage.

## Current limitations

- Supabase project and schema are provisioned for this setup. Server-side database credentials and Supabase secret key still need to be configured in the API/worker hosting environment; no live cloud deployment is claimed.
- The worker requires a dedicated Linux host with Docker Engine and the Android runner image available.
- Public Git repository URLs only are currently supported; private repository credentials are intentionally not passed to builds.
- Emulator/instrumentation tests are not implemented. Windows/MSBuild workloads require separate Windows workers.
- No live build is claimed by this repository snapshot.
