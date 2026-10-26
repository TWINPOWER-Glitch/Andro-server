
import { randomUUID } from 'node:crypto';
import { Pool } from 'pg';

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export interface BuildJob {
  id: string;
  projectId: string;
  repoUrl: string;
  ref: string;
  task: string;
  javaVersion: string;
  androidPlatform: string;
  status: JobStatus;
  createdAt: string;
  updatedAt: string;
  logs: string[];
  artifactUrl?: string;
  artifactPath?: string;
  error?: string;
}

/**
 * Official Supabase Root 2021 CA.
 * SHA-256 fingerprint:
 * 807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa
 *
 * This is a public certificate, not a database credential.
 * Certificate and hostname verification remain enabled.
 */
const SUPABASE_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIIDxDCCAqygAwIBAgIUbLxMod62P2ktCiAkxnKJwtE9VPYwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l
dyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJh
c2UgUm9vdCAyMDIxIENBMB4XDTIxMDQyODEwNTY1M1oXDTMxMDQyNjEwNTY1M1ow
azELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l
dyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJhc2Ug
Um9vdCAyMDIxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQXW
QyHOB+qR2GJobCq/CBmQ40G0oDmCC3mzVnn8sv4XNeWtE5XcEL0uVih7Jo4Dkx1Q
DmGHBH1zDfgs2qXiLb6xpw/CKQPypZW1JssOTMIfQppNQ87K75Ya0p25Y3ePS2t2
GtvHxNjUV6kjOZjEn2yWEcBdpOVCUYBVFBNMB4YBHkNRDa/+S4uywAoaTWnCJLUi
cvTlHmMw6xSQQn1UfRQHk50DMCEJ7Cy1RxrZJrkXXRP3LqQL2ijJ6F4yMfh+Gyb4
O4XajoVj/+R4GwywKYrrS8PrSNtwxr5StlQO8zIQUSMiq26wM8mgELFlS/32Uclt
NaQ1xBRizkzpZct9DwIDAQABo2AwXjALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFKjX
uXY32CztkhImng4yJNUtaUYsMB8GA1UdIwQYMBaAFKjXuXY32CztkhImng4yJNUt
aUYsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB8spzNn+4VU
tVxbdMaX+39Z50sc7uATmus16jmmHjhIHz+l/9GlJ5KqAMOx26mPZgfzG7oneL2b
VW+WgYUkTT3XEPFWnTp2RJwQao8/tYPXWEJDc0WVQHrpmnWOFKU/d3MqBgBm5y+6
jB81TU/RG2rVerPDWP+1MMcNNy0491CTL5XQZ7JfDJJ9CCmXSdtTl4uUQnSuv/Qx
Cea13BX2ZgJc7Au30vihLhub52De4P/4gonKsNHYdbWjg7OWKwNv/zitGDVDB9Y2
CMTyZKG3XEu5Ghl1LEnI3QmEKsqaCLv12BnVjbkSeZsMnevJPs1Ye6TjjJwdik5P
o/bKiIz+Fq8=
-----END CERTIFICATE-----`;

/**
 * Prefer the explicitly configured Andro DATABASE_URL.
 * Supabase integration URLs are fallbacks because they can point
 * to a different linked project.
 *
 * Never log connection URLs because they can contain credentials.
 */
const databaseUrlCandidates = [
  process.env.DATABASE_URL,
  process.env.SUPABAS_POSTGRES_URL,
  process.env.SUPABAS_POSTGRES_PRISMA_URL,
  process.env.SUPABAS_POSTGRES_URL_NON_POOLING,
];

const rawConnectionString = databaseUrlCandidates.find(
  (value): value is string =>
    typeof value === 'string' &&
    /^postgres(?:ql)?:\/\//i.test(value.trim()),
)?.trim();

if (!rawConnectionString) {
  throw new Error(
    'A valid PostgreSQL connection URL is required. Configure DATABASE_URL or a Supabase PostgreSQL URL in Vercel.',
  );
}

/**
 * Remove SSL-related URL parameters before supplying explicit TLS
 * options. This prevents connection-string options from overriding
 * the configured CA certificate and verification settings.
 */
const parsedConnectionUrl = new URL(rawConnectionString);

for (const parameter of [
  'sslmode',
  'sslcert',
  'sslkey',
  'sslrootcert',
  'ssl',
]) {
  parsedConnectionUrl.searchParams.delete(parameter);
}

const connectionString = parsedConnectionUrl.toString();
const databaseHostname = parsedConnectionUrl.hostname.toLowerCase();

const isSupabaseDatabase =
  databaseHostname.endsWith('.supabase.com') ||
  databaseHostname.endsWith('.supabase.co');

export const pool = new Pool({
  connectionString,
  max: Number(process.env.DB_POOL_MAX || 5),
  ssl:
    process.env.DATABASE_SSL === 'disable'
      ? false
      : {
          ...(isSupabaseDatabase ? { ca: SUPABASE_ROOT_CA } : {}),
          rejectUnauthorized:
            process.env.DATABASE_SSL_STRICT !== 'false',
        },
  connectionTimeoutMillis: 8000,
  idleTimeoutMillis: 30000,
});

function mapJob(row: any, logs: string[] = []): BuildJob {
  return {
    id: row.id,
    projectId: row.project_id,
    repoUrl: row.repo_url,
    ref: row.git_ref,
    task: row.gradle_task,
    javaVersion: row.java_version,
    androidPlatform: row.android_platform,
    status: row.status,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    logs,
    ...(row.artifact_url ? { artifactUrl: row.artifact_url } : {}),
    ...(row.artifact_path ? { artifactPath: row.artifact_path } : {}),
    ...(row.error ? { error: row.error } : {}),
  };
}

export async function createJob(
  input: Omit<
    BuildJob,
    'id' | 'status' | 'createdAt' | 'updatedAt' | 'logs'
  >,
): Promise<BuildJob> {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const inserted = await client.query(
      `INSERT INTO andro.build_jobs
        (id, project_id, repo_url, git_ref, gradle_task,
         java_version, android_platform, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued')
       RETURNING *`,
      [
        randomUUID(),
        input.projectId,
        input.repoUrl,
        input.ref,
        input.task,
        input.javaVersion,
        input.androidPlatform,
      ],
    );

    const row = inserted.rows[0];

    const initialLogs = [
      'Job accepted by Andro API.',
      'Queued for a registered worker. Queue acceptance is not proof of a completed build.',
    ];

    await client.query(
      `INSERT INTO andro.build_logs (job_id, line)
       VALUES ($1, $2), ($1, $3)`,
      [row.id, initialLogs[0], initialLogs[1]],
    );

    await client.query('COMMIT');

    return mapJob(row, initialLogs);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function logsFor(id: string): Promise<string[]> {
  const result = await pool.query(
    `SELECT line
     FROM andro.build_logs
     WHERE job_id = $1
     ORDER BY id ASC
     LIMIT 1000`,
    [id],
  );

  return result.rows.map((row: { line: string }) => row.line);
}

export async function getJob(
  id: string,
): Promise<BuildJob | undefined> {
  const result = await pool.query(
    'SELECT * FROM andro.build_jobs WHERE id = $1',
    [id],
  );

  if (!result.rowCount) return undefined;

  return mapJob(result.rows[0], await logsFor(id));
}

export async function listJobs(): Promise<BuildJob[]> {
  const result = await pool.query(
    `SELECT *
     FROM andro.build_jobs
     ORDER BY created_at DESC
     LIMIT 100`,
  );

  return Promise.all(
    result.rows.map(async (row) =>
      mapJob(row, await logsFor(row.id)),
    ),
  );
}

export async function appendJobLog(
  id: string,
  line: string,
): Promise<BuildJob | undefined> {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const found = await client.query(
      'SELECT id FROM andro.build_jobs WHERE id = $1 FOR UPDATE',
      [id],
    );

    if (!found.rowCount) {
      await client.query('ROLLBACK');
      return undefined;
    }

    await client.query(
      'INSERT INTO andro.build_logs (job_id, line) VALUES ($1, $2)',
      [id, line.slice(0, 4000)],
    );

    await client.query(
      'UPDATE andro.build_jobs SET updated_at = now() WHERE id = $1',
      [id],
    );

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }

  return getJob(id);
}

export async function updateJob(
  id: string,
  patch: Partial<
    Pick<BuildJob, 'status' | 'artifactUrl' | 'artifactPath' | 'error'>
  >,
): Promise<BuildJob | undefined> {
  const result = await pool.query(
    `UPDATE andro.build_jobs
     SET status = COALESCE($2, status),
         artifact_url = COALESCE($3, artifact_url),
         artifact_path = COALESCE($4, artifact_path),
         error = COALESCE($5, error),
         updated_at = now()
     WHERE id = $1
     RETURNING *`,
    [
      id,
      patch.status ?? null,
      patch.artifactUrl ?? null,
      patch.artifactPath ?? null,
      patch.error ?? null,
    ],
  );

  return result.rowCount ? getJob(id) : undefined;
}

export async function claimJob(): Promise<BuildJob | undefined> {
  const client = await pool.connect();
  let id: string | undefined;

  try {
    await client.query('BEGIN');

    const claimed = await client.query(
      `WITH candidate AS (
         SELECT id
         FROM andro.build_jobs
         WHERE status = 'queued'
         ORDER BY created_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1
       )
       UPDATE andro.build_jobs AS j
       SET status = 'running',
           updated_at = now()
       FROM candidate AS c
       WHERE j.id = c.id
       RETURNING j.id`,
    );

    id = claimed.rows[0]?.id;

    if (id) {
      await client.query(
        'INSERT INTO andro.build_logs (job_id, line) VALUES ($1, $2)',
        [id, 'Worker claimed job.'],
      );
    }

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }

  return id ? getJob(id) : undefined;
}
