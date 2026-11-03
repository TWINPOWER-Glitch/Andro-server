
import 'dotenv/config';
import express, {
  type Request,
  type Response,
  type NextFunction,
} from 'express';
import cors from 'cors';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import {
  createJob,
  getJob,
  listJobs,
  appendJobLog,
  updateJob,
  claimJob,
  pool,
} from './store.js';
import { createClient } from '@supabase/supabase-js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  createOAuthRouter,
  OAUTH_ISSUER,
  OAUTH_RESOURCE,
  verifyOAuthAccessToken,
} from './oauth.js';

const VERSION = '0.4.0';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseSecret =
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabasePublicKey =
  process.env.SUPABASE_PUBLISHABLE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  '';

const artifactBucket =
  process.env.ANDRO_ARTIFACT_BUCKET || 'andro-artifacts';

const storage =
  supabaseUrl && supabaseSecret
    ? createClient(supabaseUrl, supabaseSecret, {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
        },
      })
    : undefined;

const app = express();

app.disable('x-powered-by');

app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') ?? false,
  }),
);

app.use(express.json({ limit: '1mb' }));

// -----------------------------------------------------------------------------
// Andro website entry
//
// This uses the same Andro Supabase Auth project as the Android app.
// The public publishable/anon key is safe for client-side use when Supabase
// Row Level Security and Auth policies are correctly configured.
//
// Do not use SUPABASE_SECRET_KEY or the service-role key in browser code.
// -----------------------------------------------------------------------------

function renderAndroWebsite(): string {
  const config = JSON.stringify({
    supabaseUrl: supabaseUrl ?? '',
    supabasePublicKey,
  }).replace(/</g, '\\u003c');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Andro</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      background: #10131b;
      color: #f4f6fb;
    }

    main {
      width: min(100%, 560px);
      padding: 36px;
      border: 1px solid #2a3040;
      border-radius: 20px;
      background: #171c27;
    }

    h1 {
      margin: 0 0 12px;
      font-size: 2.4rem;
    }

    p {
      color: #b9c1d2;
      line-height: 1.6;
    }

    button {
      margin-top: 16px;
      border: 0;
      border-radius: 10px;
      padding: 13px 18px;
      font: inherit;
      font-weight: 650;
      cursor: pointer;
      background: #e7ecf7;
      color: #111521;
    }

    button.secondary {
      background: #2a3040;
      color: #f4f6fb;
      margin-left: 8px;
    }

    button:disabled {
      cursor: not-allowed;
      opacity: 0.6;
    }

    #message {
      min-height: 1.5em;
      overflow-wrap: anywhere;
    }

    .muted {
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <main>
    <h1>Andro</h1>

    <p>
      One Andro account across the Android app and website.
      Sign in securely with GitHub.
    </p>

    <div id="actions">
      <button id="signin" type="button">Continue with GitHub</button>
    </div>

    <p id="message" role="status" aria-live="polite"></p>

    <p class="muted">
      The Android app download will be listed here when the Play Store release
      is available.
    </p>
  </main>

  <script type="module">
    import { createClient } from
      'https://esm.sh/@supabase/supabase-js@2';

    const config = ${config};

    const actions = document.querySelector('#actions');
    const message = document.querySelector('#message');
    const signInButton = document.querySelector('#signin');

    if (!config.supabaseUrl || !config.supabasePublicKey) {
      message.textContent =
        'Website sign-in is not configured. Set SUPABASE_URL and ' +
        'SUPABASE_PUBLISHABLE_KEY (or SUPABASE_ANON_KEY) in the deployment environment.';

      signInButton.disabled = true;
    } else {
      const supabase = createClient(
        config.supabaseUrl,
        config.supabasePublicKey,
        {
          auth: {
            flowType: 'pkce',
            detectSessionInUrl: true,
            persistSession: true,
            autoRefreshToken: true
          }
        }
      );

      let rendering = false;

      async function renderSession() {
        if (rendering) return;
        rendering = true;

        try {
          const {
            data: { session },
            error
          } = await supabase.auth.getSession();

          if (error) {
            message.textContent = error.message;
            return;
          }

          if (!session) {
            if (location.pathname === '/auth/callback') {
              message.textContent =
                'Authentication did not complete. Please try signing in again.';
            }

            return;
          }

          actions.replaceChildren();

          const signedIn = document.createElement('p');

          const displayName =
            session.user.user_metadata?.user_name ||
            session.user.user_metadata?.preferred_username ||
            session.user.email ||
            'your GitHub account';

          signedIn.textContent = 'Signed in as ' + displayName + '.';

          const signOutButton = document.createElement('button');
          signOutButton.className = 'secondary';
          signOutButton.type = 'button';
          signOutButton.textContent = 'Sign out';

          signOutButton.addEventListener('click', async () => {
            signOutButton.disabled = true;

            const { error: signOutError } =
              await supabase.auth.signOut();

            if (signOutError) {
              message.textContent = signOutError.message;
              signOutButton.disabled = false;
              return;
            }

            actions.replaceChildren(signInButton);
            message.textContent = 'Signed out.';
          });

          actions.append(signedIn, signOutButton);

          message.textContent =
            location.pathname === '/auth/callback'
              ? 'Authentication completed.'
              : '';
        } finally {
          rendering = false;
        }
      }

      signInButton.addEventListener('click', async () => {
        signInButton.disabled = true;
        message.textContent = 'Redirecting to GitHub…';

        const { error } = await supabase.auth.signInWithOAuth({
          provider: 'github',
          options: {
            redirectTo: location.origin + '/auth/callback'
          }
        });

        if (error) {
          message.textContent = error.message;
          signInButton.disabled = false;
        }
      });

      supabase.auth.onAuthStateChange(() => {
        void renderSession();
      });

      void renderSession();
    }
  </script>
</body>
</html>`;
}

// Website paths only. These do not intercept /health, /v1/*, /internal/*,
// /mcp, or the existing OAuth discovery and authorization routes.
app.get(['/', '/auth/callback'], (_req, res) => {
  res.type('html').send(renderAndroWebsite());
});

// OAuth discovery, registration, GitHub sign-in, consent, token,
// refresh, and revocation endpoints. The existing API-key routes remain
// unchanged; only the MCP endpoint accepts either API-key or OAuth auth.
app.use(createOAuthRouter());

function paramString(
  value: string | string[] | undefined,
): string {
  if (Array.isArray(value)) return value[0] ?? '';
  return value ?? '';
}

function secureToken(
  req: Request,
  res: Response,
  next: NextFunction,
  expected: string | undefined,
  message: string,
) {
  if (!expected) {
    return res.status(503).json({ error: message });
  }

  const provided =
    req.header('authorization')?.replace(/^Bearer\s+/i, '') ?? '';

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

const apiKey = (
  req: Request,
  res: Response,
  next: NextFunction,
) =>
  secureToken(
    req,
    res,
    next,
    process.env.ANDRO_API_KEY,
    'API key is not configured. Set ANDRO_API_KEY before exposing this server.',
  );

const workerKey = (
  req: Request,
  res: Response,
  next: NextFunction,
) =>
  secureToken(
    req,
    res,
    next,
    process.env.ANDRO_WORKER_TOKEN,
    'Worker token is not configured.',
  );

/**
 * MCP keeps the existing API-key path operational while adding OAuth.
 * API-key requests retain the existing full access. OAuth requests must
 * present a live, resource-bound access token from the OAuth tables.
 */
const mcpAuth = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const provided =
    req.header('authorization')?.replace(/^Bearer\s+/i, '') ?? '';
  const expected = process.env.ANDRO_API_KEY;

  if (expected) {
    const suppliedBytes = Buffer.from(provided);
    const expectedBytes = Buffer.from(expected);

    if (
      suppliedBytes.length === expectedBytes.length &&
      timingSafeEqual(suppliedBytes, expectedBytes)
    ) {
      res.locals.androApiKeyAuthorized = true;
      res.locals.androOAuthScopes = [];
      return next();
    }
  }

  if (!provided) {
    res.set(
      'WWW-Authenticate',
      `Bearer realm="andro", resource_metadata="${OAUTH_ISSUER}/.well-known/oauth-protected-resource", scope="mcp:read mcp:build"`,
    );

    return res.status(401).json({
      error: 'Unauthorized',
      error_description:
        'A valid Andro API key or OAuth access token is required.',
    });
  }

  try {
    const authorization = await verifyOAuthAccessToken(
      provided,
      OAUTH_RESOURCE,
    );

    if (!authorization) {
      res.set(
        'WWW-Authenticate',
        `Bearer realm="andro", error="invalid_token", resource_metadata="${OAUTH_ISSUER}/.well-known/oauth-protected-resource", scope="mcp:read mcp:build"`,
      );

      return res.status(401).json({
        error: 'Invalid or expired access token.',
      });
    }

    res.locals.androApiKeyAuthorized = false;
    res.locals.androOAuthScopes = authorization.scopes;
    res.locals.androOAuthClientId = authorization.clientId;

    return next();
  } catch (error) {
    return next(error);
  }
};

function mcpHasScope(
  res: Response,
  scope: 'mcp:read' | 'mcp:build',
) {
  if (res.locals.androApiKeyAuthorized === true) return true;

  const scopes = res.locals.androOAuthScopes as string[] | undefined;

  return Array.isArray(scopes) && scopes.includes(scope);
}

// Protected, read-only database diagnostic. This exposes metadata only; it never
// returns credentials, owner records, OAuth tokens, authorization codes, or rows.
app.get('/v1/diagnostics/database', apiKey, async (_req, res) => {
  const requiredTables = [
    'oauth_authorized_principal',
    'oauth_clients',
    'oauth_authorization_codes',
    'oauth_access_tokens',
    'oauth_refresh_tokens',
    'oauth_login_transactions',
  ];

  const databaseUrlCandidates = [
    process.env.DATABASE_URL,
    process.env.SUPABAS_POSTGRES_URL,
    process.env.SUPABAS_POSTGRES_PRISMA_URL,
    process.env.SUPABAS_POSTGRES_URL_NON_POOLING,
  ];

  let databaseHost: string | null = null;

  for (const candidate of databaseUrlCandidates) {
    if (!candidate) continue;

    try {
      const parsed = new URL(candidate);

      if (
        (parsed.protocol === 'postgres:' ||
          parsed.protocol === 'postgresql:') &&
        parsed.hostname
      ) {
        databaseHost = parsed.hostname;
        break;
      }
    } catch {
      // Ignore malformed candidates and follow store.ts precedence.
    }
  }

  try {
    const result = await pool.query<{
      database_name: string;
      schema_name: string;
      table_name: string;
    }>(
      `SELECT
         current_database() AS database_name,
         current_schema() AS schema_name,
         table_name
       FROM information_schema.tables
       WHERE table_schema = 'andro'
         AND table_type = 'BASE TABLE'
         AND table_name = ANY($1::text[])`,
      [requiredTables],
    );

    const presentTables = result.rows
      .map((row) => row.table_name)
      .filter((name) => requiredTables.includes(name));
    const missingTables = requiredTables.filter(
      (name) => !presentTables.includes(name),
    );

    const identity = (await pool.query<{
      database_name: string;
      schema_name: string;
    }>(
      'SELECT current_database() AS database_name, current_schema() AS schema_name',
    )).rows[0];

    return res.json({
      service: 'andro-server',
      status: missingTables.length === 0 ? 'ok' : 'incomplete',
      readOnly: true,
      database: {
        host: databaseHost,
        name: identity?.database_name ?? null,
        currentSchema: identity?.schema_name ?? null,
        oauthSchema: 'andro',
      },
      requiredTables,
      presentTables,
      missingTables,
      allRequiredTablesPresent: missingTables.length === 0,
      checkedAt: new Date().toISOString(),
    });
  } catch (error: unknown) {
    const dbError = error as {
      name?: string;
      code?: string;
    };

    console.error('Protected database diagnostic failed', {
      name:
        typeof dbError?.name === 'string'
          ? dbError.name
          : 'UnknownError',
      code:
        typeof dbError?.code === 'string'
          ? dbError.code
          : 'NO_DATABASE_ERROR_CODE',
    });

    return res.status(503).json({
      service: 'andro-server',
      status: 'unavailable',
      readOnly: true,
      databaseHost,
      error: 'Database diagnostic query failed.',
      checkedAt: new Date().toISOString(),
    });
  }
});

// Health check. Never expose database connection details.
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');

    return res.json({
      service: 'andro-server',
      version: VERSION,
      status: 'ok',
      database: 'connected',
      time: new Date().toISOString(),
    });
  } catch (error: unknown) {
    const dbError = error as {
      name?: string;
      code?: string;
    };

    console.error('Database health check failed', {
      name:
        typeof dbError?.name === 'string'
          ? dbError.name
          : 'UnknownError',
      code:
        typeof dbError?.code === 'string'
          ? dbError.code
          : 'NO_DATABASE_ERROR_CODE',
    });

    return res.status(503).json({
      service: 'andro-server',
      version: VERSION,
      status: 'degraded',
      database: 'unavailable',
      time: new Date().toISOString(),
    });
  }
});

app.get('/v1/status', apiKey, (_req, res) =>
  res.json({
    service: 'andro-server',
    version: VERSION,
    mode: 'durable-queue',
    workerConfigured: Boolean(
      process.env.ANDRO_WORKER_TOKEN,
    ),
    artifactStorageConfigured: Boolean(storage),
    mcpEndpoint: '/mcp',
    note:
      'A queued job is not a successful build. Only a worker-reported Gradle result establishes completion.',
  }),
);

const buildSchema = z.object({
  projectId: z.string().min(1).max(128).default('default'),

  repoUrl: z
    .string()
    .url()
    .refine(
      (value) => {
        try {
          const url = new URL(value);
          const parts = url.pathname
            .split('/')
            .filter(Boolean);

          return (
            url.protocol === 'https:' &&
            [
              'github.com',
              'gitlab.com',
              'bitbucket.org',
            ].includes(url.hostname.toLowerCase()) &&
            !url.username &&
            !url.password &&
            !url.port &&
            !url.search &&
            !url.hash &&
            parts.length >= 2 &&
            parts.every(
              (part) => part !== '.' && part !== '..',
            )
          );
        } catch {
          return false;
        }
      },
      'Use a public HTTPS repository URL on github.com, gitlab.com, or bitbucket.org without credentials, query strings, or fragments.',
    ),

  ref: z
    .string()
    .min(1)
    .max(255)
    .regex(
      /^[A-Za-z0-9][A-Za-z0-9._/-]*$/,
      'Invalid Git ref',
    )
    .refine(
      (value) =>
        !value.startsWith('-') &&
        !value.includes('..') &&
        !value.endsWith('.') &&
        !value.endsWith('.lock') &&
        !value.includes('//'),
      'Invalid Git ref',
    )
    .default('main'),

  task: z
    .string()
    .min(1)
    .max(160)
    .default('assembleDebug')
    .refine(
      (value) => /^[A-Za-z0-9:_-]+$/.test(value),
      'Gradle task contains unsupported characters',
    ),

  javaVersion: z.enum(['17']).default('17'),
  androidPlatform: z.enum(['36']).default('36'),
});

app.post('/v1/builds', apiKey, async (req, res, next) => {
  try {
    const parsed = buildSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Invalid build request',
        details: parsed.error.flatten(),
      });
    }

    const job = await createJob(parsed.data);

    return res.status(202).json({
      job,
      message:
        'Accepted into the durable queue. This does not prove that a worker has executed the build.',
    });
  } catch (error) {
    next(error);
  }
});

app.get('/v1/builds', apiKey, async (_req, res, next) => {
  try {
    return res.json({ jobs: await listJobs() });
  } catch (error) {
    next(error);
  }
});

app.get('/v1/builds/:id', apiKey, async (req, res, next) => {
  try {
    const id = paramString(req.params.id);
    const job = await getJob(id);

    return job
      ? res.json({ job })
      : res.status(404).json({
          error: 'Build job not found',
        });
  } catch (error) {
    next(error);
  }
});

app.get(
  '/v1/builds/:id/logs',
  apiKey,
  async (req, res, next) => {
    try {
      const id = paramString(req.params.id);
      const job = await getJob(id);

      return job
        ? res.json({
            jobId: job.id,
            status: job.status,
            logs: job.logs,
            error: job.error ?? null,
          })
        : res.status(404).json({
            error: 'Build job not found',
          });
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  '/v1/builds/:id/artifact',
  apiKey,
  async (req, res, next) => {
    try {
      if (!storage) {
        return res.status(503).json({
          error: 'Artifact storage is not configured.',
        });
      }

      const id = paramString(req.params.id);
      const job = await getJob(id);

      if (!job) {
        return res.status(404).json({
          error: 'Build job not found',
        });
      }

      if (
        job.status !== 'succeeded' ||
        !job.artifactPath
      ) {
        return res.status(404).json({
          error:
            'No downloadable APK/AAB artifact is available.',
          status: job.status,
        });
      }

      const { data, error } = await storage.storage
        .from(artifactBucket)
        .createSignedUrl(job.artifactPath, 300, {
          download: true,
        });

      if (error || !data?.signedUrl) {
        return res.status(502).json({
          error:
            'Could not create a temporary artifact download link.',
        });
      }

      return res.json({
        jobId: id,
        expiresInSeconds: 300,
        downloadUrl: data.signedUrl,
      });
    } catch (error) {
      next(error);
    }
  },
);

// Worker operations.
app.post(
  '/internal/worker/claim',
  workerKey,
  async (_req, res, next) => {
    try {
      const job = await claimJob();
      return res.json({ job: job ?? null });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  '/internal/jobs/:id/status',
  workerKey,
  async (req, res, next) => {
    try {
      const id = paramString(req.params.id);

      const schema = z.object({
        status: z.enum([
          'running',
          'succeeded',
          'failed',
        ]),
        artifactUrl: z.string().url().optional(),
        artifactPath: z.string().min(1).max(1024).optional(),
        error: z.string().max(2000).optional(),
        log: z.string().max(4000).optional(),
      });

      const parsed = schema.safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({
          error: 'Invalid worker status payload',
        });
      }

      const current = await getJob(id);

      if (!current) {
        return res.status(404).json({
          error: 'Build job not found',
        });
      }

      if (
        current.status === 'succeeded' ||
        current.status === 'failed'
      ) {
        return res.status(409).json({
          error: 'Job is already terminal',
        });
      }

      if (parsed.data.log) {
        await appendJobLog(current.id, parsed.data.log);
      }

      const updated = await updateJob(current.id, {
        status: parsed.data.status,
        artifactUrl: parsed.data.artifactUrl,
        artifactPath: parsed.data.artifactPath,
        error: parsed.data.error,
      });

      return res.json({ job: updated });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  '/internal/jobs/:id/logs',
  workerKey,
  async (req, res, next) => {
    try {
      const id = paramString(req.params.id);

      const parsed = z
        .object({
          line: z.string().min(1).max(4000),
        })
        .safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({
          error: 'Invalid log line',
        });
      }

      const job = await appendJobLog(
        id,
        parsed.data.line,
      );

      return job
        ? res.json({ ok: true })
        : res.status(404).json({
            error: 'Build job not found',
          });
    } catch (error) {
      next(error);
    }
  },
);

function mcpText(value: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(value),
      },
    ],
  };
}

function mcpError(message: string, details?: unknown) {
  return {
    isError: true,
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify({
          error: message,
          ...(details === undefined ? {} : { details }),
        }),
      },
    ],
  };
}

// MCP endpoint. Each request gets a fresh stateless server and transport.
// API-key callers retain all existing tools. OAuth callers only receive
// tools allowed by their granted scopes.
app.post('/mcp', mcpAuth, async (req, res) => {
  const server = new McpServer({
    name: 'andro',
    version: VERSION,
  });

  if (mcpHasScope(res, 'mcp:build')) {
    server.tool(
      'andro_create_build',
      'Submit an Android Gradle build for a public GitHub, GitLab, or Bitbucket repository. Returns a job ID; the build must still be executed by a registered worker.',
      {
        projectId: z.string().min(1).max(128).optional(),
        repoUrl: z.string().url(),
        ref: z.string().optional(),
        task: z.string().optional(),
        javaVersion: z.enum(['17']).optional(),
        androidPlatform: z.enum(['36']).optional(),
      },
      async (args) => {
        const parsed = buildSchema.safeParse(args);

        if (!parsed.success) {
          return mcpError(
            'Invalid build request',
            parsed.error.flatten(),
          );
        }

        try {
          const job = await createJob(parsed.data);

          return mcpText({
            job,
            warning:
              'The job is queued. A worker must execute Gradle before the build can succeed.',
          });
        } catch {
          return mcpError(
            'Could not create the build job. Check database availability.',
          );
        }
      },
    );
  }

  if (mcpHasScope(res, 'mcp:read')) {
    server.tool(
      'andro_get_build',
      'Get the status and metadata for a specific build job using its UUID.',
      {
        jobId: z.string().uuid(),
      },
      async ({ jobId }) => {
        try {
          const job = await getJob(jobId);

          return job
            ? mcpText({ job })
            : mcpError('Build job not found', { jobId });
        } catch {
          return mcpError(
            'Could not retrieve build status.',
          );
        }
      },
    );

    server.tool(
      'andro_list_builds',
      'List recent Andro build jobs, including their status and available metadata.',
      {},
      async () => {
        try {
          const jobs = await listJobs();

          return mcpText({
            count: jobs.length,
            jobs: jobs.slice(0, 50),
          });
        } catch {
          return mcpError(
            'Could not retrieve the build list.',
          );
        }
      },
    );

    server.tool(
      'andro_get_build_logs',
      'Retrieve the persisted log lines and error information for a build job.',
      {
        jobId: z.string().uuid(),
      },
      async ({ jobId }) => {
        try {
          const job = await getJob(jobId);

          if (!job) {
            return mcpError(
              'Build job not found',
              { jobId },
            );
          }

          return mcpText({
            jobId: job.id,
            status: job.status,
            logs: job.logs,
            error: job.error ?? null,
          });
        } catch {
          return mcpError(
            'Unable to retrieve build logs.',
          );
        }
      },
    );

    server.tool(
      'andro_get_build_artifact',
      'Generate a temporary download link for the APK/AAB from a successfully completed build. The link expires after five minutes.',
      {
        jobId: z.string().uuid(),
      },
      async ({ jobId }) => {
        try {
          if (!storage) {
            return mcpError(
              'Artifact storage is not configured.',
            );
          }

          const job = await getJob(jobId);

          if (!job) {
            return mcpError(
              'Build job not found',
              { jobId },
            );
          }

          if (
            job.status !== 'succeeded' ||
            !job.artifactPath
          ) {
            return mcpError(
              'No downloadable APK/AAB artifact is available.',
              {
                status: job.status,
                hint:
                  'Inspect the build status and logs. A successful Gradle task does not guarantee that an APK/AAB was produced.',
              },
            );
          }

          const { data, error } = await storage.storage
            .from(artifactBucket)
            .createSignedUrl(job.artifactPath, 300, {
              download: true,
            });

          if (error || !data?.signedUrl) {
            return mcpError(
              'Could not create a temporary artifact download link.',
            );
          }

          return mcpText({
            jobId: job.id,
            status: job.status,
            expiresInSeconds: 300,
            downloadUrl: data.signedUrl,
          });
        } catch {
          return mcpError(
            'Unable to create an artifact download link.',
          );
        }
      },
    );

    server.tool(
      'andro_get_server_status',
      'Check Andro database connectivity and configured capabilities without revealing credentials. This does not prove that a worker is online.',
      {},
      async () => {
        let database = 'unavailable';

        try {
          await pool.query('SELECT 1');
          database = 'connected';
        } catch {
          // Do not expose database errors or connection details.
        }

        return mcpText({
          service: 'andro-server',
          version: VERSION,
          database,
          workerTokenConfigured: Boolean(
            process.env.ANDRO_WORKER_TOKEN,
          ),
          artifactStorageConfigured: Boolean(storage),
          artifactBucket,
          supportedRepositoryHosts: [
            'github.com',
            'gitlab.com',
            'bitbucket.org',
          ],
          supportedJavaVersions: ['17'],
          supportedAndroidPlatforms: ['36'],
          tools: [
            ...(mcpHasScope(res, 'mcp:build')
              ? ['andro_create_build']
              : []),
            'andro_get_build',
            'andro_list_builds',
            'andro_get_build_logs',
            'andro_get_build_artifact',
            'andro_get_server_status',
          ],
          limitations: [
            'Only public Git repositories are supported.',
            'A queued job requires a registered worker.',
            'Project file editing is not implemented.',
            'Automated repair loops are not implemented.',
            'Emulator and instrumentation testing are not implemented.',
          ],
        });
      },
    );
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  res.on('close', () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error('MCP request failed');

    if (!res.headersSent) {
      res.status(500).json({
        error: 'MCP request failed',
        requestId: randomUUID(),
      });
    }
  }
});

app.use(
  (
    err: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
  ) => {
    console.error('Unhandled API error');

    if (!res.headersSent) {
      res.status(500).json({
        error: 'Internal server error',
        requestId: randomUUID(),
      });
    }
  },
);

export { app };
export default app;
