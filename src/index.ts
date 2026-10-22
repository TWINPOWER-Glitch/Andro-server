import 'dotenv/config';
import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { createJob, getJob, listJobs, appendJobLog, updateJob, claimJob, pool } from './store.js';
import { createClient } from '@supabase/supabase-js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseSecret =
  process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
const artifactBucket = process.env.ANDRO_ARTIFACT_BUCKET || 'andro-artifacts';

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
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') ?? false }));
app.use(express.json({ limit: '1mb' }));

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

  const provided = req.header('authorization')?.replace(/^Bearer\s+/i, '') ?? '';
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

const apiKey = (req: Request, res: Response, next: NextFunction) =>
  secureToken(
    req,
    res,
    next,
    process.env.ANDRO_API_KEY,
    'API key is not configured. Set ANDRO_API_KEY before exposing this server.',
  );

const workerKey = (req: Request, res: Response, next: NextFunction) =>
  secureToken(
    req,
    res,
    next,
    process.env.ANDRO_WORKER_TOKEN,
    'Worker token is not configured.',
  );

// Fix Express parameter types that may be string or string[].
function asStringParam(value: string | string[]): string {
  return Array.isArray(value) ? (value[0] ?? '') : value;
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      service: 'andro-server',
      status: 'ok',
      database: 'connected',
      time: new Date().toISOString(),
    });
  } catch {
    res.status(503).json({
      service: 'andro-server',
      status: 'degraded',
      database: 'unavailable',
      time: new Date().toISOString(),
    });
  }
});

app.get('/v1/status', apiKey, (_req, res) =>
  res.json({
    mode: 'durable-queue',
    workerConfigured: Boolean(process.env.ANDRO_WORKER_TOKEN),
    note: 'Jobs are persisted in PostgreSQL. A queued job is not a successful build; only worker-reported results establish completion.',
  }),
);

const buildSchema = z.object({
  projectId: z.string().min(1).max(128).default('default'),

  repoUrl: z
    .string()
    .url()
    .refine(
      (v) => {
        try {
          const u = new URL(v);
          const parts = u.pathname.split('/').filter(Boolean);

          return (
            u.protocol === 'https:' &&
            ['github.com', 'gitlab.com', 'bitbucket.org'].includes(
              u.hostname.toLowerCase(),
            ) &&
            !u.username &&
            !u.password &&
            !u.port &&
            !u.search &&
            !u.hash &&
            parts.length >= 2 &&
            parts.every((part) => part !== '.' && part !== '..')
          );
        } catch {
          return false;
        }
      },
      'Use a public HTTPS repository URL on github.com, gitlab.com, or bitbucket.org without credentials, query strings, or fragments',
    ),

  ref: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._/-]*$/, 'Invalid Git ref')
    .refine(
      (v) =>
        !v.startsWith('-') &&
        !v.includes('..') &&
        !v.endsWith('.') &&
        !v.endsWith('.lock') &&
        !v.includes('//'),
      'Invalid Git ref',
    )
    .default('main'),

  task: z
    .string()
    .min(1)
    .max(160)
    .default('assembleDebug')
    .refine(
      (v) => /^[A-Za-z0-9:_-]+$/.test(v),
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

    res.status(202).json({
      job,
      message: 'Accepted into the durable queue. This is not proof that a build has run.',
    });
  } catch (error) {
    next(error);
  }
});

app.get('/v1/builds', apiKey, async (_req, res, next) => {
  try {
    res.json({ jobs: await listJobs() });
  } catch (error) {
    next(error);
  }
});

app.get('/v1/builds/:id', apiKey, async (req, res, next) => {
  try {
    const id = asStringParam(req.params.id);
    const job = await getJob(id);

    return job
      ? res.json({ job })
      : res.status(404).json({ error: 'Build job not found' });
  } catch (error) {
    next(error);
  }
});

app.get('/v1/builds/:id/logs', apiKey, async (req, res, next) => {
  try {
    const id = asStringParam(req.params.id);
    const job = await getJob(id);

    return job
      ? res.json({ jobId: job.id, logs: job.logs })
      : res.status(404).json({ error: 'Build job not found' });
  } catch (error) {
    next(error);
  }
});

app.get('/v1/builds/:id/artifact', apiKey, async (req, res, next) => {
  try {
    if (!storage) {
      return res.status(503).json({
        error: 'Artifact storage is not configured.',
      });
    }

    const id = asStringParam(req.params.id);
    const job = await getJob(id);

    if (!job) {
      return res.status(404).json({ error: 'Build job not found' });
    }

    if (job.status !== 'succeeded' || !job.artifactPath) {
      return res.status(404).json({
        error: 'No downloadable APK/AAB artifact is available for this build.',
      });
    }

    const { data, error } = await storage.storage
      .from(artifactBucket)
      .createSignedUrl(job.artifactPath, 300, { download: true });

    if (error || !data?.signedUrl) {
      return res.status(502).json({
        error: 'Could not create a temporary artifact download link.',
      });
    }

    return res.json({
      jobId: job.id,
      expiresInSeconds: 300,
      downloadUrl: data.signedUrl,
    });
  } catch (error) {
    next(error);
  }
});

// Worker polling is backed by an atomic PostgreSQL claim (FOR UPDATE SKIP LOCKED).
app.post('/internal/worker/claim', workerKey, async (_req, res, next) => {
  try {
    const job = await claimJob();
    res.json({ job: job ?? null });
  } catch (error) {
    next(error);
  }
});

app.post('/internal/jobs/:id/status', workerKey, async (req, res, next) => {
  try {
    const id = asStringParam(req.params.id);

    const schema = z.object({
      status: z.enum(['running', 'succeeded', 'failed']),
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
      return res.status(404).json({ error: 'Build job not found' });
    }

    if (current.status === 'succeeded' || current.status === 'failed') {
      return res.status(409).json({ error: 'Job is already terminal' });
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

    res.json({ job: updated });
  } catch (error) {
    next(error);
  }
});

app.post('/internal/jobs/:id/logs', workerKey, async (req, res, next) => {
  try {
    const id = asStringParam(req.params.id);

    const parsed = z
      .object({
        line: z.string().min(1).max(4000),
      })
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid log line' });
    }

    const job = await appendJobLog(id, parsed.data.line);

    return job
      ? res.json({ ok: true })
      : res.status(404).json({ error: 'Build job not found' });
  } catch (error) {
    next(error);
  }
});

app.post('/mcp', apiKey, async (req, res) => {
  const server = new McpServer({
    name: 'andro',
    version: '0.2.0',
  });

  server.tool(
    'andro_create_build',
    'Submit an Android Gradle build job to the durable queue. A worker must execute it before it can succeed.',
    {
      projectId: z.string().min(1).max(128).optional(),
      repoUrl: z.string().url(),
      ref: z.string().optional(),
      task: z.string().optional(),
      javaVersion: z.enum(['17']).optional(),
      androidPlatform: z.enum(['36']).optional(),
    },
    async (args) => {
      try {
        const parsed = buildSchema.safeParse(args);

        if (!parsed.success) {
          return {
            isError: true,
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(parsed.error.flatten()),
              },
            ],
          };
        }

        const job = await createJob(parsed.data);

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                job,
                warning:
                  'Queued does not mean built. A registered worker must claim and execute this job.',
              }),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: 'text' as const,
              text: `Failed to create build job: ${
                error instanceof Error ? error.message : 'database error'
              }`,
            },
          ],
        };
      }
    },
  );

  server.tool(
    'andro_get_build',
    'Get status, metadata, and logs for a build job.',
    { jobId: z.string().uuid() },
    async ({ jobId }) => {
      const job = await getJob(jobId);

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(job ?? { error: 'Build job not found' }),
          },
        ],
        isError: !job,
      };
    },
  );

  server.tool(
    'andro_list_builds',
    'List recent Andro build jobs.',
    {},
    async () => ({
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify((await listJobs()).slice(0, 50)),
        },
      ],
    }),
  );

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
    console.error('MCP request failed', error);

    if (!res.headersSent) {
      res.status(500).json({ error: 'MCP request failed' });
    }
  }
});

app.use(
  (
    error: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
  ) => {
    console.error(error);

    if (!res.headersSent) {
      res.status(500).json({
        error: 'Internal server error',
        requestId: randomUUID(),
      });
    }
  },
);

export { app };
