
import express, {
  type Request,
  type Response,
  type Router,
} from 'express';
import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { pool } from './store.js';

const SCOPES = ['mcp:read', 'mcp:build'] as const;
type OAuthScope = (typeof SCOPES)[number];

const configuredBaseUrl =
  process.env.ANDRO_PUBLIC_URL?.trim() ||
  (process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
    : process.env.VERCEL_URL
      ? `https://${process.env.VERCEL_URL}`
      : 'https://andro-server-kappa.vercel.app');

function normalizeBaseUrl(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error('ANDRO_PUBLIC_URL must be an HTTPS origin.');
  }
  return parsed.origin;
}

export const OAUTH_ISSUER = normalizeBaseUrl(configuredBaseUrl);
export const OAUTH_RESOURCE = `${OAUTH_ISSUER}/mcp`;
const GITHUB_CALLBACK_URL =
  process.env.GITHUB_OAUTH_REDIRECT_URI?.trim() ||
  `${OAUTH_ISSUER}/oauth/github/callback`;

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
const LOGIN_TRANSACTION_TTL_SECONDS = 10 * 60;

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function randomSecret(): string {
  return randomBytes(32).toString('base64url');
}

function stringValue(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && typeof value[0] === 'string') {
    return value[0];
  }
  return '';
}

function parseScopes(value: unknown): OAuthScope[] | undefined {
  const raw = stringValue(value).trim();
  const requested = raw ? raw.split(/\s+/) : ['mcp:read'];
  const unique = [...new Set(requested)];
  if (unique.length === 0 || unique.some((scope) => !SCOPES.includes(scope as OAuthScope))) {
    return undefined;
  }
  return unique as OAuthScope[];
}

function isValidRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.username || url.password || url.hash) return false;
    if (url.protocol === 'https:') return true;
    return (
      url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    );
  } catch {
    return false;
  }
}

function htmlEscape(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    };
    return entities[character] ?? character;
  });
}

function oauthError(
  res: Response,
  status: number,
  error: string,
  description?: string,
) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  return res.status(status).json({
    error,
    ...(description ? { error_description: description } : {}),
  });
}

function setNoStore(res: Response) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
}

type ConsentFailureReason =
  | 'transaction_missing'
  | 'transaction_expired'
  | 'github_authentication_missing'
  | 'nonce_mismatch';

function logConsentValidationFailure(
  stage: 'page' | 'submit',
  reason: ConsentFailureReason,
) {
  // Never log OAuth state, nonce, authorization codes, or bearer tokens.
  console.warn('[oauth] consent validation failed', { stage, reason });
}

/*
 * Diagnostic fingerprint of the configured PostgreSQL target.
 * This deliberately excludes usernames, passwords, query parameters,
 * and the original database connection URL.
 */
function oauthDatabaseTargetFingerprint(): string {
  const candidates = [
    process.env.DATABASE_URL,
    process.env.SUPABAS_POSTGRES_URL,
    process.env.SUPABAS_POSTGRES_PRISMA_URL,
    process.env.SUPABAS_POSTGRES_URL_NON_POOLING,
  ];

  const connectionString = candidates.find(
    (value): value is string =>
      typeof value === 'string' &&
      /^postgres(?:ql)?:\/\//i.test(value.trim()),
  );

  if (!connectionString) return 'unavailable';

  try {
    const parsed = new URL(connectionString.trim());

    return createHash('sha256')
      .update(parsed.hostname + parsed.pathname)
      .digest('hex')
      .slice(0, 12);
  } catch {
    return 'unavailable';
  }
}

function logLoginTransactionTrace(
  stage:
    | 'authorize_create'
    | 'github_callback_lookup'
    | 'github_identity_update'
    | 'consent_page_lookup'
    | 'consent_submit_lookup',
  outcome: string,
) {
  // Never log OAuth state, nonce, authorization codes, or bearer tokens.
  console.info('[oauth] login transaction trace', {
    stage,
    outcome,
    database: oauthDatabaseTargetFingerprint(),
  });
}

/*
 * OAuth token-exchange diagnostics.
 *
 * Only stage, outcome and a non-reversible database fingerprint
 * are recorded. Never log authorization codes, PKCE verifiers,
 * PKCE challenges, client IDs, access tokens, refresh tokens,
 * request bodies, or credential values.
 */
function logOAuthTokenTrace(stage: string, outcome: string) {
  console.info('[oauth] token exchange trace', {
    stage,
    outcome,
    database: oauthDatabaseTargetFingerprint(),
  });
}

/*
 * Consent handoff diagnostics. Destination details are restricted to
 * hostname and pathname; query strings can contain OAuth codes and state.
 */
function logConsentHandoffTrace(
  stage: string,
  outcome: string,
  destination?: URL,
) {
  console.info('[oauth] consent handoff trace', {
    stage,
    outcome,
    database: oauthDatabaseTargetFingerprint(),
    ...(destination
      ? { destination: { hostname: destination.hostname, pathname: destination.pathname } }
      : {}),
  });
}

function isGithubOAuthConfigured(): boolean {
  return Boolean(
    process.env.GITHUB_CLIENT_ID?.trim() &&
    process.env.GITHUB_CLIENT_SECRET?.trim(),
  );
}

async function ownerMatchesGithubUser(
  githubUserId: string,
  githubLogin: string,
): Promise<boolean> {
  const current = await pool.query(
    `SELECT provider_user_id
       FROM andro.oauth_authorized_principal
      WHERE singleton = true`,
  );

  if (!current.rowCount) {
    const expectedOwnerId =
      process.env.ANDRO_OAUTH_OWNER_GITHUB_ID?.trim();

    // Safe first-owner enrollment: the environment variable must already
    // identify the exact GitHub numeric user ID. A visitor cannot claim it.
    if (!expectedOwnerId || expectedOwnerId !== githubUserId) {
      return false;
    }

    await pool.query(
      `INSERT INTO andro.oauth_authorized_principal
         (singleton, provider, provider_user_id, provider_login)
       VALUES (true, 'github', $1, $2)
       ON CONFLICT (singleton) DO NOTHING`,
      [githubUserId, githubLogin],
    );
  }

  const verified = await pool.query(
    `SELECT provider_user_id
       FROM andro.oauth_authorized_principal
      WHERE singleton = true`,
  );

  return (
    verified.rowCount === 1 &&
    verified.rows[0].provider_user_id === githubUserId
  );
}

async function insertTokenPair(
  client: any,
  clientId: string,
  scopes: OAuthScope[],
  resource: string,
  tokenFamilyId = randomUUID(),
) {
  const accessToken = randomSecret();
  const refreshToken = randomSecret();

  await client.query(
    `INSERT INTO andro.oauth_access_tokens
       (token_hash, client_id, scopes, resource, expires_at)
     VALUES ($1, $2, $3, $4, now() + ($5 * interval '1 second'))`,
    [
      sha256(accessToken),
      clientId,
      scopes,
      resource,
      ACCESS_TOKEN_TTL_SECONDS,
    ],
  );

  await client.query(
    `INSERT INTO andro.oauth_refresh_tokens
       (token_hash, token_family_id, client_id, scopes, resource, expires_at)
     VALUES ($1, $2, $3, $4, $5, now() + ($6 * interval '1 second'))`,
    [
      sha256(refreshToken),
      tokenFamilyId,
      clientId,
      scopes,
      resource,
      REFRESH_TOKEN_TTL_SECONDS,
    ],
  );

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
    scope: scopes.join(' '),
  };
}

export async function verifyOAuthAccessToken(
  token: string,
  resource: string,
): Promise<{ clientId: string; scopes: string[] } | undefined> {
  if (!token || token.length < 32 || token.length > 512) return undefined;

  const result = await pool.query(
    `SELECT client_id, scopes
       FROM andro.oauth_access_tokens
      WHERE token_hash = $1
        AND resource = $2
        AND revoked_at IS NULL
        AND expires_at > now()
      LIMIT 1`,
    [sha256(token), resource],
  );

  if (result.rowCount !== 1) return undefined;

  return {
    clientId: result.rows[0].client_id,
    scopes: result.rows[0].scopes as string[],
  };
}

export function createOAuthRouter(): Router {
  const router = express.Router();
  router.use(express.urlencoded({ extended: false, limit: '16kb' }));

  router.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.json({
      resource: OAUTH_RESOURCE,
      authorization_servers: [OAUTH_ISSUER],
      scopes_supported: [...SCOPES],
      bearer_methods_supported: ['header'],
    });
  });

  router.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
    res.json({
      resource: OAUTH_RESOURCE,
      authorization_servers: [OAUTH_ISSUER],
      scopes_supported: [...SCOPES],
      bearer_methods_supported: ['header'],
    });
  });

  router.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({
      issuer: OAUTH_ISSUER,
      authorization_endpoint: `${OAUTH_ISSUER}/oauth/authorize`,
      token_endpoint: `${OAUTH_ISSUER}/oauth/token`,
      registration_endpoint: `${OAUTH_ISSUER}/oauth/register`,
      revocation_endpoint: `${OAUTH_ISSUER}/oauth/revoke`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: [...SCOPES],
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: false,
    });
  });

  router.post('/oauth/register', async (req, res) => {
    try {
      const body = req.body as Record<string, unknown>;
      const redirectUris = body.redirect_uris;
      const clientName =
        stringValue(body.client_name).trim().slice(0, 255) || 'MCP client';

      if (
        !Array.isArray(redirectUris) ||
        redirectUris.length < 1 ||
        redirectUris.length > 20 ||
        !redirectUris.every(
          (uri) => typeof uri === 'string' && isValidRedirectUri(uri),
        )
      ) {
        return oauthError(
          res,
          400,
          'invalid_client_metadata',
          'redirect_uris must contain 1 to 20 valid HTTPS or loopback HTTP URIs.',
        );
      }

      if (
        body.response_types !== undefined &&
        (!Array.isArray(body.response_types) ||
          !body.response_types.includes('code'))
      ) {
        return oauthError(res, 400, 'invalid_client_metadata');
      }

      if (
        body.token_endpoint_auth_method !== undefined &&
        body.token_endpoint_auth_method !== 'none'
      ) {
        return oauthError(res, 400, 'invalid_client_metadata');
      }

      const clientId = randomBytes(24).toString('base64url');
      await pool.query(
        `INSERT INTO andro.oauth_clients
           (client_id, client_name, redirect_uris, grant_types,
            response_types, token_endpoint_auth_method)
         VALUES ($1, $2, $3, $4, $5, 'none')`,
        [
          clientId,
          clientName,
          [...new Set(redirectUris as string[])],
          ['authorization_code', 'refresh_token'],
          ['code'],
        ],
      );

      setNoStore(res);
      return res.status(201).json({
        client_id: clientId,
        client_name: clientName,
        redirect_uris: [...new Set(redirectUris as string[])],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        client_id_issued_at: Math.floor(Date.now() / 1000),
      });
    } catch {
      return oauthError(res, 500, 'server_error');
    }
  });

  router.get('/oauth/authorize', async (req, res) => {
    try {
      const clientId = stringValue(req.query.client_id);
      const redirectUri = stringValue(req.query.redirect_uri);
      const responseType = stringValue(req.query.response_type);
      const codeChallenge = stringValue(req.query.code_challenge);
      const challengeMethod = stringValue(req.query.code_challenge_method);
      const clientState = stringValue(req.query.state);
      const resource = stringValue(req.query.resource);
      const scopes = parseScopes(req.query.scope);

      if (
        !clientId ||
        !redirectUri ||
        responseType !== 'code' ||
        !scopes ||
        !clientState ||
        clientState.length > 512 ||
        challengeMethod !== 'S256' ||
        !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge) ||
        resource !== OAUTH_RESOURCE
      ) {
        return oauthError(res, 400, 'invalid_request');
      }

      if (!isGithubOAuthConfigured()) {
        return oauthError(
          res,
          503,
          'temporarily_unavailable',
          'GitHub OAuth is not configured on the server.',
        );
      }

      const client = await pool.query(
        `SELECT client_id, redirect_uris
           FROM andro.oauth_clients
          WHERE client_id = $1`,
        [clientId],
      );

      if (
        client.rowCount !== 1 ||
        !(client.rows[0].redirect_uris as string[]).includes(redirectUri)
      ) {
        return oauthError(res, 400, 'invalid_request');
      }

      await pool.query(
        `DELETE FROM andro.oauth_login_transactions
          WHERE expires_at < now()`,
      );

      const loginState = randomSecret();

      const createdTransaction = await pool.query(
        `INSERT INTO andro.oauth_login_transactions
           (state_hash, client_id, redirect_uri, client_state,
            code_challenge, scopes, resource, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7,
                 now() + ($8 * interval '1 second'))
         RETURNING state_hash`,
        [
          sha256(loginState),
          clientId,
          redirectUri,
          clientState,
          codeChallenge,
          scopes,
          resource,
          LOGIN_TRANSACTION_TTL_SECONDS,
        ],
      );

      logLoginTransactionTrace(
        'authorize_create',
        createdTransaction.rowCount === 1 ? 'created' : 'insert_not_confirmed',
      );

      if (createdTransaction.rowCount !== 1) {
        throw new Error('OAuth login transaction insert was not confirmed.');
      }

      const githubUrl = new URL('https://github.com/login/oauth/authorize');
      githubUrl.searchParams.set('client_id', process.env.GITHUB_CLIENT_ID!.trim());
      githubUrl.searchParams.set('redirect_uri', GITHUB_CALLBACK_URL);
      githubUrl.searchParams.set('scope', 'read:user');
      githubUrl.searchParams.set('state', loginState);
      githubUrl.searchParams.set('allow_signup', 'false');

      return res.redirect(302, githubUrl.toString());
    } catch {
      return oauthError(res, 500, 'server_error');
    }
  });

  router.get('/oauth/github/callback', async (req, res) => {
    try {
      const state = stringValue(req.query.state);
      const githubCode = stringValue(req.query.code);
      const providerError = stringValue(req.query.error);

      if (!state || state.length > 512) {
        return res.status(400).send('Invalid OAuth login state.');
      }

      const transaction = await pool.query(
        `SELECT *
           FROM andro.oauth_login_transactions
          WHERE state_hash = $1
            AND expires_at > now()
            AND authenticated_at IS NULL`,
        [sha256(state)],
      );

      logLoginTransactionTrace(
        'github_callback_lookup',
        transaction.rowCount === 1
          ? 'found_eligible_transaction'
          : 'eligible_transaction_not_found',
      );

      if (transaction.rowCount !== 1) {
        const diagnostic = await pool.query(
          `SELECT expires_at, authenticated_at
             FROM andro.oauth_login_transactions
            WHERE state_hash = $1`,
          [sha256(state)],
        );

        const diagnosticRow = diagnostic.rows[0];

        const reason =
          !diagnosticRow
            ? 'missing'
            : new Date(diagnosticRow.expires_at).getTime() <= Date.now()
              ? 'expired'
              : diagnosticRow.authenticated_at
                ? 'already_authenticated'
                : 'eligibility_filter_mismatch';

        logLoginTransactionTrace('github_callback_lookup', reason);

        return res.status(400).send('This login request has expired. Restart the Claude connection.');
      }

      if (providerError || !githubCode) {
        await pool.query(
          `DELETE FROM andro.oauth_login_transactions WHERE state_hash = $1`,
          [sha256(state)],
        );
        return res.status(401).send('GitHub sign-in was cancelled or denied. You can close this page.');
      }

      const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: process.env.GITHUB_CLIENT_ID!.trim(),
          client_secret: process.env.GITHUB_CLIENT_SECRET!.trim(),
          code: githubCode,
          redirect_uri: GITHUB_CALLBACK_URL,
        }),
      });

      if (!tokenResponse.ok) {
        return res.status(502).send('GitHub sign-in could not be verified.');
      }

      const tokenData = (await tokenResponse.json()) as {
        access_token?: string;
        error?: string;
      };

      if (!tokenData.access_token) {
        return res.status(401).send('GitHub did not issue an access token.');
      }

      const userResponse = await fetch('https://api.github.com/user', {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${tokenData.access_token}`,
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'Andro-Server-OAuth',
        },
      });

      if (!userResponse.ok) {
        return res.status(502).send('Could not retrieve the GitHub account identity.');
      }

      const githubUser = (await userResponse.json()) as {
        id?: number;
        login?: string;
      };

      const githubUserId =
        typeof githubUser.id === 'number' ? String(githubUser.id) : '';

      const githubLogin =
        typeof githubUser.login === 'string' ? githubUser.login : '';

      if (!githubUserId || !githubLogin) {
        return res.status(502).send('GitHub returned an invalid account identity.');
      }

      const isOwner = await ownerMatchesGithubUser(githubUserId, githubLogin);

      if (!isOwner) {
        await pool.query(
          `DELETE FROM andro.oauth_login_transactions WHERE state_hash = $1`,
          [sha256(state)],
        );
        return res.status(403).send('This GitHub account is not the authorized Andro owner.');
      }

      const consentNonce = randomSecret();

      const updated = await pool.query(
        `UPDATE andro.oauth_login_transactions
            SET github_user_id = $2,
                github_login = $3,
                consent_nonce_hash = $4,
                authenticated_at = now()
          WHERE state_hash = $1
            AND expires_at > now()
            AND authenticated_at IS NULL
          RETURNING state_hash`,
        [sha256(state), githubUserId, githubLogin, sha256(consentNonce)],
      );

      logLoginTransactionTrace(
        'github_identity_update',
        updated.rowCount === 1 ? 'updated' : 'update_not_applied',
      );

      if (updated.rowCount !== 1) {
        const diagnostic = await pool.query(
          `SELECT expires_at, authenticated_at
             FROM andro.oauth_login_transactions
            WHERE state_hash = $1`,
          [sha256(state)],
        );

        const diagnosticRow = diagnostic.rows[0];

        const reason =
          !diagnosticRow
            ? 'missing'
            : new Date(diagnosticRow.expires_at).getTime() <= Date.now()
              ? 'expired'
              : diagnosticRow.authenticated_at
                ? 'already_authenticated'
                : 'update_filter_mismatch';

        logLoginTransactionTrace('github_identity_update', reason);

        return res.status(400).send('This login request has expired. Restart the Claude connection.');
      }

      const consentUrl = new URL('/oauth/consent', OAUTH_ISSUER);
      consentUrl.searchParams.set('state', state);
      consentUrl.searchParams.set('nonce', consentNonce);

      return res.redirect(302, consentUrl.toString());
    } catch {
      return res.status(500).send('Andro could not complete GitHub sign-in.');
    }
  });

  router.get('/oauth/consent', async (req, res) => {
    try {
      const state = stringValue(req.query.state);
      const nonce = stringValue(req.query.nonce);

      if (!state || !nonce || state.length > 512 || nonce.length > 512) {
        return res.status(400).send('Invalid consent request.');
      }

      const result = await pool.query(
        `SELECT t.client_id, t.redirect_uri, t.scopes, t.expires_at,
                t.authenticated_at, t.github_user_id, t.github_login,
                t.consent_nonce_hash, c.client_name
           FROM andro.oauth_login_transactions AS t
           JOIN andro.oauth_clients AS c ON c.client_id = t.client_id
          WHERE t.state_hash = $1`,
        [sha256(state)],
      );

      logLoginTransactionTrace(
        'consent_page_lookup',
        result.rowCount === 1 ? 'found' : 'not_found',
      );

      if (result.rowCount !== 1) {
        logConsentValidationFailure('page', 'transaction_missing');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      const row = result.rows[0];

      if (new Date(row.expires_at).getTime() <= Date.now()) {
        logConsentValidationFailure('page', 'transaction_expired');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      if (!row.authenticated_at) {
        logConsentValidationFailure('page', 'github_authentication_missing');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      if (
        typeof row.consent_nonce_hash !== 'string' ||
        !safeEqual(row.consent_nonce_hash, sha256(nonce))
      ) {
        logConsentValidationFailure('page', 'nonce_mismatch');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      const clientName = htmlEscape(String(row.client_name));
      const githubLogin = htmlEscape(String(row.github_login));

      const scopeLabels = (row.scopes as string[])
        .map((scope) =>
          scope === 'mcp:build'
            ? '<li><strong>Build access:</strong> submit Android build jobs.</li>'
            : '<li><strong>Read access:</strong> view build status, logs, artifacts, and server status.</li>',
        )
        .join('');

      // A fresh nonce authorizes only the script served with this consent page.
      const consentScriptNonce = randomBytes(18).toString('base64');

      res.set(
        'Content-Security-Policy',
        `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${consentScriptNonce}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
      );
      res.set('Referrer-Policy', 'no-referrer');
      res.set('Cache-Control', 'no-store');

      return res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize Andro</title>
<style>body{font:16px system-ui,sans-serif;background:#111;color:#f5f5f5;max-width:560px;margin:8vh auto;padding:24px}main{border:1px solid #444;border-radius:16px;padding:24px}h1{font-size:24px}li{margin:12px 0}button{padding:12px 18px;border:0;border-radius:8px;font-weight:600;margin:12px 8px 0 0;cursor:pointer}.approve{background:#fff;color:#111}.deny{background:#333;color:#fff}small{color:#aaa}</style></head>
<body><main><h1>Authorize Andro</h1><p><strong>${clientName}</strong> is requesting access to your Andro server.</p><p>Signed in as GitHub account <strong>${githubLogin}</strong>.</p><ul>${scopeLabels}</ul><p>Only the authorized Andro owner can approve this connection. You can revoke access later.</p>
<form id="andro-consent-form" method="post" action="/oauth/consent"><input type="hidden" name="state" value="${htmlEscape(state)}"><input type="hidden" name="nonce" value="${htmlEscape(nonce)}"><button class="approve" name="decision" value="approve">Approve access</button><button class="deny" name="decision" value="deny">Deny</button></form><p><small>Andro never receives access to your GitHub repositories through this sign-in. GitHub is used only to verify your account identity.</small></p></main>
<script nonce="${consentScriptNonce}">
(() => {
  const form = document.getElementById('andro-consent-form');
  if (!form) return;

  let submitted = false;

  form.addEventListener('submit', (event) => {
    if (submitted) {
      event.preventDefault();
      return;
    }

    submitted = true;

    const submitter = event.submitter;

    for (const button of form.querySelectorAll('button')) {
      if (button !== submitter) {
        button.disabled = true;
      }
    }

    if (submitter) {
      submitter.textContent = 'Processing…';
    }
  });
})();
</script>
</body></html>`);
    } catch {
      return res.status(500).send('Could not load the consent page.');
    }
  });

  router.post('/oauth/consent', async (req, res) => {
    const state = stringValue(req.body?.state);
    const nonce = stringValue(req.body?.nonce);
    const decision = stringValue(req.body?.decision);

    if (!state || !nonce || state.length > 512 || nonce.length > 512) {
      return res.status(400).send('Invalid consent submission.');
    }

    let db: any;
    let consentStage = 'database_connection';

    try {
      db = await pool.connect();
      await db.query('BEGIN');

      const found = await db.query(
        `SELECT t.*, c.redirect_uris
           FROM andro.oauth_login_transactions AS t
           JOIN andro.oauth_clients AS c ON c.client_id = t.client_id
          WHERE t.state_hash = $1
          FOR UPDATE OF t`,
        [sha256(state)],
      );

      logLoginTransactionTrace(
        'consent_submit_lookup',
        found.rowCount === 1 ? 'found' : 'not_found',
      );

      if (found.rowCount !== 1) {
        await db.query('ROLLBACK');
        logConsentValidationFailure('submit', 'transaction_missing');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      const row = found.rows[0];

      if (new Date(row.expires_at).getTime() <= Date.now()) {
        await db.query('ROLLBACK');
        logConsentValidationFailure('submit', 'transaction_expired');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      if (!row.authenticated_at) {
        await db.query('ROLLBACK');
        logConsentValidationFailure('submit', 'github_authentication_missing');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      if (
        typeof row.consent_nonce_hash !== 'string' ||
        !safeEqual(row.consent_nonce_hash, sha256(nonce))
      ) {
        await db.query('ROLLBACK');
        logConsentValidationFailure('submit', 'nonce_mismatch');
        return res.status(400).send('This consent request is invalid or has expired.');
      }

      const owner = await db.query(
        `SELECT provider_user_id
           FROM andro.oauth_authorized_principal
          WHERE singleton = true`,
      );

      if (
        owner.rowCount !== 1 ||
        owner.rows[0].provider_user_id !== row.github_user_id
      ) {
        await db.query('ROLLBACK');
        return res.status(403).send('The authorized Andro owner has changed.');
      }

      consentStage = 'transaction_delete';
      const deletedTransaction = await db.query(
        `DELETE FROM andro.oauth_login_transactions WHERE state_hash = $1`,
        [sha256(state)],
      );
      logConsentHandoffTrace(
        'transaction_delete',
        deletedTransaction.rowCount === 1 ? 'deleted' : 'delete_not_confirmed',
      );

      if (decision !== 'approve') {
        consentStage = 'denial_commit';
        await db.query('COMMIT');
        logConsentHandoffTrace('denial_commit', 'committed');

        const denied = new URL(String(row.redirect_uri));
        denied.searchParams.set('error', 'access_denied');
        denied.searchParams.set('iss', OAUTH_ISSUER);

        if (row.client_state) {
          denied.searchParams.set('state', String(row.client_state));
        }

        const denialResponse = res.redirect(302, denied.toString());
        logConsentHandoffTrace('denial_redirect_response', `status_${res.statusCode}`, denied);
        return denialResponse;
      }

      const authorizationCode = randomSecret();

      consentStage = 'authorization_code_insert';
      const insertedCode = await db.query(
        `INSERT INTO andro.oauth_authorization_codes
           (code_hash, client_id, redirect_uri, code_challenge,
            code_challenge_method, scopes, resource, expires_at)
         VALUES ($1, $2, $3, $4, 'S256', $5, $6,
                 now() + ($7 * interval '1 second'))`,
        [
          sha256(authorizationCode),
          row.client_id,
          row.redirect_uri,
          row.code_challenge,
          row.scopes,
          row.resource,
          AUTHORIZATION_CODE_TTL_SECONDS,
        ],
      );
      logConsentHandoffTrace(
        'authorization_code_insert',
        insertedCode.rowCount === 1 ? 'inserted' : 'insert_not_confirmed',
      );

      consentStage = 'approval_commit';
      await db.query('COMMIT');
      logConsentHandoffTrace('approval_commit', 'committed');

      consentStage = 'callback_redirect_construction';
      const callback = new URL(String(row.redirect_uri));
      callback.searchParams.set('code', authorizationCode);
      callback.searchParams.set('iss', OAUTH_ISSUER);

      if (row.client_state) {
        callback.searchParams.set('state', String(row.client_state));
      }
      logConsentHandoffTrace('callback_redirect_construction', 'constructed', callback);

      consentStage = 'callback_redirect_response';
      const callbackResponse = res.redirect(302, callback.toString());
      logConsentHandoffTrace(
        'callback_redirect_response',
        `status_${res.statusCode}`,
        callback,
      );
      return callbackResponse;
    } catch {
      logConsentHandoffTrace('consent_failure', consentStage);
      if (db) {
        try {
          await db.query('ROLLBACK');
        } catch {
          /* ignore rollback failure */
        }
      }

      return res.status(500).send('Andro could not complete the authorization.');
    } finally {
      db?.release();
    }
  });

  router.post('/oauth/token', async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const grantType = stringValue(body.grant_type);
    const clientId = stringValue(body.client_id);
    const resource = stringValue(body.resource);
    let diagnosticStage = 'token_request';

    const contentType =
      req.is('application/x-www-form-urlencoded') ? 'form' :
      req.is('application/json') ? 'json' : 'other';

    logOAuthTokenTrace(
      'token_request',
      `received_${contentType}_${grantType === 'authorization_code' || grantType === 'refresh_token' ? grantType : 'other_grant'}`,
    );

    if (!clientId) {
      logOAuthTokenTrace('token_client_validation', 'missing_client_id');
      return oauthError(res, 400, 'invalid_request');
    }
    logOAuthTokenTrace('token_client_validation', 'client_id_present');

    if (resource !== OAUTH_RESOURCE) {
      logOAuthTokenTrace('token_resource_validation', 'request_resource_mismatch');
      return oauthError(res, 400, 'invalid_request');
    }
    logOAuthTokenTrace('token_resource_validation', 'request_resource_matched');

    let db: any;

    try {
      db = await pool.connect();
      await db.query('BEGIN');

      if (grantType === 'authorization_code') {
        const code = stringValue(body.code);
        const redirectUri = stringValue(body.redirect_uri);
        const verifier = stringValue(body.code_verifier);

        diagnosticStage = 'token_request_validation';
        if (!code || !redirectUri || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
          logOAuthTokenTrace('token_request_validation', 'missing_or_invalid_code_redirect_or_verifier');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_request');
        }
        logOAuthTokenTrace('token_request_validation', 'required_parameters_present');

        diagnosticStage = 'token_code_lookup';
        const found = await db.query(
          `SELECT *
             FROM andro.oauth_authorization_codes
            WHERE code_hash = $1
            FOR UPDATE`,
          [sha256(code)],
        );

        logOAuthTokenTrace(
          'token_code_lookup',
          found.rowCount === 1 ? 'found' : 'not_found',
        );

        if (found.rowCount !== 1) {
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }

        const row = found.rows[0];

        diagnosticStage = 'token_code_validation';
        if (row.consumed_at) {
          logOAuthTokenTrace('token_code_validation', 'already_consumed');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }

        if (new Date(row.expires_at).getTime() <= Date.now()) {
          logOAuthTokenTrace('token_code_validation', 'expired');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }
        logOAuthTokenTrace('token_code_validation', 'unused_and_unexpired');

        diagnosticStage = 'token_client_validation';
        if (row.client_id !== clientId) {
          logOAuthTokenTrace('token_client_validation', 'client_id_mismatch');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }
        logOAuthTokenTrace('token_client_validation', 'matched');

        diagnosticStage = 'token_redirect_validation';
        if (row.redirect_uri !== redirectUri) {
          logOAuthTokenTrace('token_redirect_validation', 'redirect_uri_mismatch');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }
        logOAuthTokenTrace('token_redirect_validation', 'matched');

        diagnosticStage = 'token_resource_validation';
        if (row.resource !== resource) {
          logOAuthTokenTrace('token_resource_validation', 'stored_resource_mismatch');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }
        logOAuthTokenTrace('token_resource_validation', 'stored_resource_matched');

        diagnosticStage = 'token_pkce_validation';
        const verifierChallenge = createHash('sha256')
          .update(verifier)
          .digest('base64url');

        if (
          typeof row.code_challenge !== 'string' ||
          !safeEqual(row.code_challenge, verifierChallenge)
        ) {
          logOAuthTokenTrace('token_pkce_validation', 'mismatch');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }
        logOAuthTokenTrace('token_pkce_validation', 'matched');

        diagnosticStage = 'token_code_consumption';
        const consumed = await db.query(
          `UPDATE andro.oauth_authorization_codes
              SET consumed_at = now()
            WHERE code_hash = $1 AND consumed_at IS NULL
            RETURNING code_hash`,
          [sha256(code)],
        );

        if (consumed.rowCount !== 1) {
          logOAuthTokenTrace('token_code_consumption', 'not_consumed');
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }
        logOAuthTokenTrace('token_code_consumption', 'consumed');

        diagnosticStage = 'token_pair_creation';
        const tokenPair = await insertTokenPair(
          db,
          clientId,
          row.scopes as OAuthScope[],
          resource,
        );
        logOAuthTokenTrace('token_pair_creation', 'pair_inserted_pending_commit');

        await db.query('COMMIT');
        logOAuthTokenTrace('token_pair_creation', 'committed');
        setNoStore(res);
        return res.json(tokenPair);
      }

      if (grantType === 'refresh_token') {
        const refreshToken = stringValue(body.refresh_token);

        if (!refreshToken) {
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_request');
        }

        const found = await db.query(
          `SELECT *
             FROM andro.oauth_refresh_tokens
            WHERE token_hash = $1
            FOR UPDATE`,
          [sha256(refreshToken)],
        );

        if (found.rowCount !== 1) {
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }

        const row = found.rows[0];

        if (row.consumed_at) {
          await db.query(
            `UPDATE andro.oauth_refresh_tokens
                SET revoked_at = COALESCE(revoked_at, now())
              WHERE token_family_id = $1`,
            [row.token_family_id],
          );

          await db.query(
            `UPDATE andro.oauth_access_tokens
                SET revoked_at = COALESCE(revoked_at, now())
              WHERE client_id = $1`,
            [row.client_id],
          );

          await db.query('COMMIT');
          return oauthError(res, 400, 'invalid_grant');
        }

        if (
          row.revoked_at ||
          new Date(row.expires_at).getTime() <= Date.now() ||
          row.client_id !== clientId ||
          row.resource !== resource
        ) {
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_grant');
        }

        const requestedScopes =
          body.scope === undefined
            ? (row.scopes as OAuthScope[])
            : parseScopes(body.scope);

        const existingScopes = row.scopes as string[];

        if (
          !requestedScopes ||
          requestedScopes.some((scope) => !existingScopes.includes(scope))
        ) {
          await db.query('ROLLBACK');
          return oauthError(res, 400, 'invalid_scope');
        }

        await db.query(
          `UPDATE andro.oauth_refresh_tokens
              SET consumed_at = now()
            WHERE token_hash = $1 AND consumed_at IS NULL`,
          [sha256(refreshToken)],
        );

        const tokenPair = await insertTokenPair(
          db,
          clientId,
          requestedScopes,
          resource,
          row.token_family_id,
        );

        await db.query('COMMIT');
        setNoStore(res);
        return res.json(tokenPair);
      }

      await db.query('ROLLBACK');
      return oauthError(res, 400, 'unsupported_grant_type');
    } catch {
      logOAuthTokenTrace(diagnosticStage, 'database_or_runtime_error');
      try {
        await db.query('ROLLBACK');
      } catch {
        // The transaction may already have been rolled back.
      }

      return oauthError(res, 500, 'server_error');
    } finally {
      db?.release();
    }
  });

  router.post('/oauth/revoke', async (req, res) => {
    const token = stringValue(req.body?.token);

    if (!token) {
      setNoStore(res);
      return res.status(200).end();
    }

    const tokenHash = sha256(token);
    let db: any;

    try {
      db = await pool.connect();
      await db.query('BEGIN');

      const access = await db.query(
        `UPDATE andro.oauth_access_tokens
            SET revoked_at = COALESCE(revoked_at, now())
          WHERE token_hash = $1
          RETURNING client_id`,
        [tokenHash],
      );

      if (access.rowCount !== 1) {
        const refresh = await db.query(
          `SELECT token_family_id, client_id
             FROM andro.oauth_refresh_tokens
            WHERE token_hash = $1
            FOR UPDATE`,
          [tokenHash],
        );

        if (refresh.rowCount === 1) {
          await db.query(
            `UPDATE andro.oauth_refresh_tokens
                SET revoked_at = COALESCE(revoked_at, now())
              WHERE token_family_id = $1`,
            [refresh.rows[0].token_family_id],
          );

          await db.query(
            `UPDATE andro.oauth_access_tokens
                SET revoked_at = COALESCE(revoked_at, now())
              WHERE client_id = $1`,
            [refresh.rows[0].client_id],
          );
        }
      }

      await db.query('COMMIT');
      setNoStore(res);
      return res.status(200).end();
    } catch {
      if (db) {
        try {
          await db.query('ROLLBACK');
        } catch {
          /* ignore rollback failure */
        }
      }

      return oauthError(res, 500, 'server_error');
    } finally {
      db?.release();
    }
  });

  return router;
}
