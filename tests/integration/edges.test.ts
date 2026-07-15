import { createHash, randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { Config } from '../../src/config';
import { migrate } from '../../src/db/migrate';
import { createPool } from '../../src/db/pool';
import { seed } from '../../src/db/seed';
import { generateKeys, type Keys } from '../../src/oauth/tokens';
import { buildServer } from '../../src/server';

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://auth:auth@localhost:5432/auth_test';

const config: Config = {
  port: 0,
  databaseUrl: DATABASE_URL,
  issuer: 'http://localhost:3000',
  audience: 'api',
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 3600,
  authorizationCodeTtlSeconds: 60,
  logger: false,
  runMigrations: false,
};

const REDIRECT = 'http://localhost:5173/callback';
const SECOND_CLIENT = 'other-web-app';

let pool: Pool;
let app: FastifyInstance;
let keys: Keys;

beforeAll(async () => {
  pool = createPool(DATABASE_URL);
  await migrate(pool);
  await seed(pool);

  // A second public client, so "was this code issued to you" can be tested at all.
  await pool.query(
    `INSERT INTO clients (id, name, redirect_uris, allowed_scopes, allowed_grants)
     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING`,
    [SECOND_CLIENT, 'Another app', [REDIRECT], ['profile:read'], ['authorization_code', 'refresh_token']],
  );

  keys = await generateKeys();
  app = buildServer({ config, pool, keys });
  await app.ready();
});

afterAll(async () => {
  await pool.query(`DELETE FROM clients WHERE id = $1`, [SECOND_CLIENT]);
  await app.close();
  await pool.end();
});

beforeEach(async () => {
  await pool.query('TRUNCATE refresh_tokens, authorization_codes');
});

const token = (payload: Record<string, unknown>) =>
  app.inject({ method: 'POST', url: '/oauth/token', payload });

function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

async function codeFor(challenge: string, clientId = 'web-app'): Promise<string> {
  const res = await app.inject({
    method: 'POST',
    url: '/oauth/authorize',
    payload: {
      email: 'ada@example.com',
      password: 'correct-horse-battery',
      client_id: clientId,
      redirect_uri: REDIRECT,
      scope: 'profile:read',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    },
  });
  return new URL(res.headers.location as string).searchParams.get('code') as string;
}

describe('client authentication edges', () => {
  it('refuses a public client that sends a secret', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await codeFor(challenge);

    // web-app is public and has no secret on file. A request carrying one is
    // either a misconfigured client or someone guessing, and neither is the
    // registration we have.
    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      client_secret: 'i-invented-this',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_client');
  });

  it('refuses a request with no client_id at all', async () => {
    const res = await token({ grant_type: 'client_credentials' });
    expect(res.statusCode).toBe(401);
  });
});

describe('a code belongs to the client it was issued to', () => {
  it('refuses a code redeemed by a different client', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await codeFor(challenge, 'web-app');

    // Both are public clients registered for this redirect_uri, so the only thing
    // standing between them is the binding on the code itself.
    const res = await token({
      grant_type: 'authorization_code',
      client_id: SECOND_CLIENT,
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_grant');
  });
});

describe('grant type dispatch', () => {
  it('calls an unknown grant unsupported, not unauthorized', async () => {
    const res = await token({
      grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
    });

    // "unauthorized_client" reads as "ask an admin to enable it". The honest
    // answer is that this server does not implement it.
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('unsupported_grant_type');
  });

  it('refuses authorization_code with no code', async () => {
    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      redirect_uri: REDIRECT,
      code_verifier: 'a'.repeat(43),
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  it('refuses refresh_token with no token', async () => {
    const res = await token({ grant_type: 'refresh_token', client_id: 'web-app' });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  it('refuses an expired code', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await codeFor(challenge);
    await pool.query(`UPDATE authorization_codes SET expires_at = now() - interval '1 minute'`);

    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_grant');
  });

  it('refuses a revoked refresh token', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await codeFor(challenge);
    const session = (
      await token({
        grant_type: 'authorization_code',
        client_id: 'web-app',
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      })
    ).json();

    await pool.query(`UPDATE refresh_tokens SET revoked_at = now()`);

    const res = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: session.refresh_token,
    });

    expect(res.statusCode).toBe(400);
  });
});

describe('the authorize form', () => {
  it('refuses an unknown client', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=ghost&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${'a'.repeat(43)}`,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_client');
  });

  it('refuses a client not registered for the code grant, at the form', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=reporting-service&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${'a'.repeat(43)}`,
    });

    expect(res.statusCode).toBe(400);
  });

  it('renders without a scope', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${'a'.repeat(43)}`,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('No specific scopes requested');
  });

  it('refuses a challenge too short to be a real hash', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=short`,
    });

    expect(res.statusCode).toBe(400);
  });
});
