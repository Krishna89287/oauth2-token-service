import { createHash } from 'node:crypto';
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

let pool: Pool;
let app: FastifyInstance;
let keys: Keys;

beforeAll(async () => {
  pool = createPool(DATABASE_URL);
  await migrate(pool);
  await seed(pool);
  keys = await generateKeys();
  app = buildServer({ config, pool, keys });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
});

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/**
 * RFC 6749 4.4.2 says the token endpoint takes form encoded bodies, and that is
 * what every OAuth client library sends. Posting JSON at it, which is what
 * app.inject does by default, tests a path no real client ever takes: the server
 * can answer 415 to the entire world and the suite would still be green.
 */
describe('the token endpoint speaks what real clients speak', () => {
  it('accepts a form encoded client_credentials request', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload:
        'grant_type=client_credentials&client_id=reporting-service' +
        '&client_secret=reporting-secret-do-not-use-in-production&scope=reports%3Aread',
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().access_token).toBeDefined();
    expect(res.json().scope).toBe('reports:read');
  });

  it('decodes percent encoding in a form body', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload:
        'grant_type=client_credentials&client_id=reporting-service' +
        '&client_secret=reporting-secret-do-not-use-in-production' +
        '&scope=reports%3Aread%20reports%3Awrite',
    });

    // A space is %20 or +, and a colon is %3A. Getting this wrong turns a valid
    // scope request into a rejected one.
    expect(res.json().scope).toBe('reports:read reports:write');
  });

  it('handles a plus sign as a space, the way form encoding says', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload:
        'grant_type=client_credentials&client_id=reporting-service' +
        '&client_secret=reporting-secret-do-not-use-in-production' +
        '&scope=reports:read+reports:write',
    });

    expect(res.json().scope).toBe('reports:read reports:write');
  });

  it('accepts a form encoded login, which is what a browser posts', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/authorize',
      headers: FORM,
      payload: new URLSearchParams({
        email: 'ada@example.com',
        password: 'correct-horse-battery',
        client_id: 'web-app',
        redirect_uri: 'http://localhost:5173/callback',
        scope: 'profile:read',
        code_challenge: createHash('sha256').update('v'.repeat(43)).digest('base64url'),
        code_challenge_method: 'S256',
      }).toString(),
    });

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toContain('code=');
  });

  it('still accepts JSON, because some clients insist', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: {
        grant_type: 'client_credentials',
        client_id: 'reporting-service',
        client_secret: 'reporting-secret-do-not-use-in-production',
      },
    });

    expect(res.statusCode).toBe(200);
  });

  it('rejects a body it cannot parse rather than misreading it', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'text/plain' },
      payload: 'grant_type=client_credentials',
    });

    // 415 would be the more literal answer. Fastify never gets that far: with no
    // parser registered for text/plain the body does not become an object, and
    // schema validation refuses it first. Either way nothing is issued, which is
    // the part that matters.
    expect(res.statusCode).toBe(400);
    expect(res.json().access_token).toBeUndefined();
  });
});
