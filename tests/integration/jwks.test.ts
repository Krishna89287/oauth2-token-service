import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
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

const CONFIDENTIAL = {
  client_id: 'reporting-service',
  client_secret: 'reporting-secret-do-not-use-in-production',
};

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

async function getAccessToken(scope = 'reports:read'): Promise<string> {
  const res = await app.inject({
    method: 'POST',
    url: '/oauth/token',
    payload: { grant_type: 'client_credentials', ...CONFIDENTIAL, scope },
  });
  return res.json().access_token;
}

describe('GET /.well-known/jwks.json', () => {
  it('publishes the public key', async () => {
    const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    const body = res.json();

    expect(res.statusCode).toBe(200);
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0].kty).toBe('RSA');
    expect(body.keys[0].alg).toBe('RS256');
    expect(body.keys[0].use).toBe('sig');
    expect(body.keys[0].kid).toBeDefined();
  });

  it('never publishes the private half', async () => {
    const body = (await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();
    const key = body.keys[0];

    // d, p and q are the private RSA parameters. Publishing any of them would let
    // the whole world mint our tokens. This is the single worst mistake this
    // service could make, so it gets its own test.
    expect(key.d).toBeUndefined();
    expect(key.p).toBeUndefined();
    expect(key.q).toBeUndefined();
    expect(key.dp).toBeUndefined();
    expect(key.dq).toBeUndefined();
    expect(key.qi).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('"d"');
  });

  it('lets a stranger verify a token with nothing but this endpoint', async () => {
    const token = await getAccessToken();
    const jwks = (await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();

    // This is the whole point of RS256: another service verifies without ever
    // holding anything that could sign.
    const keySet = createLocalJWKSet(jwks);
    const { payload } = await jwtVerify(token, keySet, {
      issuer: 'http://localhost:3000',
      audience: 'api',
    });

    expect(payload.sub).toBe('reporting-service');
  });

  it('names the key so a verifier knows which one signed', async () => {
    const token = await getAccessToken();
    const jwks = (await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();

    // Without a matching kid, key rotation means an outage.
    expect(decodeProtectedHeader(token).kid).toBe(jwks.keys[0].kid);
  });

  it('is cacheable, because an outage here should not break every verifier', async () => {
    const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(res.headers['cache-control']).toContain('max-age');
  });

  it('rejects a token signed by a different key', async () => {
    const other = await generateKeys();
    const otherApp = buildServer({ config, pool, keys: other });
    await otherApp.ready();

    const foreign = (
      await otherApp.inject({
        method: 'POST',
        url: '/oauth/token',
        payload: { grant_type: 'client_credentials', ...CONFIDENTIAL },
      })
    ).json().access_token;

    const jwks = (await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();
    const keySet = createLocalJWKSet(jwks);

    await expect(jwtVerify(foreign, keySet, { issuer: config.issuer, audience: 'api' })).rejects.toThrow();
    await otherApp.close();
  });
});

describe('discovery', () => {
  it('describes itself', async () => {
    const body = (
      await app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })
    ).json();

    expect(body.issuer).toBe('http://localhost:3000');
    expect(body.jwks_uri).toBe('http://localhost:3000/.well-known/jwks.json');
    expect(body.grant_types_supported).toContain('client_credentials');
    expect(body.code_challenge_methods_supported).toContain('S256');
  });
});

describe('POST /oauth/introspect', () => {
  it('reports a live token as active', async () => {
    const token = await getAccessToken();
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      payload: { token, ...CONFIDENTIAL },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().active).toBe(true);
    expect(res.json().sub).toBe('reporting-service');
    expect(res.json().scope).toBe('reports:read');
  });

  it('reports rubbish as inactive rather than erroring', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      payload: { token: 'not-a-jwt', ...CONFIDENTIAL },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ active: false });
  });

  it('says nothing about why a token is inactive', async () => {
    const bad = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      payload: { token: 'not-a-jwt', ...CONFIDENTIAL },
    });
    const missing = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      payload: { ...CONFIDENTIAL },
    });

    // RFC 7662 is explicit: the response must not help someone learn the
    // difference between a forged token and an expired one.
    expect(bad.json()).toEqual(missing.json());
  });

  it('requires the caller to authenticate', async () => {
    const token = await getAccessToken();
    const res = await app.inject({ method: 'POST', url: '/oauth/introspect', payload: { token } });

    // Otherwise this endpoint is an oracle for testing whether a stolen token is
    // still live.
    expect(res.statusCode).toBe(401);
  });

  it('is never cached', async () => {
    const token = await getAccessToken();
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      payload: { token, ...CONFIDENTIAL },
    });
    expect(res.headers['cache-control']).toBe('no-store');
  });
});
