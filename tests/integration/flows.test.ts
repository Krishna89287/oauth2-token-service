import { createHash, randomBytes } from 'node:crypto';
import { decodeJwt } from 'jose';
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

beforeEach(async () => {
  await pool.query('TRUNCATE refresh_tokens, authorization_codes');
});

const token = (payload: Record<string, unknown>) =>
  app.inject({ method: 'POST', url: '/oauth/token', payload });

function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

/** Drive the browser half of the flow and pull the code out of the redirect. */
async function getAuthorizationCode(challenge: string, scope = 'profile:read'): Promise<string> {
  const res = await app.inject({
    method: 'POST',
    url: '/oauth/authorize',
    payload: {
      email: 'ada@example.com',
      password: 'correct-horse-battery',
      client_id: 'web-app',
      redirect_uri: REDIRECT,
      scope,
      state: 'xyz',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    },
  });

  expect(res.statusCode).toBe(302);
  return new URL(res.headers.location as string).searchParams.get('code') as string;
}

describe('client_credentials', () => {
  it('issues an access token to a confidential client', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
      scope: 'reports:read',
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.token_type).toBe('Bearer');
    expect(body.scope).toBe('reports:read');
    expect(body.expires_in).toBe(900);
  });

  it('does not hand out a refresh token', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
    });

    // The client already holds credentials it can reuse whenever it likes, so a
    // refresh token would be a second, weaker credential for nothing.
    expect(res.json().refresh_token).toBeUndefined();
  });

  it('signs claims a verifier can check', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
      scope: 'reports:read',
    });

    const claims = decodeJwt(res.json().access_token);
    expect(claims.iss).toBe('http://localhost:3000');
    expect(claims.aud).toBe('api');
    expect(claims.sub).toBe('reporting-service');
    expect(claims.client_id).toBe('reporting-service');
  });

  it('narrows an over-broad scope request rather than failing', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
    });

    // Asking for nothing means everything the client is registered for.
    expect(res.json().scope).toBe('reports:read reports:write');
  });

  it('refuses a scope the client is not registered for', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
      scope: 'admin',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_scope');
  });

  it('refuses a wrong secret', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'wrong',
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_client');
  });

  it('refuses a confidential client that sends no secret at all', async () => {
    const res = await token({ grant_type: 'client_credentials', client_id: 'reporting-service' });
    expect(res.statusCode).toBe(401);
  });

  it('refuses an unknown client', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'nobody',
      client_secret: 'x',
    });
    expect(res.statusCode).toBe(401);
  });

  it('refuses a client that is not registered for this grant', async () => {
    // web-app is a browser app. It has no secret, so client_credentials would
    // mean anyone who read the JS could mint tokens.
    const res = await token({ grant_type: 'client_credentials', client_id: 'web-app' });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('unauthorized_client');
  });

  it('never caches a token response', async () => {
    const res = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
    });
    expect(res.headers['cache-control']).toBe('no-store');
  });
});

describe('authorization_code with PKCE', () => {
  it('completes the flow for a public client', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().access_token).toBeDefined();
    expect(res.json().refresh_token).toBeDefined();
    expect(res.json().scope).toBe('profile:read');
  });

  it('puts the user in the subject, not the client', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    const claims = decodeJwt(res.json().access_token);
    expect(claims.sub).toBe('user-1');
    expect(claims.client_id).toBe('web-app');
  });

  it('hands state back untouched', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/authorize',
      payload: {
        email: 'ada@example.com',
        password: 'correct-horse-battery',
        client_id: 'web-app',
        redirect_uri: REDIRECT,
        scope: 'profile:read',
        state: 'the-client-csrf-value',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
    });

    const url = new URL(res.headers.location as string);
    expect(url.searchParams.get('state')).toBe('the-client-csrf-value');
  });

  it('refuses a stolen code without the verifier', async () => {
    const { challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    // This is the attack PKCE exists to stop: the code was intercepted in the
    // redirect, but the verifier never left the real client.
    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: pkcePair().verifier,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_grant');
  });

  it('refuses a code with no verifier at all', async () => {
    const { challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  it('refuses a verifier that is too short to be safe', async () => {
    const { challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: 'tiny',
    });

    expect(res.statusCode).toBe(400);
  });

  it('does not let a wrong verifier burn the real client\'s code', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    // An attacker who intercepted the code tries it with a verifier they guessed.
    const attacker = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: pkcePair().verifier,
    });
    expect(attacker.statusCode).toBe(400);

    // The real client must still be able to finish signing the user in. Consuming
    // the code on a failed attempt would hand the attacker a denial of service for
    // free, since they can never redeem it themselves anyway.
    const real = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });
    expect(real.statusCode).toBe(200);
  });

  it('burns the code after one use', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    const first = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });
    const second = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(400);
    expect(second.json().error).toBe('invalid_grant');
  });

  it('refuses a redirect_uri that does not match the one the code was issued for', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);

    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: 'http://localhost:5173/somewhere-else',
      code_verifier: verifier,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_grant');
  });

  it('refuses an unknown code', async () => {
    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code: 'never-existed',
      redirect_uri: REDIRECT,
      code_verifier: pkcePair().verifier,
    });

    expect(res.statusCode).toBe(400);
  });
});

describe('/oauth/authorize', () => {
  it('renders a login form', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=${encodeURIComponent(REDIRECT)}&scope=profile:read&code_challenge=${challenge}&code_challenge_method=S256`,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Krishna Web App');
    expect(res.body).toContain('profile:read');
  });

  it('refuses a redirect_uri that is not registered', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=${encodeURIComponent('https://evil.example.com/steal')}&code_challenge=${challenge}`,
    });

    // An open redirect here would hand the code straight to the attacker.
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  it('refuses a redirect_uri that only looks like a registered one', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=${encodeURIComponent('http://localhost:5173/callback.evil.tld')}&code_challenge=${challenge}`,
    });

    // Exact match, never prefix. A prefix check accepts this.
    expect(res.statusCode).toBe(400);
  });

  it('refuses a response_type it does not implement', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=token&client_id=web-app&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}`,
    });

    // The implicit flow is not supported, and quietly ignoring the parameter
    // would be worse than saying so.
    expect(res.statusCode).toBe(400);
  });

  it('rejects a bad password without saying which half was wrong', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/authorize',
      payload: {
        email: 'ada@example.com',
        password: 'wrong',
        client_id: 'web-app',
        redirect_uri: REDIRECT,
        code_challenge: challenge,
      },
    });

    expect(res.statusCode).toBe(401);
    expect(res.body).toContain('did not match');
  });

  it('says the same thing for an email that does not exist', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/authorize',
      payload: {
        email: 'nobody@example.com',
        password: 'whatever',
        client_id: 'web-app',
        redirect_uri: REDIRECT,
        code_challenge: challenge,
      },
    });

    // Otherwise this endpoint tells an attacker which addresses are real.
    expect(res.statusCode).toBe(401);
    expect(res.body).toContain('did not match');
  });

  it('does not reflect a markup shaped scope back to the caller', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=${encodeURIComponent(REDIRECT)}&scope=${encodeURIComponent('<script>alert(1)</script>')}&code_challenge=${challenge}`,
    });

    // Angle brackets are legal in a scope per RFC 6749, so this reaches us as a
    // perfectly valid scope string. It is rejected because the client is not
    // registered for it, and the error must not hand the payload back.
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_scope');
    expect(res.body).not.toContain('<script>');
  });

  it('still names a rejected scope that looks like a scope', async () => {
    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=${encodeURIComponent(REDIRECT)}&scope=admin:everything&code_challenge=${challenge}`,
    });

    // Refusing to echo anything at all would make this endpoint painful to
    // integrate against. Safe looking scopes still come back.
    expect(res.json().error_description).toContain('admin:everything');
  });

  it('escapes the client name it renders into the form', async () => {
    await pool.query(
      `INSERT INTO clients (id, name, redirect_uris, allowed_scopes, allowed_grants)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
      ['xss-client', '<img src=x onerror=alert(1)>', [REDIRECT], ['profile:read'], ['authorization_code']],
    );

    const { challenge } = pkcePair();
    const res = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?response_type=code&client_id=xss-client&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}`,
    });

    // The client name is attacker controlled if client registration is ever
    // self service, and it is rendered straight into the login page.
    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain('<img src=x onerror=alert(1)>');
    expect(res.body).toContain('&lt;img src=x onerror=alert(1)&gt;');

    await pool.query(`DELETE FROM clients WHERE id = 'xss-client'`);
  });

  it('sets headers that stop a browser guessing the content type', async () => {
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
  });
});

describe('refresh token rotation', () => {
  async function login(): Promise<{ access: string; refresh: string }> {
    const { verifier, challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);
    const res = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });
    return { access: res.json().access_token, refresh: res.json().refresh_token };
  }

  it('returns a new refresh token every time', async () => {
    const { refresh } = await login();

    const res = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: refresh,
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().refresh_token).toBeDefined();
    expect(res.json().refresh_token).not.toBe(refresh);
  });

  it('keeps the original scope', async () => {
    const { refresh } = await login();

    const res = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: refresh,
    });

    // A refresh must never be a way to acquire scopes the login did not grant.
    expect(res.json().scope).toBe('profile:read');
  });

  it('rejects the old token once it has been rotated', async () => {
    const { refresh } = await login();
    await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: refresh });

    const replay = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: refresh,
    });

    expect(replay.statusCode).toBe(400);
    expect(replay.json().error).toBe('invalid_grant');
  });

  it('revokes the whole family when an old token is replayed', async () => {
    const { refresh: first } = await login();

    // The real client refreshes normally.
    const second = (
      await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: first })
    ).json().refresh_token;

    // Then someone replays the first one. We cannot tell which party is the thief,
    // so we assume the chain is compromised.
    await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: first });

    // The honest client's current token is now dead too. A forced login is a
    // smaller harm than an attacker holding a renewable session.
    const afterBreach = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: second,
    });

    expect(afterBreach.statusCode).toBe(400);
  });

  it('leaves other sessions alone when one family is revoked', async () => {
    const sessionA = await login();
    const sessionB = await login();

    await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: sessionA.refresh });
    await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: sessionA.refresh });

    // Signing out of a laptop should not sign out the phone.
    const other = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: sessionB.refresh,
    });

    expect(other.statusCode).toBe(200);
  });

  it('refuses a refresh token presented by a different client', async () => {
    const { refresh } = await login();

    const res = await token({
      grant_type: 'refresh_token',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
      refresh_token: refresh,
    });

    expect(res.statusCode).toBe(400);
  });

  it('refuses an expired refresh token', async () => {
    const shortLived = buildServer({
      config: { ...config, refreshTokenTtlSeconds: 1 },
      pool,
      keys,
    });
    await shortLived.ready();

    const { verifier, challenge } = pkcePair();
    const code = await getAuthorizationCode(challenge);
    const issued = await shortLived.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: {
        grant_type: 'authorization_code',
        client_id: 'web-app',
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
      },
    });

    await pool.query(
      `UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE consumed_at IS NULL`,
    );

    const res = await shortLived.inject({
      method: 'POST',
      url: '/oauth/token',
      payload: {
        grant_type: 'refresh_token',
        client_id: 'web-app',
        refresh_token: issued.json().refresh_token,
      },
    });

    expect(res.statusCode).toBe(400);
    await shortLived.close();
  });

  it('refuses an unknown refresh token', async () => {
    const res = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: 'not-a-real-token',
    });
    expect(res.statusCode).toBe(400);
  });

  it('gives the same error for every failure', async () => {
    const { refresh } = await login();
    await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: refresh });

    const unknown = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: 'never-existed',
    });
    const replayed = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: refresh,
    });

    // Telling them apart would let someone testing stolen tokens learn which ones
    // were ever real.
    expect(unknown.json()).toEqual(replayed.json());
  });

  it('never stores the refresh token itself', async () => {
    const { refresh } = await login();

    const { rows } = await pool.query('SELECT token_hash FROM refresh_tokens');
    for (const row of rows) {
      expect(row.token_hash).not.toBe(refresh);
    }
    // A leaked backup should not be a set of working credentials.
    expect(rows.length).toBeGreaterThan(0);
  });
});

describe('grant types', () => {
  it('refuses one it does not know', async () => {
    const res = await token({
      grant_type: 'password',
      client_id: 'reporting-service',
      client_secret: 'reporting-secret-do-not-use-in-production',
    });

    // unsupported_grant_type, not unauthorized_client. The difference matters to
    // whoever is integrating: one reads as "ask an admin to turn it on", the other
    // says this server does not do that. The password grant hands the user's
    // password to the client, so it is not here on purpose.
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('unsupported_grant_type');
  });
});
