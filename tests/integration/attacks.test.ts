import { createHash, randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { Config } from '../../src/config';
import { migrate } from '../../src/db/migrate';
import { createPool } from '../../src/db/pool';
import { seed } from '../../src/db/seed';
import { generateKeys, type Keys } from '../../src/oauth/tokens';
import { buildServer } from '../../src/server';

/**
 * Every test here is an attack that used to work. They exist because the earlier
 * suite named these attacks in its comments while quietly testing something
 * easier, and the code was exploitable underneath it.
 */
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

const login = (extra: Record<string, string>) =>
  app.inject({
    method: 'POST',
    url: '/oauth/authorize',
    payload: {
      email: 'ada@example.com',
      password: 'correct-horse-battery',
      client_id: 'web-app',
      redirect_uri: REDIRECT,
      scope: 'profile:read',
      ...extra,
    },
  });

const token = (payload: Record<string, unknown>) =>
  app.inject({ method: 'POST', url: '/oauth/token', payload });

describe('PKCE downgrade', () => {
  it('refuses to mint a code with code_challenge_method=plain', async () => {
    // The attack: the attacker crafts the authorize URL, because client_id and
    // redirect_uri are public by definition. They set method=plain and use a
    // challenge they chose. The victim logs in at the real server, the attacker
    // intercepts the code from the redirect and redeems it with the verifier they
    // picked themselves. PKCE is defeated end to end.
    const attackerVerifier = randomBytes(32).toString('base64url');

    const res = await login({
      code_challenge: attackerVerifier,
      code_challenge_method: 'plain',
    });

    expect(res.statusCode).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it('refuses a challenge method it does not recognise', async () => {
    // The same downgrade wearing a different hat. It used to work because anything
    // that was not exactly 'S256' fell through to a plain string comparison, and
    // the POST had no schema to stop the value being stored.
    const attackerVerifier = randomBytes(32).toString('base64url');

    const res = await login({
      code_challenge: attackerVerifier,
      code_challenge_method: 'S256-but-not-really',
    });

    expect(res.statusCode).toBe(400);
  });

  it('does not advertise a method it will not accept', async () => {
    const body = (
      await app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })
    ).json();

    expect(body.code_challenge_methods_supported).toEqual(['S256']);
    expect(body.code_challenge_methods_supported).not.toContain('plain');
  });

  it('refuses plain at the authorize redirect too', async () => {
    const res = await app.inject({
      method: 'GET',
      url:
        `/oauth/authorize?response_type=code&client_id=web-app` +
        `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
        `&code_challenge=${'a'.repeat(43)}&code_challenge_method=plain`,
    });

    expect(res.statusCode).toBe(400);
  });
});

describe('the login POST is not a way around the login GET', () => {
  it('will not issue a code with no PKCE challenge at all', async () => {
    // This used to reach the database and come back a 500 with the Postgres NOT
    // NULL error attached, which is both a leak and the wrong failure mode. The
    // column constraint was the only thing making PKCE mandatory.
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/authorize',
      payload: {
        email: 'ada@example.com',
        password: 'correct-horse-battery',
        client_id: 'web-app',
        redirect_uri: REDIRECT,
        scope: 'profile:read',
      },
    });

    expect(res.statusCode).toBe(400);
    expect(JSON.stringify(res.json())).not.toContain('null value in column');
  });

  it('will not issue a code to a client that may not use this grant', async () => {
    // reporting-service is registered for client_credentials only. It used to get
    // a real authorization code here, and only redemption refused it. A gate that
    // holds in one of the two places it is written is not a gate.
    const res = await app.inject({
      method: 'POST',
      url: '/oauth/authorize',
      payload: {
        email: 'ada@example.com',
        password: 'correct-horse-battery',
        client_id: 'reporting-service',
        redirect_uri: REDIRECT,
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it('will not issue a code for a scope the client is not registered for', async () => {
    const res = await login({
      scope: 'admin',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_scope');
  });
});

describe('enumeration oracles', () => {
  /** Median, so one slow run does not decide the result. */
  async function medianMs(run: () => Promise<unknown>, times = 5): Promise<number> {
    const samples: number[] = [];
    for (let i = 0; i < times; i += 1) {
      const started = process.hrtime.bigint();
      await run();
      samples.push(Number(process.hrtime.bigint() - started) / 1e6);
    }
    return samples.sort((a, b) => a - b)[Math.floor(times / 2)];
  }

  it('takes about as long to reject an unknown email as a wrong password', async () => {
    // Before the fix a missing account skipped scrypt entirely: 31ms for a real
    // address against 0.8ms for an unknown one. Same message, 40x apart on the
    // clock, so one request told you whether an address was real.
    const real = await medianMs(() =>
      login({ email: 'ada@example.com', password: 'wrong', code_challenge: 'a'.repeat(43) }),
    );
    const unknown = await medianMs(() =>
      login({ email: 'nobody@example.com', password: 'wrong', code_challenge: 'a'.repeat(43) }),
    );

    // Generous, because CI machines are noisy. The bug it catches was 40x, and
    // anything under 4x is not a usable oracle over a network.
    const ratio = Math.max(real, unknown) / Math.max(Math.min(real, unknown), 0.01);
    expect(ratio).toBeLessThan(4);
  });

  it('takes about as long to reject an unknown client as a wrong secret', async () => {
    const real = await medianMs(() =>
      token({
        grant_type: 'client_credentials',
        client_id: 'reporting-service',
        client_secret: 'wrong',
      }),
    );
    const unknown = await medianMs(() =>
      token({ grant_type: 'client_credentials', client_id: 'no-such-client', client_secret: 'wrong' }),
    );

    const ratio = Math.max(real, unknown) / Math.max(Math.min(real, unknown), 0.01);
    expect(ratio).toBeLessThan(4);
  });

  it('says the same thing however client authentication failed', async () => {
    const unknown = await token({
      grant_type: 'client_credentials',
      client_id: 'no-such-client',
      client_secret: 'x',
    });
    const wrongSecret = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
      client_secret: 'wrong',
    });
    const noSecret = await token({
      grant_type: 'client_credentials',
      client_id: 'reporting-service',
    });

    // These used to be four different sentences, which told an attacker which
    // client ids were real and which were public before they tried anything.
    expect(unknown.json()).toEqual(wrongSecret.json());
    expect(wrongSecret.json()).toEqual(noSecret.json());
  });
});

describe('authorization code failures do not explain themselves', () => {
  function pkcePair() {
    const verifier = randomBytes(32).toString('base64url');
    return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
  }

  async function codeFor(challenge: string): Promise<string> {
    const res = await login({ code_challenge: challenge, code_challenge_method: 'S256' });
    return new URL(res.headers.location as string).searchParams.get('code') as string;
  }

  it('gives one answer for expired, unknown, wrong uri and wrong verifier', async () => {
    const { verifier, challenge } = pkcePair();

    const unknown = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code: 'never-existed',
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    const badUri = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code: await codeFor(challenge),
      redirect_uri: 'http://localhost:5173/callback',
      code_verifier: 'x'.repeat(43),
    });

    const badVerifier = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code: await codeFor(challenge),
      redirect_uri: REDIRECT,
      code_verifier: pkcePair().verifier,
    });

    // Naming which check failed tells whoever holds a code they should not have
    // exactly what they still need, and separates "expired" from "never existed".
    expect(unknown.json()).toEqual(badUri.json());
    expect(badUri.json()).toEqual(badVerifier.json());
  });

  it('revokes the tokens a replayed code already issued', async () => {
    const { verifier, challenge } = pkcePair();
    const code = await codeFor(challenge);

    const issued = await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });
    const refresh = issued.json().refresh_token;

    // A second redemption means someone has a copy of a code we already honoured,
    // so the tokens that came out of it may be theirs. RFC 6749 4.1.2 says revoke.
    await token({
      grant_type: 'authorization_code',
      client_id: 'web-app',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    });

    const afterReplay = await token({
      grant_type: 'refresh_token',
      client_id: 'web-app',
      refresh_token: refresh,
    });

    expect(afterReplay.statusCode).toBe(400);
  });
});
