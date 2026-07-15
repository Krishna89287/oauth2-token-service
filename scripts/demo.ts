/**
 * Walk the three grants, then steal a refresh token and watch the service notice.
 * Needs Postgres up: docker compose up -d
 */
import { createHash, randomBytes } from 'node:crypto';
import { decodeJwt } from 'jose';
import type { Config } from '../src/config';
import { migrate } from '../src/db/migrate';
import { createPool } from '../src/db/pool';
import { seed } from '../src/db/seed';
import { generateKeys } from '../src/oauth/tokens';
import { buildServer } from '../src/server';

const config: Config = {
  port: 0,
  databaseUrl: process.env.DATABASE_URL ?? 'postgres://auth:auth@localhost:5432/auth',
  issuer: 'http://localhost:3000',
  audience: 'api',
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 2_592_000,
  authorizationCodeTtlSeconds: 60,
  logger: false,
  runMigrations: false,
};

const REDIRECT = 'http://localhost:5173/callback';

function line(label: string, value: string): void {
  console.log(`  ${label.padEnd(22)} ${value}`);
}

async function main(): Promise<void> {
  const pool = createPool(config.databaseUrl);
  await migrate(pool);
  await seed(pool);
  await pool.query('TRUNCATE refresh_tokens, authorization_codes');

  const keys = await generateKeys();
  const app = buildServer({ config, pool, keys });
  await app.ready();

  const token = (payload: Record<string, unknown>) =>
    app.inject({ method: 'POST', url: '/oauth/token', payload });

  console.log('\n1. client_credentials, one service talking to another\n');
  const cc = await token({
    grant_type: 'client_credentials',
    client_id: 'reporting-service',
    client_secret: 'reporting-secret-do-not-use-in-production',
    scope: 'reports:read',
  });
  const ccBody = cc.json();
  const ccClaims = decodeJwt(ccBody.access_token);
  line('status', String(cc.statusCode));
  line('scope', ccBody.scope);
  line('sub', String(ccClaims.sub));
  line('refresh_token', ccBody.refresh_token ? 'issued' : 'none, by design');

  console.log('\n   asking for more than it is registered for\n');
  const overreach = await token({
    grant_type: 'client_credentials',
    client_id: 'reporting-service',
    client_secret: 'reporting-secret-do-not-use-in-production',
    scope: 'reports:read admin',
  });
  line('status', String(overreach.statusCode));
  line('error', overreach.json().error);
  line('description', overreach.json().error_description);

  console.log('\n2. authorization_code + PKCE, a browser app signing a user in\n');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const authorized = await app.inject({
    method: 'POST',
    url: '/oauth/authorize',
    payload: {
      email: 'ada@example.com',
      password: 'correct-horse-battery',
      client_id: 'web-app',
      redirect_uri: REDIRECT,
      scope: 'profile:read',
      state: 'client-csrf-value',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    },
  });
  const code = new URL(authorized.headers.location as string).searchParams.get('code') as string;
  line('redirect', String(authorized.statusCode) + ' back to the client with a code');

  const stolen = await token({
    grant_type: 'authorization_code',
    client_id: 'web-app',
    code,
    redirect_uri: REDIRECT,
    code_verifier: randomBytes(32).toString('base64url'),
  });
  line('code without verifier', `${stolen.statusCode} ${stolen.json().error}  <- PKCE stops this`);

  const exchanged = await token({
    grant_type: 'authorization_code',
    client_id: 'web-app',
    code,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  });
  const session = exchanged.json();
  line('code with verifier', `${exchanged.statusCode} access + refresh issued`);
  line('sub', String(decodeJwt(session.access_token).sub));

  const replayCode = await token({
    grant_type: 'authorization_code',
    client_id: 'web-app',
    code,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  });
  line('same code again', `${replayCode.statusCode} ${replayCode.json().error}  <- single use`);

  console.log('\n3. refresh rotation, and what happens when a token is stolen\n');
  const first = session.refresh_token;

  const rotated = await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: first });
  const second = rotated.json().refresh_token;
  line('honest refresh', `${rotated.statusCode} new refresh token issued`);
  line('token changed', String(first !== second));

  const thief = await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: first });
  line('thief replays old', `${thief.statusCode} ${thief.json().error}  <- already spent`);

  const honest = await token({ grant_type: 'refresh_token', client_id: 'web-app', refresh_token: second });
  line('honest client now', `${honest.statusCode} ${honest.json().error}  <- whole family revoked`);

  console.log('\n   we cannot tell thief from victim, so the chain dies and the user logs in again.\n');

  console.log('4. anyone can verify a token without holding a secret\n');
  const jwks = (await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();
  line('jwks keys', String(jwks.keys.length));
  line('key type', `${jwks.keys[0].kty} ${jwks.keys[0].alg}`);
  line('private half present', String('d' in jwks.keys[0]));
  console.log('');

  await app.close();
  await pool.end();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
