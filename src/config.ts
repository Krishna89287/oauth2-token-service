export interface Config {
  port: number;
  databaseUrl: string;
  /** Goes in the `iss` claim. Verifiers check it, so it has to be stable. */
  issuer: string;
  /** Goes in the `aud` claim: who the token is meant for. */
  audience: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
  logger: boolean;
  runMigrations: boolean;
}

function numberFrom(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;

  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`env var ${name} must be a positive number, got: ${raw}`);
  }
  return value;
}

export function loadConfig(): Config {
  return {
    port: numberFrom('PORT', 3000),
    databaseUrl: process.env.DATABASE_URL ?? 'postgres://auth:auth@localhost:5432/auth',
    issuer: process.env.ISSUER ?? 'http://localhost:3000',
    audience: process.env.AUDIENCE ?? 'api',

    // Short, because an access token cannot be revoked. Anything holding one is
    // trusted until it expires, so the expiry is the only lever there is.
    accessTokenTtlSeconds: numberFrom('ACCESS_TOKEN_TTL', 900),

    // Long, because it can be revoked, and rotation means a stolen one is
    // detectable the moment the real client uses its own.
    refreshTokenTtlSeconds: numberFrom('REFRESH_TOKEN_TTL', 60 * 60 * 24 * 30),

    // Very short. The code only has to survive a redirect back to the client.
    authorizationCodeTtlSeconds: numberFrom('AUTH_CODE_TTL', 60),

    logger: process.env.LOG_ENABLED !== 'false',
    runMigrations: process.env.RUN_MIGRATIONS !== 'false',
  };
}
