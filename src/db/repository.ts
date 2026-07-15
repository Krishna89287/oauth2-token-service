import { randomBytes } from 'node:crypto';
import type { Pool } from 'pg';
import { hashToken } from '../oauth/tokens';

export interface Client {
  id: string;
  name: string;
  secretHash: string | null;
  redirectUris: string[];
  allowedScopes: string[];
  allowedGrants: string[];
}

export interface User {
  id: string;
  email: string;
  passwordHash: string;
}

export async function findClient(pool: Pool, clientId: string): Promise<Client | null> {
  const { rows } = await pool.query(
    `SELECT id, name, secret_hash, redirect_uris, allowed_scopes, allowed_grants
       FROM clients WHERE id = $1`,
    [clientId],
  );
  if (!rows[0]) return null;

  const row = rows[0];
  return {
    id: row.id,
    name: row.name,
    secretHash: row.secret_hash,
    redirectUris: row.redirect_uris,
    allowedScopes: row.allowed_scopes,
    allowedGrants: row.allowed_grants,
  };
}

export async function findUserByEmail(pool: Pool, email: string): Promise<User | null> {
  const { rows } = await pool.query(
    `SELECT id, email, password_hash FROM users WHERE email = $1`,
    [email.toLowerCase()],
  );
  if (!rows[0]) return null;
  return { id: rows[0].id, email: rows[0].email, passwordHash: rows[0].password_hash };
}

export interface AuthorizationCodeRow {
  client_id: string;
  user_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: Date;
  consumed_at: Date | null;
}

export async function createAuthorizationCode(
  pool: Pool,
  params: {
    clientId: string;
    userId: string;
    redirectUri: string;
    scope: string;
    codeChallenge: string;
    codeChallengeMethod: string;
    ttlSeconds: number;
  },
): Promise<string> {
  const code = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + params.ttlSeconds * 1000);

  await pool.query(
    `INSERT INTO authorization_codes
       (code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      hashToken(code),
      params.clientId,
      params.userId,
      params.redirectUri,
      params.scope,
      params.codeChallenge,
      params.codeChallengeMethod,
      expiresAt,
    ],
  );

  return code;
}

export async function loadAuthorizationCode(
  pool: Pool,
  code: string,
): Promise<AuthorizationCodeRow | null> {
  const { rows } = await pool.query<AuthorizationCodeRow>(
    `SELECT client_id, user_id, redirect_uri, scope, code_challenge,
            code_challenge_method, expires_at, consumed_at
       FROM authorization_codes
      WHERE code_hash = $1`,
    [hashToken(code)],
  );
  return rows[0] ?? null;
}

/**
 * Spend the code, and say whether we were the one who spent it.
 *
 * `WHERE consumed_at IS NULL` does the work: two requests racing with the same
 * code both run this, and exactly one gets a row back. Reading the row and then
 * updating it would leave a gap where both see it unconsumed and both get a token.
 *
 * This runs only after every other check has passed, which is deliberate. If the
 * code were consumed on any attempt, then an attacker who intercepted it could
 * burn it with one wrong verifier and lock the real client out of its own login.
 * They still cannot redeem it, so failing that way buys no security and costs the
 * user a broken sign in.
 */
export async function claimAuthorizationCode(pool: Pool, code: string): Promise<boolean> {
  const { rowCount } = await pool.query(
    `UPDATE authorization_codes
        SET consumed_at = now()
      WHERE code_hash = $1
        AND consumed_at IS NULL`,
    [hashToken(code)],
  );
  return (rowCount ?? 0) > 0;
}

/**
 * Codes and tokens are worthless once expired, but they are not harmless: they
 * are a growing table of credential shaped rows. Real deployments run this on a
 * schedule.
 */
export async function deleteExpired(pool: Pool): Promise<number> {
  const codes = await pool.query(`DELETE FROM authorization_codes WHERE expires_at < now()`);
  const tokens = await pool.query(`DELETE FROM refresh_tokens WHERE expires_at < now()`);
  return (codes.rowCount ?? 0) + (tokens.rowCount ?? 0);
}
