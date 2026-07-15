import { randomBytes } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { generateOpaqueToken, hashToken } from './tokens';

export interface RefreshRow {
  family_id: string;
  client_id: string;
  user_id: string;
  scope: string;
  expires_at: Date;
  consumed_at: Date | null;
  revoked_at: Date | null;
}

export type RefreshFailure =
  | 'unknown'
  | 'revoked'
  | 'expired'
  | 'wrong_client'
  /** The token was already spent. Someone has a copy of a token they should not. */
  | 'reused';

export interface RefreshSuccess {
  ok: true;
  userId: string;
  scope: string;
  familyId: string;
  refreshToken: string;
  expiresAt: Date;
}

export interface RefreshRejected {
  ok: false;
  reason: RefreshFailure;
  /** True when we revoked the whole family because of a replay. */
  familyRevoked: boolean;
}

export type RefreshResult = RefreshSuccess | RefreshRejected;

export async function issueRefreshToken(
  db: Pool | PoolClient,
  params: { familyId?: string; clientId: string; userId: string; scope: string; ttlSeconds: number },
): Promise<{ token: string; familyId: string; expiresAt: Date }> {
  const token = generateOpaqueToken();
  const familyId = params.familyId ?? randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + params.ttlSeconds * 1000);

  await db.query(
    `INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id, scope, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [hashToken(token), familyId, params.clientId, params.userId, params.scope, expiresAt],
  );

  return { token, familyId, expiresAt };
}

/**
 * Kill every token in a chain.
 *
 * Called when a refresh token is replayed, and when an authorization code is
 * replayed: RFC 6749 4.1.2 says a code used twice SHOULD revoke what it issued,
 * because a second redemption means someone has a copy of a code we already
 * honoured, and the tokens that came out of it may be theirs.
 */
export async function revokeFamily(db: Pool | PoolClient, familyId: string): Promise<void> {
  await db.query(
    `UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`,
    [familyId],
  );
}

/**
 * Spend a refresh token and issue its replacement.
 *
 * Rotation means a refresh token is single use: every refresh returns a new one
 * and burns the old. That is what makes theft detectable. A stolen token is only
 * useful until the real client refreshes, and at that point one of the two is
 * presenting a token that has already been spent.
 *
 * We cannot tell which one is the thief, so we assume the worst and revoke the
 * entire family, logging everyone on that chain out. That is the intended
 * behaviour, not an overreaction: a forced login is a smaller harm than an
 * attacker holding a renewable session indefinitely.
 *
 * The whole thing runs in one transaction with a row lock, because two concurrent
 * refreshes with the same token are exactly the case this is trying to judge, and
 * without the lock both could read it as unconsumed and both succeed.
 */
export async function rotateRefreshToken(
  pool: Pool,
  presentedToken: string,
  clientId: string,
  ttlSeconds: number,
): Promise<RefreshResult> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query<RefreshRow>(
      `SELECT family_id, client_id, user_id, scope, expires_at, consumed_at, revoked_at
         FROM refresh_tokens
        WHERE token_hash = $1
          FOR UPDATE`,
      [hashToken(presentedToken)],
    );

    const row = rows[0];
    if (!row) {
      await client.query('COMMIT');
      return { ok: false, reason: 'unknown', familyRevoked: false };
    }

    // Bind the token to the client it was issued to. Otherwise one client could
    // refresh another's token and quietly inherit the session.
    if (row.client_id !== clientId) {
      await client.query('COMMIT');
      return { ok: false, reason: 'wrong_client', familyRevoked: false };
    }

    if (row.consumed_at) {
      // Replay. Someone is holding a token that was already spent, so the chain
      // is compromised and everything descended from it goes.
      await revokeFamily(client, row.family_id);
      await client.query('COMMIT');
      return { ok: false, reason: 'reused', familyRevoked: true };
    }

    if (row.revoked_at) {
      await client.query('COMMIT');
      return { ok: false, reason: 'revoked', familyRevoked: false };
    }

    if (row.expires_at.getTime() <= Date.now()) {
      await client.query('COMMIT');
      return { ok: false, reason: 'expired', familyRevoked: false };
    }

    await client.query(`UPDATE refresh_tokens SET consumed_at = now() WHERE token_hash = $1`, [
      hashToken(presentedToken),
    ]);

    const next = await issueRefreshToken(client, {
      familyId: row.family_id,
      clientId: row.client_id,
      userId: row.user_id,
      scope: row.scope,
      ttlSeconds,
    });

    await client.query('COMMIT');

    return {
      ok: true,
      userId: row.user_id,
      scope: row.scope,
      familyId: row.family_id,
      refreshToken: next.token,
      expiresAt: next.expiresAt,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
