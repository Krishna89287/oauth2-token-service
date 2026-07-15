import type { Pool } from 'pg';
import { migrate } from '../../src/db/migrate';
import { createPool } from '../../src/db/pool';
import { deleteExpired } from '../../src/db/repository';
import { seed } from '../../src/db/seed';
import { issueRefreshToken } from '../../src/oauth/refresh';

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://auth:auth@localhost:5432/auth_test';

let pool: Pool;

beforeAll(async () => {
  pool = createPool(DATABASE_URL);
  await migrate(pool);
  await seed(pool);
});

afterAll(async () => {
  await pool.end();
});

beforeEach(async () => {
  await pool.query('TRUNCATE refresh_tokens, authorization_codes');
});

describe('deleteExpired', () => {
  it('removes expired refresh tokens', async () => {
    await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });
    await pool.query(`UPDATE refresh_tokens SET expires_at = now() - interval '1 day'`);

    const removed = await deleteExpired(pool);

    // Expired credentials are worthless but not harmless: they are a growing
    // table of credential shaped rows waiting to be in someone's backup.
    expect(removed).toBe(1);
    const { rows } = await pool.query('SELECT 1 FROM refresh_tokens');
    expect(rows).toHaveLength(0);
  });

  it('leaves live tokens alone', async () => {
    await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });

    expect(await deleteExpired(pool)).toBe(0);
    const { rows } = await pool.query('SELECT 1 FROM refresh_tokens');
    expect(rows).toHaveLength(1);
  });

  it('removes expired authorization codes', async () => {
    await pool.query(
      `INSERT INTO authorization_codes
         (code_hash, client_id, user_id, redirect_uri, scope, code_challenge,
          code_challenge_method, expires_at)
       VALUES ('stale', 'web-app', 'user-1', 'http://localhost:5173/callback', 'profile:read',
               'challenge', 'S256', now() - interval '1 hour')`,
    );

    expect(await deleteExpired(pool)).toBe(1);
  });

  it('counts both tables together', async () => {
    await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });
    await pool.query(`UPDATE refresh_tokens SET expires_at = now() - interval '1 day'`);
    await pool.query(
      `INSERT INTO authorization_codes
         (code_hash, client_id, user_id, redirect_uri, scope, code_challenge,
          code_challenge_method, expires_at)
       VALUES ('stale', 'web-app', 'user-1', 'http://localhost:5173/callback', 'profile:read',
               'challenge', 'S256', now() - interval '1 hour')`,
    );

    expect(await deleteExpired(pool)).toBe(2);
  });

  it('is safe to run when there is nothing to do', async () => {
    expect(await deleteExpired(pool)).toBe(0);
  });
});

describe('issueRefreshToken', () => {
  it('starts a new family when none is given', async () => {
    const a = await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });
    const b = await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });

    // Two separate logins are two separate families, so revoking one for a
    // replay must not sign the other device out.
    expect(a.familyId).not.toBe(b.familyId);
  });

  it('stays in the family it is given', async () => {
    const first = await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });
    const next = await issueRefreshToken(pool, {
      familyId: first.familyId,
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });

    expect(next.familyId).toBe(first.familyId);
  });

  it('issues a different token every time', async () => {
    const a = await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });
    const b = await issueRefreshToken(pool, {
      clientId: 'web-app',
      userId: 'user-1',
      scope: 'profile:read',
      ttlSeconds: 3600,
    });

    expect(a.token).not.toBe(b.token);
  });
});
