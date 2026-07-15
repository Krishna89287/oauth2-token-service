import type { Pool } from 'pg';
import { hashPassword } from '../oauth/passwords';

/**
 * Two clients, because the interesting difference in OAuth is between a client
 * that can keep a secret and one that cannot.
 */
export const SEED_CLIENTS = [
  {
    id: 'reporting-service',
    name: 'Reporting service',
    // Confidential: it runs on a server, so it can hold a secret.
    secret: 'reporting-secret-do-not-use-in-production',
    redirectUris: [],
    allowedScopes: ['reports:read', 'reports:write'],
    allowedGrants: ['client_credentials'],
  },
  {
    id: 'web-app',
    name: 'Krishna Web App',
    // Public: a single page app. It ships to the browser, so any "secret" in it
    // is readable with view-source. PKCE does the job a secret cannot.
    secret: null,
    redirectUris: ['http://localhost:5173/callback'],
    allowedScopes: ['profile:read', 'reports:read'],
    allowedGrants: ['authorization_code', 'refresh_token'],
  },
];

export const SEED_USERS = [{ id: 'user-1', email: 'ada@example.com', password: 'correct-horse-battery' }];

export async function seed(pool: Pool): Promise<{ clients: number; users: number }> {
  for (const c of SEED_CLIENTS) {
    await pool.query(
      `INSERT INTO clients (id, name, secret_hash, redirect_uris, allowed_scopes, allowed_grants)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
      [
        c.id,
        c.name,
        c.secret ? await hashPassword(c.secret) : null,
        c.redirectUris,
        c.allowedScopes,
        c.allowedGrants,
      ],
    );
  }

  for (const u of SEED_USERS) {
    await pool.query(
      `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)
       ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email`,
      [u.id, u.email.toLowerCase(), await hashPassword(u.password)],
    );
  }

  return { clients: SEED_CLIENTS.length, users: SEED_USERS.length };
}
