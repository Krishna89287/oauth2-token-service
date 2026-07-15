import { Pool } from 'pg';

export function createPool(databaseUrl: string): Pool {
  return new Pool({
    connectionString: databaseUrl,
    connectionTimeoutMillis: 2000,
    statement_timeout: 5000,
    idleTimeoutMillis: 30_000,
    max: 20,
  });
}
