import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Pool } from 'pg';

const MIGRATIONS_DIR = join(__dirname, 'migrations');

/** Any constant works. It just has to be the same number in every replica. */
const MIGRATION_LOCK_ID = 4_017_2026;

/**
 * Apply any migration this database has not seen yet.
 *
 * Each file runs inside a transaction and is recorded in schema_migrations, so a
 * file that fails halfway leaves nothing behind and a second run is a no-op.
 *
 * The whole thing is wrapped in an advisory lock because "run it twice" is not
 * only a second deploy an hour later. A rolling update starts several replicas at
 * once, and without the lock they all read an empty schema_migrations, all run the
 * same file, and all but one crash on the primary key. The lock makes the losers
 * wait and then find the work already done.
 */
export async function migrate(pool: Pool, dir: string = MIGRATIONS_DIR): Promise<string[]> {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);

    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name       TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    const { rows } = await client.query<{ name: string }>('SELECT name FROM schema_migrations');
    const applied = new Set(rows.map((row) => row.name));

    const files = readdirSync(dir)
      .filter((name) => name.endsWith('.sql'))
      .sort();

    const ran: string[] = [];

    for (const file of files) {
      if (applied.has(file)) continue;

      const sql = readFileSync(join(dir, file), 'utf8');
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
        ran.push(file);
      } catch (error) {
        await client.query('ROLLBACK');
        throw new Error(`migration ${file} failed: ${(error as Error).message}`);
      }
    }

    return ran;
  } finally {
    // Release on the same connection that took it, before handing it back.
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]).catch(() => undefined);
    client.release();
  }
}
