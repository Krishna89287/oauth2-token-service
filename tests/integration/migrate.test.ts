import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Pool } from 'pg';
import { createPool } from '../../src/db/pool';
import { migrate } from '../../src/db/migrate';

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://auth:auth@localhost:5432/auth_test';

let pool: Pool;
let dir: string;

beforeAll(() => {
  pool = createPool(DATABASE_URL);
});

afterAll(async () => {
  await pool.end();
});

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'migrations-'));
});

afterEach(async () => {
  rmSync(dir, { recursive: true, force: true });
  await pool.query('DROP TABLE IF EXISTS widgets');
  await pool.query("DELETE FROM schema_migrations WHERE name LIKE '9%'");
});

describe('migrate', () => {
  it('applies a migration and records it', async () => {
    writeFileSync(join(dir, '900_widgets.sql'), 'CREATE TABLE widgets (id INT PRIMARY KEY)');

    const ran = await migrate(pool, dir);
    expect(ran).toEqual(['900_widgets.sql']);

    const { rows } = await pool.query("SELECT to_regclass('widgets') AS table");
    expect(rows[0].table).toBe('widgets');
  });

  it('does nothing on a second run', async () => {
    writeFileSync(join(dir, '900_widgets.sql'), 'CREATE TABLE widgets (id INT PRIMARY KEY)');

    await migrate(pool, dir);
    const second = await migrate(pool, dir);

    // The point of recording them: deploying twice must not fail.
    expect(second).toEqual([]);
  });

  it('applies files in order, not in whatever order the disk returns', async () => {
    writeFileSync(join(dir, '902_third.sql'), 'ALTER TABLE widgets ADD COLUMN c INT');
    writeFileSync(join(dir, '900_first.sql'), 'CREATE TABLE widgets (id INT PRIMARY KEY)');
    writeFileSync(join(dir, '901_second.sql'), 'ALTER TABLE widgets ADD COLUMN b INT');

    const ran = await migrate(pool, dir);

    // If these ran out of order the ALTERs would hit a table that does not exist.
    expect(ran).toEqual(['900_first.sql', '901_second.sql', '902_third.sql']);
  });

  it('rolls back a failed migration instead of half applying it', async () => {
    writeFileSync(
      join(dir, '900_broken.sql'),
      `CREATE TABLE widgets (id INT PRIMARY KEY);
       CREATE TABLE widgets (id INT PRIMARY KEY);`, // same table twice, second one fails
    );

    await expect(migrate(pool, dir)).rejects.toThrow(/900_broken\.sql failed/);

    // The first statement must not survive the failure of the second.
    const { rows } = await pool.query("SELECT to_regclass('widgets') AS table");
    expect(rows[0].table).toBeNull();

    const recorded = await pool.query('SELECT 1 FROM schema_migrations WHERE name = $1', [
      '900_broken.sql',
    ]);
    expect(recorded.rows).toHaveLength(0);
  });

  it('retries a migration that failed once it is fixed', async () => {
    const file = join(dir, '900_widgets.sql');
    writeFileSync(file, 'CREATE TABLE widgets (nonsense');
    await expect(migrate(pool, dir)).rejects.toThrow();

    writeFileSync(file, 'CREATE TABLE widgets (id INT PRIMARY KEY)');
    const ran = await migrate(pool, dir);

    expect(ran).toEqual(['900_widgets.sql']);
  });

  it('ignores files that are not sql', async () => {
    writeFileSync(join(dir, 'README.md'), 'not a migration');

    const ran = await migrate(pool, dir);
    expect(ran).toEqual([]);
  });
});
