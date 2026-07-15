import { createPool } from '../src/db/pool';
import { migrate } from '../src/db/migrate';
import { seed } from '../src/db/seed';

const DATABASE_URL = process.env.DATABASE_URL ?? 'postgres://auth:auth@localhost:5432/auth';

async function main(): Promise<void> {
  const pool = createPool(DATABASE_URL);
  try {
    const ran = await migrate(pool);
    console.log(ran.length ? `applied: ${ran.join(', ')}` : 'nothing to apply');

    if (process.argv.includes('--seed')) {
      const { clients, users } = await seed(pool);
      console.log(`seeded ${clients} clients and ${users} users`);
    }
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error((error as Error).message);
  process.exit(1);
});
