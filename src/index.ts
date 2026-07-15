import { loadConfig } from './config';
import { migrate } from './db/migrate';
import { createPool } from './db/pool';
import { generateKeys } from './oauth/tokens';
import { buildServer } from './server';

async function main(): Promise<void> {
  const config = loadConfig();
  const pool = createPool(config.databaseUrl);

  if (config.runMigrations) {
    const ran = await migrate(pool);
    if (ran.length) console.log(`applied migrations: ${ran.join(', ')}`);
  }

  // Generated at boot, which is fine for one instance and wrong for more than
  // one: each would sign with a different key and reject the others' tokens.
  // A real deployment loads a key pair from a secret manager and rotates it by
  // publishing the new public key in the JWKS before signing with it.
  const keys = await generateKeys();
  console.log(`signing key ready, kid ${keys.kid}`);

  const app = buildServer({ config, pool, keys });

  await app.listen({ port: config.port, host: '0.0.0.0' });
  console.log(`oauth2 token service listening on :${config.port}`);

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`${signal} received, draining`);
    try {
      await app.close();
      await pool.end();
      process.exit(0);
    } catch (error) {
      console.error('shutdown failed', error);
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((error) => {
  console.error('failed to start', error);
  process.exit(1);
});
