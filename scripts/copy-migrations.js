/**
 * tsc compiles TypeScript and ignores everything else, so the .sql files sit in
 * src and never reach dist. The build looks like it worked and the service dies
 * on boot looking for migrations that were never copied.
 */
const { cpSync, existsSync } = require('node:fs');
const { join } = require('node:path');

const from = join(__dirname, '..', 'src', 'db', 'migrations');
const to = join(__dirname, '..', 'dist', 'db', 'migrations');

if (!existsSync(from)) {
  console.error(`no migrations at ${from}`);
  process.exit(1);
}

cpSync(from, to, { recursive: true });
console.log(`copied migrations to ${to}`);
