import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';

/**
 * promisify loses the overload that takes options, so the cost factor cannot be
 * passed through it. This wrapper keeps the types honest.
 */
function scrypt(password: string, salt: string, keylen: number, cost: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, { N: cost }, (error, derived) => {
      if (error) reject(error);
      else resolve(derived);
    });
  });
}

const KEY_LENGTH = 64;
// The work factor. Higher is slower for us and for anyone with the stolen table.
const COST = 16_384;

/**
 * scrypt from the standard library rather than bcrypt or argon2 from npm.
 *
 * Not because it is better. argon2id would be the modern first choice. It is here
 * because it needs no native module, so this repo builds anywhere without a
 * toolchain, and scrypt is memory hard and perfectly respectable. The salt is per
 * password and stored alongside the hash, which is the part people get wrong.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, KEY_LENGTH, COST);
  return `scrypt$${COST}$${salt}$${derived.toString('hex')}`;
}

/**
 * Verify in constant time.
 *
 * A plain === would leak, through timing, how much of the hash matched, which
 * over enough attempts is a way to reconstruct it.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return false;

  const cost = Number(parts[1]);
  if (!Number.isInteger(cost) || cost <= 0) return false;

  const [, , salt, expectedHex] = parts;
  const expected = Buffer.from(expectedHex, 'hex');

  let derived: Buffer;
  try {
    derived = await scrypt(password, salt, expected.length, cost);
  } catch {
    return false;
  }

  if (derived.length !== expected.length) return false;
  return timingSafeEqual(derived, expected);
}
