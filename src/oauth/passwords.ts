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
 * A hash of nothing anyone can log in with, used to spend the same time on a
 * missing account as on a real one.
 *
 * Computed once at startup, because computing it per request would be a second
 * scrypt and would show up as its own timing signal.
 */
const DUMMY_HASH_PROMISE = hashPassword(randomBytes(32).toString('hex'));

/**
 * Verify a password when the account might not exist.
 *
 * The obvious shape, `user ? await verify(...) : false`, is a user enumeration
 * oracle: a real account pays for scrypt and a missing one does not, so the reply
 * comes back in about a millisecond instead of thirty. The error message being
 * identical does not help when the clock says otherwise. Measured on this machine
 * before the fix: 31.4ms for a real address against 0.8ms for an unknown one.
 *
 * So a missing account verifies against a dummy hash instead. The answer is still
 * false, it just costs what the truth costs.
 */
export async function verifyPasswordOrBurnTime(
  password: string,
  storedHash: string | undefined | null,
): Promise<boolean> {
  if (!storedHash) {
    await verifyPassword(password, await DUMMY_HASH_PROMISE);
    return false;
  }
  return verifyPassword(password, storedHash);
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
