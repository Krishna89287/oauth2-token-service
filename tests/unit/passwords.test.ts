import { hashPassword, verifyPassword } from '../../src/oauth/passwords';

describe('hashPassword', () => {
  it('verifies the password it hashed', async () => {
    const hash = await hashPassword('correct-horse-battery');
    expect(await verifyPassword('correct-horse-battery', hash)).toBe(true);
  });

  it('rejects the wrong password', async () => {
    const hash = await hashPassword('correct-horse-battery');
    expect(await verifyPassword('correct-horse-batteru', hash)).toBe(false);
  });

  it('produces a different hash every time for the same password', async () => {
    const a = await hashPassword('same');
    const b = await hashPassword('same');

    // Different salts. Equal hashes would mean two users with the same password
    // are visibly the same in the table, and one rainbow table would do the lot.
    expect(a).not.toBe(b);
    expect(await verifyPassword('same', a)).toBe(true);
    expect(await verifyPassword('same', b)).toBe(true);
  });

  it('stores the salt and cost with the hash', async () => {
    const hash = await hashPassword('x');
    const [scheme, cost, salt, digest] = hash.split('$');

    // Without the parameters alongside it, the cost could never be raised later
    // without locking out every existing user.
    expect(scheme).toBe('scrypt');
    expect(Number(cost)).toBeGreaterThan(0);
    expect(salt.length).toBeGreaterThan(0);
    expect(digest.length).toBeGreaterThan(0);
  });

  it('never stores the password itself', async () => {
    const hash = await hashPassword('super-secret-value');
    expect(hash).not.toContain('super-secret-value');
  });
});

describe('verifyPassword', () => {
  it('rejects a malformed stored value instead of throwing', async () => {
    // Junk in the column should be a failed login, not a 500 that takes the login
    // endpoint down.
    expect(await verifyPassword('x', '')).toBe(false);
    expect(await verifyPassword('x', 'not-a-hash')).toBe(false);
    expect(await verifyPassword('x', 'scrypt$only$three')).toBe(false);
    expect(await verifyPassword('x', 'bcrypt$16384$salt$deadbeef')).toBe(false);
  });

  it('rejects a non numeric or negative cost', async () => {
    expect(await verifyPassword('x', 'scrypt$abc$salt$deadbeef')).toBe(false);
    expect(await verifyPassword('x', 'scrypt$-1$salt$deadbeef')).toBe(false);
  });

  it('rejects an empty password against a real hash', async () => {
    const hash = await hashPassword('something');
    expect(await verifyPassword('', hash)).toBe(false);
  });

  it('handles an empty password being the actual password', async () => {
    const hash = await hashPassword('');
    expect(await verifyPassword('', hash)).toBe(true);
    expect(await verifyPassword('x', hash)).toBe(false);
  });
});
