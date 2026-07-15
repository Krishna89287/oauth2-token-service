import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair, jwtVerify, type JWK, type KeyLike } from 'jose';

export interface Keys {
  privateKey: KeyLike;
  publicKey: KeyLike;
  /** Names the key in the JWKS so a verifier knows which one to use. */
  kid: string;
}

export interface AccessTokenClaims {
  sub: string;
  scope: string;
  client_id: string;
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
}

/**
 * RS256, not HS256.
 *
 * With a shared secret every service that needs to verify a token also holds the
 * secret that mints one, so any of them can forge tokens for all the others. With
 * a key pair this service signs and everyone else verifies with the public key
 * from the JWKS, which they can fetch and cache without ever holding a secret.
 */
export async function generateKeys(): Promise<Keys> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  const kid = createHash('sha256').update(JSON.stringify(jwk)).digest('base64url').slice(0, 16);
  return { privateKey, publicKey, kid };
}

/** The public half, in the shape /.well-known/jwks.json has to return. */
export async function publicJwks(keys: Keys): Promise<{ keys: JWK[] }> {
  const jwk = await exportJWK(keys.publicKey);
  return { keys: [{ ...jwk, kid: keys.kid, use: 'sig', alg: 'RS256' }] };
}

export async function signAccessToken(
  keys: Keys,
  params: { subject: string; clientId: string; scope: string; issuer: string; audience: string; ttlSeconds: number },
): Promise<{ token: string; expiresIn: number; jti: string }> {
  const jti = randomBytes(16).toString('base64url');

  const token = await new SignJWT({ scope: params.scope, client_id: params.clientId })
    .setProtectedHeader({ alg: 'RS256', kid: keys.kid, typ: 'JWT' })
    .setSubject(params.subject)
    .setIssuer(params.issuer)
    .setAudience(params.audience)
    .setIssuedAt()
    .setExpirationTime(`${params.ttlSeconds}s`)
    .setJti(jti)
    .sign(keys.privateKey);

  return { token, expiresIn: params.ttlSeconds, jti };
}

export async function verifyAccessToken(
  keys: Keys,
  token: string,
  expected: { issuer: string; audience: string },
): Promise<AccessTokenClaims> {
  const { payload } = await jwtVerify(token, keys.publicKey, {
    issuer: expected.issuer,
    audience: expected.audience,
    algorithms: ['RS256'],
  });
  return payload as unknown as AccessTokenClaims;
}

/**
 * Refresh tokens are opaque random strings, not JWTs.
 *
 * A JWT refresh token cannot be revoked without keeping a list of the revoked
 * ones, at which point it is a database lookup with extra steps. An opaque token
 * is meaningless without the row, so revoking is deleting.
 */
export function generateOpaqueToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Store the hash, never the token.
 *
 * A leaked backup of the refresh table should not be a set of working
 * credentials. Plain sha256 without a salt is deliberate here and is not the same
 * mistake as storing passwords that way: these are 256 bits of randomness from our
 * own generator, so there is no dictionary to attack and nothing for a salt to
 * defend against, and the lookup has to be exact and fast on every refresh.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
