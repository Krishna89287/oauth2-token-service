import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * S256 only.
 *
 * RFC 7636 also defines `plain`, where the challenge is the verifier in the clear.
 * It is worse than useless here: PKCE's threat model is an attacker who can read
 * the redirect, and with `plain` that attacker can simply craft the authorize URL
 * with a challenge they chose, wait for the victim to log in at the real server,
 * intercept the code, and redeem it with the verifier they already have. Accepting
 * `plain` alongside S256 does not add compatibility, it hands anyone a downgrade.
 *
 * RFC 7636 section 4.2 says a client that can do S256 must, and OAuth 2.1 drops
 * `plain` entirely. So does this.
 */
export type CodeChallengeMethod = 'S256';

export const SUPPORTED_CODE_CHALLENGE_METHODS: readonly string[] = ['S256'];

export function isSupportedCodeChallengeMethod(method: string): method is CodeChallengeMethod {
  return method === 'S256';
}

/** base64url, which is what RFC 7636 asks for and what Buffer calls base64url. */
function sha256Base64Url(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
}

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Check a PKCE verifier against the challenge the client sent when it started.
 *
 * PKCE exists because an authorization code travels through a browser redirect,
 * where another app on the device can intercept it. The code alone is then useless:
 * whoever redeems it must also present the verifier whose hash matches the
 * challenge, and only the app that started the flow has that.
 *
 * Fails closed. An unrecognised method is not quietly treated as a plain string
 * compare, because that turns any typo, or anything an attacker can write into the
 * stored row, into a way around the check.
 */
export function verifyCodeChallenge(verifier: string, challenge: string, method: string): boolean {
  if (!isSupportedCodeChallengeMethod(method)) return false;
  return constantTimeEquals(sha256Base64Url(verifier), challenge);
}

/**
 * RFC 7636 puts the verifier between 43 and 128 characters from an unreserved
 * alphabet. Short verifiers are brute forceable, so this is a security rule
 * rather than a formatting one.
 */
const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

export function isValidCodeVerifier(verifier: string): boolean {
  return VERIFIER_PATTERN.test(verifier);
}
