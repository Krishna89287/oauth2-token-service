import { createHash, timingSafeEqual } from 'node:crypto';

export type CodeChallengeMethod = 'S256' | 'plain';

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
 * plain is in the spec and is accepted here only because some old clients still
 * send it. It offers no protection against an attacker who saw the challenge, so
 * S256 is what anything new should use.
 */
export function verifyCodeChallenge(
  verifier: string,
  challenge: string,
  method: CodeChallengeMethod,
): boolean {
  if (method === 'S256') {
    return constantTimeEquals(sha256Base64Url(verifier), challenge);
  }
  return constantTimeEquals(verifier, challenge);
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
