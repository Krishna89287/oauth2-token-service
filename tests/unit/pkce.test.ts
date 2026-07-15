import { createHash, randomBytes } from 'node:crypto';
import {
  SUPPORTED_CODE_CHALLENGE_METHODS,
  isSupportedCodeChallengeMethod,
  isValidCodeVerifier,
  verifyCodeChallenge,
} from '../../src/oauth/pkce';

/** What a well behaved client does before it starts the flow. */
function makePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url'); // 43 chars
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

describe('verifyCodeChallenge S256', () => {
  it('accepts the verifier that produced the challenge', () => {
    const { verifier, challenge } = makePair();
    expect(verifyCodeChallenge(verifier, challenge, 'S256')).toBe(true);
  });

  it('rejects a different verifier', () => {
    const { challenge } = makePair();
    const other = makePair().verifier;
    // This is the whole point of PKCE: holding the code and the challenge is not
    // enough, an attacker also needs the verifier, which never left the client.
    expect(verifyCodeChallenge(other, challenge, 'S256')).toBe(false);
  });

  it('rejects the challenge presented as its own verifier', () => {
    // A client that confuses the two, or an attacker who only saw the challenge
    // go past in the redirect, must not get in.
    const { challenge } = makePair();
    expect(verifyCodeChallenge(challenge, challenge, 'S256')).toBe(false);
  });

  it('rejects an empty verifier', () => {
    const { challenge } = makePair();
    expect(verifyCodeChallenge('', challenge, 'S256')).toBe(false);
  });

  it('hashes with base64url, not base64', () => {
    // The spec says base64url. Standard base64 would produce + and / and =, which
    // do not survive a query string, so this would fail intermittently on exactly
    // the verifiers whose hash happened to contain one.
    const verifier = 'a'.repeat(43);
    const expected = createHash('sha256').update(verifier).digest('base64url');

    expect(expected).not.toMatch(/[+/=]/);
    expect(verifyCodeChallenge(verifier, expected, 'S256')).toBe(true);
  });
});

describe('the plain method is not accepted at all', () => {
  it('refuses plain even when the verifier equals the challenge', () => {
    // This is the whole downgrade. With plain, the challenge IS the verifier, and
    // it sits in the authorize URL in the clear. An attacker crafts the URL with a
    // challenge they chose, lets the victim log in at the real server, intercepts
    // the code, and redeems it with the verifier they already have. Accepting
    // plain alongside S256 does not add compatibility, it hands out a bypass.
    expect(verifyCodeChallenge('same-value', 'same-value', 'plain')).toBe(false);
  });

  it('refuses plain for a real S256 pair too', () => {
    const { verifier, challenge } = makePair();
    expect(verifyCodeChallenge(verifier, challenge, 'plain')).toBe(false);
  });

  it('fails closed on a method nobody has heard of', () => {
    const { verifier, challenge } = makePair();

    // The dangerous shape is `if (method === 'S256') { hash } else { compare }`,
    // where anything unrecognised silently becomes a plain comparison. Then any
    // string an attacker can get written into the stored row is a way past PKCE.
    expect(verifyCodeChallenge(verifier, challenge, 'S256-but-not-really')).toBe(false);
    expect(verifyCodeChallenge(verifier, verifier, 'S256-but-not-really')).toBe(false);
    expect(verifyCodeChallenge(verifier, challenge, '')).toBe(false);
    expect(verifyCodeChallenge(verifier, challenge, 's256')).toBe(false);
  });

  it('only advertises what it accepts', () => {
    expect(SUPPORTED_CODE_CHALLENGE_METHODS).toEqual(['S256']);
    expect(isSupportedCodeChallengeMethod('S256')).toBe(true);
    expect(isSupportedCodeChallengeMethod('plain')).toBe(false);
  });
});

describe('isValidCodeVerifier', () => {
  it('accepts the shortest and longest the spec allows', () => {
    expect(isValidCodeVerifier('a'.repeat(43))).toBe(true);
    expect(isValidCodeVerifier('a'.repeat(128))).toBe(true);
  });

  it('rejects anything shorter than 43', () => {
    // Length is a security property here. A short verifier can be guessed.
    expect(isValidCodeVerifier('a'.repeat(42))).toBe(false);
    expect(isValidCodeVerifier('short')).toBe(false);
  });

  it('rejects anything longer than 128', () => {
    expect(isValidCodeVerifier('a'.repeat(129))).toBe(false);
  });

  it('accepts the unreserved characters and rejects the rest', () => {
    expect(isValidCodeVerifier('-._~' + 'a'.repeat(39))).toBe(true);
    expect(isValidCodeVerifier('has spaces' + 'a'.repeat(35))).toBe(false);
    expect(isValidCodeVerifier('has/slash' + 'a'.repeat(35))).toBe(false);
  });

  it('rejects an empty verifier', () => {
    expect(isValidCodeVerifier('')).toBe(false);
  });
});
