import {
  formatScope,
  grantableScopes,
  hasScope,
  parseScope,
  unauthorizedScopes,
} from '../../src/oauth/scopes';

describe('parseScope', () => {
  it('splits on spaces', () => {
    expect(parseScope('reports:read reports:write')).toEqual(['reports:read', 'reports:write']);
  });

  it('is empty for undefined, null and empty string', () => {
    expect(parseScope(undefined)).toEqual([]);
    expect(parseScope(null)).toEqual([]);
    expect(parseScope('')).toEqual([]);
  });

  it('does not invent an empty scope from extra whitespace', () => {
    // Splitting naively on ' ' would give ['a', '', 'b'] here, and an empty scope
    // string compares equal to nothing and grants nothing, so it hides.
    expect(parseScope('a  b')).toEqual(['a', 'b']);
    expect(parseScope('  a b  ')).toEqual(['a', 'b']);
    expect(parseScope('   ')).toEqual([]);
  });

  it('handles a tab, which some clients send', () => {
    expect(parseScope('a\tb')).toEqual(['a', 'b']);
  });
});

describe('formatScope', () => {
  it('round trips', () => {
    expect(parseScope(formatScope(['a', 'b']))).toEqual(['a', 'b']);
  });

  it('is an empty string for no scopes', () => {
    expect(formatScope([])).toBe('');
  });
});

describe('grantableScopes', () => {
  it('gives everything allowed when nothing is asked for', () => {
    expect(grantableScopes([], ['a', 'b'])).toEqual(['a', 'b']);
  });

  it('gives the intersection, not an error', () => {
    // RFC 6749 3.3 lets us narrow rather than refuse, which means tightening a
    // client's registration takes effect now instead of breaking every call.
    expect(grantableScopes(['a', 'zzz'], ['a', 'b'])).toEqual(['a']);
  });

  it('gives nothing when nothing asked for is allowed', () => {
    expect(grantableScopes(['zzz'], ['a'])).toEqual([]);
  });

  it('does not let a client widen its own registration', () => {
    expect(grantableScopes(['admin'], ['profile:read'])).toEqual([]);
  });

  it('does not alias a prefix into a real scope', () => {
    // "reports" must not satisfy "reports:read", and vice versa.
    expect(grantableScopes(['reports'], ['reports:read'])).toEqual([]);
    expect(grantableScopes(['reports:read:extra'], ['reports:read'])).toEqual([]);
  });

  it('does not mutate what it was given', () => {
    const allowed = ['a', 'b'];
    grantableScopes([], allowed);
    expect(allowed).toEqual(['a', 'b']);
  });
});

describe('unauthorizedScopes', () => {
  it('names exactly what was not allowed', () => {
    expect(unauthorizedScopes(['a', 'zzz', 'yyy'], ['a'])).toEqual(['zzz', 'yyy']);
  });

  it('is empty when everything is allowed', () => {
    expect(unauthorizedScopes(['a'], ['a', 'b'])).toEqual([]);
  });
});

describe('hasScope', () => {
  it('is exact', () => {
    expect(hasScope(['reports:read'], 'reports:read')).toBe(true);
    expect(hasScope(['reports:read'], 'reports:write')).toBe(false);
    expect(hasScope(['reports:read'], 'reports')).toBe(false);
  });
});
