/**
 * Scope handling.
 *
 * Scope is a space delimited string in the spec, which is easy to get subtly
 * wrong: splitting on ' ' turns a double space into an empty scope, and an empty
 * scope compares equal to nothing and grants nothing, so it usually goes unnoticed
 * until it does not.
 */

export function parseScope(scope: string | undefined | null): string[] {
  if (!scope) return [];
  return scope.split(/\s+/).filter((s) => s.length > 0);
}

export function formatScope(scopes: string[]): string {
  return scopes.join(' ');
}

/**
 * Narrow a request down to what the client is actually allowed to have.
 *
 * A client asking for more than it was registered with does not get an error, it
 * gets the intersection. That is what RFC 6749 section 3.3 allows, and it means
 * tightening a client's registration takes effect immediately rather than breaking
 * every request it makes.
 *
 * Asking for nothing means asking for everything the client is allowed, which is
 * the conventional default.
 */
export function grantableScopes(requested: string[], allowed: string[]): string[] {
  if (requested.length === 0) return [...allowed];
  const allowedSet = new Set(allowed);
  return requested.filter((scope) => allowedSet.has(scope));
}

/** Did the client ask for anything it is not registered for? */
export function unauthorizedScopes(requested: string[], allowed: string[]): string[] {
  const allowedSet = new Set(allowed);
  return requested.filter((scope) => !allowedSet.has(scope));
}

/** Does a token carrying these scopes satisfy the one a route requires? */
export function hasScope(tokenScopes: string[], required: string): boolean {
  return tokenScopes.includes(required);
}
