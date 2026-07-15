import formbody from '@fastify/formbody';
import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import type { Config } from './config';
import {
  claimAuthorizationCode,
  createAuthorizationCode,
  loadAuthorizationCode,
  findClient,
  findUserByEmail,
  type Client,
} from './db/repository';
import { verifyPassword } from './oauth/passwords';
import { isValidCodeVerifier, verifyCodeChallenge, type CodeChallengeMethod } from './oauth/pkce';
import { issueRefreshToken, rotateRefreshToken } from './oauth/refresh';
import { formatScope, grantableScopes, parseScope, unauthorizedScopes } from './oauth/scopes';
import { publicJwks, signAccessToken, verifyAccessToken, type Keys } from './oauth/tokens';

/**
 * The error codes RFC 6749 defines. Sticking to them matters: clients and
 * libraries branch on these strings, and inventing one means a client that does
 * not know what to do.
 */
type OAuthError =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope';

function fail(reply: FastifyReply, status: number, error: OAuthError, description: string) {
  return reply.code(status).send({ error, error_description: description });
}

/**
 * RFC 6749 lets a scope contain most printable ASCII, including angle brackets,
 * so "<script>" is a legal scope string. Naming the rejected scope back to the
 * caller is genuinely useful when integrating, but reflecting whatever they sent
 * is how a JSON error becomes a payload the moment something renders it. So the
 * ones we echo are the ones that look like scopes, and the rest are counted.
 */
const SCOPE_SAFE = /^[A-Za-z0-9_:.-]{1,64}$/;

function describeRejectedScopes(notAllowed: string[]): string {
  const safe = notAllowed.filter((s) => SCOPE_SAFE.test(s));
  const hidden = notAllowed.length - safe.length;

  if (safe.length === 0) return 'the requested scope is not allowed for this client';
  const suffix = hidden > 0 ? ` (and ${hidden} more)` : '';
  return `not allowed for this client: ${safe.join(', ')}${suffix}`;
}

export interface BuildOptions {
  config: Config;
  pool: Pool;
  keys: Keys;
}

export function buildServer({ config, pool, keys }: BuildOptions): FastifyInstance {
  const app = Fastify({ logger: config.logger, ignoreTrailingSlash: true });

  /**
   * RFC 6749 says the token endpoint takes application/x-www-form-urlencoded, and
   * every OAuth client library on earth sends exactly that. Fastify only parses
   * JSON out of the box, so without this the server answers a real client with 415
   * and looks broken to everyone except a test suite posting JSON at it.
   *
   * The login form posts form encoded too, because that is what a browser does
   * with a <form>.
   */
  app.register(formbody);

  // /oauth/authorize is reached by a browser navigating to it, so this service
  // serves HTML as well as JSON. nosniff stops a browser deciding for itself that
  // a JSON error looks close enough to HTML to render.
  app.addHook('onSend', async (_request, reply) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('x-frame-options', 'DENY');
  });

  app.get('/health', async () => ({ status: 'ok' }));

  /**
   * Everything that verifies our tokens fetches this. Publishing the public key
   * is the point: it is what lets other services check a token without ever
   * holding anything that could mint one.
   */
  app.get('/.well-known/jwks.json', async (_request, reply) => {
    // Public keys rotate rarely. Letting verifiers cache means an outage here does
    // not immediately become an outage everywhere that validates a token.
    reply.header('cache-control', 'public, max-age=300');
    return publicJwks(keys);
  });

  app.get('/.well-known/oauth-authorization-server', async () => ({
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/oauth/authorize`,
    token_endpoint: `${config.issuer}/oauth/token`,
    introspection_endpoint: `${config.issuer}/oauth/introspect`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    grant_types_supported: ['client_credentials', 'authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
  }));

  /**
   * Authenticate the client hitting /oauth/token.
   *
   * A confidential client proves itself with its secret. A public client, a mobile
   * app or a SPA, cannot hold a secret, so it sends none and PKCE does the work
   * instead. The important part is that a client registered *with* a secret is
   * never allowed to skip it, or the distinction is decorative.
   */
  async function authenticateClient(
    clientId: string | undefined,
    clientSecret: string | undefined,
  ): Promise<{ ok: true; client: Client } | { ok: false; reason: string }> {
    if (!clientId) return { ok: false, reason: 'client_id is required' };

    const client = await findClient(pool, clientId);
    if (!client) return { ok: false, reason: 'unknown client' };

    if (client.secretHash) {
      if (!clientSecret) return { ok: false, reason: 'client_secret is required for this client' };
      if (!(await verifyPassword(clientSecret, client.secretHash))) {
        return { ok: false, reason: 'bad client credentials' };
      }
    } else if (clientSecret) {
      return { ok: false, reason: 'this client is public and must not send a secret' };
    }

    return { ok: true, client };
  }

  const authorizeQuerySchema = {
    querystring: {
      type: 'object',
      required: ['response_type', 'client_id', 'redirect_uri', 'code_challenge'],
      properties: {
        response_type: { type: 'string' },
        client_id: { type: 'string' },
        redirect_uri: { type: 'string' },
        scope: { type: 'string' },
        state: { type: 'string' },
        code_challenge: { type: 'string' },
        code_challenge_method: { type: 'string', enum: ['S256', 'plain'], default: 'S256' },
      },
    },
  };

  /**
   * The login form.
   *
   * Deliberately plain. The interesting part of this endpoint is not the HTML, it
   * is that the redirect_uri is checked against the registration before we render
   * anything, and that we never redirect to an unregistered one even to report an
   * error.
   */
  app.get<{
    Querystring: {
      response_type: string;
      client_id: string;
      redirect_uri: string;
      scope?: string;
      state?: string;
      code_challenge: string;
      code_challenge_method?: CodeChallengeMethod;
    };
  }>('/oauth/authorize', { schema: authorizeQuerySchema }, async (request, reply) => {
    const q = request.query;

    if (q.response_type !== 'code') {
      return fail(reply, 400, 'invalid_request', 'only response_type=code is supported');
    }

    const client = await findClient(pool, q.client_id);
    if (!client) return fail(reply, 400, 'invalid_client', 'unknown client');

    // An open redirect here would hand the code to whoever asked. This is checked
    // by exact match against the registration, never by prefix, because a prefix
    // check on "https://app.example.com" also accepts "https://app.example.com.evil.tld".
    if (!client.redirectUris.includes(q.redirect_uri)) {
      return fail(reply, 400, 'invalid_request', 'redirect_uri is not registered for this client');
    }

    if (!client.allowedGrants.includes('authorization_code')) {
      return fail(reply, 400, 'unauthorized_client', 'client may not use authorization_code');
    }

    const requested = parseScope(q.scope);
    const notAllowed = unauthorizedScopes(requested, client.allowedScopes);
    if (notAllowed.length > 0) {
      return fail(reply, 400, 'invalid_scope', describeRejectedScopes(notAllowed));
    }

    reply.type('text/html');
    return loginPage(q, client);
  });

  app.post<{
    Body: {
      email: string;
      password: string;
      client_id: string;
      redirect_uri: string;
      scope?: string;
      state?: string;
      code_challenge: string;
      code_challenge_method?: CodeChallengeMethod;
    };
  }>('/oauth/authorize', async (request, reply) => {
    const b = request.body;

    const client = await findClient(pool, b.client_id);
    if (!client || !client.redirectUris.includes(b.redirect_uri)) {
      return fail(reply, 400, 'invalid_request', 'unknown client or redirect_uri');
    }

    const user = await findUserByEmail(pool, b.email ?? '');
    const passwordOk = user ? await verifyPassword(b.password ?? '', user.passwordHash) : false;

    if (!user || !passwordOk) {
      // One message for both cases. Saying "no such user" tells an attacker which
      // email addresses are worth guessing passwords for.
      reply.code(401).type('text/html');
      return loginPage(b, client, 'That email and password did not match.');
    }

    const scope = formatScope(grantableScopes(parseScope(b.scope), client.allowedScopes));

    const code = await createAuthorizationCode(pool, {
      clientId: client.id,
      userId: user.id,
      redirectUri: b.redirect_uri,
      scope,
      codeChallenge: b.code_challenge,
      codeChallengeMethod: b.code_challenge_method ?? 'S256',
      ttlSeconds: config.authorizationCodeTtlSeconds,
    });

    const location = new URL(b.redirect_uri);
    location.searchParams.set('code', code);
    // state is how the client detects CSRF on its own callback. We do not read it,
    // we just hand it back exactly as it came.
    if (b.state) location.searchParams.set('state', b.state);

    return reply.redirect(location.toString(), 302);
  });

  const tokenBodySchema = {
    body: {
      type: 'object',
      required: ['grant_type'],
      properties: {
        grant_type: { type: 'string' },
        client_id: { type: 'string' },
        client_secret: { type: 'string' },
        scope: { type: 'string' },
        code: { type: 'string' },
        redirect_uri: { type: 'string' },
        code_verifier: { type: 'string' },
        refresh_token: { type: 'string' },
      },
    },
  };

  app.post<{
    Body: {
      grant_type: string;
      client_id?: string;
      client_secret?: string;
      scope?: string;
      code?: string;
      redirect_uri?: string;
      code_verifier?: string;
      refresh_token?: string;
    };
  }>('/oauth/token', { schema: tokenBodySchema }, async (request, reply) => {
    const b = request.body;

    // Tokens must never be cached by anything between us and the client.
    reply.header('cache-control', 'no-store').header('pragma', 'no-cache');

    const auth = await authenticateClient(b.client_id, b.client_secret);
    if (!auth.ok) return fail(reply, 401, 'invalid_client', auth.reason);
    const { client } = auth;

    if (!client.allowedGrants.includes(b.grant_type)) {
      return fail(reply, 400, 'unauthorized_client', `client may not use ${b.grant_type}`);
    }

    if (b.grant_type === 'client_credentials') {
      const requested = parseScope(b.scope);
      const notAllowed = unauthorizedScopes(requested, client.allowedScopes);
      if (notAllowed.length > 0) {
        return fail(reply, 400, 'invalid_scope', describeRejectedScopes(notAllowed));
      }

      const scope = formatScope(grantableScopes(requested, client.allowedScopes));
      const access = await signAccessToken(keys, {
        // No user is involved, so the client is its own subject.
        subject: client.id,
        clientId: client.id,
        scope,
        issuer: config.issuer,
        audience: config.audience,
        ttlSeconds: config.accessTokenTtlSeconds,
      });

      // No refresh token here on purpose. The client already holds credentials it
      // can use to get another access token whenever it likes, so a refresh token
      // would be a second, weaker credential for no benefit. RFC 6749 4.4.3 says
      // the same.
      return reply.send({
        access_token: access.token,
        token_type: 'Bearer',
        expires_in: access.expiresIn,
        scope,
      });
    }

    if (b.grant_type === 'authorization_code') {
      if (!b.code) return fail(reply, 400, 'invalid_request', 'code is required');
      if (!b.code_verifier) return fail(reply, 400, 'invalid_request', 'code_verifier is required');
      if (!isValidCodeVerifier(b.code_verifier)) {
        return fail(reply, 400, 'invalid_request', 'code_verifier must be 43 to 128 unreserved characters');
      }

      const row = await loadAuthorizationCode(pool, b.code);

      if (!row) return fail(reply, 400, 'invalid_grant', 'code is invalid or already used');

      if (row.consumed_at) {
        // A code that turns up twice means a copy is loose. The client gets the
        // same generic error as any other failure, but this one is worth a log.
        request.log.warn({ clientId: client.id }, 'authorization code replayed');
        return fail(reply, 400, 'invalid_grant', 'code is invalid or already used');
      }

      if (row.client_id !== client.id) {
        return fail(reply, 400, 'invalid_grant', 'code was not issued to this client');
      }

      if (row.expires_at.getTime() <= Date.now()) {
        return fail(reply, 400, 'invalid_grant', 'code has expired');
      }

      // The redirect_uri is checked again even though it was checked at /authorize.
      // The spec requires it, and it stops a code obtained through one registered
      // uri being redeemed as though it came from another.
      if (b.redirect_uri !== row.redirect_uri) {
        return fail(reply, 400, 'invalid_grant', 'redirect_uri does not match the authorization request');
      }

      if (!verifyCodeChallenge(b.code_verifier, row.code_challenge, row.code_challenge_method as CodeChallengeMethod)) {
        return fail(reply, 400, 'invalid_grant', 'code_verifier does not match the challenge');
      }

      // Everything checks out, so spend it. If someone else spent it between the
      // read above and here, they win and we deny: single use has to be decided by
      // the database, not by the check we did a moment ago.
      if (!(await claimAuthorizationCode(pool, b.code))) {
        request.log.warn({ clientId: client.id }, 'authorization code redeemed twice concurrently');
        return fail(reply, 400, 'invalid_grant', 'code is invalid or already used');
      }

      const access = await signAccessToken(keys, {
        subject: row.user_id,
        clientId: client.id,
        scope: row.scope,
        issuer: config.issuer,
        audience: config.audience,
        ttlSeconds: config.accessTokenTtlSeconds,
      });

      const refresh = await issueRefreshToken(pool, {
        clientId: client.id,
        userId: row.user_id,
        scope: row.scope,
        ttlSeconds: config.refreshTokenTtlSeconds,
      });

      return reply.send({
        access_token: access.token,
        token_type: 'Bearer',
        expires_in: access.expiresIn,
        refresh_token: refresh.token,
        scope: row.scope,
      });
    }

    if (b.grant_type === 'refresh_token') {
      if (!b.refresh_token) return fail(reply, 400, 'invalid_request', 'refresh_token is required');

      const result = await rotateRefreshToken(
        pool,
        b.refresh_token,
        client.id,
        config.refreshTokenTtlSeconds,
      );

      if (!result.ok) {
        if (result.reason === 'reused') {
          request.log.warn(
            { clientId: client.id },
            'refresh token replayed, revoking the whole family',
          );
        }
        // Every failure returns the same thing. Telling the caller whether a token
        // was expired, revoked, or never existed is free information for someone
        // testing stolen tokens.
        return fail(reply, 400, 'invalid_grant', 'refresh token is not valid');
      }

      const access = await signAccessToken(keys, {
        subject: result.userId,
        clientId: client.id,
        scope: result.scope,
        issuer: config.issuer,
        audience: config.audience,
        ttlSeconds: config.accessTokenTtlSeconds,
      });

      return reply.send({
        access_token: access.token,
        token_type: 'Bearer',
        expires_in: access.expiresIn,
        refresh_token: result.refreshToken,
        scope: result.scope,
      });
    }

    return fail(reply, 400, 'unsupported_grant_type', `${b.grant_type} is not supported`);
  });

  /**
   * RFC 7662 introspection.
   *
   * Anything holding the public key can verify our tokens itself and should. This
   * exists for the callers that would rather ask than implement JWT validation,
   * and it is client authenticated so it cannot be used as an oracle to test
   * whether a stolen token is live.
   */
  app.post<{ Body: { token?: string; client_id?: string; client_secret?: string } }>(
    '/oauth/introspect',
    async (request, reply) => {
      const auth = await authenticateClient(request.body?.client_id, request.body?.client_secret);
      if (!auth.ok) return fail(reply, 401, 'invalid_client', auth.reason);

      reply.header('cache-control', 'no-store');

      if (!request.body?.token) return reply.send({ active: false });

      try {
        const claims = await verifyAccessToken(keys, request.body.token, {
          issuer: config.issuer,
          audience: config.audience,
        });
        return reply.send({
          active: true,
          sub: claims.sub,
          scope: claims.scope,
          client_id: claims.client_id,
          exp: claims.exp,
          iat: claims.iat,
          jti: claims.jti,
        });
      } catch {
        // Anything unverifiable is simply inactive. The spec is explicit that we
        // should not explain why, so a caller cannot learn from the difference.
        return reply.send({ active: false });
      }
    },
  );

  return app;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function loginPage(
  params: {
    client_id: string;
    redirect_uri: string;
    scope?: string;
    state?: string;
    code_challenge: string;
    code_challenge_method?: string;
  },
  client: Client,
  error?: string,
): string {
  const hidden = Object.entries({
    client_id: params.client_id,
    redirect_uri: params.redirect_uri,
    scope: params.scope ?? '',
    state: params.state ?? '',
    code_challenge: params.code_challenge,
    code_challenge_method: params.code_challenge_method ?? 'S256',
  })
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(String(v))}">`)
    .join('\n      ');

  const scopes = parseScope(params.scope);
  const scopeList = scopes.length
    ? `<ul>${scopes.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul>`
    : '<p class="muted">No specific scopes requested.</p>';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           background: #f6f7f9; color: #16181d; display: flex; justify-content: center;
           padding: 60px 20px; }
    .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 28px;
            width: 100%; max-width: 380px; }
    h1 { font-size: 1.2rem; margin: 0 0 4px; }
    .muted { color: #5c6370; font-size: 0.9rem; }
    ul { margin: 8px 0 0; padding-left: 18px; color: #5c6370; font-size: 0.9rem; }
    label { display: block; margin-top: 16px; font-size: 0.85rem; font-weight: 600; }
    input[type=email], input[type=password] { width: 100%; padding: 9px 10px; margin-top: 5px;
           border: 1px solid #d5d9de; border-radius: 6px; font-size: 0.95rem; }
    button { width: 100%; margin-top: 20px; padding: 10px; background: #1f6feb; color: #fff;
             border: 0; border-radius: 6px; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
    .error { margin-top: 14px; padding: 9px 10px; background: #fff1f0; border: 1px solid #ffccc7;
             border-radius: 6px; color: #a8071a; font-size: 0.85rem; }
  </style>
</head>
<body>
  <form class="card" method="post" action="/oauth/authorize">
    <h1>Sign in to continue</h1>
    <p class="muted"><strong>${escapeHtml(client.name)}</strong> wants access to your account.</p>
    ${scopeList}
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    <label for="email">Email</label>
    <input id="email" type="email" name="email" required autocomplete="username">
    <label for="password">Password</label>
    <input id="password" type="password" name="password" required autocomplete="current-password">
    <button type="submit">Sign in</button>
    ${hidden}
  </form>
</body>
</html>`;
}
