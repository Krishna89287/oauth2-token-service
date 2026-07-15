# oauth2-token-service

> An OAuth2 server small enough to read, strict enough to trust

[![tests](https://img.shields.io/github/actions/workflow/status/Krishna89287/oauth2-token-service/ci.yml?label=tests&style=flat-square)](https://github.com/Krishna89287/oauth2-token-service/actions)
[![Node](https://img.shields.io/badge/node-20+-green?style=flat-square)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/typescript-5.5-blue?style=flat-square)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

Most of us integrate against an OAuth server rather than write one, and that is
usually the right call. The trouble is that it leaves the spec as folklore: you
know you need PKCE, you are less sure what it actually stops, and the difference
between a public and a confidential client is something you look up each time.

So this is the other half of the exercise. It implements the three grants worth
having, and every security rule in it exists because of a specific attack, which
the tests name and carry out.

## What it looks like running

```
$ npm run demo

1. client_credentials, one service talking to another

  status                 200
  scope                  reports:read
  sub                    reporting-service
  refresh_token          none, by design

   asking for more than it is registered for

  status                 400
  error                  invalid_scope
  description            not allowed for this client: admin

2. authorization_code + PKCE, a browser app signing a user in

  redirect               302 back to the client with a code
  code without verifier  400 invalid_grant  <- PKCE stops this
  code with verifier     200 access + refresh issued
  sub                    user-1
  same code again        400 invalid_grant  <- single use

3. refresh rotation, and what happens when a token is stolen

  honest refresh         200 new refresh token issued
  token changed          true
  thief replays old      400 invalid_grant  <- already spent
  honest client now      400 invalid_grant  <- whole family revoked

   we cannot tell thief from victim, so the chain dies and the user logs in again.

4. anyone can verify a token without holding a secret

  jwks keys              1
  key type               RSA RS256
  private half present   false
```

Block 3 is the one worth sitting with. The honest client refreshes and gets a new
token. Then someone replays the old one, which is only possible if they have a copy
they should not. At that point two parties hold tokens from the same chain and
there is no way to tell which is the thief, so both lose. The user signs in again,
which is a far smaller harm than an attacker holding a renewable session forever.

## How it flows

```mermaid
flowchart TD
    A[Browser app] -->|1. redirect with code_challenge| B[GET /oauth/authorize]
    B --> C{redirect_uri registered?<br/>exact match}
    C -->|no| D[400, never redirect]
    C -->|yes| E[Login form]
    E -->|2. email + password| F[POST /oauth/authorize]
    F --> G[Store code + challenge]
    G -->|3. redirect back with code + state| A
    A -->|4. code + code_verifier| H[POST /oauth/token]
    H --> I{Code known and unspent?}
    H --> J{redirect_uri matches?}
    H --> K{SHA256 verifier == challenge?}
    I --> L{All checks pass?}
    J --> L
    K --> L
    L -->|no| M[400 invalid_grant<br/>code NOT spent]
    L -->|yes| N[Spend code, issue access + refresh]
    N -->|5. later| O[POST /oauth/token refresh]
    O --> P{Already spent?}
    P -->|yes| Q[Replay: revoke whole family]
    P -->|no| R[Rotate: new refresh, burn old]
    N --> S[Other services verify<br/>via /.well-known/jwks.json]
```

## Getting started

```bash
docker compose up -d          # postgres and the service, migrations run on boot
npm install
npm run migrate -- --seed     # two clients and a user
npm run demo                  # the output above
npm test                      # 118 tests, unit and integration
```

A service asking for a token:

```bash
curl -s -X POST localhost:3000/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=reporting-service \
  -d client_secret=reporting-secret-do-not-use-in-production \
  -d scope=reports:read
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "reports:read"
}
```

Endpoints: `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`,
`/.well-known/jwks.json`, `/.well-known/oauth-authorization-server`, `/health`.

## The rules, and the attack each one stops

**PKCE, so a stolen code is useless.** The authorization code comes back through a
browser redirect, where another app on the device can read it. So the code alone
is not enough: whoever redeems it must also send the verifier whose SHA256 matches
the challenge sent at the start, and only the app that began the flow has it. There
is a test that steals the code and fails without the verifier.

**A failed verifier does not spend the code.** Every check runs before the code is
consumed. If a wrong verifier burned it, an attacker holding a stolen code could
break the real user's sign in with one bad request, while still never being able to
redeem it themselves. That is a denial of service for free. Single use is decided
by `UPDATE ... WHERE consumed_at IS NULL`, so two racing redemptions cannot both
win, and the loser is treated as a replay.

**Refresh rotation with family revocation.** Every refresh burns the old token and
issues a new one, which is what makes theft detectable at all: a token presented
twice means someone has a copy. Since we cannot tell which party is honest, the
whole family goes. Rotation runs in a transaction with `FOR UPDATE`, because two
concurrent refreshes of the same token are exactly the case being judged.

**No refresh token for client_credentials.** The client already holds credentials
it can reuse whenever it likes, so a refresh token would just be a second, weaker
credential. RFC 6749 4.4.3 says the same.

**Redirect URIs match exactly, never by prefix.** A prefix check on
`https://app.example.com` also accepts `https://app.example.com.evil.tld`. And an
unregistered redirect_uri gets a 400 rendered here, never a redirect, because
redirecting to report the error is itself the open redirect.

**RS256, not HS256.** With a shared secret, every service that can verify a token
can also mint one. With a key pair this service signs and everyone else verifies
using the public key from the JWKS, holding nothing dangerous. A test asserts the
private parameters never appear in that endpoint, because publishing them would be
the worst thing this service could do.

**Refresh tokens are opaque and stored hashed.** A JWT refresh token cannot be
revoked without a list of revoked ones, at which point it is a database lookup with
extra steps. Hashing means a leaked backup is not a set of working credentials.

**Every failure looks the same.** Unknown token, expired token, revoked token and
replayed token all return the same `invalid_grant`. Telling them apart is free
information for someone working through a list of stolen tokens. Same for the login
form: a wrong password and an unknown email give the same message, or the endpoint
becomes a way to find out which addresses are real.

**Scope narrows, it does not escalate.** Asking for more than the client is
registered for is refused, asking for nothing gives everything it is allowed, and a
refresh keeps the scope the login granted.

## What is not here

**The signing key is generated at boot.** Fine for one instance, wrong for more
than one: each would sign with a different key and reject the others' tokens. A
real deployment loads a key pair from a secret manager, and rotates by publishing
the new public key in the JWKS before it starts signing with it. That sequencing is
the whole difficulty and it is not implemented.

**No consent screen.** The login form authenticates the user and goes straight to
issuing a code. A real server shows what is being granted and lets the user refuse.

**No rate limiting.** The login form and the token endpoint are both worth
brute forcing, and neither is protected here. That belongs in front of the app
rather than inside it, but it has to exist somewhere.

**The password grant is not implemented, deliberately.** It hands the user's
password to the client. It is deprecated and I would rather not have it in a repo
someone might copy.

**Stack:** Node.js · TypeScript · Fastify · PostgreSQL · jose · Docker · jest

---

Built by [Krishna Gove](https://github.com/Krishna89287), working on backend and AI systems in Munich.
