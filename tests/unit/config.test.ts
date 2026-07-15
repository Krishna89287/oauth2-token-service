import { loadConfig } from '../../src/config';

const original = process.env;

beforeEach(() => {
  process.env = { ...original };
});

afterAll(() => {
  process.env = original;
});

describe('loadConfig', () => {
  it('has defaults that run locally without any environment', () => {
    delete process.env.PORT;
    delete process.env.ISSUER;
    delete process.env.ACCESS_TOKEN_TTL;

    const config = loadConfig();
    expect(config.port).toBe(3000);
    expect(config.issuer).toBe('http://localhost:3000');
    expect(config.audience).toBe('api');
  });

  it('gives access tokens a short life and refresh tokens a long one', () => {
    const config = loadConfig();

    // An access token cannot be revoked, so its expiry is the only lever there
    // is. A refresh token can be revoked, so it is allowed to live.
    expect(config.accessTokenTtlSeconds).toBe(900);
    expect(config.refreshTokenTtlSeconds).toBe(60 * 60 * 24 * 30);
    expect(config.accessTokenTtlSeconds).toBeLessThan(config.refreshTokenTtlSeconds);
  });

  it('gives an authorization code barely any life at all', () => {
    // It only has to survive one redirect back to the client.
    expect(loadConfig().authorizationCodeTtlSeconds).toBe(60);
  });

  it('reads overrides from the environment', () => {
    process.env.PORT = '8080';
    process.env.ISSUER = 'https://auth.example.com';
    process.env.AUDIENCE = 'internal-api';
    process.env.ACCESS_TOKEN_TTL = '300';

    const config = loadConfig();
    expect(config.port).toBe(8080);
    expect(config.issuer).toBe('https://auth.example.com');
    expect(config.audience).toBe('internal-api');
    expect(config.accessTokenTtlSeconds).toBe(300);
  });

  it('refuses a ttl that is not a number', () => {
    process.env.ACCESS_TOKEN_TTL = 'fifteen minutes';
    // Number('fifteen minutes') is NaN, and a NaN expiry mints tokens that no
    // verifier will accept, which is a confusing way to find a typo.
    expect(() => loadConfig()).toThrow(/ACCESS_TOKEN_TTL must be a positive number/);
  });

  it('refuses a zero or negative ttl', () => {
    process.env.ACCESS_TOKEN_TTL = '0';
    expect(() => loadConfig()).toThrow(/ACCESS_TOKEN_TTL/);

    process.env.ACCESS_TOKEN_TTL = '-60';
    expect(() => loadConfig()).toThrow(/ACCESS_TOKEN_TTL/);
  });

  it('refuses a port that is not a number', () => {
    process.env.PORT = 'http';
    expect(() => loadConfig()).toThrow(/PORT/);
  });

  it('can turn migrations and logging off', () => {
    process.env.RUN_MIGRATIONS = 'false';
    process.env.LOG_ENABLED = 'false';

    const config = loadConfig();
    expect(config.runMigrations).toBe(false);
    expect(config.logger).toBe(false);
  });

  it('leaves migrations and logging on unless told otherwise', () => {
    delete process.env.RUN_MIGRATIONS;
    delete process.env.LOG_ENABLED;

    const config = loadConfig();
    expect(config.runMigrations).toBe(true);
    expect(config.logger).toBe(true);
  });
});
