import {
  getProxyEnvConfig,
  resolveProxy,
  toAxiosProxy,
} from '../proxy';

const envSave: Record<string, string | undefined> = {};

beforeEach(() => {
  ['http_proxy', 'https_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'].forEach((k) => {
    envSave[k] = process.env[k];
    delete process.env[k];
  });
});

afterEach(() => {
  ['http_proxy', 'https_proxy', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY'].forEach((k) => {
    if (envSave[k] !== undefined) {
      process.env[k] = envSave[k];
    } else {
      delete process.env[k];
    }
  });
});

// ─── getProxyEnvConfig ────────────────────────────────────────────────

describe('getProxyEnvConfig', () => {
  test('returns empty when no proxy vars are set', () => {
    const cfg = getProxyEnvConfig();
    expect(cfg.httpProxy).toBeUndefined();
    expect(cfg.httpsProxy).toBeUndefined();
    expect(cfg.noProxy).toBeUndefined();
  });

  test('reads http_proxy (lowercase)', () => {
    process.env.http_proxy = 'http://proxy.example.com:3128';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpProxy).toMatchObject({ host: 'proxy.example.com', port: 3128 });
  });

  test('reads HTTP_PROXY (uppercase)', () => {
    process.env.HTTP_PROXY = 'http://proxy.example.com:3128';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpProxy).toMatchObject({ host: 'proxy.example.com', port: 3128 });
  });

  test('lowercase takes precedence over uppercase', () => {
    process.env.http_proxy = 'http://lower.example.com:8080';
    process.env.HTTP_PROXY = 'http://upper.example.com:9090';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpProxy).toMatchObject({ host: 'lower.example.com', port: 8080 });
  });

  test('reads https_proxy', () => {
    process.env.https_proxy = 'http://ssl-proxy.example.com:8443';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpsProxy).toMatchObject({ host: 'ssl-proxy.example.com', port: 8443 });
  });

  test('reads NO_PROXY', () => {
    process.env.no_proxy = 'localhost,.internal.corp,10.0.0.0/8';
    const cfg = getProxyEnvConfig();
    expect(cfg.noProxy).toBe('localhost,.internal.corp,10.0.0.0/8');
  });

  test('parses proxy URL without scheme (bare host:port)', () => {
    process.env.http_proxy = 'proxy:8080';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpProxy).toMatchObject({ host: 'proxy', port: 8080, protocol: 'http' });
  });

  test('parses proxy URL with auth', () => {
    process.env.https_proxy = 'http://user:pass@proxy.example.com:3128';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpsProxy).toMatchObject({
      host: 'proxy.example.com',
      port: 3128,
      auth: { username: 'user', password: 'pass' },
    });
  });

  test('returns undefined for empty string env var', () => {
    process.env.http_proxy = '';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpProxy).toBeUndefined();
  });

  test('default port to 8080 when absent', () => {
    process.env.http_proxy = 'http://proxy.example.com';
    const cfg = getProxyEnvConfig();
    expect(cfg.httpProxy).toMatchObject({ host: 'proxy.example.com', port: 8080 });
  });
});

// ─── resolveProxy ─────────────────────────────────────────────────────

describe('resolveProxy', () => {
  test('returns null when no proxy configured', () => {
    expect(resolveProxy('http://example.com/api')).toBeNull();
  });

  test('uses HTTP_PROXY for http:// target', () => {
    process.env.http_proxy = 'http://http-proxy:3128';
    const p = resolveProxy('http://example.com/api');
    expect(p).toMatchObject({ host: 'http-proxy', port: 3128 });
  });

  test('uses HTTPS_PROXY for https:// target', () => {
    process.env.https_proxy = 'http://ssl-proxy:8443';
    const p = resolveProxy('https://example.com/api');
    expect(p).toMatchObject({ host: 'ssl-proxy', port: 8443 });
  });

  test('falls back to HTTP_PROXY for https:// target when HTTPS_PROXY is absent', () => {
    process.env.http_proxy = 'http://http-proxy:3128';
    const p = resolveProxy('https://example.com/api');
    expect(p).toMatchObject({ host: 'http-proxy', port: 3128 });
  });

  test('does NOT fall back for http:// target when only HTTPS_PROXY is set', () => {
    process.env.https_proxy = 'http://ssl-proxy:8443';
    const p = resolveProxy('http://example.com/api');
    expect(p).toBeNull();
  });

  test('uses HTTPS_PROXY for wss:// target', () => {
    process.env.https_proxy = 'http://ws-proxy:8443';
    const p = resolveProxy('wss://ws.example.com/callback');
    expect(p).toMatchObject({ host: 'ws-proxy' });
  });

  // ─── NO_PROXY matching ──────────────────────────────────────────────

  test('NO_PROXY exact host match bypasses proxy', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = 'example.com';
    expect(resolveProxy('http://example.com/path')).toBeNull();
    expect(resolveProxy('http://other.com/path')).not.toBeNull();
  });

  test('NO_PROXY wildcard * bypasses all', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = '*';
    expect(resolveProxy('http://example.com/path')).toBeNull();
    expect(resolveProxy('https://other.com/path')).toBeNull();
  });

  test('NO_PROXY leading dot matches domain and subdomains', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = '.internal.corp';
    expect(resolveProxy('http://internal.corp/api')).toBeNull();
    expect(resolveProxy('http://api.internal.corp/api')).toBeNull();
    expect(resolveProxy('http://deep.sub.internal.corp/api')).toBeNull();
    expect(resolveProxy('http://other-internal.corp/api')).not.toBeNull();
  });

  test('NO_PROXY CIDR match', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = '10.0.0.0/8';
    expect(resolveProxy('http://10.1.2.3/api')).toBeNull();
    expect(resolveProxy('http://192.168.1.1/api')).not.toBeNull();
  });

  test('NO_PROXY localhost', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = 'localhost,127.0.0.1';
    expect(resolveProxy('http://localhost:3000/api')).toBeNull();
    expect(resolveProxy('http://127.0.0.1/api')).toBeNull();
  });

  test('NO_PROXY case insensitive', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = 'Example.COM';
    expect(resolveProxy('http://example.com/api')).toBeNull();
    expect(resolveProxy('http://EXAMPLE.COM/api')).toBeNull();
  });

  test('NO_PROXY multiple comma-separated entries', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = 'localhost, .internal.corp, 192.168.1.0/24';
    expect(resolveProxy('http://localhost/api')).toBeNull();
    expect(resolveProxy('http://svc.internal.corp/api')).toBeNull();
    expect(resolveProxy('http://192.168.1.42/api')).toBeNull();
    expect(resolveProxy('http://public.example.com/api')).not.toBeNull();
  });
});

// ─── toAxiosProxy ─────────────────────────────────────────────────────

describe('toAxiosProxy', () => {
  test('converts ProxyConfig to axios proxy format', () => {
    const result = toAxiosProxy({
      host: 'proxy.example.com',
      port: 3128,
      protocol: 'http',
    });
    expect(result).toEqual({
      protocol: 'http',
      host: 'proxy.example.com',
      port: 3128,
    });
  });

  test('includes auth when present', () => {
    const result = toAxiosProxy({
      host: 'proxy.example.com',
      port: 3128,
      protocol: 'http',
      auth: { username: 'user', password: 'pass' },
    });
    expect(result).toEqual({
      protocol: 'http',
      host: 'proxy.example.com',
      port: 3128,
      auth: { username: 'user', password: 'pass' },
    });
  });
});

// ─── edge cases ───────────────────────────────────────────────────────

describe('edge cases', () => {
  test('empty NO_PROXY means no exclusion', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = '';
    expect(resolveProxy('http://example.com/api')).not.toBeNull();
  });

  test('NO_PROXY with CIDR /32 exact IP', () => {
    process.env.http_proxy = 'http://proxy:3128';
    process.env.no_proxy = '192.168.1.42/32';
    expect(resolveProxy('http://192.168.1.42/api')).toBeNull();
    expect(resolveProxy('http://192.168.1.43/api')).not.toBeNull();
  });
});
