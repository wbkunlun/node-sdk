import http from 'http';
import https from 'https';
import tls from 'tls';
import net from 'net';
import { URL } from 'url';

// ─── types ────────────────────────────────────────────────────────────

export interface ProxyConfig {
  host: string;
  port: number;
  /** Protocol of the proxy server itself (almost always 'http') */
  protocol: string;
  auth?: { username: string; password: string };
}

// ─── env-var reading ──────────────────────────────────────────────────

/**
 * Read a proxy environment variable, checking lowercase first (standard on
 * most Linux systems) and falling back to uppercase (older convention).
 * Returns undefined when the var is unset or explicitly empty.
 */
function readEnv(name: string): string | undefined {
  const lower = process.env[name.toLowerCase()];
  if (lower !== undefined) return lower || undefined;
  const upper = process.env[name.toUpperCase()];
  if (upper !== undefined) return upper || undefined;
  return undefined;
}

// ─── proxy URL parsing ────────────────────────────────────────────────
//
// NOTE: resolveProxy / getProxyEnvConfig are only kept for
// createProxiedPinnedAgent (SSRF-protected media upload). For general
// HTTP/WS proxy, prefer getProxyForUrl + HttpsProxyAgent/HttpProxyAgent
// (consistent with aibot-node-sdk). See http/index.ts and ws-client/index.ts.

function parseProxyUrl(raw: string): ProxyConfig | null {
  // Add a scheme if missing — `proxy.example.com:8080` is common
  let urlStr = raw.trim();
  if (!/^https?:\/\//i.test(urlStr)) {
    urlStr = 'http://' + urlStr;
  }
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return null;
  }
  const host = parsed.hostname;
  const port = Number(parsed.port) || 8080;
  if (!host) return null;

  const auth =
    parsed.username || parsed.password
      ? { username: decodeURIComponent(parsed.username), password: decodeURIComponent(parsed.password) }
      : undefined;

  return { host, port, protocol: parsed.protocol.replace(/:$/, ''), auth };
}

// ─── NO_PROXY matching ────────────────────────────────────────────────

/**
 * Match `targetHost` against the NO_PROXY pattern list.
 *
 * Supported pattern forms:
 *  - `*`            — match all
 *  - `.example.com` — match example.com and any subdomain
 *  - `example.com`  — exact host match
 *  - `10.0.0.0/8`   — CIDR notation (IPv4 only)
 *  - `192.168.1.1`  — exact IP match
 */
function matchNoProxy(targetHost: string, noProxy: string): boolean {
  const patterns = noProxy
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  return patterns.some((pattern) => {
    // Wildcard
    if (pattern === '*') return true;

    // CIDR — check before general host matching
    const cidrMatch = pattern.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
    if (cidrMatch) {
      return ipInCidr(targetHost, cidrMatch[1], Number(cidrMatch[2]));
    }

    const lowerTarget = targetHost.toLowerCase();
    const lowerPattern = pattern.toLowerCase();

    // Leading dot: matches the domain and all subdomains
    if (lowerPattern.startsWith('.')) {
      const suffix = lowerPattern; // includes the dot
      return lowerTarget === suffix.slice(1) || lowerTarget.endsWith(suffix);
    }

    // Exact host or IP match
    return lowerTarget === lowerPattern;
  });
}

function ipInCidr(host: string, network: string, bits: number): boolean {
  const targetNum = ipv4ToNumber(host);
  if (targetNum === null) return false;
  const networkNum = ipv4ToNumber(network);
  if (networkNum === null) return false;
  if (bits <= 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : ((-1) << (32 - bits)) >>> 0;
  return (targetNum & mask) === (networkNum & mask);
}

function ipv4ToNumber(ip: string): number | null {
  if (!net.isIPv4(ip)) return null;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// ─── public API ───────────────────────────────────────────────────────

/** Parse proxy config from the standard Linux env vars. */
export function getProxyEnvConfig(): {
  httpProxy?: ProxyConfig;
  httpsProxy?: ProxyConfig;
  noProxy?: string;
} {
  const httpProxyRaw = readEnv('HTTP_PROXY');
  const httpsProxyRaw = readEnv('HTTPS_PROXY');
  const noProxy = readEnv('NO_PROXY');

  return {
    httpProxy: httpProxyRaw ? parseProxyUrl(httpProxyRaw) ?? undefined : undefined,
    httpsProxy: httpsProxyRaw ? parseProxyUrl(httpsProxyRaw) ?? undefined : undefined,
    noProxy,
  };
}

/**
 * Resolve which (if any) proxy should be used for `targetUrl`.
 *
 * 1. If target is https:// → prefer HTTPS_PROXY, fall back to HTTP_PROXY
 * 2. If target is http://  → use HTTP_PROXY
 * 3. If NO_PROXY matches target host → no proxy (returns null)
 */
export function resolveProxy(targetUrl: string): ProxyConfig | null {
  const { httpProxy, httpsProxy, noProxy } = getProxyEnvConfig();
  if (noProxy) {
    let host: string;
    try {
      host = new URL(targetUrl).hostname;
    } catch {
      return null;
    }
    if (matchNoProxy(host, noProxy)) return null;
  }

  const isHttps = targetUrl.startsWith('https:') || targetUrl.startsWith('wss:');
  if (isHttps) {
    return httpsProxy ?? httpProxy ?? null;
  }
  return httpProxy ?? null;
}

// ─── CONNECT tunnel helper (used by createProxiedPinnedAgent) ─────────

/**
 * Execute an HTTP CONNECT handshake through `proxySocket` to reach
 * `connectHost:connectPort`. Returns a Promise that resolves when the
 * tunnel is established (the socket is ready for raw data).
 */
function connectThrough(
  proxySocket: net.Socket,
  connectHost: string,
  connectPort: number,
  auth?: ProxyConfig['auth'],
): Promise<void> {
  return new Promise((resolve, reject) => {
    proxySocket.once('error', reject);
    const authHeader = auth
      ? `Proxy-Authorization: Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}\r\n`
      : '';
    proxySocket.write(
      `CONNECT ${connectHost}:${connectPort} HTTP/1.1\r\nHost: ${connectHost}:${connectPort}\r\n${authHeader}\r\n`
    );

    let buf = '';
    const onData = (chunk: Buffer) => {
      buf += chunk.toString();
      const statusEnd = buf.indexOf('\r\n');
      if (statusEnd === -1) return;
      proxySocket.removeListener('data', onData);

      const statusLine = buf.slice(0, statusEnd);
      const match = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)/);
      const statusCode = match ? Number(match[1]) : 0;
      if (statusCode !== 200) {
        proxySocket.destroy();
        reject(new Error(`Proxy CONNECT returned ${statusCode}`));
        return;
      }
      // Drain remaining headers
      const onHeadersEnd = (more: Buffer) => {
        buf += more.toString();
        if (buf.includes('\r\n\r\n')) {
          proxySocket.removeListener('data', onHeadersEnd);
          proxySocket.removeListener('error', reject);
          resolve();
        }
      };
      if (buf.includes('\r\n\r\n')) {
        proxySocket.removeListener('error', reject);
        resolve();
      } else {
        proxySocket.on('data', onHeadersEnd);
      }
    };
    proxySocket.on('data', onData);
  });
}

/**
 * Build an agent for SSRF-protected URL fetches that must also respect proxy
 * env vars. When a proxy is configured the agent tunnels CONNECT to pinnedIp
 * (bypassing DNS rebinding), then upgrades to TLS with SNI = originalHost.
 * When no proxy is configured the agent pins the connection directly to
 * pinnedIp (same as the existing SSRF-only code path).
 */
export function createProxiedPinnedAgent(
  targetUrl: string,
  pinnedIp: string,
  originalHost: string,
): http.Agent | https.Agent {
  const proxyConfig = resolveProxy(targetUrl);
  if (!proxyConfig) return makeDirectPinnedAgent(targetUrl, pinnedIp);

  const target = new URL(targetUrl);
  const isSecure = target.protocol === 'https:';
  const targetPort = Number(target.port) || (isSecure ? 443 : 80);

  const AgentClass = isSecure ? https.Agent : http.Agent;
  const agent = new AgentClass({ keepAlive: true });

  agent.createConnection = (_opts, cb) => {
    const proxySocket = net.connect(proxyConfig.port, proxyConfig.host);
    proxySocket.once('error', (err) => { proxySocket.destroy(); cb(err); });

    proxySocket.once('connect', () => {
      connectThrough(proxySocket, pinnedIp, targetPort, proxyConfig.auth)
        .then(() => {
          if (isSecure) {
            const tlsSocket = tls.connect({
              socket: proxySocket,
              servername: originalHost,
            });
            tlsSocket.once('error', (err) => { tlsSocket.destroy(); cb(err); });
            cb(null, tlsSocket);
          } else {
            cb(null, proxySocket);
          }
        })
        .catch((err) => cb(err));
    });

    return proxySocket;
  };

  return agent;
}

/**
 * Create an agent whose DNS is pinned to `pinnedIp` — used for SSRF
 * protection when no proxy is configured.
 */
export function makeDirectPinnedAgent(targetUrl: string, pinnedIp: string): http.Agent | https.Agent {
  const AgentClass = targetUrl.startsWith('https:') ? https.Agent : http.Agent;
  const agent = new AgentClass();
  const family: 4 | 6 = pinnedIp.includes(':') ? 6 : 4;

  const origCreateConnection = agent.createConnection.bind(agent);
  (agent as unknown as {
    createConnection: (opts: unknown, cb: unknown) => unknown;
  }).createConnection = (opts, cb) =>
    origCreateConnection({ ...(opts as object), lookup: (_h: string, _o: unknown, c: (err: Error | null, addr: string, fam: number) => void) => c(null, pinnedIp, family) }, cb as never);

  return agent;
}
