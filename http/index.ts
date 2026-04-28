import axios, { AxiosInstance } from 'axios';
import { getProxyForUrl } from 'proxy-from-env';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { HttpProxyAgent } from 'http-proxy-agent';
import { buildUserAgent } from '@node-sdk/utils/user-agent';

const defaultHttpInstance: AxiosInstance = axios.create();

// Fallback UA for callers that bypass Client/WSClient and hit
// `defaultHttpInstance` directly. Client.formatPayload overrides this with
// a source-enriched UA when a `source` option is configured.
const FALLBACK_UA = buildUserAgent();

defaultHttpInstance.interceptors.request.use(
    (req) => {
        if (req.headers && !req.headers['User-Agent']) {
            req.headers['User-Agent'] = FALLBACK_UA;
        }

        // Resolve proxy from Linux env vars (HTTP_PROXY / HTTPS_PROXY /
        // NO_PROXY) per-request, so different target hosts get the correct
        // proxy (or none when NO_PROXY matches). Uses CONNECT-tunneling
        // agents (same pattern as aibot-node-sdk) — never absolute-URI
        // proxying which causes Squid to return 501 for HTTPS targets.
        if (!req.proxy && !req.httpAgent && !req.httpsAgent && req.url) {
            const proxyUrl = getProxyForUrl(req.url);
            if (proxyUrl) {
                try {
                    if (req.url.startsWith('https:')) {
                        req.httpsAgent = new HttpsProxyAgent(proxyUrl);
                        req.proxy = false;
                    } else if (req.url.startsWith('http:')) {
                        req.httpAgent = new HttpProxyAgent(proxyUrl);
                        req.proxy = false;
                    }
                } catch (_) {
                    // ignore proxy URL parse errors, fall through to direct
                }
            }
        }

        return req;
    },
    undefined,
    { synchronous: true }
);

defaultHttpInstance.interceptors.response.use((resp) => {
    if (resp.config['$return_headers']) {
        return {
            data: resp.data,
            headers: resp.headers
        }
    }
    return resp.data;
});

export { AxiosRequestConfig, AxiosError } from 'axios';

export default defaultHttpInstance;
