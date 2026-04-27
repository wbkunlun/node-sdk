import axios, { AxiosInstance } from 'axios';
import { buildUserAgent } from '@node-sdk/utils/user-agent';
import { resolveProxy, toAxiosProxy } from '@node-sdk/utils/proxy';

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
        // proxy (or none when NO_PROXY matches). Skip when the caller has
        // already set an explicit proxy or httpAgent/httpsAgent.
        if (!req.proxy && !req.httpAgent && !req.httpsAgent && req.url) {
            const proxyConfig = resolveProxy(req.url);
            if (proxyConfig) {
                req.proxy = toAxiosProxy(proxyConfig);
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
