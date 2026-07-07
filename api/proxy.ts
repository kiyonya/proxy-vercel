
const X_VERCEL_PROXY_TOKEN = process.env.X_VERCEL_PROXY_TOKEN
const X_ALLOWHOST = process.env.X_ALLOWHOST || ""
const X_ALLOWHEADERS = process.env.X_ALLOWHEADERS || "User-Agent,Cookie,Referer,Origin"
const X_ALLOWMETHODS = process.env.X_ALLOWMETHODS || "GET,POST,PUT,DELETE,OPTIONS,HEAD,PATCH"
const X_ACCESS_CONTROL_ALLOW_ORIGIN = process.env.X_ACCESS_CONTROL_ALLOW_ORIGIN || "*"
const X_ACCESS_CONTROL_ALLOW_METHODS = process.env.X_ACCESS_CONTROL_ALLOW_METHODS || "GET, POST, PUT, DELETE, OPTIONS"
const X_ACCESS_CONTROL_ALLOW_HEADERS = process.env.X_ACCESS_CONTROL_ALLOW_HEADERS || "*"

const DEFAULT_TIMEOUT = parseInt(process.env.DEFAULT_TIMEOUT || "60000")
const MIN_TIMEOUT = parseInt(process.env.MIN_TIMEOUT || "1000")
const MAX_TIMEOUT = parseInt(process.env.MAX_TIMEOUT || "300000")

function isMethodAllowed(method: string): boolean {
    const allowedMethods = X_ALLOWMETHODS.split(",").map(i => i.trim().toLowerCase()).filter(Boolean);
    return allowedMethods.includes(method.toLowerCase());
}

function isHostAllowed(target: URL): boolean {
    if (!X_ALLOWHOST) {
        return true;
    }
    const hosts = X_ALLOWHOST.split(",").map(i => i.trim().toLowerCase()).filter(Boolean);
    try {
        return hosts.some(host => {
            const pattern = new URLPattern({ hostname: host });
            return pattern.test(target);
        });
    } catch {
        return false;
    }
}

function filterHeaders(headers: Headers): Headers {
    const filteredHeaders = new Headers();
    const allowHeaders = X_ALLOWHEADERS.split(",").map(i => i.trim().toLowerCase()).filter(Boolean);
    for (const header of allowHeaders) {
        if (headers.has(header)) {
            filteredHeaders.set(header, headers.get(header) as string);
        }
    }
    return filteredHeaders;
}

async function handleRequest(request: Request): Promise<Response> {
    try {
        const requestURL = new URL(request.url);
        // auth
        if (X_VERCEL_PROXY_TOKEN) {
            const requestToken = request.headers.get('Authorization')?.replace('Bearer ', '')?.trim() || requestURL.searchParams.get('token')?.trim();
            if (requestToken !== X_VERCEL_PROXY_TOKEN) {
                return new Response('Unauthorized: Invalid proxy token', { status: 401 });
            }
        }

        const targetUrl = requestURL.searchParams.get('url');
        if (!targetUrl || targetUrl.trim() === '') {
            return new Response('Missing URL parameter', { status: 400 });
        }

        let targetURL: URL;
        try {
            targetURL = new URL(decodeURIComponent(targetUrl));
        } catch {
            return new Response("Invalid Target URL", { status: 400 })
        }

        // check method
        const isMethodAllow = isMethodAllowed(request.method);
        if (!isMethodAllow) {
            return new Response(`Method not allowed`, { status: 405 });
        }

        // check host
        const isHostAllow = isHostAllowed(targetURL);
        if (!isHostAllow) {
            return new Response('URL not allowed', { status: 403 });
        }

        // get timeout
        let proxyTimeout: number = DEFAULT_TIMEOUT;
        if (request.headers.has('c-proxy-timeout')) {
            proxyTimeout = parseInt(request.headers.get('c-proxy-timeout') as string)
        }
        else if (requestURL.searchParams.has('timeout')) {
            proxyTimeout = parseInt(requestURL.searchParams.get('timeout') as string)
        }
        proxyTimeout = Math.max(MIN_TIMEOUT, Math.min(MAX_TIMEOUT, proxyTimeout));

        // get header
        const proxyHeaders = filterHeaders(request.headers);
        proxyHeaders.set('Accept-Encoding', 'identity');


        const proxyFetchOptions: RequestInit = {
            method: request.method,
            headers: proxyHeaders,
            redirect: 'manual',
        };

        // PUT POST DELETE PATCH requests may have a body, so we need to clone the request and pass the body to the fetch options
        if (request.method !== 'GET' && request.method !== 'HEAD' && request.method !== 'OPTIONS') {
            const clonedRequest = request.clone();
            proxyFetchOptions.body = clonedRequest.body;
            //@ts-ignore
            proxyFetchOptions.duplex = 'half'
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), proxyTimeout);

        try {
            const response = await fetch(targetUrl, {
                ...proxyFetchOptions,
                signal: controller.signal
            });

            clearTimeout(timeout);
            const responseHeaders = new Headers();

            response.headers.forEach((value, key) => {
                const lowerKey = key.toLowerCase();
                if (lowerKey === 'content-encoding') return;
                responseHeaders.set(key, value);
            });

            responseHeaders.set('Access-Control-Allow-Origin', X_ACCESS_CONTROL_ALLOW_ORIGIN);
            responseHeaders.set('Access-Control-Allow-Methods', X_ACCESS_CONTROL_ALLOW_METHODS);
            responseHeaders.set('Access-Control-Allow-Headers', X_ACCESS_CONTROL_ALLOW_HEADERS);

            if (request.method === 'OPTIONS') {
                return new Response(null, {
                    status: 204,
                    headers: responseHeaders
                });
            }
            return new Response(response.body, {
                status: response.status,
                headers: responseHeaders
            });

        } catch (fetchError) {
            clearTimeout(timeout);
            if (fetchError instanceof Error && fetchError.name === 'AbortError') {
                return new Response("Request timed out", { status: 504 });
            }
            throw fetchError;
        }

    } catch (error) {
        console.error('Proxy error:', error);
        const message = error instanceof Error ? error.message : 'Unknown error';
        return new Response(message, {
            status: 500
        });
    }
}

export default {
    fetch: handleRequest
}