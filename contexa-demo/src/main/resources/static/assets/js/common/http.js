export class ApiError extends Error {
    constructor(status, data) {
        super(data?.state || data?.code || 'Request failed');
        this.status = status;
        this.data = data;
    }
}

export async function request(path, { origin = location.origin, method = 'GET', body } = {}) {
    const headers = { Accept: 'application/json' };
    if (method !== 'GET') {
        const csrf = await request('/api/auth/csrf', { origin });
        if (!csrf?.headerName || !csrf?.token) throw new ApiError(403, { state: 'CSRF_UNAVAILABLE' });
        headers[csrf.headerName] = csrf.token;
    }
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(new URL(path, origin), {
        method, headers, credentials: 'include', cache: 'no-store', redirect: 'error',
        signal: AbortSignal.timeout(20000),
        body: body === undefined ? undefined : JSON.stringify(body)
    });
    const contentType = response.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await response.json() : null;
    if (!response.ok) throw new ApiError(response.status, data);
    if (response.status !== 204 && data === null) throw new ApiError(502, { state: 'UNEXPECTED_RESPONSE' });
    return data;
}

export function localLink(path, origin = location.origin) {
    const base = new URL(origin);
    const url = new URL(path, base);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== base.origin) {
        throw new Error('Invalid application link');
    }
    return url.href;
}

export async function nativeLogout() {
    const csrf = await request('/api/auth/csrf');
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/logout';
    const token = document.createElement('input');
    token.type = 'hidden';
    token.name = csrf.parameterName;
    token.value = csrf.token;
    form.append(token);
    document.body.append(form);
    form.submit();
}
