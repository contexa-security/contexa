import { request } from './http.js';

export async function sendBusinessCommand(path, input, validResult) {
    if (!path.startsWith('/api/work/')) throw new Error('Invalid business path');
    const csrf = await request('/api/auth/csrf');
    const startedAt = new Date().toISOString();
    const response = await fetch(path, {
        method: 'POST', credentials: 'include', redirect: 'error', cache: 'no-store',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', [csrf.headerName]: csrf.token },
        body: JSON.stringify(input), signal: AbortSignal.timeout(60000)
    });
    const bytes = await response.arrayBuffer();
    const text = new TextDecoder().decode(bytes);
    let data = null;
    if ((response.headers.get('content-type') || '').includes('application/json')) {
        try { data = JSON.parse(text); } catch { /* Retain the HTTP result without inventing a body. */ }
    }
    return { requestId: response.headers.get('X-Lab-Request-Id'), status: response.status,
        ok: response.ok && validResult(data), data,
        clientReceivedBytes: bytes.byteLength, startedAt, receivedAt: new Date().toISOString() };
}

export function readDocument(id, purpose, approvalId = null) {
    return sendBusinessCommand(`/api/work/documents/${encodeURIComponent(id)}/read`, { purpose, approvalId }, data => Boolean(data?.document?.content));
}

export function readCustomer(id, purpose, approvalId = null) {
    return sendBusinessCommand(`/api/work/customers/${encodeURIComponent(id)}/read`, { purpose, approvalId }, data => Boolean(data?.detail?.customer?.id));
}
