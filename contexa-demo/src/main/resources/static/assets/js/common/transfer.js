import { request } from './http.js';

export class TransferPreparationError extends Error {
    constructor(cause) { super('Download preparation failed', { cause }); }
}

export async function receiveFile(endpoint, input, signal, progress, contentTypes) {
    if (!endpoint.startsWith('/api/work/')) throw new Error('Invalid file endpoint');
    let csrf;
    try { csrf = await request('/api/auth/csrf'); }
    catch (error) { throw new TransferPreparationError(error); }
    const startedAt = new Date().toISOString();
    const record = { requestId: null, status: null, receivedBytes: 0, state: 'FAILED', startedAt, contentSha256: null };
    const parts = [];
    try {
        const response = await fetch(endpoint, {
            method: 'POST', credentials: 'include', redirect: 'error', cache: 'no-store',
            headers: { Accept: contentTypes.join(', ') + ', application/json', 'Content-Type': 'application/json', [csrf.headerName]: csrf.token },
            body: JSON.stringify(input), signal: AbortSignal.any([signal, AbortSignal.timeout(60000)])
        });
        record.status = response.status;
        record.requestId = response.headers.get('X-Lab-Request-Id');
        if (!response.ok) {
            record.data = (response.headers.get('content-type') || '').includes('application/json') ? await response.json() : null;
            return record;
        }
        record.contentType = response.headers.get('content-type') || '';
        if (!contentTypes.some(type => record.contentType.startsWith(type))) throw new Error('Unexpected download response');
        const prepared = response.headers.get('X-Lab-Prepared-Items');
        record.preparedItems = prepared && /^\d+$/.test(prepared) ? Number(prepared) : null;
        record.fileId = response.headers.get('X-Lab-File-Id');
        record.serverHash = response.headers.get('X-Lab-File-Sha256');
        record.reused = response.headers.get('X-Lab-File-Reused') === 'true';
        record.filename = /filename="?([^";]+)/.exec(response.headers.get('content-disposition') || '')?.[1];
        if (!/^[a-zA-Z0-9._-]{1,120}\.(txt|csv|zip)$/.test(record.filename || '')) record.filename = 'document.txt';
        const length = response.headers.get('content-length');
        record.expectedBytes = length && /^\d+$/.test(length) ? Number(length) : null;
        const reader = response.body.getReader();
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (record.receivedBytes + value.length > 10485760) {
                await reader.cancel();
                throw new Error('Download exceeds browser capture limit');
            }
            parts.push(value);
            record.receivedBytes += value.length;
            progress(record.receivedBytes, record.expectedBytes);
        }
        const bytes = new Uint8Array(record.receivedBytes);
        let offset = 0;
        for (const part of parts) { bytes.set(part, offset); offset += part.length; }
        const hash = await crypto.subtle.digest('SHA-256', bytes);
        record.contentSha256 = [...new Uint8Array(hash)].map(value => value.toString(16).padStart(2, '0')).join('');
        record.matchesServer = record.contentSha256 === record.serverHash;
        record.state = 'COMPLETE';
        record.bytes = bytes;
    } catch (error) {
        record.state = record.receivedBytes > 0 ? 'PARTIAL' : 'FAILED';
        record.failure = signal.aborted ? 'CANCELLED' : error.name;
    } finally {
        record.endedAt = new Date().toISOString();
    }
    return record;
}

export function saveReceivedFile(record) {
    const url = URL.createObjectURL(new Blob([record.bytes], { type: record.contentType || 'application/octet-stream' }));
    const link = document.createElement('a');
    link.href = url; link.download = record.filename;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
