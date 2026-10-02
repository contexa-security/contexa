const key = 'lab.documentTransfer';

export class FileTransferState {
    constructor(username, targetId, returnPath) {
        let saved = JSON.parse(sessionStorage.getItem(key) || 'null');
        if (saved && saved.username !== username) {
            if (saved.pending || saved.inFlight) throw new Error('TRANSFER_OWNER_CHANGED');
            saved = null;
        }
        const savedTarget = saved?.targetId || saved?.documentId;
        if (saved && savedTarget !== targetId && saved.pending) {
            this.pendingReturnPath = saved.returnPath || `/download.html?id=${encodeURIComponent(saved.documentId)}`;
        }
        this.value = savedTarget === targetId ? { ...saved, targetId, returnPath } : { username, targetId, returnPath };
    }

    save(changes) {
        if (this.pendingReturnPath) throw new Error('PENDING_TRANSFER_REPORT');
        const next = { ...this.value, ...changes };
        sessionStorage.setItem(key, JSON.stringify(next));
        this.value = next;
    }

    begin(command) {
        this.save({ command, inFlight: true, result: null });
    }

    received(result) {
        const { bytes, data, ...summary } = result;
        const pending = result.requestId ? {
            requestId: result.requestId,
            receipt: {
                id: crypto.randomUUID(), state: result.state,
                receivedBytes: result.receivedBytes, contentSha256: result.contentSha256,
                startedAt: result.startedAt, endedAt: result.endedAt
            }
        } : null;
        this.save({ result: summary, pending, inFlight: false });
    }
}
