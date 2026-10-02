import { t } from './i18n.js';
import { ApiError, localLink, request } from './http.js';
import { appendDefinition, busy, byId, notice } from './ui.js';
import { showWorkError } from './work.js';
import { receiveFile, saveReceivedFile, TransferPreparationError } from './transfer.js';
import { FileTransferState } from './transfer-state.js';

export class FileDownloadController {
    constructor(identity, options) {
        this.identity = identity;
        this.options = options;
        this.state = new FileTransferState(identity.username, options.targetId, options.returnPath);
        this.command = this.state.value.command;
        this.result = this.state.value.result;
        this.restored = Boolean(this.result);
        this.nativeRequired = false;
        byId('download-form').addEventListener('submit', event => {
            event.preventDefault();
            if (this.state.value.pending || this.state.pendingReturnPath) return;
            void busy(byId('download'), () => this.receive()).finally(() => this.controls());
        });
        byId('cancel').addEventListener('click', () => this.controller?.abort());
        byId('new-command').addEventListener('click', () => {
            this.command = null;
            this.state.save({ command: null });
            notice(byId('feedback'), t('download.new.ready'));
            this.controls();
        });
        byId('retry-report').addEventListener('click', () => void busy(byId('retry-report'), () => this.reportReceipt()));
        document.addEventListener('lab:language', () => this.render());
    }

    ready() {
        if (this.state.pendingReturnPath) {
            byId('pending-transfer-link').href = localLink(this.state.pendingReturnPath);
            byId('pending-transfer-link').hidden = false;
            notice(byId('feedback'), t('download.pending.other'), 'warning');
        } else {
            notice(byId('feedback'), this.state.value.inFlight ? t('download.interrupted') : '', 'warning');
            if (this.state.value.pending) notice(byId('receipt-result'), t('download.report.failed'), 'warning');
        }
        this.controls();
        this.render();
    }

    controls() {
        const pending = Boolean(this.state.value.pending || this.state.pendingReturnPath);
        byId('download').disabled = this.nativeRequired || pending || this.running;
        byId('new-command').disabled = pending || this.running;
        byId('new-command').hidden = !this.command;
        byId('retry-report').hidden = !this.state.value.pending || Boolean(this.state.pendingReturnPath);
    }

    render() {
        const result = this.result;
        if (!result) return;
        const complete = result.state === 'COMPLETE' && result.matchesServer;
        const denied = [401, 403, 423].includes(result.status) && result.receivedBytes === 0;
        const message = complete ? 'download.complete'
            : result.state === 'COMPLETE' ? 'download.mismatch'
                : denied ? 'download.denied' : 'download.incomplete';
        notice(byId('restored-result'), this.restored ? t('download.restored') : '');
        notice(byId('download-result'), t(message), complete ? '' : 'warning');
        const facts = byId('download-facts');
        facts.replaceChildren();
        appendDefinition(facts, t('download.received'), `${result.receivedBytes} B`);
        const technical = byId('download-technical');
        technical.replaceChildren();
        byId('download-technical-section').hidden = false;
        appendDefinition(technical, t('download.http'), result.status == null ? t('unknown') : String(result.status));
        if (result.preparedItems != null) appendDefinition(facts, t('export.prepared.items'), String(result.preparedItems));
        if (result.fileId) appendDefinition(technical, t('download.file.id'), result.fileId);
        if (result.contentSha256) appendDefinition(technical, 'SHA-256', result.contentSha256);
        byId('evidence-link').hidden = !result.requestId;
        if (result.requestId) byId('evidence-link').href = localLink(`/request.html?arm=${this.identity.role}&id=${encodeURIComponent(result.requestId)}`, this.identity.portalUrl);
    }

    async receive() {
        notice(byId('feedback'));
        notice(byId('receipt-result'));
        byId('retry-report').hidden = true;
        const input = this.options.input();
        const previous = this.command ? Object.fromEntries(Object.entries(this.command).filter(([key]) => key !== 'commandId')) : null;
        if (JSON.stringify(previous) !== JSON.stringify(input)) this.command = { commandId: crypto.randomUUID(), ...input };
        try { this.state.begin(this.command); }
        catch { notice(byId('feedback'), t('download.storage.failed'), 'danger'); return; }
        this.restored = false;
        this.running = true;
        this.controller = new AbortController();
        byId('cancel').hidden = false;
        byId('new-command').disabled = true;
        ['purpose', 'file-language', 'work-approval'].forEach(id => { byId(id).disabled = true; });
        notice(byId('download-result'), t('download.receiving'));
        try {
            this.result = await receiveFile(this.options.endpoint, this.command, this.controller.signal, (received, expected) => {
                const progress = byId('transfer-progress');
                progress.hidden = false;
                if (expected > 0) { progress.max = expected; progress.value = received; }
                else progress.removeAttribute('value');
                byId('transfer-bytes').textContent = `${received} B`;
            }, this.options.contentTypes);
            if (this.result.data) this.nativeRequired = showWorkError(new ApiError(this.result.status, this.result.data));
            this.state.received(this.result);
            this.render();
            if (this.result.state === 'COMPLETE' && this.result.matchesServer) saveReceivedFile(this.result);
            await this.reportReceipt();
        } catch (error) {
            if (error instanceof TransferPreparationError) this.state.save({ inFlight: false });
            this.nativeRequired = showWorkError(error instanceof TransferPreparationError ? error.cause : error);
            notice(byId('download-result'), t(error instanceof TransferPreparationError ? 'download.not.sent' : 'download.incomplete'), 'warning');
        } finally {
            this.running = false;
            byId('cancel').hidden = true;
            byId('transfer-progress').hidden = true;
            byId('transfer-bytes').textContent = '';
            ['purpose', 'file-language', 'work-approval'].forEach(id => { byId(id).disabled = false; });
        }
    }

    async reportReceipt() {
        const pending = this.state.value.pending;
        if (!pending) return;
        notice(byId('receipt-result'), t('download.report.saving'));
        try {
            await request(`/api/lab/workspaces/requests/${this.identity.role}/${pending.requestId}/receipts`, {
                origin: this.identity.portalUrl, method: 'POST', body: pending.receipt
            });
            this.state.save({ pending: null });
            notice(byId('receipt-result'), t('download.report.saved'));
        } catch {
            notice(byId('receipt-result'), t('download.report.failed'), 'warning');
        }
        this.controls();
    }
}
