import { currentLanguage, t } from '../common/i18n.js';
import { localLink, request } from '../common/http.js';
import { byId, notice } from '../common/ui.js';
import { initializeWork, query, showWorkError, translated } from '../common/work.js';
import { WorkApprovalSelection } from '../common/work-approval.js';
import { FileDownloadController } from '../common/file-download.js';
import { initialApprovalId, querySelection } from '../common/work-form-options.js';

const id = query.get('id');
let metadata;
let approval;
let identity;
function render() {
    if (!metadata) return;
    byId('document-title').textContent = translated(metadata.title);
    byId('back-document').href = `/document.html?id=${encodeURIComponent(id)}`;
    const parameters = new URLSearchParams({ document: id, account: identity.username,
        purpose: byId('purpose').value, operation: 'DOWNLOAD', language: byId('file-language').value });
    byId('compare-link').href = localLink(`/comparison.html?${parameters}`, identity.portalUrl);
}

document.addEventListener('lab:language', render);
document.addEventListener('lab:approval', render);
for (const control of ['purpose', 'file-language']) byId(control).addEventListener('change', render);
notice(byId('feedback'), t('work.loading'));
try {
    identity = await initializeWork();
    metadata = await request(`/api/work/documents/${encodeURIComponent(id)}`);
    const transfer = new FileDownloadController(identity, {
        targetId: id, returnPath: location.pathname + location.search,
        endpoint: `/api/work/documents/${encodeURIComponent(id)}/download`, contentTypes: ['text/plain'],
        input: () => ({ purpose: byId('purpose').value, language: byId('file-language').value, approvalId: approval.value() })
    });
    byId('file-language').value = querySelection('language', 'file-language') || transfer.command?.language || currentLanguage().toUpperCase();
    if (transfer.command && !querySelection('purpose', 'purpose')) byId('purpose').value = transfer.command.purpose;
    approval = new WorkApprovalSelection(identity, 'DOCUMENT', metadata, initialApprovalId(transfer.command));
    await approval.load();
    render();
    transfer.ready();
} catch (error) {
    if (error.message === 'TRANSFER_OWNER_CHANGED') {
        notice(byId('feedback'), t('download.owner.changed'), 'warning');
    } else if (error instanceof SyntaxError || error instanceof DOMException) {
        notice(byId('feedback'), t('download.storage.failed'), 'danger');
    } else showWorkError(error);
}
