import { currentLanguage, t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { byId, element, notice } from '../common/ui.js';
import { initializeWork, query, showWorkError, translated } from '../common/work.js';
import { WorkApprovalSelection } from '../common/work-approval.js';
import { FileDownloadController } from '../common/file-download.js';
import { initialApprovalId, querySelection } from '../common/work-form-options.js';

const type = query.get('type');
const ids = query.getAll('id').sort();
let targets;
let approval;
function render() {
    if (!targets) return;
    byId('export-target-summary').textContent = t('export.target.summary').replace('{n}', String(targets.length));
    byId('export-selection-title').textContent = t(type === 'DOCUMENT' ? 'export.document.count' : 'export.customer.count')
        .replace('{n}', String(targets.length));
    document.querySelectorAll('.work-navigation a').forEach(link => {
        if (link.getAttribute('href') === (type === 'DOCUMENT' ? '/projects.html' : '/customers.html')) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
    });
    byId('export-format-badge').textContent = type === 'DOCUMENT' ? 'ZIP' : 'CSV · UTF-8';
    byId('export-targets').replaceChildren(...targets.map(target => element('li', `${translated(target.label)} · ${target.resource.projectId.toUpperCase()} · v${target.resource.version}`)));
    byId('export-format').textContent = t(type === 'DOCUMENT' ? 'export.zip.note' : 'export.csv.note').replace('{n}', String(targets.length));
    byId('back-document').href = type === 'DOCUMENT' ? `/documents.html?project=${encodeURIComponent(targets[0].resource.projectId)}` : '/customers.html';
}

document.addEventListener('lab:language', render);
notice(byId('feedback'), t('work.loading'));
try {
    const identity = await initializeWork();
    byId('export-security-mode').hidden = identity.role !== 'contexa';
    byId('export-runtime-note').hidden = identity.role === 'contexa';
    if (!['DOCUMENT', 'CUSTOMER'].includes(type) || !ids.length || ids.length > 50 || new Set(ids).size !== ids.length) throw new Error('INVALID_EXPORT_SELECTION');
    const parameters = new URLSearchParams({ type });
    ids.forEach(id => parameters.append('ids', id));
    targets = await request(`/api/work/exports/preview?${parameters}`);
    byId('export-target-panel').open = targets.length <= 5;
    const transfer = new FileDownloadController(identity, {
        targetId: `export:${type}:${ids.join(',')}`, returnPath: location.pathname + location.search,
        endpoint: '/api/work/exports/download', contentTypes: type === 'DOCUMENT' ? ['application/zip'] : ['text/csv'],
        input: () => ({ resourceType: type, targetIds: ids, purpose: byId('purpose').value,
            language: byId('file-language').value, approvalId: approval.value() })
    });
    byId('file-language').value = querySelection('language', 'file-language') || transfer.command?.language || currentLanguage().toUpperCase();
    if (transfer.command && !querySelection('purpose', 'purpose')) byId('purpose').value = transfer.command.purpose;
    approval = new WorkApprovalSelection(identity, type, targets.map(target => target.resource), initialApprovalId(transfer.command));
    await approval.load();
    render();
    transfer.ready();
} catch (error) {
    if (error.message === 'INVALID_EXPORT_SELECTION') notice(byId('feedback'), t('export.selection.invalid'), 'warning');
    else if (error.message === 'TRANSFER_OWNER_CHANGED') notice(byId('feedback'), t('download.owner.changed'), 'warning');
    else if (error instanceof SyntaxError || error instanceof DOMException) notice(byId('feedback'), t('download.storage.failed'), 'danger');
    else showWorkError(error);
}
