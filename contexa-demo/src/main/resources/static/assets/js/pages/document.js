import { WorkApprovalSelection } from '../common/work-approval.js';
import { dateTime, t } from '../common/i18n.js';
import { ApiError, localLink, request } from '../common/http.js';
import { readDocument } from '../common/business-http.js';
import { badge, busy, byId, element, notice } from '../common/ui.js';
import { initializeWork, query, showWorkError, translated } from '../common/work.js';

const id = query.get('id');
let identity;
let approval;
let metadata;
let result;
let received;
let nativeRequired = false;

function render() {
    if (!metadata) return;
    byId('page-title').removeAttribute('data-i18n');
    byId('page-title').textContent = translated(metadata.title);
    byId('document-classification').replaceChildren(badge(t(`work.${metadata.sensitivity}`), metadata.sensitivity === 'CONFIDENTIAL' ? 'warning' : ''));
    const meta = byId('document-meta'); meta.replaceChildren();
    [[t('work.author'), metadata.author], [t('work.updated'), dateTime(metadata.updatedAt)], [t('work.version'), String(metadata.version)]].forEach(([label, value]) => {
        const item = element('div'); item.append(element('span', label), element('strong', value)); meta.append(item);
    });
    byId('download-link').href = `/download.html?id=${encodeURIComponent(id)}` + (approval?.value() ? `&approval=${encodeURIComponent(approval.value())}` : '');
    byId('compare-link').href = localLink(`/comparison.html?document=${encodeURIComponent(id)}&account=${encodeURIComponent(identity.username)}&purpose=${encodeURIComponent(byId('purpose').value)}`, identity.portalUrl);
    byId('back-documents').href = `/documents.html?project=${encodeURIComponent(metadata.projectId)}`;
    byId('content-empty').hidden = Boolean(received);
    byId('document-content').hidden = !received;
    byId('document-content').textContent = received ? translated(received.data.document.content) : '';
    if (result) {
        let message = t(result.ok ? 'work.success' : result.preparationFailed ? 'work.request.not.sent' : 'work.failed');
        if (result.status != null) message += ` (HTTP ${result.status})`;
        if (!result.ok && received) message += ' ' + t('work.previous.content');
        notice(byId('read-result'), message, result.ok ? '' : 'warning');
        const observedId = result.requestId || received?.requestId;
        byId('evidence-link').hidden = !observedId;
        if (observedId) byId('evidence-link').href = localLink(`/request.html?arm=${identity.role}&id=${encodeURIComponent(observedId)}`, identity.portalUrl);
    }
}

byId('read-form').addEventListener('submit', event => {
    event.preventDefault();
    void busy(byId('read'), async () => {
        notice(byId('feedback'));
        notice(byId('read-result'), t('working'));
        try {
            result = await readDocument(id, byId('purpose').value, approval.value());
            if (result.ok) received = result;
            else nativeRequired = showWorkError(new ApiError(result.status, result.data));
            render();
        } catch (error) {
            nativeRequired = showWorkError(error);
            if (error instanceof ApiError) {
                result = { ok: false, preparationFailed: true, status: error.status, requestId: null };
                render();
            } else {
                notice(byId('read-result'), t('work.request.network'), 'warning');
            }
        }
    }).finally(() => { byId('read').disabled = nativeRequired; });
});
byId('purpose').addEventListener('change', render);
document.addEventListener('lab:language', render);
document.addEventListener('lab:approval', render);
notice(byId('feedback'), t('work.loading'));
try {
    identity = await initializeWork();
    metadata = await request(`/api/work/documents/${encodeURIComponent(id)}`);
    approval = new WorkApprovalSelection(identity, 'DOCUMENT', metadata, query.get('approval'));
    await approval.load();
    notice(byId('feedback'));
    render();
    byId('read').disabled = false;
}
catch (error) { showWorkError(error); }
