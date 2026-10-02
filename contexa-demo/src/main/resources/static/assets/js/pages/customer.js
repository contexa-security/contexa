import { WorkApprovalSelection } from '../common/work-approval.js';
import { dateTime, t } from '../common/i18n.js';
import { ApiError, localLink, request } from '../common/http.js';
import { readCustomer } from '../common/business-http.js';
import { appendDefinition, badge, busy, byId, element, notice } from '../common/ui.js';
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
    byId('compare-link').href = localLink(`/comparison.html?customer=${encodeURIComponent(id)}&account=${encodeURIComponent(identity.username)}&purpose=${encodeURIComponent(byId('purpose').value)}`, identity.portalUrl);
    byId('page-title').removeAttribute('data-i18n');
    byId('page-title').textContent = translated(metadata.name);
    byId('customer-classification').replaceChildren(badge(t(`work.${metadata.sensitivity}`), 'warning'));
    const meta = byId('customer-meta');
    meta.replaceChildren();
    [[t('customer.industry'), translated(metadata.industry)], [t('customer.region'), translated(metadata.region)],
        [t('work.version'), String(metadata.version)]].forEach(([label, value]) => {
        const item = element('div');
        item.append(element('span', label), element('strong', value));
        meta.append(item);
    });
    byId('content-empty').hidden = Boolean(received);
    byId('customer-content').hidden = !received;
    if (received) {
        const detail = received.data.detail;
        const contact = byId('customer-contact');
        contact.replaceChildren();
        appendDefinition(contact, t('customer.contact'), detail.contactName);
        appendDefinition(contact, t('customer.email'), detail.contactEmail);
        appendDefinition(contact, t('customer.plan'), translated(detail.servicePlan));
        const activity = byId('activity-list');
        activity.replaceChildren();
        detail.activities.forEach(entry => {
            const item = element('li');
            item.append(element('time', dateTime(entry.occurredAt)), element('h4', translated(entry.title)),
                    element('p', translated(entry.note)));
            activity.append(item);
        });
    }
    if (result) {
        let text = t(result.ok ? 'work.success' : result.preparationFailed ? 'work.request.not.sent' : 'work.failed');
        if (result.status != null) text += ` (HTTP ${result.status})`;
        if (!result.ok && received) text += ' ' + t('work.previous.content');
        notice(byId('read-result'), text, result.ok ? '' : 'warning');
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
            result = await readCustomer(id, byId('purpose').value, approval.value());
            if (result.ok) received = result;
            else nativeRequired = showWorkError(new ApiError(result.status, result.data));
            render();
        } catch (error) {
            nativeRequired = showWorkError(error);
            if (error instanceof ApiError) {
                result = { ok: false, preparationFailed: true, status: error.status };
                render();
            } else notice(byId('read-result'), t('work.request.network'), 'warning');
        }
    }).finally(() => { byId('read').disabled = nativeRequired; });
});

document.addEventListener('lab:language', render);
byId('purpose').addEventListener('change', render);
notice(byId('feedback'), t('work.loading'));
try {
    identity = await initializeWork();
    metadata = await request(`/api/work/customers/${encodeURIComponent(id)}`);
    approval = new WorkApprovalSelection(identity, 'CUSTOMER', metadata, query.get('approval'));
    await approval.load();
    notice(byId('feedback'));
    render();
    byId('read').disabled = false;
} catch (error) { showWorkError(error); }
