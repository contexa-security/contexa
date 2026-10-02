import { dateTime, t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { busy, byId, element, notice } from '../common/ui.js';
import { initializeWork } from '../common/work.js';
import { approvalError, approvalStatus } from '../common/approval-ui.js';

let approvals;
function render() {
    if (!approvals) return;
    const list = byId('approval-list');
    list.replaceChildren();
    if (!approvals.length) {
        list.append(element('p', t('approval.empty'), 'empty'));
        return;
    }
    approvals.forEach(view => {
        const row = element('article', null, 'approval-row');
        const info = element('div');
        const heading = element('h3');
        const link = element('a', t(`approval.purpose.${view.request.purpose}`));
        link.href = `/approval.html?id=${encodeURIComponent(view.request.id)}`;
        heading.append(link);
        info.append(heading, element('p', `${view.request.requester} · ${t('approval.target.count').replace('{n}', view.request.targets.length)} · ${dateTime(view.request.requestedAt)}`, 'small muted'));
        row.append(info, approvalStatus(view.effectiveStatus));
        list.append(row);
    });
}
async function refresh() {
    notice(byId('feedback'), t('work.loading'));
    try {
        approvals = await request('/api/work/approvals');
        notice(byId('feedback'));
        render();
    } catch (error) { approvalError(error); }
}
byId('refresh').addEventListener('click', () => void busy(byId('refresh'), refresh));
document.addEventListener('lab:language', render);
try { await initializeWork(); await refresh(); }
catch (error) { approvalError(error); }
