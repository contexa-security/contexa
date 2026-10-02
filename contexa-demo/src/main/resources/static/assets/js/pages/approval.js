import { dateTime, t } from '../common/i18n.js';
import { ApiError, localLink, request } from '../common/http.js';
import { sendBusinessCommand } from '../common/business-http.js';
import { CommandDraft } from '../common/command-draft.js';
import { approvalError, approvalStatus } from '../common/approval-ui.js';
import { appendDefinition, busy, byId, element, notice } from '../common/ui.js';
import { initializeWork, query, translated } from '../common/work.js';

const id = query.get('id');
let view;
let refreshing = false;
let stale = false;
let identity;
let draft;
let lastRequest = query.get('request');
function render() {
    if (!view) return;
    byId('approval-status').replaceChildren(approvalStatus(view.effectiveStatus));
    const facts = byId('approval-facts');
    facts.replaceChildren();
    const original = view.request;
    [[t('approval.requester'), original.requester], [t('work.purpose'), t(`approval.purpose.${original.purpose}`)],
        [t('approval.requested'), dateTime(original.requestedAt)], [t('approval.expires'), dateTime(original.expiresAt)],
        [t('approval.observed'), dateTime(view.observedAt)], [t('approval.reason'), original.reason]].forEach(([key, value]) => appendDefinition(facts, key, value));
    byId('approval-targets').replaceChildren(...original.targets.map(target => {
        const item = element('li');
        if (original.requester === identity.username) {
            const link = element('a', `${translated(target.label)} · ${target.projectId.toUpperCase()} · v${target.version}`);
            link.href = `/${original.resourceType === 'CUSTOMER' ? 'customer' : 'document'}.html?id=${encodeURIComponent(target.id)}&approval=${encodeURIComponent(original.id)}`;
            item.append(link);
        } else item.textContent = `${translated(target.label)} · ${target.projectId.toUpperCase()} · v${target.version}`;
        return item;
    }));
    const history = byId('approval-history');
    history.replaceChildren();
    const submitted = element('li');
    submitted.append(element('time', dateTime(original.requestedAt)), element('h4', t('approval.submitted')), element('p', `${original.requester}: ${original.reason}`));
    history.append(submitted);
    if (view.decision) {
        const decision = element('li');
        decision.append(element('time', dateTime(view.decision.decidedAt)), element('h4', t(`approval.status.${view.decision.verdict}`)), element('p', `${view.decision.reviewer}: ${view.decision.reason}`));
        history.append(decision);
    }
    byId('expiry-note').hidden = view.effectiveStatus !== 'EXPIRED';
    byId('approval-work-return').hidden = original.requester !== identity.username;
    const exportQuery = new URLSearchParams({ type: original.resourceType, approval: original.id });
    original.targets.forEach(target => exportQuery.append('id', target.id));
    byId('approval-export').href = `/export.html?${exportQuery}`;
    byId('approval-return-note').textContent = t(view.effectiveStatus === 'APPROVED'
        ? 'approval.return.approved' : 'approval.return.notApproved');
    byId('review-panel').hidden = stale || !view.canReview;
    byId('approval-request-evidence').hidden = !lastRequest;
    if (lastRequest) byId('approval-request-evidence').href = localLink(`/request.html?arm=${identity.role}&id=${encodeURIComponent(lastRequest)}`, identity.portalUrl);
}
async function refresh(silent = false) {
    if (refreshing) return;
    refreshing = true;
    if (!silent) notice(byId('feedback'), t('work.loading'));
    try {
        view = await request(`/api/work/approvals/${encodeURIComponent(id)}`);
        const recovered = stale;
        stale = false;
        if (!silent || recovered) notice(byId('feedback'));
        render();
    } catch (error) {
        stale = true;
        render();
        approvalError(error);
    } finally { refreshing = false; }
}
byId('review-form').addEventListener('submit', event => {
    event.preventDefault();
    void busy(byId('review-submit'), async () => {
        try {
            const input = draft.prepare({ verdict: byId('verdict').value, reason: byId('review-reason').value });
            const result = await sendBusinessCommand(`/api/work/admin/approvals/${encodeURIComponent(id)}/decision`, input, data => Boolean(data?.decision?.id));
            if (!result.ok) throw new ApiError(result.status, result.data);
            view = result.data;
            lastRequest = result.requestId;
            history.replaceState(null, '', `/approval.html?id=${encodeURIComponent(id)}&request=${encodeURIComponent(lastRequest || '')}`);
            notice(byId('feedback'), t('approval.review.saved'));
            render();
        } catch (error) { approvalError(error); }
    });
});
byId('refresh').addEventListener('click', () => void busy(byId('refresh'), refresh));
document.addEventListener('lab:language', render);
try {
    identity = await initializeWork();
    draft = new CommandDraft(`approval-review.${id}`, identity.username);
    const saved = draft.input();
    if (saved) { byId('verdict').value = saved.verdict; byId('review-reason').value = saved.reason; }
    await refresh();
} catch (error) { approvalError(error); }

const refreshTimer = setInterval(() => {
    if (!document.hidden && ['PENDING', 'APPROVED'].includes(view?.effectiveStatus)) void refresh(true);
}, 5000);
window.addEventListener('pagehide', () => clearInterval(refreshTimer), { once: true });
document.addEventListener('visibilitychange', () => { if (!document.hidden) void refresh(true); });
