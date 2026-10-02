import { setSessionPreparation } from '../common/comparison-sessions.js';
import { setSubmissionPreparation } from '../common/run-submissions.js';
import { setComparisonFlow } from '../common/comparison-flow.js';
import { comparisonTargetName, loadComparisonTargets, lockComparisonTarget, selectComparisonTarget } from '../common/comparison-targets.js';
import { journeyReference, setJourneyReference } from '../common/journey-link.js';
import { approvalReferences, approvalPairMatches, loadComparisonApprovals, lockApprovals, setApprovalReferences } from '../common/comparison-approvals.js';
import '../common/shell.js';
import { comparisonContextUrl } from '../common/comparison-context-url.js';
import { currentLanguage, dateTime, t } from '../common/i18n.js';
import { workPurposeText } from '../common/work-purpose.js';
import { ApiError, request } from '../common/http.js';
import { appendDefinition, badge, busy, byId, element, errorText, notice } from '../common/ui.js';

const endpoint = '/api/lab/comparisons/preparations';
const query = new URLSearchParams(location.search);
const pendingKey = 'lab.comparison.pending';
let prepared;
let pending;
let available = false;
let sending = false;
let feedback;
let parentRunId = query.get('parent');
let historyReportId = query.get('historyReport');
try { pending = JSON.parse(sessionStorage.getItem(pendingKey) || 'null'); } catch { pending = null; }

function label(group, value) {
    const key = `compare.${group}.${value}`;
    return t(key) === key ? t(`compare.${group}.other`) : t(key);
}

function armLabel(arm) {
    return arm === 'baseline' ? t('connect.baseline') : arm === 'contexa' ? 'Contexa'
        : arm === 'portal' ? 'Runtime Lab' : t('compare.all');
}

function remember() {
    try {
        if (pending) sessionStorage.setItem(pendingKey, JSON.stringify(pending));
        else sessionStorage.removeItem(pendingKey);
    } catch { /* Persistence of a pending browser command is optional. */ }
}

function formValues() {
    const resourceKey = byId('resource-type').value === 'CUSTOMER' ? 'customerId' : 'documentId';
    return { [resourceKey]: byId('document-id').value.trim(), requestedAccount: byId('requested-account').value,
        purpose: byId('purpose').value, ...(parentRunId ? { parentRunId } : {}), ...(journeyReference() ? { journeyStep: journeyReference() } : {}),
        ...(historyReportId ? { historyReportId } : {}),
        ...(approvalReferences() ? { approvalReferences: approvalReferences() } : {}), ...(resourceKey === 'documentId' && byId('operation').value === 'DOWNLOAD'
            ? { operation: 'DOWNLOAD', language: byId('file-language').value } : {}) };
}

function fill(values) {
    historyReportId = values.historyReportId || historyReportId;
    parentRunId = values.parentRunId || parentRunId;
    selectComparisonTarget(values.customerId || values.documentId);
    byId('requested-account').value = values.requestedAccount || '';
    byId('purpose').value = values.purpose || 'PROJECT_REVIEW';
    byId('operation').value = values.operation || 'READ';
    byId('file-language').value = values.language || currentLanguage().toUpperCase();
    setApprovalReferences(values.approvalReferences);
    if (values.approvalReferences || ['APPROVED_BULK_DELIVERY', 'EMERGENCY_MAINTENANCE'].includes(values.purpose)) byId('comparison-approvals').open = true;
}

function render() {
    if (feedback) notice(byId('feedback'), feedback.key ? t(feedback.key) : errorText(feedback.error), feedback.tone);
    byId('prepare').textContent = t(sending ? 'working' : pending ? 'compare.retry' : 'compare.check');
    byId('new-check').hidden = !prepared && !pending;
    byId('new-check').disabled = sending;
    byId('preparation-result').hidden = !prepared;
    byId('preparation-form').hidden = Boolean(prepared);
    byId('selected-task').hidden = !prepared;
    byId('requested-account').disabled = sending || Boolean(pending) || Boolean(parentRunId);
    byId('comparison-parent-note').hidden = !parentRunId;
    if (parentRunId) byId('comparison-parent-link').href = `/run.html?id=${encodeURIComponent(parentRunId)}`;
    byId('purpose').disabled = sending || Boolean(pending);
    const customer = byId('resource-type').value === 'CUSTOMER';
    byId('file-operation-options').hidden = customer;
    if (customer) byId('operation').value = 'READ';
    byId('file-language-field').hidden = byId('operation').value !== 'DOWNLOAD';
    byId('operation').disabled = sending || Boolean(pending);
    byId('file-language').disabled = sending || Boolean(pending);
    lockComparisonTarget(sending || Boolean(pending));
    lockApprovals(sending || Boolean(pending));
    byId('prepare').disabled = !available || sending || !byId('document-id').value || !approvalPairMatches();
    setComparisonFlow(prepared);
    void setSessionPreparation(prepared?.id);
    setSubmissionPreparation(prepared?.id);
    if (!prepared) return;
    const snapshot = prepared.snapshot;
    byId('preparation-result').hidden = false;
    const plan = snapshot.requestPlan;
    const sources = snapshot.customers || snapshot.documents;
    const source = sources[0];
    const savedName = source?.name || source?.title;
    byId('selected-title').textContent = savedName?.[currentLanguage()]
        || comparisonTargetName(source?.customerId || source?.documentId, source?.version);
    byId('saved-plan').textContent = `${t('compare.saved.plan')} · ${plan.requestedAccount} · ${workPurposeText(plan.purpose)}`;
    byId('selected-purpose').textContent = `${workPurposeText(plan.purpose)} · ${t(plan.fileRequest
        ? 'compare.operation.DOWNLOAD' : 'compare.operation.READ')}${plan.fileRequest ? ` · ${plan.fileRequest.language}` : ''}`;
    byId('selected-account').textContent = plan.requestedAccount;
    byId('checked-at').textContent = `${t('compare.time')} · ${dateTime(prepared.preparedAt)}`;
    const resourcesMatch = snapshot.customersMatch ?? snapshot.documentsMatch;
    byId('document-match').replaceChildren(badge(t(resourcesMatch ? 'compare.match' : 'compare.mismatch'), resourcesMatch ? 'good' : 'warning'));
    byId('document-sources').replaceChildren(...sources.map(source => {
        const section = element('section', null, 'source-arm');
        const title = element('h3'); title.append(element('span', armLabel(source.arm)), badge(label('state', source.state), source.state === 'CAPTURED' ? '' : 'warning'));
        const details = element('dl', null, 'definition');
        appendDefinition(details, t('compare.source.id'), source.customerId || source.documentId);
        appendDefinition(details, t('compare.version'), source.version == null ? t('unknown') : String(source.version));
        appendDefinition(details, t('compare.hash'), source.customerSha256 || source.documentSha256 || t('unknown'));
        details.lastElementChild.querySelector('dd').classList.add('mono');
        section.append(title, details); return section;
    }));
    const groups = new Map();
    for (const blocker of snapshot.blockers) {
        const key = `${blocker.component}:${blocker.state}`;
        if (!groups.has(key)) groups.set(key, { ...blocker, arms: [] });
        groups.get(key).arms.push(armLabel(blocker.arm));
    }
    byId('blockers').replaceChildren(...[...groups.values()].map(blocker => {
        const item = element('li'), description = element('div');
        description.append(element('span', label('check', blocker.component)), element('span', [...new Set(blocker.arms)].join(' · '), 'blocker-scope'));
        item.append(description, badge(label('state', blocker.state), 'warning')); return item;
    }));
    byId('record-meta').replaceChildren();
    appendDefinition(byId('record-meta'), t('compare.record'), prepared.id);
    appendDefinition(byId('record-meta'), 'SHA-256', prepared.snapshotSha256);
    byId('preparation-json').textContent = JSON.stringify(prepared, null, 2);
}

function displayError(error) {
    const key = error instanceof ApiError && error.status === 410 ? 'compare.expired'
        : error instanceof ApiError && error.status === 409 ? 'compare.changed'
        : error instanceof ApiError && error.status === 403 ? 'compare.forbidden'
        : error instanceof ApiError && error.status === 404 ? 'compare.absent' : null;
    showFeedback(key, 'danger', error);
}

function showFeedback(key, tone = '', error = null) {
    feedback = { key, tone, error };
    notice(byId('feedback'), key ? t(key) : errorText(error), tone);
}

byId('preparation-form').addEventListener('submit', event => {
    event.preventDefault();
    void busy(byId('prepare'), async () => {
        sending = true;
        const input = formValues();
        if (!pending) pending = { commandId: crypto.randomUUID(), ...input };
        const { commandId, ...remembered } = pending;
        if (JSON.stringify(input) !== JSON.stringify(remembered)) {
            showFeedback('compare.changed', 'warning'); sending = false; render(); return;
        }
        remember(); render(); showFeedback('working');
        try {
            prepared = await request(endpoint, { method: 'POST', body: pending });
            pending = null; remember();
            history.replaceState(null, '', `/comparison.html?id=${prepared.id}`);
            showFeedback('compare.saved');
            render(); byId('result-title').focus();
        } catch (error) {
            if (!(error instanceof ApiError) || error.status >= 500) showFeedback('compare.retry.note', 'warning');
            else displayError(error);
        } finally { sending = false; }
    }).finally(render);
});

byId('new-check').addEventListener('click', () => {
    pending = null; prepared = null; remember();
    feedback = null;
    const values = formValues();
    const resource = values.customerId ? `customer=${encodeURIComponent(values.customerId)}` : `document=${encodeURIComponent(values.documentId)}`;
    const file = values.operation === 'DOWNLOAD' ? `&operation=DOWNLOAD&language=${values.language}` : '';
    const path = `/comparison.html?${resource}&account=${encodeURIComponent(values.requestedAccount)}&purpose=${encodeURIComponent(values.purpose)}${file}`;
    history.replaceState(null, '', comparisonContextUrl(path, { parentRunId, historyReportId, journeyStep: journeyReference() }));
    notice(byId('feedback')); render(); byId(values.customerId ? 'customer-id' : 'document-id').focus();
});
document.addEventListener('lab:language', render);
document.addEventListener('lab:comparison-targets', render);
document.addEventListener('lab:approval-selection', render);
byId('document-id').addEventListener('change', render);
byId('operation').addEventListener('change', render);

try {
    const entry = await request('/api/lab/entry/session');
    if (entry.state !== 'VERIFIED') location.assign('/entry.html');
    else {
        const workspace = await request('/api/lab/workspaces/current');
        for (const account of workspace.allowedAccounts) {
            const option = element('option', account); option.value = account; byId('requested-account').append(option);
        }
        let values;
        if (query.has('id')) {
            prepared = await request(`${endpoint}/${encodeURIComponent(query.get('id'))}`);
            const plan = prepared.snapshot.requestPlan;
            historyReportId = plan.historyReportId || null;
            await setJourneyReference(plan.journeyStep);
            parentRunId = plan.parentRunId || null;
            values = { documentId: prepared.snapshot.documents[0]?.documentId,
                customerId: prepared.snapshot.customers?.[0]?.customerId, requestedAccount: plan.requestedAccount, purpose: plan.purpose,
                operation: plan.fileRequest ? 'DOWNLOAD' : 'READ', language: plan.fileRequest?.language, parentRunId: plan.parentRunId,
                approvalReferences: plan.approvalReferences };
        } else if (pending) { values = pending; await setJourneyReference(pending.journeyStep); }
        else if (parentRunId) {
            const parent = await request(`/api/lab/runs/${encodeURIComponent(parentRunId)}`);
            const plan = parent.run.manifest.plan;
            await setJourneyReference(plan.journeyStep);
            const target = plan.path.split('/')[4];
            values = { ...(plan.kind === 'CUSTOMER_READ_PAIR' ? { customerId: target } : { documentId: target }),
                requestedAccount: plan.requestedAccount, purpose: plan.purpose, parentRunId,
                operation: plan.fileRequest ? 'DOWNLOAD' : 'READ', language: plan.fileRequest?.language, approvalReferences: plan.approvalReferences };
        }
        else {
            await setJourneyReference();
            values = { documentId: query.get('document'), customerId: query.get('customer'),
            requestedAccount: query.get('account') || workspace.allowedAccounts[0], purpose: query.get('purpose'),
            operation: query.get('operation') === 'DOWNLOAD' ? 'DOWNLOAD' : 'READ', language: query.get('language') };
        }
        await loadComparisonTargets(values.customerId ? 'CUSTOMER' : 'DOCUMENT');
        fill(values);
        await loadComparisonApprovals();
        available = true; render();
    }
} catch (error) { displayError(error); }
