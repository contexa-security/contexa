import '../common/shell.js';
import { comparisonContextUrl } from '../common/comparison-context-url.js';
import { journeyReference, setJourneyReference } from '../common/journey-link.js';
import { setSessionPreparation } from '../common/comparison-sessions.js';
import { setSubmissionPreparation } from '../common/run-submissions.js';
import { setComparisonFlow } from '../common/comparison-flow.js';
import { batchSelection, batchSelectionValid, loadBatchCatalog, lockBatchSelection, setBatchSelection } from '../common/comparison-batch-catalog.js';
import { currentLanguage, dateTime, t } from '../common/i18n.js';
import { workPurposeText } from '../common/work-purpose.js';
import { ApiError, request } from '../common/http.js';
import { appendDefinition, badge, busy, byId, element, errorText, notice } from '../common/ui.js';

const endpoint = '/api/lab/comparisons/preparations';
const query = new URLSearchParams(location.search);
const storageKey = 'lab.comparison.batch.pending';
let parentRunId = query.get('parent');
let historyReportId = query.get('historyReport');
let prepared;
let pending;
let sending = false;
let available = false;
try { pending = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch { pending = null; }

function remember() {
    try {
        if (pending) sessionStorage.setItem(storageKey, JSON.stringify(pending));
        else sessionStorage.removeItem(storageKey);
    } catch { /* The current command can still be retried without reissuing work. */ }
}

function values() {
    return { requestedAccount: byId('requested-account').value, purpose: byId('purpose').value,
        operation: 'EXPORT', language: byId('file-language').value,
        ...(parentRunId ? { parentRunId } : {}), ...(journeyReference() ? { journeyStep: journeyReference() } : {}),
        ...(historyReportId ? { historyReportId } : {}), exportSelection: batchSelection() };
}

function fill(input) {
    historyReportId = input.historyReportId || historyReportId;
    parentRunId = input.parentRunId || null;
    byId('requested-account').value = input.requestedAccount;
    byId('purpose').value = input.purpose;
    byId('file-language').value = input.language || currentLanguage().toUpperCase();
    setBatchSelection(input.exportSelection);
}

function fromPlan(plan) {
    return { requestedAccount: plan.requestedAccount, purpose: plan.purpose, language: plan.fileRequest?.language,
        parentRunId: plan.parentRunId, exportSelection: plan.exportSelection, journeyStep: plan.journeyStep, historyReportId: plan.historyReportId };
}

function render() {
    const selection = batchSelection();
    const locked = sending || Boolean(pending);
    lockBatchSelection(locked);
    byId('requested-account').disabled = locked || Boolean(parentRunId);
    byId('purpose').disabled = locked;
    byId('file-language').disabled = locked;
    byId('prepare').disabled = !available || sending || !selection.targetIds.length || !batchSelectionValid()
        || Boolean(selection.baselineApprovalId) !== Boolean(selection.contexaApprovalId);
    byId('prepare').textContent = t(sending ? 'working' : pending ? 'compare.retry' : 'batch.choose');
    byId('comparison-parent-note').hidden = !parentRunId;
    if (parentRunId) byId('comparison-parent-link').href = `/run.html?id=${parentRunId}`;
    byId('preparation-form').hidden = Boolean(prepared);
    byId('selected-task').hidden = !prepared;
    byId('preparation-result').hidden = !prepared;
    byId('new-check').hidden = !prepared && !pending;
    byId('new-check').disabled = sending;
    setComparisonFlow(prepared);
    void setSessionPreparation(prepared?.id);
    setSubmissionPreparation(prepared?.id);
    if (!prepared) return;
    const snapshot = prepared.snapshot;
    const plan = snapshot.requestPlan;
    byId('selected-title').textContent = t('batch.selected').replace('{n}', String(plan.exportSelection.targetIds.length));
    byId('selected-account').textContent = plan.requestedAccount;
    byId('selected-purpose').textContent = `${workPurposeText(plan.purpose)} · ${plan.fileRequest.language}`;
    byId('checked-at').textContent = dateTime(prepared.preparedAt);
    byId('document-match').replaceChildren(badge(t(snapshot.batchesMatch ? 'compare.match' : 'compare.mismatch'), snapshot.batchesMatch ? 'good' : 'warning'));
    byId('saved-plan').textContent = t('batch.plan.note');
    byId('document-sources').replaceChildren(...snapshot.batches.map(source => {
        const section = element('section', null, 'source-arm');
        section.append(element('h3', source.arm === 'baseline' ? t('connect.baseline') : 'Contexa'));
        const list = element('ul');
        for (const item of source.items) list.append(element('li', item.title?.[currentLanguage()] || item.id));
        section.append(list, element('p', `SHA-256 · ${source.batchSha256 || t('unknown')}`, 'mono'));
        return section;
    }));
    byId('blockers').replaceChildren(...snapshot.blockers.map(value => element('li', `${value.arm} · ${value.component} · ${value.state}`)));
    byId('record-meta').replaceChildren();
    appendDefinition(byId('record-meta'), t('compare.record'), prepared.id);
    byId('preparation-json').textContent = JSON.stringify(prepared, null, 2);
}

byId('preparation-form').addEventListener('submit', event => {
    event.preventDefault();
    void busy(byId('prepare'), async () => {
        sending = true;
        pending ||= { commandId: crypto.randomUUID(), ...values() };
        remember(); render();
        try {
            prepared = await request(endpoint, { method: 'POST', body: pending });
            pending = null; remember();
            history.replaceState(null, '', `/batch-comparison.html?id=${prepared.id}`);
            render(); notice(byId('feedback'), t('compare.saved')); byId('result-title').focus();
        } catch (error) {
            if (error instanceof ApiError && error.status < 500) { pending = null; remember(); }
            notice(byId('feedback'), errorText(error), 'warning');
        } finally { sending = false; }
    }).finally(render);
});
byId('new-check').addEventListener('click', () => {
    prepared = null; pending = null; remember();
    history.replaceState(null, '', comparisonContextUrl('/batch-comparison.html', { parentRunId, historyReportId, journeyStep: journeyReference() }));
    notice(byId('feedback')); render();
    byId('purpose').focus();
});
document.addEventListener('lab:batch-selection', render);
document.addEventListener('lab:language', render);

try {
    const entry = await request('/api/lab/entry/session');
    if (entry.state !== 'VERIFIED') location.assign('/entry.html');
    else {
        const workspace = await request('/api/lab/workspaces/current');
        for (const account of workspace.allowedAccounts) {
            const option = element('option', account); option.value = account; byId('requested-account').append(option);
        }
        let input = { requestedAccount: query.get('account') || workspace.allowedAccounts[0], purpose: query.get('purpose') || 'PROJECT_REVIEW',
            journeyStep: journeyReference(), exportSelection: { resourceType: query.get('type') === 'CUSTOMER' ? 'CUSTOMER' : 'DOCUMENT', targetIds: [] } };
        if (query.has('id')) {
            prepared = await request(`${endpoint}/${encodeURIComponent(query.get('id'))}`);
            historyReportId = prepared.snapshot.requestPlan.historyReportId || null;
            if (!prepared.snapshot.requestPlan.exportSelection) throw new Error('Not an export plan');
            input = fromPlan(prepared.snapshot.requestPlan);
        } else if (pending) input = pending;
        else if (parentRunId) {
            const parent = await request(`/api/lab/runs/${encodeURIComponent(parentRunId)}`);
            if (!parent.run.manifest.plan.exportSelection) throw new Error('Not an export plan');
            input = { ...fromPlan(parent.run.manifest.plan), parentRunId };
        }
        await setJourneyReference(input.journeyStep);
        fill(input); await loadBatchCatalog(); available = true; render();
    }
} catch (error) { notice(byId('feedback'), errorText(error), 'warning'); }
