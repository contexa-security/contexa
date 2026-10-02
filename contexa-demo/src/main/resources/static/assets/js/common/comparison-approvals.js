import { t } from './i18n.js';
import { localLink, request } from './http.js';
import { byId, element, notice } from './ui.js';
import { securityContinuation } from './security-feedback.js';
import { matchingApprovedTargets } from './journey-approvals.js';

let selected = { baselineApprovalId: null, contexaApprovalId: null };
let records = { baseline: [], contexa: [] };
let loading = false, locked = false, failed = false;
let recoveries = [];

function render() {
    for (const arm of ['baseline', 'contexa']) {
        const picker = byId(`${arm}-approval`);
        const key = `${arm}ApprovalId`;
        const none = element('option', t('batch.noApproval')); none.value = '';
        picker.replaceChildren(none, ...records[arm].map(value => {
            const option = element('option', `${t(`approval.purpose.${value.request.purpose}`)} · ${value.request.targets.length} · ${t(`approval.status.${value.effectiveStatus}`)}`);
            option.value = value.request.id; option.disabled = value.effectiveStatus !== 'APPROVED'; return option;
        }));
        if (selected[key] && !records[arm].some(value => value.request.id === selected[key])) {
            const previous = element('option', `${t('unknown')} · ${selected[key].slice(0, 8)}`);
            previous.value = selected[key]; picker.append(previous);
        }
        picker.value = selected[key] || ''; picker.disabled = locked || loading;
    }
    byId('approval-refresh').disabled = locked || loading;
    notice(byId('approval-feedback'), failed ? t('batch.approval.missing')
        : !approvalPairMatches() ? t('batch.approval.partial') : '', 'warning');
    if (recoveries.length) {
        const panel = byId('approval-feedback');
        panel.replaceChildren(); panel.hidden = false;
        for (const recovery of recoveries) {
            const name = recovery.arm === 'baseline' ? t('connect.baseline') : 'Contexa';
            panel.append(element('p', `${name} · ${t(`security.${recovery.name}.body`)}`));
            if (recovery.href) {
                const actions = element('div', null, 'actions');
                const link = element('a', `${name} · ${t(recovery.labelKey)}`, 'button secondary compact');
                link.href = recovery.href; link.target = '_blank'; link.rel = 'noopener'; actions.append(link); panel.append(actions);
            }
        }
        panel.append(element('p', t('batch.approval.resume'), 'small'));
    }
}

export function approvalReferences() { return selected.baselineApprovalId || selected.contexaApprovalId ? { ...selected } : null; }
export function approvalPairMatches() { return Boolean(selected.baselineApprovalId) === Boolean(selected.contexaApprovalId); }
export function comparisonApprovedTargets(account, purpose) {
    return matchingApprovedTargets([records.baseline, records.contexa], account, purpose);
}
export function setApprovalReferences(value) {
    selected = { baselineApprovalId: value?.baselineApprovalId || null, contexaApprovalId: value?.contexaApprovalId || null }; render();
}
export function lockApprovals(value) { if (locked !== value) { locked = value; render(); } }

export async function loadComparisonApprovals(configuration) {
    if (loading) return;
    loading = true; failed = false; recoveries = []; records = { baseline: [], contexa: [] }; render();
    try {
        const origins = configuration || await request('/api/lab/identity');
        const outcomes = await Promise.allSettled(['baseline', 'contexa'].map(async arm => {
            const origin = origins[`${arm}Url`];
            byId(`${arm}-approval-link`).href = localLink('/approvals.html', origin);
            records[arm] = await request('/api/work/approvals', { origin });
        }));
        failed = outcomes.some(outcome => outcome.status === 'rejected');
        outcomes.forEach((outcome, index) => {
            if (outcome.status !== 'rejected') return;
            const arm = ['baseline', 'contexa'][index];
            const recovery = securityContinuation(outcome.reason?.data, origins[`${arm}Url`], '/approvals.html');
            if (recovery) recoveries.push({ ...recovery, arm });
        });
    } catch { failed = true; }
    finally { loading = false; render(); document.dispatchEvent(new Event('lab:approval-selection')); }
}

for (const arm of ['baseline', 'contexa']) byId(`${arm}-approval`).addEventListener('change', event => {
    selected[`${arm}ApprovalId`] = event.target.value || null; render(); document.dispatchEvent(new Event('lab:approval-selection'));
});
byId('approval-refresh').addEventListener('click', () => void loadComparisonApprovals());
document.addEventListener('lab:language', render);
