import { currentLanguage, t } from './i18n.js';
import { localLink } from './http.js';
import { badge, byId } from './ui.js';
import { workPath } from './work-resource-path.js';
import { workPurposeText } from './work-purpose.js';

function responseLabel(http) {
    if (http.failureType || http.httpStatus >= 500) return 'failed';
    if (http.httpStatus >= 400) return 'rejected';
    if (http.httpStatus >= 300) return 'redirected';
    if (http.completedAt && http.httpStatus >= 200) return 'responded';
    return 'unconfirmed';
}

export function renderRequestOutcome(evidence, businessOrigin) {
    const snapshot = evidence.snapshot;
    const resource = snapshot?.document?.title || snapshot?.customer?.name;
    let name = resource?.[currentLanguage()];
    if (!name && snapshot?.targets?.length) {
        const key = snapshot.resourceType === 'CUSTOMER' ? 'export.customer.count' : 'export.document.count';
        name = t(key).replace('{n}', String(snapshot.targets.length));
    }
    byId('outcome-subject').hidden = !name;
    byId('outcome-resource').textContent = name || '';
    const purpose = snapshot?.declaredPurpose;
    byId('outcome-purpose').textContent = purpose
        ? `${t('work.purpose')}: ${workPurposeText(purpose)}` : '';
    const response = responseLabel(evidence.http);
    byId('outcome-response').textContent = t(`outcome.${response}`);
    byId('outcome-response-code').replaceChildren(badge(evidence.http.httpStatus == null
        ? t('unknown') : `HTTP ${evidence.http.httpStatus}`, response === 'responded' ? '' : 'warning'));
    const decisions = evidence.decisions || [];
    let decisionLabel;
    let note = 'outcome.decision.note';
    if (evidence.role === 'baseline') {
        decisionLabel = t('outcome.baseline');
        note = 'outcome.baseline.note';
    } else if (evidence.decisionReadState === 'UNAVAILABLE') {
        decisionLabel = t('outcome.unavailable');
    } else if (!decisions.length) {
        decisionLabel = t('outcome.missing');
        note = 'outcome.missing.note';
    } else if (decisions.length > 1) {
        decisionLabel = t('outcome.multiple').replace('{n}', String(decisions.length));
    } else {
        const decision = decisions[0];
        decisionLabel = decision.success === true
            ? t(`work.action.${decision.finalAction}`) : t('outcome.incomplete');
    }
    byId('outcome-decision').textContent = decisionLabel;
    byId('outcome-decision-note').textContent = t(note);
    byId('outcome-fallback').hidden = !decisions.some(decision => decision.technicalFallback === true);
    byId('outcome-return').href = localLink(workPath(evidence), businessOrigin);
    byId('outcome-summary').hidden = false;
}

byId('outcome-reason').addEventListener('click', () => {
    const details = byId('decision-evidence-group');
    details.open = true;
    details.querySelector('summary').focus();
});
