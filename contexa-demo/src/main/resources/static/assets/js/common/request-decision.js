import { t } from './i18n.js';
import { badge, byId, element } from './ui.js';

function source(value, key) {
    const details = element('details', undefined, 'decision-source');
    details.dataset.sourceKey = key;
    details.append(element('summary', t('work.source')), element('pre', JSON.stringify(value, null, 2)));
    return details;
}

function candidatesFor(decision, events) {
    if (!decision.requestId || !decision.processingGeneration) return [];
    return events.filter(event => ['LAYER1_CANDIDATE', 'LAYER2_CANDIDATE'].includes(event.kind)
        && event.payload?.requestId === decision.requestId
        && event.payload?.eventProcessingOwnerToken === decision.processingGeneration);
}

export function renderDecisions(evidence) {
    const list = byId('decision-list');
    list.replaceChildren();
    for (const decision of evidence.decisions) {
        const item = element('article', undefined, 'decision-record');
        const heading = element('div', undefined, 'decision-record-heading');
        heading.append(element('h3', t('outcome.finalDecision')),
            badge(t(`work.action.${decision.finalAction}`), decision.success ? '' : 'warning'));
        item.append(heading, element('p', t(decision.success ? 'work.decision.saved' : 'work.decision.failed'), 'hint'));
        if (decision.failureType) item.append(element('p', `${t('work.failure.type')}: ${decision.failureType}`, 'mono'));
        const candidates = candidatesFor(decision, evidence.analysisEvents || []);
        if (!candidates.length) item.append(element('p', t('outcome.reasonMissing'), 'hint'));
        for (const event of candidates) {
            const candidate = event.payload;
            const explanation = element('section', undefined, 'decision-explanation');
            const title = element('div', undefined, 'decision-record-heading');
            title.append(element('h4', t(event.kind === 'LAYER1_CANDIDATE' ? 'outcome.initialReview' : 'outcome.furtherReview')),
                badge(t(`work.action.${candidate.action}`)));
            explanation.append(title);
            if (candidate.selectedModelId) explanation.append(element('p', candidate.selectedModelId, 'mono muted'));
            explanation.append(element('p', candidate.reasoningSanitized || t('outcome.reasonMissing'), 'decision-explanation-text'),
                element('p', t('outcome.candidateNote'), 'hint'));
            if (candidate.technicalFallbackApplied === true) explanation.append(element('p', t('outcome.fallback'), 'notice warning'));
            explanation.append(source(event, event.id));
            item.append(explanation);
        }
        item.append(source(decision, decision.observationId || decision.id || decision.decisionId));
        list.append(item);
    }
}
