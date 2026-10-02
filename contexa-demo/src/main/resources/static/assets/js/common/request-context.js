import { dateTime, t } from './i18n.js';
import { appendDefinition, byId, element } from './ui.js';

const known = value => value == null ? t('unknown') : String(value);
const availability = (available, established) => available == null ? t('unknown')
    : t(available ? established ? 'work.history.established' : 'work.history.available' : 'work.history.absent');

export function renderContextEvidence(evidence) {
    const section = byId('context-evidence');
    section.hidden = evidence.role === 'baseline';
    if (section.hidden) return;
    const candidates = evidence.analysisEvents.filter(event => event.kind === 'GENERATED_PROMPT');
    const list = byId('context-evidence-list');
    list.replaceChildren();
    byId('context-evidence-empty').hidden = candidates.some(event => event.payload?.contextEvidence);
    for (const event of candidates) {
        const captured = event.payload?.contextEvidence;
        if (!captured) continue;
        const item = element('div', null, 'context-candidate');
        item.append(element('p', dateTime(captured.projectedAt), 'small muted'));
        const facts = element('dl', null, 'definition');
        appendDefinition(facts, t('work.history.personal'), availability(captured.baseline?.personalAvailable, captured.baseline?.personalEstablished));
        appendDefinition(facts, t('work.history.organization'), availability(captured.baseline?.organizationAvailable, captured.baseline?.organizationEstablished));
        appendDefinition(facts, t('work.history.updates'), known(captured.baseline?.updateCount));
        appendDefinition(facts, t('work.history.requests'), known(captured.session?.requestCount));
        appendDefinition(facts, t('work.history.references'), known(captured.attachedReferenceCount));
        appendDefinition(facts, t('rag.search.state'), captured.retrieval
            ? t(`rag.search.${captured.retrieval.state}`) : t('unknown'));
        appendDefinition(facts, t('rag.search.queries'), known(captured.retrieval?.queryCount));
        item.append(facts, element('p', t('work.history.counts.note'), 'hint'));
        if (captured.retrieval) item.append(element('p', t('rag.search.boundary'), 'hint'));
        if (captured.referencesTruncated) item.append(element('p', t('work.history.truncated'), 'notice warning'));
        const details = element('details');
        details.dataset.sourceKey = `context-${event.id}`;
        details.append(element('summary', t('work.history.source')),
            element('pre', JSON.stringify({ observationId: event.id,
                eventId: event.payload.eventId, generation: event.payload.eventProcessingOwnerToken,
                promptCapturedAt: event.observedAt, ...captured }, null, 2)));
        item.append(details);
        list.append(item);
    }
}
