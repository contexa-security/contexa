import { dateTime, t } from './i18n.js';
import { appendDefinition, badge, byId, element } from './ui.js';
import { renderRagWrites } from './request-rag-writes.js';

export function renderLearningEvidence(evidence) {
    const section = byId('learning-evidence');
    section.hidden = evidence.role === 'baseline';
    renderRagWrites(evidence);
    const events = evidence.analysisEvents.filter(event => ['BASELINE_LEARNING_CALL', 'BASELINE_WRITE'].includes(event.kind));
    byId('learning-empty').hidden = events.length > 0;
    byId('learning-list').replaceChildren(...events.map(event => {
        const payload = event.payload;
        const row = element('li');
        const title = element('h3', t(`work.event.${event.kind}`));
        const facts = element('dl', null, 'definition');
        appendDefinition(facts, t('learning.observedAt'), dateTime(event.observedAt));
        if (event.kind === 'BASELINE_WRITE') {
            title.append(badge(t(payload.sameValueObserved ? 'learning.same' : 'learning.unconfirmed'), payload.sameValueObserved ? '' : 'warning'));
            appendDefinition(facts, t('learning.submitted'), payload.submitted?.updates == null ? t('unknown') : String(payload.submitted.updates));
            appendDefinition(facts, t('learning.read'), payload.observed?.updates == null ? t('unknown') : String(payload.observed.updates));
        } else appendDefinition(facts, t('learning.returned'), payload.returned == null ? t('unknown') : t(payload.returned ? 'learning.accepted' : 'learning.skipped'));
        const details = element('details'); details.dataset.sourceKey = event.id;
        const source = element('pre', JSON.stringify(event, null, 2)); source.tabIndex = 0;
        details.append(element('summary', t('work.source')), source);
        row.append(title, facts, details); return row;
    }));
}
