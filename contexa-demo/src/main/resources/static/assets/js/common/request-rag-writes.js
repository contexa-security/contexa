import { dateTime, t } from './i18n.js';
import { appendDefinition, badge, byId, element } from './ui.js';

export function renderRagWrites(evidence) {
    const calls = evidence.analysisEvents.filter(event => event.kind === 'RAG_STORAGE_CALL');
    const writes = evidence.analysisEvents.filter(event => event.kind === 'RAG_WRITE');
    const counts = byId('rag-write-counts');
    counts.replaceChildren();
    counts.hidden = calls.length === 0 && writes.length === 0;
    byId('rag-write-empty').hidden = !counts.hidden;
    if (!counts.hidden) {
        appendDefinition(counts, t('rag.write.calls'), String(calls.length));
        appendDefinition(counts, t('rag.write.attempts'), String(writes.length));
        appendDefinition(counts, t('rag.write.matches'), String(writes.filter(event => event.payload.matchingDocumentObserved).length));
    }
    byId('rag-write-list').replaceChildren(...[...writes, ...calls].map(event => {
        const payload = event.payload;
        const row = element('li');
        const title = element('h3', t(`work.event.${event.kind}`));
        const facts = element('dl', null, 'definition');
        appendDefinition(facts, t('learning.observedAt'), dateTime(event.observedAt));
        if (event.kind === 'RAG_WRITE') {
            const matched = payload.matchingDocumentObserved === true;
            title.append(badge(t(matched ? 'rag.write.matched' : 'rag.write.unconfirmed'), matched ? '' : 'warning'));
            appendDefinition(facts, t('rag.write.document'), payload.submitted?.documentId || t('unknown'));
            appendDefinition(facts, t('rag.write.readAt'), dateTime(payload.readback?.readAt));
            appendDefinition(facts, t('rag.write.readState'), t(`rag.write.state.${payload.readback?.state || 'UNAVAILABLE'}`));
            appendDefinition(facts, t('rag.write.embedding'), payload.readback?.embeddingPresent == null
                ? t('unknown') : t(payload.readback.embeddingPresent ? 'rag.write.present' : 'rag.write.absent'));
        } else {
            appendDefinition(facts, t('rag.write.return'), t('rag.write.return.note'));
        }
        if (payload.failureType) {
            title.append(badge(t('rag.write.failure'), 'warning'));
            appendDefinition(facts, t('rag.write.failureType'), payload.failureType);
        }
        const details = element('details');
        details.dataset.sourceKey = event.id;
        const source = element('pre', JSON.stringify(event, null, 2));
        source.tabIndex = 0;
        details.append(element('summary', t('work.source')), source);
        row.append(title, facts, details);
        return row;
    }));
}
