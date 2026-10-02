import { dateTime, t } from './i18n.js';
import { appendDefinition, badge, byId, element } from './ui.js';

function bodyDetails(body, title, key) {
    const details = element('details');
    details.dataset.sourceKey = key;
    details.append(element('summary', title));
    const facts = element('dl', null, 'definition');
    appendDefinition(facts, t('provider.capture'), t(`provider.body.${body?.state || 'INCOMPLETE'}`));
    appendDefinition(facts, t('provider.bytes'), body?.observedBytes == null ? t('unknown') : `${body.observedBytes} B`);
    appendDefinition(facts, t('provider.fingerprint'), body?.observedBytesSha256 || t('unknown'));
    details.append(facts);
    if (body?.sanitizedJson) {
        let text = body.sanitizedJson;
        try { text = JSON.stringify(JSON.parse(text), null, 2); } catch { /* Preserve the stored display value. */ }
        details.append(element('pre', text));
    }
    return details;
}

export function renderProviderEvidence(evidence) {
    const captured = evidence.providerHttp;
    const records = captured?.observations || [];
    byId('provider-http-empty').hidden = records.length > 0;
    byId('provider-http-empty').textContent = t(captured?.state === 'UNAVAILABLE' ? 'provider.unavailable' : 'provider.empty');
    byId('provider-http-limited').hidden = !captured?.limited;
    byId('model-boundary-note').textContent = t(records.length ? 'provider.boundary' : 'model.boundary');
    const list = byId('provider-http-observations');
    list.replaceChildren();
    const modelIds = new Set((evidence.modelBoundary?.observations || []).map(value => value.id));
    records.forEach((record, index) => {
        const item = element('li');
        const heading = element('div', null, 'model-row-heading');
        heading.append(element('h3', `${t('provider.attempt')} ${index + 1}`),
            badge(record.httpStatus == null ? t('provider.no.response') : `HTTP ${record.httpStatus}`,
                record.httpStatus == null || record.httpStatus >= 400 ? 'warning' : ''));
        const facts = element('dl', null, 'definition');
        appendDefinition(facts, t('provider.destination'), record.endpoint);
        appendDefinition(facts, t('model.started'), dateTime(record.startedAt));
        appendDefinition(facts, t('provider.call'), record.call?.observationId || t('unknown'));
        item.append(heading, facts);
        if (!modelIds.has(record.call?.observationId)) item.append(element('p', t('provider.orphan'), 'notice warning'));
        if (record.failureType) item.append(element('p', `${t('provider.failure')}: ${record.failureType}`, 'notice warning'));
        item.append(bodyDetails(record.requestBody, t('provider.request'), `provider-request-${record.id}`),
            bodyDetails(record.responseBody, t('provider.response'), `provider-response-${record.id}`));
        const source = element('details');
        source.dataset.sourceKey = `provider-source-${record.id}`;
        source.append(element('summary', t('provider.source')), element('pre', JSON.stringify({ id: record.id,
            call: record.call, startedAt: record.startedAt, completedAt: record.completedAt,
            captureBoundary: 'SYNCHRONOUS_RESTCLIENT_HTTP', headersCaptured: false }, null, 2)));
        item.append(source);
        list.append(item);
    });
}
