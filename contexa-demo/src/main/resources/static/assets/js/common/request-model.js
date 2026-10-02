import { dateTime, t } from './i18n.js';
import { renderProviderEvidence } from './request-provider.js';
import { appendDefinition, badge, byId, element } from './ui.js';

let chart;
const known = value => value == null ? t('unknown') : String(value);

export function renderModelEvidence(evidence) {
    chart?.destroy();
    chart = null;
    const section = byId('model-evidence');
    section.hidden = evidence.role === 'baseline';
    if (section.hidden) return;
    renderProviderEvidence(evidence);
    const captured = evidence.modelBoundary;
    const records = captured?.observations || [];
    const state = captured?.state || 'NOT_CAPTURED';
    const empty = byId('model-empty');
    empty.hidden = records.length > 0;
    empty.textContent = t(state === 'UNAVAILABLE' ? 'model.UNAVAILABLE' : 'model.NOT_CAPTURED');
    byId('model-limited').hidden = !captured?.limited;
    const list = byId('model-observations');
    list.replaceChildren();
    records.forEach((record, index) => {
        const item = element('li');
        const header = element('div', null, 'model-row-heading');
        header.append(element('h3', `${t('model.observation')} ${index + 1}`),
            badge(t(record.failureType ? 'model.response.failed' : 'model.response.received'), record.failureType ? 'warning' : ''));
        const facts = element('dl', null, 'definition model-facts');
        appendDefinition(facts, t('model.name'), record.responseModel || t('unknown'));
        appendDefinition(facts, t('model.started'), dateTime(record.startedAt));
        appendDefinition(facts, t('model.ended'), dateTime(record.completedAt));
        appendDefinition(facts, t('model.input'), known(record.inputTokens));
        appendDefinition(facts, t('model.output'), known(record.outputTokens));
        const details = element('details');
        details.dataset.sourceKey = `model-${record.id}`;
        details.append(element('summary', t('model.source')), element('p', t('model.source.note'), 'hint'),
            element('pre', JSON.stringify({ captureBoundary: 'CHAT_CLIENT_ADVISOR', transportEvidence: false, ...record }, null, 2)));
        item.append(header, facts);
        if (record.outputTruncated) item.append(element('p', t('model.truncated'), 'notice warning'));
        item.append(details);
        list.append(item);
    });
    const hasUsage = records.some(record => record.inputTokens != null || record.outputTokens != null);
    byId('model-usage').hidden = !hasUsage;
    byId('model-chart-limited').hidden = records.length <= 12;
    byId('model-usage-chart').setAttribute('aria-label', t('model.usage'));
    if (hasUsage && typeof Chart !== 'undefined') {
        const visible = records.slice(0, 12);
        chart = new Chart(byId('model-usage-chart'), {
            type: 'bar',
            data: {
                labels: visible.map((record, index) => `${t('model.observation')} ${index + 1}`),
                datasets: [
                    { label: t('model.input'), data: visible.map(record => record.inputTokens), backgroundColor: '#006e60', borderRadius: 3 },
                    { label: t('model.output'), data: visible.map(record => record.outputTokens), backgroundColor: '#52727d', borderRadius: 3 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false, animation: false, indexAxis: 'y',
                plugins: { legend: { position: 'bottom' } },
                scales: { x: { beginAtZero: true, stacked: true }, y: { stacked: true, grid: { display: false } } }
            }
        });
    }
}
