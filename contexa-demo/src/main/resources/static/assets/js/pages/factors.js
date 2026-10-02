import '../common/shell.js';
import { dateTime, t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { badge, busy, byId, element, errorNotice, notice } from '../common/ui.js';
import { appendDecisionState } from '../common/decision-state.js';

const query = new URLSearchParams(location.search);
let runs = [], comparison, chart, exportUrl, sending = false;
const selected = { before: ['', '', ''], after: ['', '', ''] };
const pending = new Map();
function renderPickers() {
    byId('factor-setup').hidden = !runs.length;
    byId('factor-purpose').textContent = t(`factor.note.${byId('factor-kind').value}`);
    byId('factor-pickers').replaceChildren(...['before', 'after'].map(group => {
        const section = element('section'); section.append(element('h3', t(`factor.${group}`)));
        for (let index = 0; index < 3; index++) {
            const id = `${group}-${index}`; const label = element('label', `${t('factor.repetition')} ${index + 1}`); label.htmlFor = id;
            const picker = element('select'); picker.id = id; picker.required = true; picker.disabled = sending;
            const empty = element('option', t('factor.select')); empty.value = ''; picker.append(empty);
            for (const run of runs) { const option = element('option', `${dateTime(run.createdAt)} · ${run.account} · ${t(`run.state.${run.state}`)}`); option.value = run.id; picker.append(option); }
            picker.value = selected[group][index]; picker.addEventListener('change', () => { selected[group][index] = picker.value; });
            section.append(label, picker);
        } return section;
    }));
    byId('factor-compare').disabled = sending || runs.length < 6;
    byId('factor-kind').disabled = sending;
}
function outcome(report, group) {
    const section = element('section'); section.append(element('h3', t(`factor.${group}`)));
    const step = report.payload.execution.steps.find(value => value.arm === 'contexa');
    const evidence = report.payload.sources.find(value => value.arm === 'contexa')?.evidence;
    section.append(element('p', dateTime(report.payload.execution.run.createdAt), 'small muted'), badge(step?.httpStatus ? `HTTP ${step.httpStatus}` : t('unknown')));
    for (const decision of evidence?.decisions || []) {
        section.append(badge(t(`review.action.${decision.finalAction}`), decision.finalAction === 'ALLOW' && decision.success === true ? 'good' : 'warning'));
        appendDecisionState(section, decision);
    }
    if (!evidence?.decisions?.length) section.append(element('p', t('factor.noDecision'), 'small muted'));
    const provider = evidence?.providerHttp;
    const attempts = provider?.state === 'HTTP_OBSERVED' && Array.isArray(provider.observations)
        ? `${provider.limited ? '≥ ' : ''}${provider.observations.length}` : t('unknown');
    section.append(element('p', `${t('factor.model')}: ${attempts}`, 'small muted'));
    const link = element('a', t('factor.source')); link.href = `/report.html?id=${report.id}`; section.append(link); return section;
}
function renderResults() {
    byId('factor-result').hidden = !comparison; chart?.destroy(); chart = null;
    if (!comparison) return;
    byId('factor-pairs').replaceChildren(...comparison.repetitions.map(pair => {
        const article = element('article', null, 'surface factor-pair');
        const head = element('div', null, 'surface-head'); head.append(element('h2', `${t('factor.repetition')} ${pair.repetition}`));
        const body = element('div', null, 'surface-body'), outcomes = element('div', null, 'factor-outcomes');
        outcomes.append(outcome(pair.before, 'before'), outcome(pair.after, 'after')); body.append(outcomes);
        const changed = pair.conditions.conditions.filter(value => value.state === 'CHANGED');
        const unknown = pair.conditions.conditions.filter(value => value.state === 'UNKNOWN');
        body.append(element('p', `${t('factor.changed')}: ${changed.length ? [...new Set(changed.map(value => t(`variation.${value.condition}`)))].join(' · ') : t('factor.noChanges')}`, 'factor-conditions'),
            element('p', `${t('factor.unknown')}: ${unknown.length}`, 'small muted'),
            element('p', t(unknown.length ? 'variation.incomplete' : changed.length > 1 ? 'variation.multiple' : changed.length === 1 ? 'variation.one' : 'variation.none'), 'notice'));
        article.append(head, body); return article;
    }));
    const entries = comparison.repetitions.flatMap(pair => ['before', 'after'].map(group => ({ label: `${t(`factor.${group}`)} ${pair.repetition}`, report: pair[group] })));
    const values = entries.map(value => { const http = value.report.payload.sources.find(source => source.arm === 'contexa')?.evidence?.http; return http?.outputCaptureState === 'SERVLET_OUTPUT_STREAM' ? http.servletOutputBytes : null; });
    byId('factor-chart-panel').hidden = values.every(value => value == null);
    if (!byId('factor-chart-panel').hidden) chart = new Chart(byId('factor-chart'), { type: 'bar', data: { labels: entries.map(value => value.label), datasets: [{ data: values, backgroundColor: '#006b5c', borderRadius: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } } });
    if (exportUrl) URL.revokeObjectURL(exportUrl);
    exportUrl = URL.createObjectURL(new Blob([JSON.stringify(comparison, null, 2)], { type: 'application/json' })); byId('factor-export').href = exportUrl;
}
async function readComparison(parameters) {
    comparison = await request(`/api/lab/factors?${parameters}`); renderResults();
}
byId('factor-kind').addEventListener('change', renderPickers);
byId('factor-form').addEventListener('submit', event => {
    event.preventDefault(); void busy(byId('factor-compare'), async () => {
        const ids = [...selected.before, ...selected.after];
        if (ids.some(value => !value) || new Set(ids).size !== 6) { notice(byId('factor-feedback'), t('factor.validation'), 'warning'); return; }
        const selection = { before: [...selected.before], after: [...selected.after] };
        const factor = byId('factor-kind').value;
        sending = true; renderPickers();
        try {
            const parameters = new URLSearchParams({ factor });
            for (const group of ['before', 'after']) {
                const reports = [];
                for (const id of selection[group]) {
                    if (!pending.has(id)) pending.set(id, crypto.randomUUID());
                    const report = await request(`/api/lab/runs/${id}/reports`, { method: 'POST', body: { commandId: pending.get(id) } });
                    reports.push(report.id);
                }
                parameters.set(group, reports.join(','));
            }
            await readComparison(parameters); history.replaceState(null, '', `/factors.html?${parameters}`); notice(byId('factor-feedback'));
        } catch (error) { errorNotice(byId('factor-feedback'), error); }
        finally { sending = false; renderPickers(); }
    });
});
document.addEventListener('lab:language', () => { renderPickers(); renderResults(); });
try {
    runs = await request('/api/lab/runs');
    if (['BASELINE', 'RAG', 'BUSINESS_CONTEXT'].includes(query.get('factor'))) byId('factor-kind').value = query.get('factor');
    renderPickers();
    if (query.has('before') && query.has('after')) {
        await readComparison(query);
        comparison.repetitions.forEach((pair, index) => {
            for (const group of ['before', 'after']) {
                const report = pair[group], run = report.payload.execution.run;
                selected[group][index] = report.runId;
                if (!runs.some(value => value.id === run.id)) {
                    runs.push({ id: run.id, account: run.manifest.plan.requestedAccount, createdAt: run.createdAt, state: run.state });
                }
            }
        });
        renderPickers();
    }
    if (runs.length < 6) notice(byId('factor-feedback'), t('factor.noSource'));
} catch (error) { errorNotice(byId('factor-feedback'), error); }
