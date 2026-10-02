import { currentLanguage, dateTime, t } from './i18n.js';
import { badge, byId, element } from './ui.js';
import { armResult } from './run-arm-result.js';
import { renderVariation } from './run-variation.js';
import { workPurposeText } from './work-purpose.js';

let chart;
const label = arm => arm === 'baseline' ? t('connect.baseline') : 'Contexa';
const state = value => t(`run.state.${value}`);
export function renderRun(view, evidence, clients, active, origins) {
    const focused = document.activeElement?.dataset.runFocus;
    const opened = new Set([...byId('run-pair').querySelectorAll('details[open][data-attempt]')]
        .map(value => value.dataset.attempt));
    const run = view.run;
    renderVariation(run.manifest.variation);
    const open = ['READY', 'RUNNING'].includes(run.state);
    byId('run-state').replaceChildren(badge(state(run.state), open || run.state === 'RESPONDED' ? '' : 'warning'));
    const businessDocument = evidence.baseline?.snapshot?.document || evidence.contexa?.snapshot?.document;
    const customer = evidence.baseline?.snapshot?.customer || evidence.contexa?.snapshot?.customer;
    const initial = run.manifest.initialConditions[0]?.snapshot;
    const documentTitle = customer?.name?.[currentLanguage()] || businessDocument?.title?.[currentLanguage()]
        || initial?.customer?.name?.[currentLanguage()] || initial?.document?.title?.[currentLanguage()]
        || t('run.selectedResource');
    byId('run-plan').textContent = run.manifest.plan.exportSelection
        ? t('batch.selected').replace('{n}', String(run.manifest.plan.exportSelection.targetIds.length)) : documentTitle;
    const plan = run.manifest.plan;
    byId('run-purpose').textContent = `${plan.requestedAccount} · ${workPurposeText(plan.purpose)}${plan.fileRequest
        ? ` · ${t(plan.exportSelection ? 'batch.export' : 'compare.operation.DOWNLOAD')} · ${plan.fileRequest.language}` : ''}`;
    byId('run-deadline').textContent = `${t('run.deadline')} · ${dateTime(run.dispatchDeadline)}`;
    byId('run-start').disabled = active || run.state !== 'READY' || !view.steps.every(step => step.state === 'PLANNED')
        || Date.parse(run.dispatchDeadline) <= Date.now();
    byId('run-cancel').disabled = !open;
    byId('run-start').hidden = !open;
    byId('run-cancel').hidden = !open;
    byId('run-cancel-note').hidden = !open;
    byId('run-deadline').hidden = !open;
    byId('run-prepare-again').hidden = !['CANCELLED', 'EXPIRED', 'INTERRUPTED'].includes(run.state);
    const summaryKey = view.steps.every(step => step.state === 'RESPONDED') ? 'returned'
        : run.state === 'READY' ? 'ready' : open ? 'running' : 'closed';
    byId('run-summary').textContent = t(`run.summary.${summaryKey}`);
    byId('run-limitations').hidden = !run.manifest.evidenceLimitations.length;
    byId('run-review-contract').hidden = !run.manifest.reviewContract;
    byId('run-review-contract').textContent = t('run.reviewContract');
    byId('run-pair').replaceChildren(...view.steps.map(step => armResult(step, evidence[step.arm], clients[step.arm], view.clientReports || [], step.arm === 'baseline' ? origins?.baselineUrl : origins?.contexaUrl)));
    for (const details of byId('run-pair').querySelectorAll('details[data-attempt]')) {
        details.open = opened.has(details.dataset.attempt);
    }
    if (focused) [...byId('run-pair').querySelectorAll('[data-run-focus]')]
        .find(value => value.dataset.runFocus === focused)?.focus({ preventScroll: true });
    const values = view.steps.map(step => {
        const http = evidence[step.arm]?.http;
        return http?.outputCaptureState === 'SERVLET_OUTPUT_STREAM' ? http.servletOutputBytes : null;
    });
    byId('run-chart-wrap').hidden = values.every(value => value == null);
    chart?.destroy(); chart = null;
    if (!byId('run-chart-wrap').hidden) chart = new Chart(byId('run-chart'), {
        type: 'bar', data: { labels: view.steps.map(step => label(step.arm)), datasets: [{
            data: values, backgroundColor: ['#647b86', '#006e60'], borderRadius: 4
        }] }, options: { responsive: true, maintainAspectRatio: false, animation: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, title: { display: true, text: 'Bytes' } }, y: { grid: { display: false } } } }
    });
    byId('run-events').replaceChildren(...view.events.map(event => {
        const row = element('li');
        const timestamp = element('time', dateTime(event.occurredAt)); timestamp.dateTime = event.occurredAt;
        const key = `run.event.${event.kind}`;
        const step = view.steps.find(value => value.id === event.stepId);
        row.append(timestamp, element('span', t(key) === key ? event.kind : t(key)), element('span', step ? label(step.arm) : '', 'small muted'));
        return row;
    }));
    byId('run-event-limit').hidden = !view.moreEventsAvailable;
    byId('run-json').textContent = JSON.stringify(view, null, 2);
}
