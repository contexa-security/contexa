import { currentLanguage, dateTime, t } from './i18n.js';
import { badge, byId, element } from './ui.js';
import { renderReportScenario } from './report-scenario.js';
import { appendDecisionState } from './decision-state.js';

let chart;
const armName = arm => arm === 'baseline' ? t('connect.baseline') : 'Contexa';

export function renderReport(report) {
    const payload = report.payload;
    const execution = payload.execution;
    renderReportScenario(report);
    byId('report-time').textContent = dateTime(report.createdAt);
    byId('report-state').replaceChildren(badge(t(`run.state.${execution.run.state}`)));
    for (const format of ['json', 'html']) {
        byId(`report-${format}`).href = `/api/lab/reports/${report.id}/export?format=${format}&language=${currentLanguage()}`;
    }
    byId('report-arms').replaceChildren(...execution.steps.map(step => {
        const source = payload.sources.find(value => value.arm === step.arm && value.requestId === step.requestId);
        const evidence = source?.evidence;
        const section = element('article', null, 'report-arm');
        section.append(element('h3', armName(step.arm)));
        const http = element('div', null, 'report-fact');
        http.append(element('span', t('report.http'), 'small muted'),
            badge(step.httpStatus == null ? t('unknown') : `HTTP ${step.httpStatus}`),
            element('p', t(`run.step.${step.state}`) === `run.step.${step.state}` ? step.state : t(`run.step.${step.state}`), 'small muted'));
        section.append(http);
        if (step.arm === 'contexa') {
            const native = element('div', null, 'report-fact');
            native.append(element('span', t('report.native'), 'small muted'));
            if (!evidence?.decisions?.length) native.append(element('p', t('report.noDecision'), 'small muted'));
            for (const decision of evidence?.decisions || []) {
                native.append(badge(decision.finalAction || t('unknown'), decision.finalAction === 'ALLOW' && decision.success === true ? 'good' : 'warning'));
                appendDecisionState(native, decision);
            }
            section.append(native);
        }
        if (step.failureType) section.append(element('p', `${t('report.failure')}: ${step.failureType}`, 'notice warning'));
        if (source?.state !== 'CAPTURED') section.append(element('p', t(`report.source.${source?.state}`), 'small muted'));
        if (step.requestId) {
            const link = element('a', t('report.evidence'), 'button secondary compact');
            link.href = `/request.html?arm=${step.arm}&id=${step.requestId}`;
            section.append(link);
        }
        return section;
    }));
    byId('report-limit-list').replaceChildren(...payload.limitations.map(value => {
        const key = `report.limit.${value}`;
        return element('li', t(key) === key ? value : t(key));
    }));
    if (report.archiveState !== 'PRESERVED_JSON_V2') {
        byId('report-limit-list').append(element('li', t('report.encoding')));
    }
    byId('report-hash').textContent = `SHA-256 · ${report.contentSha256}`;
    byId('report-original').textContent = JSON.stringify(report, null, 2);
    const selected = byId('review-request').value;
    const all = element('option', t('report.all')); all.value = '';
    byId('review-request').replaceChildren(all, ...payload.sources.filter(value => value.requestId).map(source => {
        const option = element('option', `${armName(source.arm)} · ${source.requestId.slice(0, 8)}`);
        option.value = source.requestId;
        return option;
    }));
    byId('review-request').value = selected;
    const values = execution.steps.map(step => {
        const http = payload.sources.find(source => source.arm === step.arm && source.requestId === step.requestId)?.evidence?.http;
        return http?.outputCaptureState === 'SERVLET_OUTPUT_STREAM' ? http.servletOutputBytes : null;
    });
    chart?.destroy(); chart = null;
    byId('report-chart-section').hidden = values.every(value => value == null);
    if (!byId('report-chart-section').hidden) chart = new Chart(byId('report-chart'), {
        type: 'bar', data: { labels: execution.steps.map(step => armName(step.arm)), datasets: [{
            data: values, backgroundColor: ['#647b86', '#006b5c'], borderRadius: 4
        }] }, options: { responsive: true, maintainAspectRatio: false, animation: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, title: { display: true, text: 'Bytes' } }, y: { grid: { display: false } } } }
    });
}

export function renderReviews(values) {
    byId('report-reviews').replaceChildren(...values.map(value => {
        const article = element('article', null, 'report-review');
        article.append(badge(t(`report.${value.position}`)), element('p', value.comment),
            element('p', `${dateTime(value.createdAt)} · ${value.requestId || t('report.all')}`, 'small'));
        return article;
    }));
    if (!values.length) byId('report-reviews').append(element('p', t('report.reviews.empty'), 'small muted'));
}
