import { dateTime, t } from './i18n.js';
import { localLink } from './http.js';
import { appendDefinition, badge, element } from './ui.js';
import { workPath } from './work-resource-path.js';

function responseState(step, evidence) {
    const status = evidence?.http?.httpStatus ?? step.httpStatus;
    if (evidence?.http?.failureType || status >= 500) return 'failed';
    if (status >= 400) return 'rejected';
    if (step.state === 'RESPONDED' && status >= 200 && status < 300) return 'returned';
    if (status >= 300) return 'redirected';
    return step.state === 'PLANNED' ? 'planned' : step.state === 'NOT_DISPATCHED' ? 'notSent' : 'unconfirmed';
}

function decisionSummary(evidence) {
    const values = evidence?.decisions || [];
    if (evidence?.decisionReadState === 'UNAVAILABLE') return t('outcome.unavailable');
    if (!values.length) return t('outcome.missing');
    if (values.length > 1) return t('outcome.multiple').replace('{n}', String(values.length));
    const decision = values[0];
    return decision.success === true ? t(`work.action.${decision.finalAction}`) : t('outcome.incomplete');
}

function responseDetails(step, evidence, client, reports) {
    const details = element('details', null, 'run-response-details');
    details.dataset.attempt = `response-${step.id}`;
    const summary = element('summary', t('run.responseDetails'));
    summary.dataset.runFocus = `response-${step.id}`;
    details.append(summary);
    const facts = element('dl', null, 'definition');
    const http = evidence?.http;
    const status = http?.httpStatus ?? step.httpStatus;
    appendDefinition(facts, t('run.http'), status == null ? t('unknown') : `HTTP ${status}`);
    const duration = http?.completedAt && http?.startedAt ? Date.parse(http.completedAt) - Date.parse(http.startedAt) : null;
    appendDefinition(facts, t('run.elapsed'), duration == null ? t('unknown') : `${duration} ms`);
    appendDefinition(facts, t('run.output'), http?.outputCaptureState === 'SERVLET_OUTPUT_STREAM' ? `${http.servletOutputBytes} B` : t('unknown'));
    if (evidence?.download) {
        appendDefinition(facts, t('download.prepared'), `${evidence.download.preparedBytes} B`);
        appendDefinition(facts, t('download.file.reuse'), t(evidence.download.reused ? 'download.reused' : 'download.created'));
        appendDefinition(facts, 'SHA-256', evidence.download.contentSha256);
    }
    details.append(facts);
    const attempts = new Map();
    reports.filter(value => value.observation.stepId === step.id).forEach(value => {
        const current = attempts.get(value.observation.attemptId);
        if (!current || value.observation.stage === 'FINISHED') attempts.set(value.observation.attemptId, value);
    });
    if (attempts.size) {
        const browser = element('div', null, 'run-browser');
        browser.append(element('h3', t('run.client.title')));
        attempts.forEach(value => {
            const observed = value.observation;
            const report = element('details'); report.dataset.attempt = observed.attemptId;
            const title = element('summary', t(`run.client.${observed.outcome}`));
            title.dataset.runFocus = `report-${observed.attemptId}`;
            report.append(title);
            if (observed.httpStatus != null) report.append(element('p', `HTTP ${observed.httpStatus}`, 'small'));
            report.append(element('p', `${t('run.client.saved')} · ${dateTime(value.receivedAt)}`, 'small muted'));
            const source = element('pre', JSON.stringify(value, null, 2)); source.tabIndex = 0;
            source.dataset.runFocus = `report-source-${observed.attemptId}`;
            report.append(source); browser.append(report);
        });
        details.append(browser);
    } else if (client) details.append(element('p', t('run.client.unsaved'), 'small muted'));
    return details;
}

export function armResult(step, evidence, client, reports, origin) {
    const baseline = step.arm === 'baseline';
    const section = element('section', null, `run-arm${baseline ? '' : ' run-arm-contexa'}`);
    section.dataset.arm = step.arm;
    const heading = element('div', null, 'run-arm-heading');
    heading.append(element('h2', baseline ? t('connect.baseline') : 'Contexa'),
        badge(t(baseline ? 'run.baselineRole' : 'run.contexaRole'), baseline ? '' : 'good'));
    const response = responseState(step, evidence);
    const outcome = element('div', null, `run-response run-response-${response}`);
    outcome.append(element('p', t('run.businessResponse'), 'small muted'),
        element('h3', t(`run.response.${response}`)), element('p', t(`run.responseNote.${response}`), 'small muted'));
    const decision = element('div', null, 'run-decision');
    decision.append(element('p', t(baseline ? 'run.baselineControl' : 'run.runtimeControl'), 'small muted'),
        element('h3', baseline ? t('outcome.baseline') : decisionSummary(evidence)),
        element('p', t(baseline ? 'run.no.ai' : 'run.decisionTiming'), 'small muted'));
    if (evidence?.decisions?.some(value => value.technicalFallback)) {
        decision.append(badge(t('run.technicalFallback'), 'warning'));
    }
    section.append(heading, outcome, decision);
    const actions = element('div', null, 'actions run-arm-actions');
    if (step.requestId) {
        const link = element('a', t('run.evidence'), 'button secondary');
        link.href = `/request.html?arm=${step.arm}&id=${encodeURIComponent(step.requestId)}`;
        link.dataset.runFocus = `evidence-${step.id}`; actions.append(link);
    }
    if (evidence && origin) {
        const link = element('a', t('run.returnToWork'), 'run-work-link');
        link.href = localLink(workPath(evidence), origin);
        link.dataset.runFocus = `work-${step.id}`; actions.append(link);
    }
    const needsLogin = reports.some(value => value.observation.stepId === step.id
        && [401, 403].includes(value.observation.httpStatus)) && step.state !== 'RESPONDED';
    if (needsLogin) {
        const link = element('a', t('run.client.checkLogin'), 'button secondary');
        link.href = '/connect.html'; link.dataset.runFocus = `login-${step.id}`; actions.append(link);
    }
    section.append(actions);
    if (!evidence && step.requestId) section.append(element('p', t('run.missing'), 'small muted'));
    section.append(responseDetails(step, evidence, client, reports));
    return section;
}
