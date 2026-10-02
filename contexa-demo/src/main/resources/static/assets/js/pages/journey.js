import '../common/shell.js';
import { currentLanguage, dateTime, t } from '../common/i18n.js';
import { localLink, request } from '../common/http.js';
import { badge, busy, byId, element, errorNotice, errorText, notice } from '../common/ui.js';
import { operationCopy, scenarioCopy, selectorCopy } from '../common/scenario-copy.js';
import { readJourneyApprovals } from '../common/journey-approvals.js';
import { securityContinuation } from '../common/security-feedback.js';
import { selectJourneyRecords } from '../common/journey-selection.js';

const query = new URLSearchParams(location.search);
let view, scenario, workspace, origins, currentStep = query.get('step');
let projects = [], records = [], catalogFailed = false, catalogResults = [];
let approvalCatalog = { targets: new Set(), failures: [] };
const copy = (map, value) => map[value]?.[currentLanguage() === 'en' ? 1 : 0] || value;
const link = (text, href, secondary = false) => {
    const node = element('a', text, `button${secondary ? ' secondary' : ''}`); node.href = href; return node;
};
const purpose = () => ({ S02: 'APPROVED_BULK_DELIVERY', S03: 'EMERGENCY_MAINTENANCE', S04: 'UNDECLARED',
    S05: 'CROSS_PROJECT_REVIEW', S06: 'UNDECLARED', S07: 'EMERGENCY_MAINTENANCE', S09: 'UNDECLARED' }[scenario.key] || 'PROJECT_REVIEW');
const needsApproval = step => ['EXCEPTION_APPROVED_DOCUMENTS', 'APPROVED_PROJECT_DOCUMENTS'].includes(step.selector);
function reference(step) {
    return { journey: view.journey.id, step: step.stepId, account: view.journey.snapshot.account, purpose: purpose() };
}
function selectedRecords(step) {
    return selectJourneyRecords(records, projects, step.selector, approvalCatalog.targets);
}
function appendRecovery(target, result, returnPath) {
    const recovery = securityContinuation(result.data, origins[`${result.arm}Url`], returnPath);
    target.append(element('p', t(recovery ? `security.${recovery.name}.body` : 'journey.noCatalog'), 'notice'));
    if (recovery?.href) {
        const action = link(t(recovery.labelKey), recovery.href, true);
        action.target = '_blank'; action.rel = 'noopener'; target.append(action);
    } else target.append(link(t('journey.signin'), '/connect.html', true));
}
function appendApprovalHelp(target, actions) {
    target.append(element('p', t(approvalCatalog.failures.length ? 'journey.approval.unavailable'
        : approvalCatalog.targets.size ? 'journey.approval.matched' : 'journey.approval.empty'), 'notice'));
    for (const failure of approvalCatalog.failures) {
        const section = element('section');
        section.append(element('h3', failure.arm === 'baseline' ? t('connect.baseline') : 'Contexa'));
        appendRecovery(section, failure, '/approvals.html'); target.append(section);
    }
    for (const arm of ['baseline', 'contexa']) {
        actions.append(link(`${arm === 'baseline' ? t('connect.baseline') : 'Contexa'} · ${t('journey.approval')}`,
            localLink('/approvals.html', origins[`${arm}Url`]), true));
    }
}
function renderCatalog() {
    byId('journey-catalog').hidden = !catalogResults.length;
    byId('journey-catalog-results').replaceChildren(...catalogResults.map(result => {
        const section = element('section'); section.append(element('h3', result.arm === 'baseline' ? t('connect.baseline') : 'Contexa'));
        section.append(badge(result.status ? `HTTP ${result.status}` : t('unknown')));
        if (Array.isArray(result.data)) {
            const list = element('ul');
            for (const value of result.data) list.append(element('li', value.title?.[currentLanguage()]
                || `${t(`approval.purpose.${value.request?.purpose}`)} · ${t(`approval.status.${value.effectiveStatus}`)}`));
            section.append(list);
        } else appendRecovery(section, result, '/approvals.html');
        return section;
    }));
}
function render() {
    if (!scenario) return;
    byId('journey-title').textContent = scenario.definition.display.title[currentLanguage()];
    byId('journey-description').textContent = copy(scenarioCopy, scenario.key);
    byId('journey-version').textContent = `${scenario.key} · ${t('explore.version')} ${scenario.version}`;
    byId('journey-start-panel').hidden = Boolean(view);
    byId('journey-active').hidden = !view;
    byId('journey-initial-note').hidden = scenario.key !== 'S08';
    if (!view) return;
    const steps = scenario.definition.requestPlan;
    currentStep ||= steps[0].stepId;
    const step = steps.find(value => value.stepId === currentStep) || steps[0];
    currentStep = step.stepId;
    byId('journey-steps').replaceChildren(...steps.map((value, index) => {
        const button = element('button'); button.type = 'button'; button.dataset.step = value.stepId;
        button.append(element('span', String(index + 1), 'step-number'), element('span', copy(operationCopy, value.operation)));
        if (value.stepId === currentStep) button.setAttribute('aria-current', 'step');
        button.addEventListener('click', () => {
            currentStep = value.stepId; catalogResults = [];
            history.replaceState(null, '', `/journey.html?id=${view.journey.id}&step=${currentStep}`);
            render(); byId('journey-step-title').focus();
        }); return button;
    }));
    byId('journey-step-number').textContent = `${steps.indexOf(step) + 1} / ${steps.length}`;
    byId('journey-step-title').textContent = copy(operationCopy, step.operation);
    byId('journey-step-description').textContent = copy(selectorCopy, step.selector);
    byId('journey-limit').textContent = t('journey.max').replace('{n}', String(step.maxItems));
    byId('journey-pace').hidden = !['S04', 'S06', 'S08'].includes(scenario.key);
    byId('journey-pace').textContent = t(scenario.key === 'S06' ? 'journey.paced' : scenario.key === 'S08' ? 'journey.sparse' : 'journey.rapid');
    const actions = byId('journey-step-actions'); actions.replaceChildren();
    const targets = byId('journey-targets'); targets.replaceChildren();
    const approvalStep = needsApproval(step);
    if (approvalStep) appendApprovalHelp(targets, actions);
    if (['LIST_PROJECTS', 'READ_APPROVAL'].includes(step.operation)) {
        const button = element('button', t('journey.read'), 'button'); button.id = 'journey-read';
        button.addEventListener('click', () => void busy(button, () => readCatalog(step)));
        actions.append(button); targets.append(element('p', t('journey.read.note'), 'small muted'));
        if (step.operation === 'READ_APPROVAL') {
            targets.append(element('p', t('journey.approval.note'), 'notice'));
            for (const arm of ['baseline', 'contexa']) actions.append(link(`${arm === 'baseline' ? t('connect.baseline') : 'Contexa'} · ${t('journey.approval')}`, localLink('/approvals.html', origins[`${arm}Url`]), true));
        }
    } else if (step.operation.startsWith('EXPORT_')) {
        const parameters = new URLSearchParams({ ...reference(step), type: step.operation === 'EXPORT_CUSTOMERS' ? 'CUSTOMER' : 'DOCUMENT' });
        if (!approvalStep || !catalogFailed && !approvalCatalog.failures.length && selectedRecords(step).length) {
            actions.prepend(link(t('journey.export'), `/batch-comparison.html?${parameters}`));
        }
    } else {
        const candidates = selectedRecords(step);
        if (catalogFailed || !candidates.length && !approvalStep) {
            targets.append(element('p', t(catalogFailed ? 'journey.noCatalog' : 'journey.noTarget'), 'notice'));
            if (catalogFailed) actions.append(link(t('journey.signin'), '/connect.html', true));
        }
        for (const record of candidates.slice(0, step.maxItems)) {
            const row = element('article', null, 'journey-target');
            const text = element('div'); text.append(element('strong', (record.title || record.name)[currentLanguage()]));
            const project = projects.find(value => value.id === record.projectId);
            text.append(element('p', project?.title[currentLanguage()] || record.projectId, 'small muted'));
            const parameters = new URLSearchParams({ ...reference(step), [step.operation === 'READ_CUSTOMERS' ? 'customer' : 'document']: record.id });
            row.append(text, link(t('journey.prepare'), `/comparison.html?${parameters}`, true)); targets.append(row);
        }
        if (step.selector === 'DOCUMENT_WITH_UNTRUSTED_INSTRUCTION') {
            const control = records.find(record => record.id === 'harbor-external-control');
            if (control) {
                const details = element('details', null, 'journey-control');
                details.append(element('summary', t('journey.control.title')), element('p', t('journey.control.note'), 'small muted'));
                const parameters = new URLSearchParams({ account: view.journey.snapshot.account,
                    document: control.id, purpose: purpose() });
                details.append(link(t('journey.control.prepare'), `/comparison.html?${parameters}`, true)); targets.append(details);
            }
        }
    }
    const runs = view.runs.filter(run => run.stepId === currentStep);
    const reads = view.browserReports.filter(read => read.reported.stepId === currentStep);
    byId('journey-empty').hidden = runs.length + reads.length > 0;
    byId('journey-runs').replaceChildren(...runs.map(run => {
        const row = element('article', null, 'experience-record');
        const text = element('div');
        text.append(element('p', dateTime(run.createdAt)), badge(t(`run.state.${run.state}`)),
            element('p', run.requests.map(value => `${value.arm === 'baseline' ? t('connect.baseline') : 'Contexa'} · ${value.httpStatus ? `HTTP ${value.httpStatus}` : t('unknown')}`).join(' / '), 'small muted'));
        const links = element('div', null, 'actions');
        links.append(link(t('journey.open'), `/run.html?id=${run.id}`, true), link(t('report.link'), `/report.html?run=${run.id}`, true));
        row.append(text, links); return row;
    }), ...reads.map(read => element('p', `${dateTime(read.createdAt)} · ${read.reported.observations.map(value => `${value.arm} HTTP ${value.httpStatus || t('unknown')}`).join(' / ')} · ${t('journey.read.note')}`, 'small muted')));
    byId('journey-source').textContent = JSON.stringify(view.journey, null, 2);
    byId('journey-truncated').hidden = !view.runsTruncated;
    renderCatalog();
}
async function readCatalog(step) {
    const path = step.operation === 'LIST_PROJECTS' ? '/api/work/projects' : '/api/work/approvals';
    catalogResults = await Promise.all(['baseline', 'contexa'].map(async arm => {
        try {
            const response = await fetch(new URL(path, origins[`${arm}Url`]), { credentials: 'include', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(20000) });
            const body = await response.text();
            const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)))].map(value => value.toString(16).padStart(2, '0')).join('');
            let data; try { data = JSON.parse(body); } catch { data = null; }
            return { arm, status: response.status, hash, data, observedAt: new Date().toISOString() };
        } catch { return { arm, status: null, hash: null, data: null, observedAt: new Date().toISOString() }; }
    }));
    try {
        await request(`/api/lab/journeys/${view.journey.id}/reads`, { method: 'POST', body: { commandId: crypto.randomUUID(), stepId: step.stepId,
            observations: catalogResults.map(value => ({ arm: value.arm, path, httpStatus: value.status, contentSha256: value.hash, observedAt: value.observedAt })) } });
        await refresh();
    } catch (error) { notice(byId('journey-feedback'), `${t('journey.unsavedRead')} ${errorText(error)}`, 'warning'); renderCatalog(); }
}
async function loadCatalog() {
    approvalCatalog = { targets: new Set(), failures: [] };
    try {
        const catalog = async () => {
            projects = await request('/api/work/projects', { origin: origins.baselineUrl });
            records = scenario.definition.requestPlan.some(step => step.operation === 'READ_CUSTOMERS')
                ? (await request('/api/work/customers', { origin: origins.baselineUrl })).customers
                : (await Promise.all(projects.map(project => request(`/api/work/projects/${project.id}/documents`, { origin: origins.baselineUrl })))).flat();
        };
        const results = await Promise.allSettled([catalog(), scenario.definition.requestPlan.some(needsApproval)
            ? readJourneyApprovals(origins, view.journey.snapshot.account, purpose()).then(value => { approvalCatalog = value; })
            : Promise.resolve()]);
        catalogFailed = results[0].status === 'rejected';
        if (catalogFailed) { projects = []; records = []; }
    } catch { projects = []; records = []; catalogFailed = true; }
}
async function refresh() {
    view = await request(`/api/lab/journeys/${view.journey.id}`); await loadCatalog(); render();
}
byId('journey-start-form').addEventListener('submit', event => {
    event.preventDefault(); void busy(byId('journey-start'), async () => {
        const key = `lab.journey.pending.${scenario.id}`;
        try {
            let command; try { command = JSON.parse(sessionStorage.getItem(key)); } catch { /* No saved draft. */ }
            command ||= { commandId: crypto.randomUUID(), scenarioId: scenario.id, account: byId('journey-account').value };
            if (command.account !== byId('journey-account').value) throw new Error(t('error.COMMAND_INPUT_CHANGED'));
            sessionStorage.setItem(key, JSON.stringify(command));
            const created = await request('/api/lab/journeys', { method: 'POST', body: command });
            sessionStorage.removeItem(key); location.assign(`/journey.html?id=${created.id}`);
        } catch (error) { errorNotice(byId('journey-feedback'), error); }
    });
});
byId('journey-refresh').addEventListener('click', () => void busy(byId('journey-refresh'), refresh).catch(error => errorNotice(byId('journey-feedback'), error)));
document.addEventListener('lab:language', render);
try {
    [workspace, origins] = await Promise.all([request('/api/lab/workspaces/current'), request('/api/lab/identity')]);
    for (const account of workspace.allowedAccounts) { const option = element('option', account); option.value = account; byId('journey-account').append(option); }
    if (query.has('id')) {
        view = await request(`/api/lab/journeys/${encodeURIComponent(query.get('id'))}`);
        scenario = view.journey.snapshot.scenario; await loadCatalog();
    } else {
        const summaries = await request('/api/lab/scenarios');
        const selected = summaries.find(value => value.key === (query.get('scenario') || 'S01'));
        scenario = await request(`/api/lab/scenarios/${selected.id}`);
    }
    render();
} catch (error) { errorNotice(byId('journey-feedback'), error); }
