import '../common/shell.js';
import { currentLanguage, dateTime, t } from '../common/i18n.js';
import { workPurposeText } from '../common/work-purpose.js';
import { localLink, request } from '../common/http.js';
import { badge, busy, byId, element, notice } from '../common/ui.js';

const requested = new URLSearchParams(location.search).get('step');
const step = ['normal', 'change', 'exception'].includes(requested) ? requested : 'normal';
let configuration;
let identity;
let resource;
let runs = [];
let journeys = [];
let state = 'loading';
let recordsFailed = false;

function link(label, href, secondary = false) {
    const value = element('a', label, `button${secondary ? ' secondary' : ''}`);
    value.href = href; return value;
}

function render() {
    document.querySelector(`[data-step="${step}"]`).setAttribute('aria-current', 'step');
    byId('stage-title').textContent = t(`experience.${step}.title`);
    byId('stage-description').textContent = t(`experience.${step}.body`);
    byId('stage-observe').textContent = t(`experience.${step}.observe`);
    byId('stage-resource').replaceChildren();
    byId('stage-actions').replaceChildren();
    if (step === 'exception' && configuration) {
        byId('stage-resource').append(element('h3', t('experience.exception')), element('p', t('experience.exception.observe'), 'small muted'));
        byId('stage-actions').append(link(t('journey.start'), '/journey.html?scenario=S03'));
        for (const arm of ['baseline', 'contexa']) byId('stage-actions').append(link(
            `${arm === 'baseline' ? t('connect.baseline') : 'Contexa'} · ${t('experience.approval')}`,
            localLink('/approvals.html', configuration[`${arm}Url`]), true));
        byId('stage-actions').append(link(t('batch.compare'), '/batch-comparison.html', true));
    } else if (resource) {
        byId('stage-resource').append(element('h3', resource.document.title[currentLanguage()]),
            element('p', resource.project.title[currentLanguage()], 'small muted'));
        const query = new URLSearchParams({ document: resource.document.id, account: identity.username,
            purpose: step === 'normal' ? 'PROJECT_REVIEW' : 'UNDECLARED' });
        byId('stage-actions').append(link(t('journey.start'), `/journey.html?scenario=${step === 'normal' ? 'S01' : 'S04'}`),
            link(t('experience.compare'), `/comparison.html?${query}`, true));
    } else {
        byId('stage-resource').append(element('p', t(state === 'loading' ? 'loading'
            : state === 'empty' ? 'experience.noTarget' : 'experience.noResource')));
        if (state !== 'loading') byId('stage-actions').append(link(t('experience.prepare'), '/connect.html'));
    }
    byId('experience-empty').hidden = runs.length > 0;
    byId('experience-journeys').hidden = !journeys.length;
    byId('experience-journey-list').replaceChildren(...journeys.map(value => {
        const item = element('article', null, 'experience-record');
        const text = element('div'); text.append(element('p', value.snapshot.scenario.definition.display.title[currentLanguage()]),
            element('p', `${value.snapshot.account} · ${dateTime(value.createdAt)}`, 'small muted'));
        item.append(text, link(t('journey.return'), `/journey.html?id=${value.id}`, true)); return item;
    }));
    byId('experience-empty').textContent = t(state === 'loading' ? 'loading' : recordsFailed ? 'experience.records.failed' : 'experience.records.empty');
    byId('experience-records').replaceChildren(...runs.map(run => {
        const item = element('article', null, 'experience-record');
        const details = element('div');
        details.append(element('p', `${run.account} · ${workPurposeText(run.purpose)}`),
            element('p', dateTime(run.createdAt), 'small muted'), badge(t(`run.state.${run.state}`)));
        const actions = element('div', null, 'actions');
        actions.append(link(t('experience.open'), `/run.html?id=${run.id}`, true),
            link(t('report.link'), `/report.html?run=${run.id}`, true));
        item.append(details, actions); return item;
    }));
}

async function load() {
    state = 'loading'; render();
    const result = await Promise.allSettled([
        request('/api/lab/identity'), request('/api/lab/runs'), request('/api/lab/journeys')
    ]);
    configuration = result[0].status === 'fulfilled' ? result[0].value : null;
    recordsFailed = result[1].status !== 'fulfilled';
    runs = recordsFailed ? [] : result[1].value;
    journeys = result[2].status === 'fulfilled' ? result[2].value : [];
    resource = null;
    state = 'signin';
    try {
        if (configuration && step !== 'exception') {
            const origin = configuration.baselineUrl;
            identity = await request('/api/lab/identity', { origin });
            const projects = await request('/api/work/projects', { origin });
            const project = projects.find(value => value.assigned === (step === 'normal'));
            state = 'empty';
            if (project) {
                const documents = await request(`/api/work/projects/${encodeURIComponent(project.id)}/documents`, { origin });
                if (documents.length) { resource = { project, document: documents[0] }; state = 'ready'; }
            }
        }
    } catch { state = 'signin'; }
    notice(byId('experience-feedback'));
    render();
}
byId('experience-refresh').addEventListener('click', () => void busy(byId('experience-refresh'), load));
document.addEventListener('lab:language', render);
void load();
