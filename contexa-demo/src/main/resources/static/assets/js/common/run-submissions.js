import { request } from './http.js';
import { dateTime, t } from './i18n.js';
import { badge, byId, element, errorText, notice } from './ui.js';

let preparationId;
let rows = [];
let loading = false;
let failure;

function render() {
    byId('run-submissions').hidden = !preparationId;
    byId('run-submissions-refresh').disabled = loading;
    notice(byId('run-submissions-feedback'), failure ? errorText(failure) : loading ? t('working')
        : rows.length ? t('run.submissions.note') : t('run.submissions.empty'), failure ? 'danger' : '');
    byId('run-submissions-list').replaceChildren(...rows.map(row => {
        const item = element('li');
        const heading = element('div', null, 'submission-heading');
        heading.append(element('time', dateTime(row.startedAt)), badge(t(`run.submissions.${row.state}`),
            row.state === 'RUN_AVAILABLE' ? '' : 'warning'));
        item.append(heading);
        if (row.reason) {
            const key = `error.${row.reason}`;
            item.append(element('p', t(key) === key ? t('run.submissions.failed') : t(key), 'small muted'));
        }
        if (row.httpStatus != null) item.append(element('p', `HTTP ${row.httpStatus}`, 'small mono'));
        item.append(element('p', `${t('run.submissions.command')} · ${row.commandId}`, 'small mono'));
        if (row.runId) {
            const link = element('a', t('run.submissions.open'));
            link.href = `/run.html?id=${encodeURIComponent(row.runId)}`;
            item.append(link);
        }
        return item;
    }));
}

async function load() {
    if (!preparationId || loading) return;
    const current = preparationId;
    const refresh = byId('run-submissions-refresh');
    const restoreFocus = document.activeElement === refresh;
    loading = true; failure = null; render();
    try {
        const result = await request(`/api/lab/comparisons/preparations/${encodeURIComponent(current)}/run-submissions`);
        if (preparationId === current) rows = result;
    } catch (error) {
        if (preparationId === current) failure = error;
    } finally {
        loading = false; render();
        if (restoreFocus && preparationId === current && document.activeElement === document.body) {
            refresh.focus({ preventScroll: true });
        }
        if (preparationId && preparationId !== current) void load();
    }
}

export function setSubmissionPreparation(id) {
    if (preparationId === id) return;
    preparationId = id; rows = []; failure = null; render();
    if (id) void load();
}

byId('run-submissions-refresh').addEventListener('click', () => void load());
document.addEventListener('lab:run-submission', () => void load());
document.addEventListener('lab:language', render);
