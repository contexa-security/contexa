import '../common/shell.js';
import { dateTime, t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { appendDefinition, busy, byId, element, errorNotice, notice } from '../common/ui.js';

let runs = [], view, evidence, chart, events = [], state = 'loading', failure;
let sending = false;
let selected = new URLSearchParams(location.search).get('run');
let loadVersion = 0;
function render() {
    byId('memory-run').replaceChildren(...runs.map(run => {
        const option = element('option', `${run.account} · ${dateTime(run.createdAt)} · ${t(`run.state.${run.state}`)}`);
        option.value = run.id; return option;
    }));
    if (selected) byId('memory-run').value = selected;
    byId('memory-picker').hidden = !runs.length;
    byId('memory-run').disabled = sending;
    byId('memory-refresh').disabled = sending;
    byId('memory-continue').disabled = sending || state !== 'ready';
    byId('memory-result').hidden = state !== 'ready';
    byId('memory-details').hidden = !view;
    byId('memory-source-link').hidden = !view;
    const key = { loading: 'loading', empty: 'memory.noRuns', missing: 'memory.noWrite', notIssued: 'memory.notIssued', failed: 'memory.failed' }[state];
    notice(byId('memory-feedback'), key ? t(key) : '', state === 'failed' ? 'warning' : '');
    if (state === 'failed' && failure) errorNotice(byId('memory-feedback'), failure);
    chart?.destroy(); chart = null;
    if (!view) return;
    byId('memory-source-link').href = `/run.html?id=${view.run.id}`;
    byId('memory-source').textContent = JSON.stringify({ runId: view.run.id, manifestSha256: view.run.manifestSha256,
        initialConditions: view.run.manifest.initialConditions, actualWriteObservations: events }, null, 2);
    const counts = [events.filter(value => value.kind === 'BASELINE_WRITE').length, events.filter(value => value.kind === 'RAG_WRITE').length];
    const labels = [t('memory.baseline'), t('memory.rag')];
    byId('memory-counts').replaceChildren(); labels.forEach((label, index) => appendDefinition(byId('memory-counts'), label, String(counts[index])));
    if (state === 'ready') chart = new Chart(byId('memory-chart'), { type: 'bar', data: { labels, datasets: [{ data: counts, backgroundColor: ['#006b5c', '#537485'], borderRadius: 5 }] },
        options: { responsive: true, maintainAspectRatio: false, animation: false, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { ticks: { display: false }, grid: { display: false } } } } });
}
async function loadSelected() {
    const version = ++loadVersion, runId = selected;
    state = 'loading'; view = null; evidence = null; events = []; failure = null; render();
    try {
        const original = await request(`/api/lab/runs/${encodeURIComponent(runId)}`);
        const step = original.steps.find(value => value.arm === 'contexa');
        let source, observed = [], nextState;
        if (!step?.requestId) nextState = 'notIssued';
        else {
            source = await request(`/api/lab/workspaces/requests/contexa/${step.requestId}`);
            observed = source.analysisEvents.filter(event => event.kind === 'BASELINE_WRITE' && event.payload.sameValueObserved === true
                || event.kind === 'RAG_WRITE' && event.payload.matchingDocumentObserved === true);
            nextState = observed.length ? 'ready' : 'missing';
        }
        if (version !== loadVersion) return;
        view = original; evidence = source; events = observed; state = nextState;
    } catch (error) {
        if (version !== loadVersion) return;
        state = 'failed'; failure = error;
    }
    render();
}
async function load() {
    try {
        runs = await request('/api/lab/runs');
        if (selected && !runs.some(run => run.id === selected)) {
            const original = await request(`/api/lab/runs/${encodeURIComponent(selected)}`);
            runs.unshift({ id: selected, account: original.run.manifest.plan.requestedAccount, createdAt: original.run.createdAt, state: original.run.state });
        }
        selected ||= runs[0]?.id;
        if (!selected) { state = 'empty'; render(); } else await loadSelected();
    } catch (error) { state = 'failed'; failure = error; render(); }
}
byId('memory-run').addEventListener('change', () => { selected = byId('memory-run').value; history.replaceState(null, '', `/memory.html?run=${selected}`); void loadSelected(); });
byId('memory-refresh').addEventListener('click', () => void busy(byId('memory-refresh'), load));
byId('memory-continue').addEventListener('click', () => void busy(byId('memory-continue'), async () => {
    if (sending || state !== 'ready' || !view || view.run.id !== selected) return;
    const sourceRun = view.run.id;
    const destination = view.run.manifest.plan.exportSelection ? '/batch-comparison.html' : '/comparison.html';
    const key = `lab.memory.pending.${sourceRun}`;
    sending = true;
    render();
    try {
        const commandId = sessionStorage.getItem(key) || crypto.randomUUID();
        sessionStorage.setItem(key, commandId);
        const report = await request(`/api/lab/runs/${sourceRun}/reports`, { method: 'POST', body: { commandId } });
        sessionStorage.removeItem(key);
        location.assign(`${destination}?parent=${sourceRun}&historyReport=${report.id}`);
    } catch (error) {
        sending = false;
        render();
        errorNotice(byId('memory-feedback'), error);
    }
}));
document.addEventListener('lab:language', render);
void load();
