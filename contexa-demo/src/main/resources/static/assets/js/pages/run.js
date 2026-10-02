import '../common/shell.js';
import { setJourneyReference } from '../common/journey-link.js';
import { renderHistoryReference } from '../common/run-history-reference.js';
import { request } from '../common/http.js';
import { t } from '../common/i18n.js';
import { byId, errorText, notice } from '../common/ui.js';
import { renderRun } from '../common/run-results.js';
import { dispatchStep } from '../common/run-dispatch.js';
import { pendingRunReports, retryRunReports } from '../common/run-client-reports.js';

const id = new URLSearchParams(location.search).get('id');
let view;
let origins;
let active = false;
let loading = false;
let timer;
let lastChange;
let journeyLinked = false;
let pollUntil = Date.now() + 120000;
const evidence = {};
const clients = {};
function reportStatus() {
    const state = pendingRunReports(id);
    byId('run-report-recovery').hidden = state.count === 0 && state.storageAvailable;
    byId('run-report-status').textContent = t(!state.storageAvailable ? 'run.reports.cacheFailed'
        : state.sending ? 'run.reports.saving' : 'run.reports.pending');
    byId('run-report-retry').disabled = state.sending || state.count === 0;
}
function render() {
    if (view) { renderRun(view, evidence, clients, active, origins); renderHistoryReference(view.run.manifest); }
    if (!pendingRunReports(id).capacityAvailable) byId('run-start').disabled = true;
    reportStatus();
}
async function refresh(manual = false) {
    if (loading) return;
    loading = true;
    try {
        const fresh = await request(`/api/lab/runs/${encodeURIComponent(id)}`);
        view = fresh;
        if (!journeyLinked) { await setJourneyReference(view.run.manifest.plan.journeyStep); journeyLinked = true; }
        byId('run-report-link').href = `/report.html?run=${encodeURIComponent(view.run.id)}`;
        byId('run-report-link').hidden = false;
        byId('run-variation-link').href = `${view.run.manifest.plan.exportSelection ? '/batch-comparison.html' : '/comparison.html'}?parent=${encodeURIComponent(view.run.id)}`;
        byId('run-variation-link').hidden = false;
        await Promise.all(view.steps.filter(step => step.requestId).map(async step => {
            try { evidence[step.arm] = await request(`/api/lab/workspaces/requests/${step.arm}/${step.requestId}`); }
            catch { evidence[step.arm] = null; }
        }));
        const changed = JSON.stringify([view, evidence, clients, active]);
        if (manual || changed !== lastChange) { lastChange = changed; render(); }
        notice(byId('run-feedback'));
    } catch (error) { notice(byId('run-feedback'), errorText(error), 'danger'); }
    finally {
        loading = false;
        clearTimeout(timer);
        if (!document.hidden && Date.now() < pollUntil) timer = setTimeout(() => void refresh(), 2500);
    }
}
byId('run-start').addEventListener('click', async () => {
    if (active || !view || view.run.state !== 'READY' || !view.steps.every(step => step.state === 'PLANNED')) return;
    if (!pendingRunReports(id).capacityAvailable) {
        notice(byId('run-feedback'), t('run.reports.capacity'), 'warning');
        return;
    }
    active = true; pollUntil = Date.now() + 120000; render();
    try {
        origins ||= await request('/api/lab/identity');
        const frozen = view;
        await Promise.all(frozen.steps.map(async step => {
            clients[step.arm] = await dispatchStep(frozen.run, step, step.arm === 'baseline' ? origins.baselineUrl : origins.contexaUrl);
            void refresh();
        }));
    } catch (error) { notice(byId('run-feedback'), errorText(error), 'danger'); }
    finally { active = false; await refresh(true); }
});
byId('run-cancel').addEventListener('click', async () => {
    byId('run-cancel').disabled = true;
    try { view = await request(`/api/lab/runs/${encodeURIComponent(id)}/cancel`, { method: 'POST' }); render(); }
    catch (error) { notice(byId('run-feedback'), errorText(error), 'danger'); }
});
byId('run-refresh').addEventListener('click', () => { pollUntil = Date.now() + 120000; void refresh(true); });
document.addEventListener('lab:language', render);
document.addEventListener('lab:run-reports', reportStatus);
byId('run-report-retry').addEventListener('click', async () => {
    await retryRunReports(id);
    await refresh(true);
});
document.addEventListener('visibilitychange', () => {
    clearTimeout(timer);
    if (!document.hidden) { pollUntil = Date.now() + 120000; void refresh(); }
});
window.addEventListener('pagehide', () => clearTimeout(timer));
try { origins = await request('/api/lab/identity'); }
catch { /* Saved results remain readable when work navigation is unavailable. */ }
await refresh(true);
