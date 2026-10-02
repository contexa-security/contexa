import '../common/shell.js';
import { t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { appendDefinition, busy, byId, errorNotice, notice } from '../common/ui.js';

let view, chart, clockOffset = 0, failure, renderedState;
const labels = () => ['workspace.comparison', 'workspace.chat', 'workspace.embedding', 'workspace.work'].map(t);
function state() {
    if (!view) return null;
    if (!view.enabled) return 'PRIVATE';
    if (!view.lease) return 'EMPTY';
    if (view.lease.state === 'ACTIVE' && Date.parse(view.lease.expiresAt) <= Date.now() + clockOffset) return 'EXPIRED';
    return view.lease.state;
}
function clock() {
    const seconds = state() === 'ACTIVE' ? Math.max(0, Math.floor((Date.parse(view.lease.expiresAt) - Date.now() - clockOffset) / 1000)) : 0;
    byId('workspace-clock').textContent = view?.lease ? `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}` : '—';
    if (state() !== renderedState) render();
}
function render() {
    const current = state();
    renderedState = current;
    byId('workspace-state').textContent = current ? t(`workspace.state.${current}`) : t('loading');
    byId('workspace-note').textContent = current ? t(`workspace.note.${current}`) : '';
    byId('workspace-start').hidden = current !== 'EMPTY';
    byId('workspace-continue').hidden = !['ACTIVE', 'PRIVATE'].includes(current);
    byId('workspace-end').hidden = current !== 'ACTIVE';
    byId('workspace-usage').hidden = !view?.enabled || !view.lease;
    if (current !== 'ACTIVE') byId('workspace-confirm').hidden = true;
    chart?.destroy(); chart = null;
    if (view?.enabled && view.lease) {
        const u = view.lease.usage, used = [u.comparisonsUsed, u.chatUsed, u.embeddingUsed, u.workUsed];
        const maximum = [u.comparisonLimit, u.chatLimit, u.embeddingLimit, u.workLimit];
        byId('workspace-counts').replaceChildren();
        labels().forEach((label, i) => appendDefinition(byId('workspace-counts'), label, `${used[i]} / ${maximum[i]}`));
        byId('workspace-chart').setAttribute('aria-label', labels().map((label, i) => `${label}: ${used[i]} / ${maximum[i]}`).join('; '));
        chart = new Chart(byId('workspace-chart'), { type: 'bar', data: { labels: labels(), datasets: [
            { label: t('workspace.used'), data: used.map((value, i) => value * 100 / maximum[i]), backgroundColor: '#006b5c', borderRadius: 4 },
            { label: t('workspace.available'), data: used.map((value, i) => 100 - value * 100 / maximum[i]), backgroundColor: '#d9e4e3', borderRadius: 4 }
        ] }, options: { responsive: true, maintainAspectRatio: false, animation: false, indexAxis: 'y', scales: {
            x: { stacked: true, min: 0, max: 100, ticks: { callback: value => `${value}%` } }, y: { stacked: true, grid: { display: false } }
        }, plugins: { legend: { position: 'bottom' }, tooltip: { enabled: false } } } });
    }
    if (failure) errorNotice(byId('workspace-feedback'), failure); else notice(byId('workspace-feedback'));
    clock();
}
function update(value) {
    view = value;
    clockOffset = Date.parse(view.serverTime) - Date.now();
    failure = null;
    render();
}
async function load() {
    try { update(await request('/api/lab/workspaces/current/lease')); }
    catch (error) { failure = error; render(); }
}
byId('workspace-refresh').addEventListener('click', () => void busy(byId('workspace-refresh'), load));
byId('workspace-start').addEventListener('click', () => void busy(byId('workspace-start'), async () => {
    try { await request('/api/lab/workspaces', { method: 'POST' }); await load(); }
    catch (error) { failure = error; render(); }
}));
byId('workspace-end').addEventListener('click', () => { byId('workspace-confirm').hidden = false; byId('workspace-end-confirm').focus(); });
byId('workspace-end-back').addEventListener('click', () => { byId('workspace-confirm').hidden = true; byId('workspace-end').focus(); });
byId('workspace-end-confirm').addEventListener('click', () => void busy(byId('workspace-end-confirm'), async () => {
    try { update(await request('/api/lab/workspaces/current/lease/cancel', { method: 'POST' })); }
    catch (error) { failure = error; render(); }
}));
document.addEventListener('lab:language', render);
document.addEventListener('visibilitychange', () => { if (!document.hidden) void load(); });
setInterval(clock, 1000);
void load();
