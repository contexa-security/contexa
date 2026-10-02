import '../common/shell.js';
import { t } from '../common/i18n.js';
import { ApiError, localLink, request } from '../common/http.js';
import { classification, groups, renderChecks } from '../common/diagnostics.js';
import { busy, byId, errorText, notice } from '../common/ui.js';

let report;
let chart;

function render() {
    if (!report) return;
    renderChecks(byId('checks'), report);
    const counts = [0, 0, 0, 0];
    for (const group of groups(report)) {
        for (const check of group.report?.checks || [{ state: 'UNAVAILABLE' }]) {
            counts[classification(check.state).group]++;
        }
    }
    const labels = ['ready', 'configured', 'missing', 'remaining'].map(t);
    const summary = labels.map((label, index) => `${label}: ${counts[index]}`).join(' · ');
    byId('chart-summary').textContent = summary;
    byId('check-chart').setAttribute('aria-label', summary);
    if (typeof window.Chart !== 'function') return;
    chart?.destroy();
    chart = new window.Chart(byId('check-chart'), {
        type: 'doughnut',
        data: { labels, datasets: [{ data: counts, backgroundColor: ['#006b5c', '#677f8e', '#bd6333', '#dce3e7'], borderWidth: 2, borderColor: '#ffffff' }] },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '76%', animation: false,
            plugins: { legend: { display: false }, tooltip: { enabled: true } }
        }
    });
}

async function refresh() {
    try {
        report = await request('/api/lab/readiness/details');
        byId('authorization').hidden = true;
        byId('diagnostic-content').hidden = false;
        notice(byId('feedback'));
        render();
    } catch (error) {
        byId('diagnostic-content').hidden = true;
        if (error instanceof ApiError && [401, 403].includes(error.status)) {
            byId('authorization').hidden = false;
            byId('authorization-message').textContent = t(error.status === 401 ? 'operator.auth' : 'operator.denied');
            if (error.data?.state === 'EMAIL_VERIFICATION_REQUIRED') {
                byId('authorization-message').textContent = errorText(error);
                byId('operator-login').href = '/entry.html';
                byId('operator-login').textContent = t('entry.title');
            } else {
                const identity = await request('/api/lab/identity').catch(() => null);
                byId('operator-login').href = localLink(identity?.loginUrl || '/login');
                byId('operator-login').textContent = t('operator.signin');
            }
        } else { notice(byId('feedback'), errorText(error), 'danger'); }
    }
}

byId('refresh').addEventListener('click', () => void busy(byId('refresh'), refresh));
byId('capture').addEventListener('click', () => void busy(byId('capture'), async () => {
    try {
        const saved = await request('/api/lab/readiness/snapshots', { method: 'POST' });
        notice(byId('feedback'), `${t('operator.saved')} ${saved.id}`);
    } catch (error) { notice(byId('feedback'), errorText(error), 'danger'); }
}));
document.addEventListener('lab:language', () => { if (report) render(); else void refresh(); });
window.addEventListener('load', () => { if (report && !chart) render(); });
void refresh();
