import '../common/shell.js';
import { dateTime, t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { groups, localReady } from '../common/diagnostics.js';
import { badge, busy, byId, element, errorText, notice } from '../common/ui.js';

let report;

function render() {
    if (!report) return;
    byId('readiness-title').textContent = t(report.foundationReady ? 'status.connected' : 'status.attention');
    byId('checked-at').textContent = `${t('status.time')}: ${dateTime(report.observedAt)}`;
    byId('work-pending').hidden = report.experimentReady;
    byId('environments').replaceChildren();
    for (const group of groups(report)) {
        const row = element('tr');
        const name = element('td', t(group.role));
        const status = element('td');
        const ready = group.state === 'REACHABLE' && localReady(group.report);
        status.append(badge(t(ready ? 'ready' : group.state === 'REACHABLE' ? 'missing' : 'unreachable'), ready ? 'good' : 'warning'));
        const failures = group.report?.checks.filter(check => !['READY', 'CONFIGURED_UNVERIFIED', 'NOT_IMPLEMENTED', 'NOT_APPLICABLE', 'MATCHED'].includes(check.state));
        if (failures?.length) status.append(element('span', failures.map(check => t(check.component)).join(' · '), 'subtext'));
        if (group.role === 'contexa' && group.report?.runtimeMode?.mode) {
            status.append(element('span', t(`mode.${group.report.runtimeMode.mode}`), 'subtext'));
        }
        row.append(name, status, element('td', dateTime(group.report?.observedAt || group.checkedAt), 'small muted'));
        byId('environments').append(row);
    }
}

async function refresh() {
    try { report = await request('/api/lab/readiness'); notice(byId('feedback')); render(); }
    catch (error) {
        byId('readiness-title').textContent = t('status.unavailable');
        byId('environments').replaceChildren();
        notice(byId('feedback'), errorText(error), 'danger');
    }
}

byId('refresh').addEventListener('click', () => void busy(byId('refresh'), refresh));
document.addEventListener('lab:language', render);
void refresh();
