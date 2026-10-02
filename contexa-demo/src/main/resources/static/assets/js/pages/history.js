import '../common/shell.js';
import { dateTime, t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { busy, byId, element, errorText, notice } from '../common/ui.js';

let records;

function render() {
    if (!records) return;
    byId('history').replaceChildren();
    byId('empty').hidden = records.length > 0;
    byId('empty').textContent = t('history.empty');
    for (const record of records) {
        const row = element('tr');
        row.append(element('td', dateTime(record.observedAt)), element('td', t(record.role)),
            element('td', record.id, 'mono'), element('td', record.sha256, 'mono'));
        byId('history').append(row);
    }
}

async function refresh() {
    try { records = await request('/api/lab/readiness/snapshots'); notice(byId('feedback')); render(); }
    catch (error) {
        byId('empty').hidden = true;
        notice(byId('feedback'), errorText(error), 'danger');
    }
}

byId('refresh').addEventListener('click', () => void busy(byId('refresh'), refresh));
document.addEventListener('lab:language', render);
void refresh();
