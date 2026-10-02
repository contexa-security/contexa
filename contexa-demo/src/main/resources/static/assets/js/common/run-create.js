import { request } from './http.js';
import { t } from './i18n.js';
import { byId, errorText, notice } from './ui.js';

let conditions;
let active = false;
let pending;
let failure;
const key = 'lab.comparison.run.pending';
try { pending = JSON.parse(sessionStorage.getItem(key) || 'null'); } catch { pending = null; }
function remember() {
    try {
        if (pending) sessionStorage.setItem(key, JSON.stringify(pending));
        else sessionStorage.removeItem(key);
    } catch { /* Server command identity remains authoritative. */ }
}
function render() {
    byId('create-run').disabled = active || (!pending && !conditions?.initialConditionsMatch);
    byId('create-run').textContent = t(active ? 'working' : pending ? 'run.create.retry' : 'run.create');
    notice(byId('run-create-feedback'), failure ? errorText(failure) : '', 'danger');
    const recovery = byId('run-create-recovery');
    recovery.hidden = !failure;
    if (failure) {
        const loginNeeded = [401, 403, 410].includes(failure.status);
        const conditionsChanged = failure.data?.state === 'INITIAL_CONDITIONS_NOT_MATCHED';
        const attemptsExhausted = failure.data?.state === 'PREPARATION_ATTEMPT_LIMIT';
        recovery.href = loginNeeded ? '/connect.html' : attemptsExhausted ? '#preparation-form'
            : conditionsChanged ? '#session-title' : '/status.html';
        recovery.textContent = t(loginNeeded ? 'compare.account.return' : attemptsExhausted ? 'compare.recheck'
            : conditionsChanged ? 'sessions.renew' : 'status');
    }
}
export function setRunConditions(pair) { conditions = pair; render(); }
byId('create-run').addEventListener('click', async () => {
    if (active || (!pending && !conditions?.initialConditionsMatch)) return;
    active = true;
    failure = null;
    pending ||= { commandId: crypto.randomUUID(), preparationId: conditions.preparationId,
        baselineAttestationId: conditions.attestations.find(value => value.arm === 'baseline').id,
        contexaAttestationId: conditions.attestations.find(value => value.arm === 'contexa').id };
    remember(); render();
    try {
        const view = await request('/api/lab/runs', { method: 'POST', body: pending });
        pending = null; remember(); location.assign(`/run.html?id=${encodeURIComponent(view.run.id)}`);
    } catch (error) {
        if (error.status && error.status < 500) { pending = null; remember(); }
        failure = error;
    } finally {
        active = false; render();
        document.dispatchEvent(new Event('lab:run-submission'));
    }
});
document.addEventListener('lab:language', render);
render();
