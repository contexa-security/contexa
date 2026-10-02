import { setRunConditions } from './run-create.js';
import { dateTime, t } from './i18n.js';
import { ApiError, request } from './http.js';
import { appendDefinition, badge, byId, element, errorText, notice } from './ui.js';
import { securityContinuation } from './security-feedback.js';

let preparationId;
let pair;
let active = false;
let origins;
let pending;
let feedback;
let sessionFailures = [];
const storageKey = 'lab.comparison.sessions.pending';

try { pending = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch { pending = null; }

function showFeedback(key, kind = '', error = null) {
    feedback = { key, kind, error };
    notice(byId('session-feedback'), error ? errorText(error) : t(key), kind);
}

function remember() {
    try {
        if (pending) sessionStorage.setItem(storageKey, JSON.stringify(pending));
        else sessionStorage.removeItem(storageKey);
    } catch { /* A failed browser cache never changes saved server evidence. */ }
}

function label(group, value) {
    const key = `sessions.${group}.${value}`;
    return t(key) === key ? t(`sessions.${group}.other`) : t(key);
}

function renderRecovery() {
    const target = byId('session-recovery');
    target.replaceChildren();
    target.hidden = !sessionFailures.length;
    for (const failure of sessionFailures) {
        const section = element('section', null, 'notice warning');
        section.append(element('h3', failure.arm === 'baseline' ? t('connect.baseline') : 'Contexa'));
        const continuation = securityContinuation(failure.error?.data, origins[`${failure.arm}Url`], '/session.html');
        section.append(element('p', continuation ? t(`security.${continuation.name}.body`) : errorText(failure.error)));
        if (continuation && !continuation.href) {
            section.append(element('p', t('security.link.unavailable'), 'small'));
        } else {
            const action = element('a', t(continuation?.labelKey || 'compare.account.return'), 'button secondary compact');
            action.href = continuation?.href || '/connect.html';
            action.target = '_blank';
            action.rel = 'noopener';
            section.append(action);
        }
        section.append(element('p', t('sessions.recovery.return'), 'small'));
        target.append(section);
    }
}

export function renderSessions() {
    setRunConditions(pair);
    document.dispatchEvent(new CustomEvent('lab:comparison-pair', { detail: pair }));
    if (feedback) notice(byId('session-feedback'), feedback.error ? errorText(feedback.error) : t(feedback.key), feedback.kind);
    byId('session-capture').disabled = !preparationId || active;
    byId('session-capture').textContent = t(active ? 'working' : pending ? 'sessions.retry' : 'sessions.capture');
    byId('session-renew').hidden = !pair && !pending;
    byId('session-renew').disabled = active;
    byId('session-result').hidden = !pair;
    renderRecovery();
    if (!pair) return;
    byId('session-check-state').replaceChildren(badge(t(pair.initialConditionsMatch ? 'sessions.matched' : 'sessions.incomplete'), pair.initialConditionsMatch ? 'good' : 'warning'));
    byId('session-sources').replaceChildren(...pair.attestations.map(record => {
        const section = element('section', null, 'source-arm');
        section.append(element('h3', record.arm === 'baseline' ? t('connect.baseline') : 'Contexa'));
        const details = element('dl', null, 'definition');
        const snapshot = record.snapshot;
        appendDefinition(details, t('sessions.account'), snapshot.identity.username || t('unknown'));
        appendDefinition(details, t('sessions.permissions'), snapshot.identity.accountAuthorities?.map(value => t(`sessions.role.${value}`) === `sessions.role.${value}` ? value : t(`sessions.role.${value}`)).join(' / ') || t('unknown'));
        appendDefinition(details, t('sessions.captured'), dateTime(record.capturedAt));
        if (snapshot.approval) {
            appendDefinition(details, t('batch.approval'), t(`approval.status.${snapshot.approval.status}`) === `approval.status.${snapshot.approval.status}`
                ? snapshot.approval.status : t(`approval.status.${snapshot.approval.status}`));
        }
        appendDefinition(details, t('sessions.history'), snapshot.history.state === 'NOT_APPLICABLE' ? t('sessions.noAI')
            : snapshot.history.updates == null ? t('sessions.historyUnknown') : String(snapshot.history.updates));
        const models = snapshot.environment.nativeConfiguration?.models?.filter(model => model.type === 'CHAT');
        if (record.arm === 'contexa') {
            appendDefinition(details, t('sessions.models'), models?.map(model => model.defaultOptions?.model).filter(Boolean).join(' / ') || t('unknown'));
            appendDefinition(details, t('sessions.modelOptions'), models?.length && models.every(model => model.optionsSnapshot?.state === 'CAPTURED')
                ? t('sessions.modelOptions.captured') : t('sessions.modelOptions.incomplete'));
            const history = snapshot.history.contextHistory;
            const requests = history?.sequences?.sessionProtectableAccesses?.observedEntries;
            appendDefinition(details, t('sessions.sessionHistory'), requests == null ? t('unknown') : String(requests));
            const roleScope = history?.roleScopeHistory;
            appendDefinition(details, t('sessions.roleHistory'), roleScope?.state === 'API_RETURN_OBSERVED'
                ? String(roleScope.observedEntries) : label('state', roleScope?.state || 'NOT_OBSERVED'));
            appendDefinition(details, t('sessions.organization'), history?.organizationState === 'NO_ORGANIZATION_IN_NATIVE_REQUEST'
                ? t('sessions.organizationNotProvided') : history?.organizationBaseline?.updates == null
                    ? t('unknown') : String(history.organizationBaseline.updates));
            const inventory = snapshot.environment.ragInventory;
            appendDefinition(details, t('sessions.corpus'), inventory?.state === 'CAPTURED'
                ? String(inventory.documentsObserved) : t('unknown'));
        }
        section.append(details);
        if (record.arm === 'contexa') section.append(element('p', t('sessions.corpus.note'), 'small muted'));
        return section;
    }));
    byId('session-blockers').replaceChildren(...pair.blockers.map(check => {
        const row = element('li');
        const name = element('span', label('check', check.component));
        name.append(element('small', check.arm === 'baseline' ? t('connect.baseline') : check.arm === 'contexa' ? 'Contexa' : t('compare.all'), 'blocker-scope'));
        row.append(name, badge(label('state', check.state), 'warning')); return row;
    }));
    byId('session-json').textContent = JSON.stringify(pair, null, 2);
}

async function loadPair(ids) {
    const parameters = new URLSearchParams();
    for (const arm of ['baseline', 'contexa']) if (ids[arm]) parameters.set(arm, ids[arm]);
    pair = await request(`/api/lab/comparisons/preparations/${encodeURIComponent(preparationId)}/sessions?${parameters}`);
    const url = new URL(location.href);
    for (const arm of ['baseline', 'contexa']) {
        if (ids[arm]) url.searchParams.set(arm, ids[arm]);
        else url.searchParams.delete(arm);
    }
    history.replaceState(null, '', url);
    renderSessions();
}

export async function setSessionPreparation(id) {
    if (preparationId === id) return;
    preparationId = id;
    pair = null;
    sessionFailures = [];
    if (pending?.preparationId !== id) { pending = null; remember(); }
    renderSessions();
    if (!id) return;
    const url = new URL(location.href);
    const ids = { baseline: url.searchParams.get('baseline'), contexa: url.searchParams.get('contexa') };
    if (ids.baseline || ids.contexa) {
        try { await loadPair(ids); }
        catch (error) { showFeedback(null, 'danger', error); }
    }
}

byId('session-capture').addEventListener('click', async () => {
    if (!preparationId || active) return;
    active = true;
    sessionFailures = [];
    pending ||= { preparationId, baseline: crypto.randomUUID(), contexa: crypto.randomUUID(), ids: {} };
    remember(); renderSessions(); showFeedback('working');
    try {
        origins ||= await request('/api/lab/identity');
        const results = await Promise.allSettled(['baseline', 'contexa'].map(async arm => {
            if (pending.ids[arm]) return;
            const record = await request('/api/lab/comparisons/attestations', {
                origin: arm === 'baseline' ? origins.baselineUrl : origins.contexaUrl,
                method: 'POST', body: { commandId: pending[arm], preparationId }
            });
            pending.ids[arm] = record.id; remember();
        }));
        sessionFailures = results.flatMap((result, index) => result.status === 'rejected'
            ? [{ arm: ['baseline', 'contexa'][index], error: result.reason }] : []);
        await loadPair(pending.ids);
        const failures = results.filter(result => result.status === 'rejected');
        if (failures.length) {
            const authenticationNeeded = failures.some(result => result.reason instanceof ApiError && [401, 403].includes(result.reason.status));
            showFeedback(authenticationNeeded ? 'sessions.signinNeeded' : 'sessions.failed', 'warning');
        } else {
            pending = null; remember(); showFeedback('sessions.saved');
            byId('session-result-title').focus();
        }
    } catch (error) {
        showFeedback(null, 'danger', error);
    } finally { active = false; renderSessions(); }
});

byId('session-renew').addEventListener('click', () => {
    if (active) return;
    pending = null; remember(); pair = null; sessionFailures = [];
    const url = new URL(location.href); url.searchParams.delete('baseline'); url.searchParams.delete('contexa');
    history.replaceState(null, '', url);
    showFeedback('sessions.renewNote'); renderSessions();
});

document.addEventListener('lab:language', renderSessions);
