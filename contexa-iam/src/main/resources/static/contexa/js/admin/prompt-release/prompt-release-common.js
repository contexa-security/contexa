// W7-14: shared helpers of the prompt version screens. Every text taken from the registry, a manifest or the gate is
// set as text content, never as markup. The element, number, time and address helpers are the inspection screens'.
import {dayEnd, dayStart, el, formatTime, localDate, number, query, setStatus}
    from '../prompt-inspection/prompt-inspection-common.js';

export {dayEnd, dayStart, el, formatTime, localDate, number, query, setStatus};

const pageElement = document.querySelector('[data-pr-page]');

export const apiRoot = pageElement?.dataset.apiRoot || '/contexa/admin/api/prompt-quality/releases';
export const pageRoot = pageElement?.dataset.pageRoot || '/contexa/admin/prompt-quality/releases';

function readJson(id) {
    try {
        return JSON.parse(document.getElementById(id)?.textContent || '{}');
    } catch (error) {
        return {};
    }
}

const words = readJson('prompt-release-messages');

/** The screens' lists as the server keeps them: canonical states, chip tones, buttons, release statuses, codes. */
export const settings = readJson('prompt-release-settings');

/** The word of the key in the reader's language, with {0}, {1}... filled in. */
export function t(key, ...values) {
    let text = words[key] ?? key;
    values.forEach((value, index) => {
        text = text.split(`{${index}}`).join(String(value));
    });
    return text;
}

function csrf() {
    const token = document.querySelector('meta[name="_csrf"]')?.content;
    if (!token) {
        return null;
    }
    return {
        header: document.querySelector('meta[name="_csrf_header"]')?.content || 'X-CSRF-TOKEN',
        token
    };
}

/**
 * Calls the version API and gives back the status with the body, so a refusal (422) shows what the gate or the
 * rollback recorded.
 */
export async function call(path, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (method !== 'GET') {
        const token = csrf();
        if (token) {
            headers.set(token.header, token.token);
        }
        if (options.body !== undefined) {
            headers.set('Content-Type', 'application/json');
        }
    }
    const response = await fetch(apiRoot + path, {
        method,
        headers,
        credentials: 'same-origin',
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined
    });
    const text = await response.text();
    let body = null;
    if (text) {
        try {
            body = JSON.parse(text);
        } catch (error) {
            body = null;
        }
    }
    return {status: response.status, ok: response.ok, body};
}

/** Reads from the version API; a failed read throws an error carrying its HTTP status. */
export async function read(path) {
    const answer = await call(path);
    if (!answer.ok) {
        const error = new Error(`HTTP ${answer.status}`);
        error.status = answer.status;
        throw error;
    }
    return answer.body;
}

/** A state by its canonical name (decision 1, PV-14); a stored status of no vocabulary says it is none of them. */
export function stateChip(state, unknownStatus) {
    if (!state) {
        return el('span', {class: 'pi-chip pi-chip-unverifiable', text: t('promptRelease.state.unknown',
            unknownStatus || '-')});
    }
    return el('span', {class: `pi-chip pi-chip-${settings.tones?.[state] || 'neutral'}`, text: state,
        title: t(`promptRelease.state.${state}`)});
}

/** The gate's answer for one next state: ready only when the gate has no blocker for it (PV-8). */
export function gateChip(target) {
    if (target.ready) {
        return el('span', {class: 'pi-chip pi-chip-matched', text: t('promptRelease.gate.ready', target.targetState)});
    }
    return el('span', {class: 'pi-chip pi-chip-mismatch', title: (target.blockers || []).join('\n'),
        text: t('promptRelease.gate.blocked', target.targetState, number((target.blockers || []).length))});
}

/** A blocker or a refusal in the reader's words when its code is known; the recorded sentence stays as the title. */
export function reasonItem(reason, kind) {
    const text = String(reason || '');
    const code = text.split(/\s+/)[0];
    const known = (kind === 'blocker' ? settings.blockers : settings.refusals) || [];
    return el('li', {title: text, text: known.includes(code) ? t(`promptRelease.${kind}.${code}`) : text});
}

export function shortHash(hash) {
    return hash ? `${hash.slice(0, 12)}…` : '-';
}

export function list(values) {
    return values && values.length ? values.join(', ') : '-';
}

export function yesNo(value) {
    if (value === null || value === undefined) {
        return '-';
    }
    return t(value ? 'promptRelease.common.yes' : 'promptRelease.common.no');
}

/** The scope of a bundle: its registry scope, then the canary share and targets when it has them. */
export function scopeText(row) {
    const parts = [row.registryScope];
    const canary = row.canary || {};
    if (canary.percent !== null && canary.percent !== undefined) {
        parts.push(t('promptRelease.canary.percent', number(canary.percent)));
    }
    if (canary.tenants) {
        parts.push(t('promptRelease.canary.tenants', canary.tenants));
    }
    if (canary.resourceFamilies) {
        parts.push(t('promptRelease.canary.families', canary.resourceFamilies));
    }
    return parts.join(' / ');
}

/** Whether this build holds the bundle, with the same hash as the registry row. */
export function buildChip(row) {
    if (!row.inBuild) {
        return el('span', {class: 'pi-chip pi-chip-neutral', text: t('promptRelease.build.absent')});
    }
    return row.hashMatchesBuild
        ? el('span', {class: 'pi-chip pi-chip-matched', text: t('promptRelease.build.present')})
        : el('span', {class: 'pi-chip pi-chip-mismatch', text: t('promptRelease.build.hashDiffers')});
}

export function detailHref(registryScope, promptKey, bundleVersion) {
    return `${pageRoot}/detail${query({registryScope, promptKey, promptVersion: bundleVersion})}`;
}

export function fillTable(table, rows, columns) {
    const body = table.querySelector('tbody');
    body.replaceChildren();
    if (!rows.length) {
        body.append(el('tr', {}, el('td', {class: 'pi-empty', colspan: columns, text: t('promptRelease.common.empty')})));
        return;
    }
    rows.forEach((row) => body.append(row));
}
