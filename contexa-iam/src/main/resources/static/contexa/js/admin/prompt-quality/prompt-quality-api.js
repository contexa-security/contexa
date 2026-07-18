import { appPath, fetchJson } from '../verification-ui-common.js';
import { has, t } from './prompt-quality-i18n.js';

const JSON_HEADERS = Object.freeze({ 'Accept': 'application/json', 'Content-Type': 'application/json' });

export function promptQualityApiRoot(scope = document) {
    const scopedElement = scope?.dataset?.pqaApiRoot ? scope : scope?.querySelector?.('[data-pqa-api-root]');
    const metaElement = document.querySelector('meta[name="contexa-pqa-api-root"]');
    const value = String(scopedElement?.dataset?.pqaApiRoot || metaElement?.content || '').trim();
    if (!value || !value.startsWith('/')) {
        throw new Error('Prompt-quality API root page contract is required.');
    }
    return value.replace(/\/+$/, '');
}

export function promptQualityApiPath(relativePath = '', scope = document) {
    const suffix = String(relativePath || '').trim();
    if (!suffix) {
        return promptQualityApiRoot(scope);
    }
    return `${promptQualityApiRoot(scope)}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}
export async function getJson(path) {
    return requireJsonResponse(await fetchJson(appPath(path)));
}

export async function postJson(path, body = {}) {
    return requireJsonResponse(await fetchJson(appPath(path), {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify(body)
    }));
}

export async function putJson(path, body = {}) {
    return requireJsonResponse(await fetchJson(appPath(path), {
        method: 'PUT',
        headers: JSON_HEADERS,
        body: JSON.stringify(body)
    }));
}

export async function patchJson(path, body = {}) {
    return requireJsonResponse(await fetchJson(appPath(path), {
        method: 'PATCH',
        headers: JSON_HEADERS,
        body: JSON.stringify(body)
    }));
}

export async function deleteJson(path, body = {}) {
    return requireJsonResponse(await fetchJson(appPath(path), {
        method: 'DELETE',
        headers: JSON_HEADERS,
        body: JSON.stringify(body)
    }));
}

function requireJsonResponse(value) {
    if (typeof value !== 'string') {
        return value;
    }
    const trimmed = value.trim();
    const looksLikeHtml = trimmed.startsWith('<!DOCTYPE')
            || trimmed.startsWith('<html')
            || trimmed.includes('<title>');
    const message = looksLikeHtml
            ? t('enterprise.pqa.api.response.htmlInsteadOfJson')
            : t('enterprise.pqa.api.response.nonJson');
    const error = new Error(message);
    error.body = { message };
    throw error;
}

export function publicError(error) {
    if (error?.body?.message) {
        const cause = String(error.body.cause || '').trim();
        const message = String(error.body.message || '').trim();
        return cause && cause !== message ? `${message}: ${cause}` : message;
    }
    if (error?.message) {
        return error.message;
    }
    return t('enterprise.pqa.common.error.fallback');
}

export function publicErrorGuidance(error) {
    const parts = [];
    if (error?.body?.nextAction) {
        parts.push(error.body.nextAction);
    }
    if (error?.body?.traceId) {
        parts.push(has('enterprise.pqa.api.traceId') ? t('enterprise.pqa.api.traceId', error.body.traceId) : `Trace ID ${error.body.traceId}`);
    }
    return parts.join(' | ');
}
