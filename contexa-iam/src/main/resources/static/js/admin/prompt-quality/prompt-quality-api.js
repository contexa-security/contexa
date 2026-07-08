import { appPath, fetchJson } from '../verification-ui-common.js';
import { has, t } from './prompt-quality-i18n.js';

const JSON_HEADERS = Object.freeze({ 'Accept': 'application/json', 'Content-Type': 'application/json' });
const FALLBACK_ERROR_MESSAGE = 'The request could not be processed. Please check the input and server status.';

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
            ? 'API가 JSON 데이터가 아니라 HTML 화면을 반환했습니다. 로그인 상태와 API 라우팅을 확인하십시오.'
            : 'API가 JSON이 아닌 응답을 반환했습니다.';
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
    return has('enterprise.pqa.common.error.fallback')
            ? t('enterprise.pqa.common.error.fallback')
            : FALLBACK_ERROR_MESSAGE;
}

export function publicErrorGuidance(error) {
    const parts = [];
    if (error?.body?.nextAction) {
        parts.push(error.body.nextAction);
    }
    if (error?.body?.traceId) {
        parts.push(`Trace ID ${error.body.traceId}`);
    }
    return parts.join(' | ');
}
