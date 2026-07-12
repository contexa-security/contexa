function normalizeQueryArgs(first, second) {
    if (typeof first === 'string') {
        return {
            root: second || document,
            selector: first
        };
    }
    return {
        root: first,
        selector: second
    };
}

export const __i18n = (() => {
    try {
        return JSON.parse(document.getElementById('vc-i18n')?.textContent || '{}');
    } catch (e) {
        return {};
    }
})();

export function t(key, fallback) {
    if (!key) return fallback || '';
    const value = __i18n[key];
    if (value == null || value === '') return fallback || '';
    return value;
}

export const $ = (first, second) => {
    const { root, selector } = normalizeQueryArgs(first, second);
    if (!root || typeof root.querySelector !== 'function' || !selector) {
        return null;
    }
    return root.querySelector(selector);
};

export const $$ = (first, second) => {
    const { root, selector } = normalizeQueryArgs(first, second);
    if (!root || typeof root.querySelectorAll !== 'function' || !selector) {
        return [];
    }
    return Array.from(root.querySelectorAll(selector));
};

export const rawText = (value) => {
    if (value === null || value === undefined) {
        return null;
    }
    const normalized = String(value).trim();
    return normalized === '' ? null : normalized;
};

export const text = (value) => rawText(value) ?? '-';

export const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

export const ensureObject = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {};

export const ensureArray = (value) => Array.isArray(value) ? value : [];

const ADMIN_ASSET_PATH = '/contexa/js/admin/';
const CORE_PQA_ROUTE_ROOT = '/contexa/admin/prompt-quality';
const CORE_PQA_API_ROOT = '/contexa/admin/api/prompt-quality';
const ADMIN_ROUTE_PREFIX = '/contexa/admin/';
const ADMIN_API_PREFIX = '/contexa/admin/api/';
const PROMPT_QUALITY_ROUTE_SUFFIX = '/prompt-quality';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

function appContextPath() {
    try {
        const modulePath = new URL(import.meta.url).pathname;
        const assetIndex = modulePath.indexOf(ADMIN_ASSET_PATH);
        return assetIndex > 0 ? modulePath.slice(0, assetIndex) : '';
    } catch {
        return '';
    }
}

export function appPath(path) {
    const normalized = rewritePromptQualityPath(
            String(path || '').startsWith('/') ? String(path || '') : `/${path || ''}`);
    const contextPath = appContextPath();
    if (!contextPath || normalized === contextPath || normalized.startsWith(`${contextPath}/`)) {
        return normalized;
    }
    return `${contextPath}${normalized}`;
}

function rewritePromptQualityPath(path) {
    if (!path || typeof document === 'undefined') {
        return path;
    }
    const root = document.querySelector('[data-pqa-api-root], [data-pqa-route-root]');
    const apiRoot = rawText(root?.dataset?.pqaApiRoot) || inferredPromptQualityApiRoot();
    if (apiRoot && apiRoot !== CORE_PQA_API_ROOT && path.startsWith(CORE_PQA_API_ROOT)) {
        return `${apiRoot}${path.slice(CORE_PQA_API_ROOT.length)}`;
    }
    const routeRoot = rawText(root?.dataset?.pqaRouteRoot) || inferredPromptQualityRouteRoot();
    if (routeRoot && routeRoot !== CORE_PQA_ROUTE_ROOT && path.startsWith(CORE_PQA_ROUTE_ROOT)) {
        return `${routeRoot}${path.slice(CORE_PQA_ROUTE_ROOT.length)}`;
    }
    return path;
}

function inferredPromptQualityRouteRoot() {
    if (typeof window === 'undefined' || !window.location) {
        return null;
    }
    const pathname = String(window.location.pathname || '');
    const suffixIndex = pathname.indexOf(PROMPT_QUALITY_ROUTE_SUFFIX);
    if (suffixIndex < 0) {
        return null;
    }
    const routeRoot = pathname.slice(0, suffixIndex + PROMPT_QUALITY_ROUTE_SUFFIX.length);
    return routeRoot.startsWith(ADMIN_ROUTE_PREFIX) && routeRoot !== CORE_PQA_ROUTE_ROOT
            ? routeRoot
            : null;
}

function inferredPromptQualityApiRoot() {
    const routeRoot = inferredPromptQualityRouteRoot();
    if (!routeRoot || !routeRoot.startsWith(ADMIN_ROUTE_PREFIX)) {
        return null;
    }
    return `${ADMIN_API_PREFIX}${routeRoot.slice(ADMIN_ROUTE_PREFIX.length)}`;
}

export function rewritePromptQualityHref(href) {
    if (!href || typeof window === 'undefined' || !window.location) {
        return href;
    }
    let url;
    try {
        url = new URL(href, window.location.href);
    } catch {
        return href;
    }
    if (url.origin !== window.location.origin) {
        return href;
    }
    const before = `${url.pathname}${url.search}${url.hash}`;
    const after = rewritePromptQualityPath(before);
    return after === before ? href : appPath(after);
}

export function normalizePromptQualityLinks(root = document) {
    if (!root || typeof root.querySelectorAll !== 'function') {
        return;
    }
    root.querySelectorAll('a[href]').forEach(anchor => {
        const current = anchor.getAttribute('href');
        const rewritten = rewritePromptQualityHref(current);
        if (rewritten && rewritten !== current) {
            anchor.setAttribute('href', rewritten);
        }
    });
}

if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => normalizePromptQualityLinks(document));
    document.addEventListener('click', event => {
        const anchor = event.target?.closest?.('a[href]');
        if (!anchor) {
            return;
        }
        const current = anchor.getAttribute('href');
        const rewritten = rewritePromptQualityHref(current);
        if (rewritten && rewritten !== current) {
            event.preventDefault();
            window.location.assign(rewritten);
        }
    }, true);
}

export function setText(root, selector, value) {
    const element = $(root, selector);
    if (element) {
        element.textContent = value;
    }
}

function csrfMetadata() {
    if (typeof document === 'undefined') {
        return null;
    }
    const token = document.querySelector('meta[name="_csrf"]')?.content
            || document.querySelector('meta[name="csrf-token"]')?.content
            || document.querySelector('input[name="_csrf"]')?.value;
    if (!token) {
        return null;
    }
    return {
        header: document.querySelector('meta[name="_csrf_header"]')?.content
                || document.querySelector('meta[name="csrf-header"]')?.content
                || 'X-CSRF-TOKEN',
        token
    };
}

function isSameOrigin(url) {
    if (typeof window === 'undefined' || !window.location) {
        return true;
    }
    try {
        return new URL(url, window.location.href).origin === window.location.origin;
    } catch {
        return true;
    }
}

function enrichHeaders(url, options) {
    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    if (!headers.has('Accept')) {
        headers.set('Accept', 'application/json');
    }
    if (isSameOrigin(url) && !headers.has('X-Requested-With')) {
        headers.set('X-Requested-With', 'XMLHttpRequest');
    }
    if (!headers.has('Cache-Control')) {
        headers.set('Cache-Control', 'no-cache');
    }
    const csrf = SAFE_METHODS.has(method) || !isSameOrigin(url) ? null : csrfMetadata();
    if (csrf && !headers.has(csrf.header)) {
        headers.set(csrf.header, csrf.token);
    }
    return headers;
}

function publicHttpErrorMessage(status, detail) {
    if (status === 401) {
        return t('enterprise.verification.http.error.401', 'Login required. Please log in again then try.');
    }
    if (status === 403) {
        return t('enterprise.verification.http.error.403', 'No execution permission or security info mismatch. Verify permissions and security tokens.');
    }
    if (status === 404) {
        return t('enterprise.verification.http.error.404', 'Cannot find the requested target. Refresh the screen and select again.');
    }
    if (status >= 500) {
        return t('enterprise.verification.http.error.5xx', 'An issue occurred during processing. Try again later or contact administrator.');
    }
    if (detail) {
        return detail;
    }
    return t('enterprise.verification.http.error.default', 'Failed to process request. Verify input values and server state.');
}

export async function fetchJson(url, options = {}) {
    const response = await fetchWithCsrf(url, options);
    await ensureOkResponse(response, url);
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
        const bodyText = await response.text();
        throw nonJsonResponseError(response, url, contentType, bodyText);
    }
    return response.json();
}

function nonJsonResponseError(response, url, contentType, bodyText) {
    const textBody = String(bodyText || '').trim();
    const looksLikeHtml = textBody.startsWith('<!DOCTYPE')
            || textBody.startsWith('<html')
            || textBody.includes('<title>');
    const targetUrl = response.url || url || '';
    const message = looksLikeHtml
            ? t('enterprise.pqa.common.error.nonJsonHtml',
                    'API가 JSON 데이터가 아니라 HTML 화면을 반환했습니다. 로그인 상태와 API 라우팅을 확인하십시오.')
            : t('enterprise.pqa.common.error.nonJson',
                    'API가 JSON 데이터가 아닌 응답을 반환했습니다.');
    const error = new Error(message);
    error.status = response.status;
    error.targetUrl = targetUrl;
    error.contentType = contentType;
    error.detail = textBody.slice(0, 500);
    error.body = {
        message,
        cause: targetUrl ? `API 경로: ${targetUrl}` : '',
        nextAction: looksLikeHtml
                ? '로그인 상태와 API 라우팅을 확인한 뒤 다시 실행하십시오.'
                : 'API 응답 Content-Type을 확인하십시오.',
        targetUrl,
        contentType
    };
    return error;
}

export async function ensureOkResponse(response, url = null) {
    if (response.ok) {
        return response;
    }
    const bodyText = await response.text();
    let parsedBody = null;
    let detail = '';
    if (bodyText) {
        try {
            parsedBody = JSON.parse(bodyText);
            detail = rawText(parsedBody?.message) || rawText(parsedBody?.error) || bodyText;
        } catch {
            detail = bodyText;
        }
    }
    const targetUrl = response.url || url || '';
    const message = publicHttpErrorMessage(response.status, detail);
    const error = new Error(message);
    error.status = response.status;
    error.targetUrl = targetUrl;
    error.detail = detail;
    error.body = parsedBody;
    error.code = rawText(parsedBody?.code) || rawText(parsedBody?.errorCode) || '';
    error.nextAction = rawText(parsedBody?.nextAction) || '';
    error.traceId = rawText(parsedBody?.traceId) || '';
    error.total = parsedBody?.total;
    throw error;
}

export async function fetchWithCsrf(url, options = {}) {
    return fetch(url, {
        ...options,
        credentials: options.credentials || 'same-origin',
        headers: enrichHeaders(url, options)
    });
}
