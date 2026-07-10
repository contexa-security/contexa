import { getJson } from './prompt-quality-api.js';

const CORE_BUNDLE_ENDPOINT = '/contexa/admin/api/prompt-quality/i18n';
const ENTERPRISE_BUNDLE_ENDPOINT = '/contexa/admin/api/enterprise/prompt-quality/i18n';
const DEFAULT_MISSING_LABEL = '-';
const MISSING_LABEL_KEY = 'enterprise.pqa.common.missingLabel';
const I18N_DEBUG_ACTIVE = typeof window !== 'undefined' && window.location
        ? /[?&]pqa(Debug|I18nDebug)=1/.test(window.location.search)
        : false;

let bundlePromise = null;
let bundleCache = {};

export async function ensureBundle() {
    if (!bundlePromise) {
        bundlePromise = getJson(cacheBust(bundleEndpoint()))
                .then(payload => {
                    bundleCache = payload && payload.messages ? payload.messages : {};
                    return bundleCache;
                })
                .catch(error => {
                    bundlePromise = null;
                    throw error;
                });
    }
    return bundlePromise;
}


function bundleEndpoint() {
    if (typeof window !== 'undefined' && window.location) {
        const path = window.location.pathname || '';
        if (path.includes('/contexa/admin/enterprise/prompt-quality')) {
            return ENTERPRISE_BUNDLE_ENDPOINT;
        }
    }
    return CORE_BUNDLE_ENDPOINT;
}

function cacheBust(endpoint) {
    const separator = endpoint.includes('?') ? '&' : '?';
    return `${endpoint}${separator}_=${Date.now()}`;
}

export function t(key, ...args) {
    const raw = bundleCache[key];
    if (!raw) {
        return resolveMissing(key);
    }
    return format(raw, args);
}

export function has(key) {
    return Object.prototype.hasOwnProperty.call(bundleCache, key);
}

function resolveMissing(key) {
    if (typeof console !== 'undefined' && console.error) {
        console.error('[i18n] missing bundle key: ' + key);
    }
    if (I18N_DEBUG_ACTIVE) {
        return '[MISSING] ' + humanize(key);
    }
    const fallback = bundleCache[MISSING_LABEL_KEY];
    return fallback || DEFAULT_MISSING_LABEL;
}

function format(template, args) {
    if (!args || !args.length) {
        return template;
    }
    return template.replace(/\{(\d+)\}/g, (match, index) => {
        const value = args[Number(index)];
        return value === undefined || value === null ? match : String(value);
    });
}

function humanize(key) {
    if (typeof key !== 'string' || !key) {
        return '';
    }
    const segments = key.split('.');
    const last = segments[segments.length - 1] || key;
    const spaced = last
            .replace(/([a-z])([A-Z])/g, '$1 $2')
            .replace(/[_-]+/g, ' ')
            .trim();
    if (!spaced) {
        return '';
    }
    return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}
