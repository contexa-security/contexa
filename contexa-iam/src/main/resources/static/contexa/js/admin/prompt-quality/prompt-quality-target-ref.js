import { ensureArray, rawText } from '../verification-ui-common.js';

export function targetRefToken() {
    if (typeof window === 'undefined' || !window.location) {
        return '';
    }
    return rawText(new URLSearchParams(window.location.search || '').get('targetRef')) || '';
}

export function targetRefMatches(item, fields, token = targetRefToken()) {
    const normalizedToken = normalize(token);
    if (!normalizedToken || !item) {
        return false;
    }
    return ensureArray(fields).some(field => {
        const value = normalize(item[field]);
        return value && (value.includes(normalizedToken) || normalizedToken.includes(value));
    });
}

export function focusHighlightedRow(root) {
    requestAnimationFrame(() => {
        const row = root?.querySelector?.('.pqa-row-highlight');
        if (row && typeof row.scrollIntoView === 'function') {
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    });
}

export function normalize(value) {
    return rawText(value)?.toLowerCase() || '';
}
