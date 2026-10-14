// Shared helpers of the prompt inspection screens. Every text taken from a sealed prompt or a finding is set as
// text content, never as markup.

const pageElement = document.querySelector('[data-pi-page]');

export const apiRoot = pageElement?.dataset.apiRoot || '/contexa/admin/api/prompt-inspection';
export const pageRoot = pageElement?.dataset.pageRoot || '/contexa/admin/prompt-inspection';

const words = (() => {
    try {
        return JSON.parse(document.getElementById('prompt-inspection-messages')?.textContent || '{}');
    } catch (error) {
        return {};
    }
})();

/** The screens' lists and defaults as the server keeps them (verdict order, chip tones, period days, page size). */
export const settings = (() => {
    try {
        return JSON.parse(document.getElementById('prompt-inspection-settings')?.textContent || '{}');
    } catch (error) {
        return {};
    }
})();

/** The word of the key in the reader's language, with {0}, {1}… filled in. */
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

/** Calls the inspection API; a failed call throws an error carrying its HTTP status. */
export async function api(path, options = {}) {
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
    if (!response.ok) {
        const error = new Error(`HTTP ${response.status}`);
        error.status = response.status;
        throw error;
    }
    return response.json();
}

/** An element with its attributes and children; strings become text nodes. */
export function el(tag, attributes = {}, children = []) {
    const element = document.createElement(tag);
    Object.entries(attributes).forEach(([name, value]) => {
        if (value === null || value === undefined || value === false) {
            return;
        }
        if (name === 'class') {
            element.className = value;
        } else if (name === 'text') {
            element.textContent = value;
        } else if (name.startsWith('on') && typeof value === 'function') {
            element.addEventListener(name.slice(2), value);
        } else {
            element.setAttribute(name, value === true ? '' : String(value));
        }
    });
    (Array.isArray(children) ? children : [children]).forEach((child) => {
        if (child === null || child === undefined) {
            return;
        }
        element.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
    return element;
}

export function verdictChip(verdict) {
    const value = verdict || settings.notInspected;
    return el('span', {class: `pi-chip pi-chip-${settings.tones?.[value] || 'neutral'}`,
        text: t(`promptInspection.verdict.${value}`)});
}

export function outcomeChip(outcome) {
    return el('span', {class: `pi-chip pi-chip-${String(outcome).toLowerCase()}`,
        text: t(`promptInspection.outcome.${outcome}`)});
}

export function checkName(code) {
    return t(`promptInspection.check.${code}`);
}

export function formatTime(value) {
    if (!value) {
        return '-';
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

/** The local calendar date of a date, as an input of type date reads it. */
export function localDate(date) {
    const pad = (number) => String(number).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** The instant a local calendar date starts. */
export function dayStart(value) {
    return value ? new Date(`${value}T00:00:00`).toISOString() : null;
}

/** The last instant of a local calendar date. */
export function dayEnd(value) {
    return value ? new Date(`${value}T23:59:59.999`).toISOString() : null;
}

/** The period of the page address; when none is given, the server's default number of days up to today. */
export function periodOf(params) {
    const today = new Date();
    const first = new Date(today);
    first.setDate(today.getDate() - (Number(settings.periodDays) || 1) + 1);
    return {
        from: params.get('from') || localDate(first),
        to: params.get('to') || localDate(today)
    };
}

export function query(values) {
    const params = new URLSearchParams();
    Object.entries(values).forEach(([name, value]) => {
        if (value !== null && value !== undefined && String(value).trim() !== '') {
            params.set(name, String(value).trim());
        }
    });
    const text = params.toString();
    return text ? `?${text}` : '';
}

export function setStatus(node, text, kind = 'info') {
    if (!node) {
        return;
    }
    node.textContent = text || '';
    node.dataset.kind = kind;
}

export function fillTable(table, rows, emptyColumns) {
    const body = table.querySelector('tbody');
    body.replaceChildren();
    if (!rows.length) {
        body.append(el('tr', {}, el('td', {class: 'pi-empty', colspan: emptyColumns, text: t('promptInspection.common.empty')})));
        return;
    }
    rows.forEach((row) => body.append(row));
}

export function number(value) {
    return value === null || value === undefined ? '-' : Number(value).toLocaleString();
}
