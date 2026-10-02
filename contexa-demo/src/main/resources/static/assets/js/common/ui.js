import { t } from './i18n.js';
import { ApiError } from './http.js';

export const byId = id => document.getElementById(id);

export function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    if (className) node.className = className;
    return node;
}

export function notice(target, message = '', tone = '') {
    target.textContent = message;
    target.className = `notice feedback ${tone}`;
    target.hidden = !message;
}

export function errorText(error) {
    if (!(error instanceof ApiError)) return t('error.network');
    const key = `error.${error.data?.state}`;
    const translated = t(key);
    return translated === key ? t('error.generic') : translated;
}

export function errorNotice(target, error) {
    const candidate = error instanceof ApiError ? `error.${error.data?.state}` : 'error.network';
    const key = t(candidate) === candidate ? 'error.generic' : candidate;
    notice(target, t(key), 'warning');
    const message = element('span', t(key));
    message.dataset.i18n = key;
    target.replaceChildren(message);
    if (error instanceof ApiError && error.data?.state === 'EMAIL_VERIFICATION_REQUIRED') {
        const link = element('a', t('entry.return'), 'button secondary compact');
        link.dataset.i18n = 'entry.return';
        link.href = '/entry.html';
        const actions = element('div', null, 'actions');
        actions.append(link);
        target.append(actions);
    }
}

export function badge(label, tone = '') { return element('span', label, `badge ${tone}`); }

export async function busy(button, work) {
    if (button.disabled) return;
    const previous = button.textContent;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    button.textContent = t('working');
    try { return await work(); }
    finally {
        button.disabled = false;
        button.removeAttribute('aria-busy');
        button.textContent = previous;
    }
}

export function appendDefinition(target, label, value) {
    const row = element('div');
    row.append(element('dt', label), element('dd', value || t('none')));
    target.append(row);
}
