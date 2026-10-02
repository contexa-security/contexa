import { messages } from './messages.js';

let language = 'ko';
try { language = localStorage.getItem('contexa.lab.language') === 'en' ? 'en' : 'ko'; } catch { /* Preferences are optional. */ }

export function currentLanguage() { return language; }

export function t(key) {
    return messages[key]?.[language === 'en' ? 1 : 0] ?? key;
}

export function applyLanguage() {
    document.documentElement.lang = language;
    document.querySelectorAll('[data-i18n]').forEach(node => { node.textContent = t(node.dataset.i18n); });
    const title = document.body.dataset.title;
    if (title) document.title = `${t(title)} · Contexa Runtime Lab`;
    const button = document.querySelector('#language');
    if (button) {
        button.textContent = language === 'ko' ? 'EN' : '한국어';
        button.setAttribute('aria-label', language === 'ko' ? 'Switch to English' : '한국어로 변경');
    }
}

export function initializeLanguage() {
    applyLanguage();
    document.querySelector('#language')?.addEventListener('click', () => {
        language = language === 'ko' ? 'en' : 'ko';
        try { localStorage.setItem('contexa.lab.language', language); } catch { /* No persistent preference. */ }
        applyLanguage();
        document.dispatchEvent(new Event('lab:language'));
    });
}

export function dateTime(value) {
    if (!value || !Number.isFinite(Date.parse(value))) return t('unknown');
    return new Intl.DateTimeFormat(language === 'ko' ? 'ko-KR' : 'en-GB', {
        dateStyle: 'medium', timeStyle: 'medium'
    }).format(new Date(value));
}
