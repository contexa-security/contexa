import { t } from './i18n.js';
import { localLink } from './http.js';
import { byId, element } from './ui.js';

const states = {
    MFA_CHALLENGE_REQUIRED: { name: 'verify', verification: true },
    BLOCK_MFA_REQUIRED: { name: 'blockVerify', verification: true },
    ACCOUNT_BLOCKED: { name: 'blocked' },
    SECURITY_REVIEW_IN_PROGRESS: { name: 'review' },
    ZERO_TRUST_CHALLENGE: { name: 'verify', recheck: true },
    ZERO_TRUST_BLOCK: { name: 'blocked', recheck: true },
    ZERO_TRUST_ESCALATE: { name: 'review', recheck: true },
    ZERO_TRUST_PENDING_ANALYSIS: { name: 'pending', recheck: true }
};

export function isSecurityResponse(data) {
    return Object.hasOwn(states, data?.error) || Object.hasOwn(states, data?.code);
}

export function securityContinuation(data, origin = location.origin, returnPath = location.pathname + location.search) {
    const state = Object.hasOwn(states, data?.error) ? states[data.error]
        : Object.hasOwn(states, data?.code) ? states[data.code] : null;
    if (!state) return null;
    const labelKey = state.recheck ? 'security.recheck' : state.verification ? 'work.mfa.continue' : 'work.security.notice';
    const target = state.verification ? data.challengeNoticeUrl || data.mfaUrl : data.redirectUrl;
    let href;
    try {
        if (state.recheck) href = localLink(returnPath, origin);
        else if (typeof target === 'string') {
            const url = new URL(localLink(target, origin));
            if (url.pathname.startsWith('/contexa/zero-trust/') || url.pathname.startsWith('/mfa/')) href = url.href;
        }
    } catch { /* Use only an existing native continuation on the configured arm origin. */ }
    return { name: state.name, labelKey, href };
}

function copy(tag, key, className) {
    const node = element(tag, t(key), className);
    node.dataset.i18n = key;
    return node;
}

export function resetSecurityFeedback() {
    const recovery = byId('recovery');
    recovery.hidden = true;
    recovery.classList.remove('security-recovery');
    const link = byId('native-verification');
    link.hidden = true;
    link.removeAttribute('href');
    recovery.querySelector('a[href="/session.html"]').hidden = false;
    byId('connect-link').hidden = false;
}

export function showSecurityFeedback(data) {
    const state = Object.hasOwn(states, data?.error) ? states[data.error]
        : Object.hasOwn(states, data?.code) ? states[data.code] : null;
    if (!state) return false;
    const panel = byId('feedback');
    panel.hidden = false;
    panel.className = `security-feedback security-feedback-${state.name}`;
    const symbol = element('span', undefined, 'security-symbol');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.classList.add('icon');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `/assets/icons.svg#${state.name === 'review' ? 'refresh' : 'lock'}`);
    svg.append(use);
    symbol.append(svg);
    const content = element('div', undefined, 'security-content');
    content.append(copy('p', 'security.label', 'security-label'),
        copy('h2', `security.${state.name}.title`), copy('p', `security.${state.name}.body`),
        copy('p', state.recheck ? 'security.recheck.next' : `security.${state.name}.next`, 'security-next'));
    panel.replaceChildren(symbol, content);

    const recovery = byId('recovery');
    recovery.hidden = false;
    recovery.classList.add('security-recovery');
    recovery.querySelector('a[href="/session.html"]').hidden = true;
    byId('connect-link').hidden = true;
    const link = byId('native-verification');
    const continuation = securityContinuation(data);
    link.dataset.i18n = continuation.labelKey;
    link.textContent = t(continuation.labelKey);
    if (continuation.href) { link.href = continuation.href; link.hidden = false; }
    if (link.hidden) {
        content.append(copy('p', 'security.link.unavailable', 'security-next'));
        recovery.hidden = true;
    }
    panel.tabIndex = -1;
    panel.focus({ preventScroll: false });
    return true;
}
