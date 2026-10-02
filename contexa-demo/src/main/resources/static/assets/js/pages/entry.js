import '../common/shell.js';
import { currentLanguage, dateTime, t } from '../common/i18n.js';
import { ApiError, localLink, request } from '../common/http.js';
import { busy, byId, errorText, notice } from '../common/ui.js';

let session;
let pendingRequest;
let submitting = false;
const feedback = byId('feedback');

function render() {
    byId('entry-loading').hidden = true;
    byId('entry-panel').removeAttribute('aria-busy');
    const showCode = Boolean(session?.pending) && session.pending.state !== 'FAILED';
    byId('entry-request').hidden = session?.state === 'VERIFIED' || showCode;
    byId('entry-code').hidden = !showCode || session.state === 'VERIFIED';
    byId('entry-verified').hidden = session?.state !== 'VERIFIED';
    byId('entry-recovery').hidden = Boolean(session?.mailConfigured) && session?.pending?.state !== 'SENDING';
    byId('request-button').disabled = !session?.mailConfigured;
    if (session?.pending) {
        byId('code-expiry').textContent = `${t('entry.expiry')}: ${dateTime(session.pending.expiresAt)}`;
        byId('retry-time').textContent = `${t('entry.retry')}: ${dateTime(session.pending.retryAt)}`;
        byId('verify-button').disabled = session.pending.state !== 'SENT';
    }
    if (!session?.mailConfigured && session?.state !== 'VERIFIED') {
        notice(feedback, t('entry.unconfigured'), 'warning');
    } else if (session?.pending && !['SENT', 'SENDING'].includes(session.pending.state)) {
        notice(feedback, errorText(new ApiError(409, { state: session.pending.state })), 'warning');
    }
}

async function refresh() {
    try {
        const location = await request('/api/lab/entry/location');
        if (location.role !== 'portal') {
            window.location.replace(localLink('/entry.html', location.portalUrl));
            return;
        }
        session = await request('/api/lab/entry/session');
        notice(feedback);
        render();
    } catch (error) {
        byId('entry-loading').hidden = true;
        byId('entry-panel').removeAttribute('aria-busy');
        byId('entry-recovery').hidden = false;
        notice(feedback, errorText(error), 'danger');
    }
}

async function sendCode(button, newRequest) {
    if (submitting) return;
    if (!byId('email').value || !byId('email').checkValidity()) {
        session = { ...session, pending: null };
        render();
        byId('email').focus();
        byId('email').reportValidity();
        return;
    }
    submitting = true;
    await busy(button, async () => {
        const email = byId('email').value.trim();
        if (newRequest || !pendingRequest || pendingRequest.email !== email) {
            pendingRequest = { requestId: crypto.randomUUID(), email };
        }
        try {
            const result = await request('/api/lab/entry/requests', {
                method: 'POST', body: { ...pendingRequest, language: currentLanguage() }
            });
            session = await request('/api/lab/entry/session');
            render();
            notice(feedback, t(result.state === 'SENT' ? 'entry.sent' : 'entry.sending'));
            byId('code').focus();
        } catch (error) {
            notice(feedback, errorText(error), 'danger');
            if (error instanceof ApiError && error.data?.state !== 'RESEND_TOO_SOON') pendingRequest = null;
        } finally { submitting = false; }
    });
}

byId('request-form').addEventListener('submit', event => {
    event.preventDefault();
    void sendCode(byId('request-button'), false);
});

byId('verify-form').addEventListener('submit', event => {
    event.preventDefault();
    if (submitting || !session?.pending) return;
    submitting = true;
    void busy(byId('verify-button'), async () => {
        try {
            await request('/api/lab/entry/verify', {
                method: 'POST', body: { requestId: session.pending.requestId, code: byId('code').value.trim() }
            });
            byId('code').value = '';
            await refresh();
            byId('entry-verified').querySelector('a').focus();
        } catch (error) {
            if (['EXPIRED', 'LOCKED', 'CONSUMED', 'SUPERSEDED'].includes(error.data?.state)) {
                await refresh();
            }
            notice(feedback, errorText(error), 'danger');
            byId('code').select();
        } finally { submitting = false; }
    }).finally(render);
});

byId('resend-button').addEventListener('click', () => void sendCode(byId('resend-button'), true));
byId('change-email').addEventListener('click', () => {
    if (submitting) return;
    session = { ...session, pending: null };
    pendingRequest = null;
    byId('code').value = '';
    render();
    notice(feedback);
    byId('email').focus();
});
byId('entry-refresh').addEventListener('click', () => void busy(byId('entry-refresh'), refresh));
document.addEventListener('lab:language', () => { if (session) render(); });
void refresh();
