import './shell.js';
import { currentLanguage, t } from './i18n.js';
import { localLink, request } from './http.js';
import { badge, byId, element, errorText, notice } from './ui.js';
import { rememberWorkPage } from './work-navigation.js';
import { resetSecurityFeedback, showSecurityFeedback } from './security-feedback.js';
import { bindWorkFormOptions } from './work-form-options.js';

export const translated = value => value?.[currentLanguage()] || '';
export const query = new URLSearchParams(location.search);

export function showEnvironment(role) {
    const label = badge(t(role), role === 'contexa' ? 'good' : '');
    label.dataset.i18n = role;
    byId('environment').replaceChildren(label);
}

export async function initializeWork() {
    const identity = await request('/api/lab/identity');
    showEnvironment(identity.role);
    byId('work-username').textContent = identity.username || t('disconnected');
    byId('connect-link').href = localLink('/connect.html', identity.portalUrl);
    if (!byId('experience-link')) {
        const guide = element('a', t('about'), 'header-link');
        guide.id = 'experience-link';
        guide.dataset.i18n = 'about';
        guide.href = localLink('/experience.html', identity.portalUrl);
        byId('connect-link').before(guide);
    }
    if (!identity.authenticated || !['baseline', 'contexa'].includes(identity.role)) {
        throw new Error('BUSINESS_LOGIN_REQUIRED');
    }
    rememberWorkPage(identity.username);
    bindWorkFormOptions(identity.username);
    return identity;
}

export function showWorkError(error) {
    resetSecurityFeedback();
    if (error?.data?.code === 'WORK_APPROVAL_UNUSABLE') {
        notice(byId('feedback'), `${t('approval.work.rejected')} ${t(`approval.status.${error.data.approvalStatus}`)}`, 'warning');
        return false;
    }
    if (showSecurityFeedback(error?.data)) return true;
    if (error?.status === 404) {
        notice(byId('feedback'), t('work.unavailable.here'), 'warning');
        const explanation = element('p', t('work.unavailable.here'));
        explanation.dataset.i18n = 'work.unavailable.here';
        byId('feedback').replaceChildren(explanation);
        const original = byId('breadcrumb')?.querySelector('a');
        if (original) {
            const link = element('a', t('work.reopen.list'), 'button secondary compact');
            link.href = original.href;
            link.dataset.i18n = 'work.reopen.list';
            const actions = element('div', undefined, 'actions');
            actions.append(link);
            byId('feedback').append(actions);
        }
        return false;
    }
    notice(byId('feedback'), errorText(error), 'danger');
    byId('recovery').hidden = false;
    return false;
}

export function countLabel(count) {
    return t('work.count').replace('{n}', String(count));
}
