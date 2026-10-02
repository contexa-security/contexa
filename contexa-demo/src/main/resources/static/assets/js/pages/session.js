import '../common/shell.js';
import { t } from '../common/i18n.js';
import { localLink, nativeLogout, request } from '../common/http.js';
import { appendDefinition, badge, busy, byId, errorText, notice } from '../common/ui.js';
import { previousWorkPage } from '../common/work-navigation.js';

let identity;

function render() {
    if (!identity) return;
    const pending = identity.authenticationProgress?.resumeUrl;
    byId('session-badge').replaceChildren(badge(t(pending ? 'additional' : identity.authenticated ? 'connected' : 'disconnected'),
        pending ? 'warning' : identity.authenticated ? 'good' : ''));
    const details = byId('session-details');
    details.replaceChildren();
    appendDefinition(details, t('connect.environment'), t(identity.role));
    appendDefinition(details, t('connect.user'), identity.username);
    appendDefinition(details, t('session.roles'), identity.accountAuthorities?.join(', ') || t('unknown'));
    appendDefinition(details, t('session.effectiveRoles'), identity.authorities.join(', '));
    appendDefinition(details, t('session.type'), identity.authenticationType);
    byId('signin').hidden = identity.authenticated || Boolean(pending);
    byId('signin').href = localLink(identity.loginUrl);
    byId('logout').hidden = !identity.authenticated;
    byId('work-start').hidden = !identity.authenticated || Boolean(pending) || !['baseline', 'contexa'].includes(identity.role);
    const previous = previousWorkPage(identity.username);
    byId('work-start').href = localLink(previous || '/projects.html');
    byId('resume').hidden = !pending;
    if (pending) byId('resume').href = localLink(pending);
    byId('portal-return').href = localLink('/connect.html', identity.portalUrl);
}

byId('logout').addEventListener('click', () => void busy(byId('logout'), async () => {
    try { await nativeLogout(); }
    catch (error) { notice(byId('feedback'), errorText(error), 'danger'); }
}));
document.addEventListener('lab:language', render);
try { identity = await request('/api/lab/identity'); render(); }
catch (error) { notice(byId('feedback'), errorText(error), 'danger'); }
