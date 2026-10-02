import '../common/shell.js';
import { t } from '../common/i18n.js';
import { localLink, request } from '../common/http.js';
import { badge, busy, byId, element, errorText, notice } from '../common/ui.js';

let connections = [];

function render() {
    byId('accounts').replaceChildren();
    for (const connection of connections) {
        const row = element('tr');
        const environment = element('td');
        environment.append(element('strong', connection.role === 'contexa' ? 'Contexa' : t('connect.baseline')),
            element('span', t(`connect.${connection.role}.detail`), 'subtext'));
        const state = element('td');
        const user = element('td');
        const action = element('td');
        const identity = connection.identity;
        if (identity) {
            const pending = Boolean(identity.authenticationProgress?.resumeUrl);
            state.append(badge(t(pending ? 'additional' : identity.authenticated ? 'connected' : 'disconnected'),
                pending ? 'warning' : identity.authenticated ? 'good' : ''));
            user.append(element('strong', identity.username || '—'),
                element('span', identity.accountAuthorities?.join(', ') || (identity.authenticated ? t('unknown') : '—'), 'subtext role-list'));
            const link = element('a', t(identity.authenticated ? 'connect.inspect' : 'connect.signin'), 'button secondary compact');
            link.href = localLink(identity.authenticated ? '/session.html' : identity.loginUrl, connection.origin);
            action.append(link);
        } else {
            state.append(badge(t('unreachable'), 'danger'));
            user.textContent = '—';
            action.textContent = t('refresh');
        }
        row.append(environment, state, user, action);
        byId('accounts').append(row);
    }
    byId('loading').hidden = true;
    const identities = connections.map(value => value.identity);
    if (identities.length === 2 && identities.every(value => value?.authenticated && !value.authenticationProgress?.resumeUrl)) {
        const [first, second] = identities;
        const known = Array.isArray(first.accountAuthorities) && Array.isArray(second.accountAuthorities);
        const matching = known && first.username === second.username
            && JSON.stringify(first.accountAuthorities) === JSON.stringify(second.accountAuthorities)
            && first.staticPolicySha256 === second.staticPolicySha256;
        notice(byId('feedback'), t(!known ? 'connect.unverified' : matching ? 'connect.matched' : 'connect.mismatch'), matching ? '' : 'warning');
    } else {
        notice(byId('feedback'), t('connect.pending'));
    }
}

async function refresh() {
    try {
        const entry = await request('/api/lab/entry/session');
        if (entry.state !== 'VERIFIED') { location.assign('/entry.html'); return; }
        await request('/api/lab/workspaces', { method: 'POST' });
        const configuration = await request('/api/lab/identity');
        connections = await Promise.all(['baseline', 'contexa'].map(async role => {
            const origin = configuration[`${role}Url`];
            try { return { role, origin, identity: await request('/api/lab/identity', { origin }) }; }
            catch { return { role, origin, identity: null }; }
        }));
        render();
    } catch (error) {
        byId('loading').hidden = true;
        notice(byId('feedback'), errorText(error), 'danger');
    }
}

byId('refresh').addEventListener('click', () => void busy(byId('refresh'), refresh));
document.addEventListener('lab:language', render);
void refresh();
