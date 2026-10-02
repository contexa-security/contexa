import { currentLanguage, t } from './i18n.js';
import { badge, element } from './ui.js';

const failures = new Set(['MISSING', 'UNAVAILABLE', 'INVALID_CONFIGURATION', 'ENFORCEMENT_DISABLED',
    'SOURCE_CHANGED', 'BASELINE_CHANGED', 'FAILED']);

export function classification(state) {
    if (state === 'READY' || state === 'MATCHED') return { key: 'ready', tone: 'good', group: 0 };
    if (state === 'CONFIGURED_UNVERIFIED') return { key: 'configured', tone: '', group: 1 };
    if (state === 'NOT_IMPLEMENTED') return { key: 'notImplemented', tone: 'warning', group: 3 };
    if (state === 'NOT_APPLICABLE') return { key: 'notApplicable', tone: '', group: 3 };
    return { key: failures.has(state) ? 'missing' : 'unknown', tone: 'danger', group: 2 };
}

export function stateBadge(state) {
    const view = classification(state);
    return badge(t(view.key), view.tone);
}

export function groups(report) {
    return [{ role: report.role, report, state: 'REACHABLE' }, ...(report.workers || [])];
}

export function localReady(report) {
    return Boolean(report?.checks?.length) && !report.checks.some(check => classification(check.state).group === 2);
}

export function renderChecks(target, report) {
    target.replaceChildren();
    for (const group of groups(report)) {
        const section = element('section', null, 'surface check-group');
        const heading = element('div', null, 'surface-head');
        heading.append(element('h2', t(group.role)));
        section.append(heading);
        const list = element('ul', null, 'check-list');
        for (const check of group.report?.checks || [{ component: group.role, state: 'UNAVAILABLE' }]) {
            const item = element('li', null, 'check-row');
            const label = element('div', null, 'check-label');
            label.append(element('span', t(check.component)), stateBadge(check.state));
            item.append(label);
            if (check.detail && currentLanguage() === 'ko') item.append(element('p', check.detail));
            if (check.observed !== null && check.observed !== undefined) {
                const details = element('details');
                details.append(element('summary', t('operator.observed')),
                    element('pre', JSON.stringify(check.observed, null, 2)));
                item.append(details);
            }
            list.append(item);
        }
        section.append(list);
        target.append(section);
    }
}
