import { t } from './i18n.js';
import { badge, byId, element } from './ui.js';

let prepared;
let pair;

function render() {
    const confirmed = pair?.initialConditionsMatch === true;
    const stage = !prepared ? 1 : confirmed ? 3 : 2;
    for (const item of document.querySelectorAll('[data-comparison-step]')) {
        const step = Number(item.dataset.comparisonStep);
        item.classList.toggle('is-complete', step < stage);
        item.classList.toggle('is-current', step === stage);
        if (step === stage) item.setAttribute('aria-current', 'step');
        else item.removeAttribute('aria-current');
    }
    byId('execution-state').replaceChildren(badge(t(confirmed ? 'compare.flow.confirmed'
        : pair ? 'compare.flow.attention' : 'compare.flow.unchecked'), confirmed ? 'good' : 'warning'));
    byId('comparison-next').textContent = t(!prepared ? 'compare.flow.select'
        : confirmed ? 'compare.flow.next' : pair ? 'compare.flow.resolve' : 'compare.flow.verify');
    byId('comparison-arms').replaceChildren(...['baseline', 'contexa'].map(arm => {
        const record = pair?.attestations?.find(value => value.arm === arm);
        const checks = pair?.blockers?.filter(value => value.arm === arm || value.arm === 'comparison') || [];
        const state = !record ? 'compare.flow.unchecked' : checks.length ? 'compare.flow.attention' : 'compare.flow.confirmed';
        const section = element('section', null, `comparison-environment ${arm}`);
        const heading = element('div', null, 'environment-heading');
        heading.append(element('h3', arm === 'baseline' ? t('connect.baseline') : 'Contexa'),
            badge(t(state), state === 'compare.flow.confirmed' ? 'good' : ''));
        section.append(heading, element('p', t(arm === 'baseline' ? 'compare.baseline.role' : 'compare.contexa.role'), 'small muted'));
        if (record) section.append(element('p', `${t('sessions.account')} · ${record.snapshot.identity.username || t('unknown')}`, 'environment-account'));
        return section;
    }));
}

export function setComparisonFlow(value) {
    if (prepared?.id !== value?.id) pair = null;
    prepared = value;
    render();
}

document.addEventListener('lab:comparison-pair', event => {
    pair = event.detail?.preparationId === prepared?.id ? event.detail : null;
    render();
});
document.addEventListener('lab:language', render);
