import { t } from './i18n.js';
import { badge, byId, element } from './ui.js';

export function renderVariation(variation) {
    byId('run-variation').hidden = !variation;
    if (!variation) return;
    byId('variation-parent').href = `/run.html?id=${variation.parentRunId}`;
    const changed = variation.conditions.filter(value => value.state === 'CHANGED');
    const unknown = variation.conditions.some(value => value.state === 'UNKNOWN');
    byId('variation-summary').replaceChildren(element('p', t(unknown ? 'variation.incomplete'
        : changed.length > 1 ? 'variation.multiple' : changed.length ? 'variation.one' : 'variation.none')));
    const names = [...new Set(changed.map(value => value.condition))];
    for (const name of names) byId('variation-summary').append(badge(t(`variation.${name}`), 'warning'));
    byId('variation-conditions').replaceChildren(...variation.conditions.map(value => {
        const row = element('p', null, 'small');
        const arm = value.arm === 'both' ? t('compare.all') : value.arm === 'baseline' ? t('connect.baseline') : 'Contexa';
        row.append(element('span', `${arm} · ${t(`variation.${value.condition}`)} · `), badge(t(`variation.${value.state}`)));
        return row;
    }));
}
