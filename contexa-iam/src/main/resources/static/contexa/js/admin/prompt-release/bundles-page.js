import {buildChip, detailHref, el, fillTable, formatTime, gateChip, query, read, scopeText, setStatus, settings,
    shortHash, stateChip, t}
    from './prompt-release-common.js';

const form = document.querySelector('[data-pr-filters]');
const status = document.querySelector('[data-pr-status]');
const table = document.querySelector('[data-pr-bundles]');

/** The gate's answer for the transitions the screens offer; nothing else decides 'ready' (PV-8). */
function gateCell(row) {
    if (!row.gateRead) {
        return el('span', {class: 'pi-chip pi-chip-unverifiable', text: t('promptRelease.gate.unavailable')});
    }
    const offered = (row.gate || []).filter((target) => (settings.actions || []).includes(target.targetState));
    if (!offered.length) {
        return el('span', {class: 'pi-note', text: t('promptRelease.gate.none')});
    }
    return el('div', {class: 'pr-chips'}, offered.map(gateChip));
}

function line(row) {
    return el('tr', {'data-pr-bundle': row.bundleVersion}, [
        el('td', {class: 'pi-code', text: scopeText(row)}),
        el('td', {class: 'pi-code', text: row.promptKey}),
        el('td', {}, el('a', {class: 'pi-link pi-code', href: detailHref(row.registryScope, row.promptKey,
            row.bundleVersion), text: row.bundleVersion})),
        el('td', {class: 'pi-code', title: row.bundleHash || '', text: shortHash(row.bundleHash)}),
        el('td', {}, stateChip(row.state, row.unknownStatus)),
        el('td', {}, buildChip(row)),
        el('td', {}, gateCell(row)),
        el('td', {text: formatTime(row.updatedAt)})
    ]);
}

async function load() {
    const params = new URLSearchParams(window.location.search);
    form.elements.registryScope.value = params.get('registryScope') || '';
    setStatus(status, t('promptRelease.common.loading'));
    try {
        const rows = await read('/bundles' + query({registryScope: params.get('registryScope')}));
        fillTable(table, rows.map(line), 8);
        setStatus(status, '');
    } catch (error) {
        setStatus(status, t('promptRelease.common.error'), 'error');
    }
}

form.addEventListener('submit', (event) => {
    event.preventDefault();
    window.location.search = query({registryScope: form.elements.registryScope.value});
});

document.querySelector('[data-pr-reset]').addEventListener('click', () => {
    window.location.search = '';
});

load();
