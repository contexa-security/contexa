import {api, checkName, dayEnd, dayStart, el, fillTable, number, pageRoot, periodOf, query, setStatus, settings, t,
    verdictChip}
    from './prompt-inspection-common.js';

const form = document.querySelector('[data-pi-period]');
const status = document.querySelector('[data-pi-status]');

function packagesLink(period, filter, label) {
    return el('a', {class: 'pi-link', href: pageRoot + '/packages' + query({...period, ...filter}), text: label});
}

function render(overview, period) {
    const verdicts = document.querySelector('[data-pi-verdicts]');
    verdicts.replaceChildren(...(settings.verdicts || []).map((verdict) => el('a', {
        class: 'pi-verdict-card',
        href: pageRoot + '/packages' + query({...period, verdict})
    }, [verdictChip(verdict), el('strong', {class: 'pi-verdict-count', text: number(overview.verdicts?.[verdict] ?? 0)})])));

    fillTable(document.querySelector('[data-pi-checks]'), (overview.checks || []).map((row) => el('tr', {}, [
        el('td', {}, packagesLink(period, {checkCode: row.checkCode}, checkName(row.checkCode))),
        el('td', {class: 'pi-number', text: number(row.mismatch)}),
        el('td', {class: 'pi-number', text: number(row.unverifiable)})
    ])), 3);

    fillTable(document.querySelector('[data-pi-entries]'), (overview.entries || []).map((row) => el('tr', {}, [
        el('td', {}, packagesLink(period, {block: row.block, entry: row.entry},
            [row.block, row.entry].filter(Boolean).join('.'))),
        el('td', {class: 'pi-number', text: number(row.mismatch)}),
        el('td', {class: 'pi-number', text: number(row.unverifiable)})
    ])), 3);

    fillTable(document.querySelector('[data-pi-resources]'), (overview.resources || []).map((row) => el('tr', {}, [
        el('td', {class: 'pi-code', text: row.resourceId}),
        el('td', {class: 'pi-number', text: number(row.packages)}),
        el('td', {class: 'pi-number', text: number(row.mismatch)})
    ])), 3);

    fillTable(document.querySelector('[data-pi-trend]'), (overview.trend || []).map((row) => el('tr', {}, [
        el('td', {text: row.day}),
        el('td', {text: checkName(row.checkCode)}),
        el('td', {class: 'pi-number', text: number(row.mismatch)}),
        el('td', {class: 'pi-number', text: number(row.unverifiable)})
    ])), 4);

    fillTable(document.querySelector('[data-pi-versions]'), (overview.versions || []).map((row) => el('tr', {}, [
        el('td', {class: 'pi-code', text: row.bundleVersion || '-'}),
        el('td', {class: 'pi-code', text: row.dictionaryVersion || '-'}),
        el('td', {class: 'pi-code', text: row.inspectorVersion || '-'}),
        el('td', {class: 'pi-number', text: number(row.packages)}),
        el('td', {class: 'pi-number', text: number(row.passed)}),
        el('td', {class: 'pi-number', text: number(row.failed)}),
        el('td', {class: 'pi-number', text: number(row.incomplete)}),
        el('td', {class: 'pi-number', text: number(row.notApplicable)}),
        el('td', {class: 'pi-number', text: number(row.errors)})
    ])), 9);
}

async function load() {
    const period = periodOf(new URLSearchParams(window.location.search));
    form.elements.from.value = period.from;
    form.elements.to.value = period.to;
    setStatus(status, t('promptInspection.common.loading'));
    try {
        const overview = await api('/overview' + query({from: dayStart(period.from), to: dayEnd(period.to)}));
        render(overview, period);
        setStatus(status, '');
    } catch (error) {
        setStatus(status, t('promptInspection.common.error'), 'error');
    }
}

form.addEventListener('submit', (event) => {
    event.preventDefault();
    window.location.search = query({from: form.elements.from.value, to: form.elements.to.value});
});

load();
