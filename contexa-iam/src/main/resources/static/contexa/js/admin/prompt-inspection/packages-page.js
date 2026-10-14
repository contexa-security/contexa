import {api, dayEnd, dayStart, el, fillTable, formatTime, number, pageRoot, periodOf, query, setStatus, settings, t,
    verdictChip}
    from './prompt-inspection-common.js';

const form = document.querySelector('[data-pi-filters]');
const status = document.querySelector('[data-pi-status]');
const total = document.querySelector('[data-pi-total]');
const previous = document.querySelector('[data-pi-previous]');
const next = document.querySelector('[data-pi-next]');
const FILTERS = ['verdict', 'checkCode', 'block', 'entry'];
const PAGE_SIZE = Number(settings.pageSize) || 1;

function currentState() {
    const params = new URLSearchParams(window.location.search);
    const state = {...periodOf(params), page: Number(params.get('page') || 0)};
    FILTERS.forEach((name) => {
        state[name] = params.get(name) || '';
    });
    return state;
}

function go(state) {
    const {page, ...rest} = state;
    window.location.search = query({...rest, page: page > 0 ? page : null});
}

function row(item) {
    const link = el('a', {class: 'pi-link pi-code', href: `${pageRoot}/packages/${encodeURIComponent(item.packageId)}`,
        text: item.packageId});
    return el('tr', {}, [
        el('td', {text: formatTime(item.capturedAt)}),
        el('td', {}, link),
        el('td', {text: item.userId || '-'}),
        el('td', {class: 'pi-code', text: [item.httpMethod, item.requestPath].filter(Boolean).join(' ') || '-'}),
        el('td', {}, verdictChip(item.verdict)),
        el('td', {class: 'pi-number', text: number(item.mismatchCount)}),
        el('td', {class: 'pi-number', text: number(item.unverifiableCount)}),
        el('td', {class: 'pi-code', text: item.inspectorVersion || '-'}),
        el('td', {text: formatTime(item.inspectedAt)})
    ]);
}

async function load() {
    const state = currentState();
    form.elements.from.value = state.from;
    form.elements.to.value = state.to;
    FILTERS.forEach((name) => {
        form.elements[name].value = state[name];
    });
    setStatus(status, t('promptInspection.common.loading'));
    try {
        const page = await api('/packages' + query({
            from: dayStart(state.from), to: dayEnd(state.to), verdict: state.verdict, checkCode: state.checkCode,
            block: state.block, entry: state.entry, page: state.page, size: PAGE_SIZE
        }));
        fillTable(document.querySelector('[data-pi-packages]'), page.rows.map(row), 9);
        total.textContent = t('promptInspection.packages.total', number(page.total));
        previous.disabled = state.page <= 0;
        next.disabled = (state.page + 1) * PAGE_SIZE >= page.total;
        setStatus(status, '');
    } catch (error) {
        setStatus(status, t('promptInspection.common.error'), 'error');
    }
}

// R1b-6: the automatic round inspects the period again; its progress is how many of the period's packages are left.
async function followPeriod(period, requested) {
    setStatus(status, t('promptInspection.reinspect.started', number(requested.uninspected)));
    let current = requested;
    while (current.uninspected > 0) {
        await new Promise((resolve) => window.setTimeout(resolve, 5000));
        current = await api('/reinspections' + query(period));
        if (current.uninspected > 0) {
            setStatus(status, t('promptInspection.reinspect.progress', number(current.uninspected),
                number(current.packages)));
        }
    }
    setStatus(status, t('promptInspection.reinspect.done', number(current.packages)), 'done');
    await load();
    setStatus(status, t('promptInspection.reinspect.done', number(current.packages)), 'done');
}

form.addEventListener('submit', (event) => {
    event.preventDefault();
    const state = {from: form.elements.from.value, to: form.elements.to.value, page: 0};
    FILTERS.forEach((name) => {
        state[name] = form.elements[name].value;
    });
    go(state);
});

document.querySelector('[data-pi-reset]').addEventListener('click', () => {
    window.location.search = '';
});

document.querySelector('[data-pi-reinspect-period]').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
        const period = {from: dayStart(form.elements.from.value), to: dayEnd(form.elements.to.value)};
        const requested = await api('/reinspections', {method: 'POST', body: period});
        await followPeriod(period, requested);
    } catch (error) {
        setStatus(status, t('promptInspection.reinspect.failed'), 'error');
    } finally {
        button.disabled = false;
    }
});

previous.addEventListener('click', () => go({...currentState(), page: currentState().page - 1}));
next.addEventListener('click', () => go({...currentState(), page: currentState().page + 1}));

load();
