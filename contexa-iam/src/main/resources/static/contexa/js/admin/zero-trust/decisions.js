/*
 * Zero Trust console, decision records (console design 6.4, the list): "why was this decision made?". The decisions of
 * the period read by time with an opaque cursor, filtered by the address; the review queue and the unreviewed blocks as
 * tabs; the chosen decision previewed beside the list. The band and the tab counts come from the overview.
 */
(function (ZT) {
    'use strict';

    const {t, el} = ZT;
    const P = 'zt.console.ui.decisions.';
    const PAGES = '/contexa/admin/zero-trust';
    // K84: a challenge's code request is an outcome of its own (console design 6.2)
    const OUTCOMES = ['CHALLENGE_CODE_REQUESTED', 'CHALLENGE_PASSED', 'CHALLENGE_FAILED', 'CHALLENGE_EXPIRED',
        'UNBLOCK_REQUESTED', 'ADMIN_RELEASED', 'BLOCK_KEPT', 'EVALUATED_VALID', 'EVALUATED_INVALID'];
    /** The filters of the list, in the order of design 6.4; each names a parameter of /decisions. */
    const FILTERS = [
        {key: 'action', values: ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK', 'NO_DECISION'],
            label: value => t('zt.console.ui.action.' + value)},
        {key: 'source', values: ['MODEL', 'ENGINE_CHANGED', 'MODEL_LESS'], label: value => t(P + 'source.' + value)},
        {key: 'hypothesis', values: ['H1', 'H2', 'H3', 'H4', 'H5'], label: value => t(P + 'hypothesis.' + value)},
        {key: 'actor', values: ['HUMAN', 'AGENT', 'SERVICE'], label: value => t(P + 'actor.' + value)},
        {key: 'resourceClass', values: ['CRITICAL', 'SENSITIVE', 'NORMAL', 'PUBLIC'],
            label: value => t(P + 'resourceClass.' + value)},
        {key: 'outcome', values: ['NONE', 'UNREVIEWED'].concat(OUTCOMES), label: value => t(P + 'outcome.' + value)},
        {key: 'mode', values: ['SHADOW', 'ENFORCE'], label: value => t(P + 'mode.' + value)}
    ];
    /**
     * The parameters the unreviewed-blocks tab sets; every other filter is cleared with it. K81: the blocks no
     * administrator released, kept or evaluated, a request to be unblocked or not, as the overview counts them.
     */
    const UNREVIEWED = {action: 'BLOCK', outcome: 'UNREVIEWED'};

    /** A message, or the given text when the key has none (a value the server added later). */
    function known(key, fallback) {
        const text = t(key);
        return text === key ? fallback : text;
    }

    function muted(text) {
        return el('div', {class: 'zt-muted', text});
    }

    function show(node, visible) {
        node.style.display = visible ? '' : 'none';
    }

    function span(card, columns) {
        card.classList.add('zt-span-' + columns);
        return card;
    }

    function detailUrl(observationId) {
        return PAGES + '/decisions/' + encodeURIComponent(observationId);
    }

    // ----- the address: the filters, the search and the tab live in the query string -----

    function filterValue(name) {
        const value = ZT.query().get(name);
        return value == null || value.trim() === '' ? null : value.trim().toUpperCase();
    }

    function rewrite(changes) {
        const params = ZT.query();
        Object.entries(changes).forEach(([name, value]) => {
            if (value == null || value === '') {
                params.delete(name);
            } else {
                params.set(name, value);
            }
        });
        params.delete('cursor');
        const search = params.toString();
        window.history.replaceState(null, '', window.location.pathname + (search ? '?' + search : ''));
    }

    function currentView() {
        if (ZT.query().get('view') === 'review') {
            return 'review';
        }
        // console plan 5-2 ③: the slowest decisions under the filters, as the AI monitor's slow requests
        if (ZT.query().get('view') === 'slowest') {
            return 'slowest';
        }
        return filterValue('action') === UNREVIEWED.action && filterValue('outcome') === UNREVIEWED.outcome
            ? 'unreviewed' : 'all';
    }

    /** Every filter cleared, for a tab that brings its own. */
    function clearedFilters() {
        const cleared = {q: null};
        FILTERS.forEach(filter => {
            cleared[filter.key] = null;
        });
        return cleared;
    }

    // ----- labels of a row -----

    function hypothesisLabel(id) {
        return id ? known(P + 'hypothesis.' + String(id).toUpperCase(), id) : '—';
    }

    function outcomeLabel(row) {
        if (row.outcome) {
            return known(P + 'outcome.' + row.outcome, row.outcome);
        }
        return row.action === 'BLOCK' ? t(P + 'outcome.unreviewed') : '—';
    }

    function target(row) {
        const path = [row.method, row.resource].filter(Boolean).join(' ') || '—';
        return row.resourceClass ? t(P + 'row.target', path, known(P + 'resourceClass.' + row.resourceClass,
            row.resourceClass)) : path;
    }

    // ----- the header: the search and the CSV of the current filters (design 6.0) -----

    // The search and the CSV sit in the filter box, as the policy center's search does (filterBox below).
    const searchBox = el('input', {class: 'modern-input', type: 'search', name: 'q', maxlength: '200',
        'aria-label': t(P + 'search.label'), placeholder: t(P + 'search.placeholder')});
    const csvLink = el('a', {class: 'modern-btn-secondary', title: t(P + 'csvTitle')},
        el('i', {class: 'fas fa-download', 'aria-hidden': 'true'}), t(P + 'csv'));

    function search() {
        rewrite({q: searchBox.value.trim(), view: null});
        refresh();
    }

    searchBox.addEventListener('keydown', event => {
        if (event.key === 'Enter') {
            event.preventDefault();
            search();
        }
    });

    // ----- the screen -----

    let screen = null;

    function render(content, overview) {
        const state = {stack: [null], next: null, token: 0, previewToken: 0, overview};
        screen = state;
        state.tabs = tabsRow(state);
        state.filters = filterBox(overview);
        state.list = listCard(state);
        state.preview = previewCard();
        // The preview stays beside the rows while the list scrolls, its height its own, never the list's.
        state.preview.card.classList.add('zt-sticky');
        // The filters run across the top in the policy center's filter box, so the list keeps the width its five
        // columns need beside the preview.
        content.append(state.tabs.node, state.filters.card,
            el('div', {class: 'zt-grid'}, span(state.list.card, 8), span(state.preview.card, 4)));
        sync(state);
        loadCounts(state);
        loadList(state);
    }

    /** The address changed: the tabs and the filters follow it and the list starts again from the top. */
    function refresh() {
        const state = screen;
        if (!state) {
            return;
        }
        state.stack = [null];
        state.next = null;
        sync(state);
        clearPreview(state);
        loadList(state);
    }

    function sync(state) {
        const view = currentView();
        Object.entries(state.tabs.buttons).forEach(([key, button]) => {
            button.setAttribute('aria-selected', String(key === view));
        });
        state.filters.selects.forEach(select => {
            const value = filterValue(select.name) || '';
            if (!Array.from(select.options).some(option => option.value === value)) {
                // A value from a link the list does not offer (a class added later): shown as it is, never hidden.
                select.append(el('option', {value, text: value}));
            }
            select.value = value;
            select.disabled = view === 'review';
        });
        show(state.filters.reviewNote, view === 'review');
        searchBox.value = ZT.query().get('q') || '';
        // the slowest decisions' CSV keeps their order, the slowest first
        csvLink.setAttribute('href', ZT.apiUrl('/decisions.csv', {view: null, cursor: null,
            order: currentView() === 'slowest' ? 'slowest' : null}));
    }

    // ----- tabs: all decisions, the review queue, the unreviewed blocks -----

    function tabsRow(state) {
        const node = el('div', {class: 'zt-tabs', role: 'tablist', 'aria-label': t(P + 'tabs.label')});
        const buttons = {};
        const decisions = state.overview && state.overview.header ? state.overview.header.decisions : null;
        [['all', t(P + 'tab.all', ZT.count(decisions))], ['review', t(P + 'tab.review', '…')],
            ['unreviewed', t(P + 'tab.unreviewed', '…')], ['slowest', t(P + 'tab.slowest')]].forEach(([key, text]) => {
            const button = el('button', {type: 'button', role: 'tab', 'aria-selected': 'false', text});
            button.addEventListener('click', () => {
                const view = currentView();
                if (key === 'review' || key === 'slowest') {
                    rewrite({view: key});
                } else if (key === 'unreviewed') {
                    rewrite(Object.assign(clearedFilters(), UNREVIEWED, {view: null}));
                } else {
                    rewrite(view === 'unreviewed' ? {view: null, action: null, outcome: null} : {view: null});
                }
                refresh();
            });
            buttons[key] = button;
            node.append(button);
        });
        return {node, buttons};
    }

    function countText(count, more) {
        return more ? t(P + 'countMore', ZT.count(count)) : ZT.count(count);
    }

    /**
     * The counts of the two tabs. The review queue is counted by the server (every entry waiting); the
     * unreviewed blocks as the tab lists them: blocks of the period no administrator reviewed, the first page and
     * "more" past it.
     */
    function loadCounts(state) {
        ZT.load('/review-queue', {cursor: null}).then(page => {
            // the server counts every entry waiting, past the page it returns
            state.tabs.buttons.review.textContent = t(P + 'tab.review', ZT.count(page.pending));
        }).catch(() => {
            state.tabs.buttons.review.textContent = t(P + 'tab.review', '—');
        });
        ZT.load('/decisions', Object.assign(clearedFilters(), UNREVIEWED, {cursor: null, view: null})).then(page => {
            state.tabs.buttons.unreviewed.textContent = t(P + 'tab.unreviewed', countText(page.rows.length,
                Boolean(page.nextCursor)));
        }).catch(() => {
            state.tabs.buttons.unreviewed.textContent = t(P + 'tab.unreviewed', '—');
        });
    }

    // ----- filters -----

    /** The counts of the period beside the actions: from the overview's summary, over all other filters. */
    function actionCounts(overview) {
        const counts = {};
        if (!overview) {
            return counts;
        }
        if (overview.summary) {
            counts.ALLOW = Math.max(0, overview.summary.decisions - overview.summary.stopped);
        }
        ((overview.stopped && overview.stopped.byAction) || []).forEach(share => {
            counts[share.key] = share.count;
        });
        if (overview.header && !overview.header.tenant && overview.coverage) {
            const failures = (overview.coverage.noDecisionReasons || []).find(share => share.key === 'TECHNICAL_FAILURE');
            counts.NO_DECISION = failures ? failures.count : 0;
        }
        return counts;
    }

    /**
     * The policy center's filter box: one choice per filter, its name beside it (the list takes one value each, the
     * period's count beside each action), then the search with its button, the clearing of every filter and the CSV.
     */
    function filterBox(overview) {
        const counts = actionCounts(overview);
        const grid = el('div', {class: 'zt-filter-grid'});
        const form = el('form', {class: 'zt-filter-form', 'aria-label': t(P + 'filters.title')}, grid);
        const selects = FILTERS.map(filter => {
            const select = el('select', {class: 'modern-select', name: filter.key,
                'aria-label': t(P + 'filter.' + filter.key)},
                el('option', {value: '', text: t(P + 'filter.all')}),
                filter.values.map(value => el('option', {value, text: filter.key === 'action' && counts[value] != null
                    ? t(P + 'filter.withCount', filter.label(value), ZT.count(counts[value])) : filter.label(value)})));
            grid.append(el('label', {class: 'zt-filter-field'},
                el('span', {class: 'zt-filter-name', text: t(P + 'filter.' + filter.key)}), select));
            return select;
        });
        const searchButton = el('button', {type: 'submit', class: 'modern-btn-primary'},
            el('i', {class: 'fas fa-search', 'aria-hidden': 'true'}), t(P + 'filters.search'));
        const clearButton = el('button', {type: 'button', class: 'modern-btn-secondary'},
            el('i', {class: 'fas fa-times', 'aria-hidden': 'true'}), t(P + 'filters.clear'));
        clearButton.addEventListener('click', () => {
            rewrite(Object.assign(clearedFilters(), {q: null, view: null}));
            refresh();
        });
        form.append(el('div', {class: 'zt-filter-search'}, searchBox, searchButton, clearButton, csvLink));
        form.addEventListener('submit', event => {
            event.preventDefault();
            search();
        });
        form.addEventListener('change', event => {
            const select = event.target;
            if (select && select.tagName === 'SELECT') {
                rewrite({[select.name]: select.value, view: null});
                refresh();
            }
        });
        const reviewNote = muted(t(P + 'filters.reviewNote'));
        const card = el('div', {class: 'filter-container zt-filter-box'}, form, reviewNote);
        return {card, form, selects, reviewNote};
    }

    // ----- the list -----

    function listCard(state) {
        const holder = el('div', {class: 'zt-item'});
        const previous = el('button', {type: 'button', class: 'modern-btn-secondary'},
            el('i', {class: 'fas fa-chevron-left', 'aria-hidden': 'true'}), t(P + 'list.previous'));
        const next = el('button', {type: 'button', class: 'modern-btn-secondary'},
            t(P + 'list.next'), el('i', {class: 'fas fa-chevron-right', 'aria-hidden': 'true'}));
        const page = el('span', {class: 'zt-muted'});
        const pager = el('div', {class: 'zt-card-foot'}, previous, next, page);
        previous.addEventListener('click', () => {
            if (state.stack.length > 1) {
                state.stack.pop();
                loadList(state);
            }
        });
        next.addEventListener('click', () => {
            if (state.next) {
                state.stack.push(state.next);
                loadList(state);
            }
        });
        const card = ZT.card(t(P + 'list.title'), t(P + 'list.aside'), holder);
        card.append(pager);
        return {card, holder, previous, next, page, pager, title: card.querySelector('h2'),
            aside: card.querySelector('.zt-aside')};
    }

    async function loadList(state) {
        const token = ++state.token;
        const list = state.list;
        const review = currentView() === 'review';
        const slowest = currentView() === 'slowest';
        const titles = review ? ['list.reviewTitle', 'list.reviewAside']
            : slowest ? ['list.slowestTitle', 'list.slowestAside'] : ['list.title', 'list.aside'];
        list.title.textContent = t(P + titles[0]);
        list.aside.textContent = t(P + titles[1]);
        list.holder.replaceChildren(muted(t(P + 'loading')));
        list.previous.disabled = true;
        list.next.disabled = true;
        // the slowest decisions are one page: their order has no cursor; the review queue reads on by its own
        show(list.pager, !slowest);
        try {
            if (review) {
                const page = await ZT.load('/review-queue', {cursor: state.stack[state.stack.length - 1]});
                if (token !== state.token) {
                    return;
                }
                state.next = page.nextCursor || null;
                list.holder.replaceChildren(page.items.length ? reviewTable(state, page.items)
                    : muted(t(P + 'review.empty')));
                list.previous.disabled = state.stack.length <= 1;
                list.next.disabled = !state.next;
                list.page.textContent = t(P + 'list.page', ZT.count(state.stack.length), ZT.count(page.items.length));
                return;
            }
            const page = await ZT.load('/decisions', {cursor: slowest ? null : state.stack[state.stack.length - 1],
                view: null, order: slowest ? 'slowest' : null});
            if (token !== state.token) {
                return;
            }
            state.next = page.nextCursor || null;
            list.holder.replaceChildren(page.rows.length ? decisionTable(state, page.rows, slowest)
                : muted(t(P + 'list.empty')));
            list.previous.disabled = state.stack.length <= 1;
            list.next.disabled = !state.next;
            list.page.textContent = t(P + 'list.page', ZT.count(state.stack.length), ZT.count(page.rows.length));
        } catch (error) {
            if (token === state.token) {
                ZT.failed(list.holder, error);
            }
        }
    }

    function table(columns, rows) {
        const node = el('table', {class: 'zt-table'});
        node.append(el('thead', {}, el('tr', {}, columns.map(column => el('th', {scope: 'col',
            class: [column.number ? 'zt-num' : '', column.wide ? 'zt-wide' : ''].join(' ').trim() || null,
            text: t(P + 'column.' + column.key)})))));
        node.append(el('tbody', {}, rows));
        return el('div', {class: 'modern-table zt-table-wrap'}, node);
    }

    function cell(text, attributes) {
        return el('td', Object.assign({title: text, text}, attributes || {}));
    }

    /** A row that previews its decision when chosen; its link opens the detail. */
    function selectable(state, observationId, cells) {
        const row = el('tr', {tabindex: '0', 'data-selectable': true, 'data-id': observationId}, cells);
        row.addEventListener('click', event => {
            if (!event.target.closest('a')) {
                select(state, observationId, row);
            }
        });
        row.addEventListener('keydown', event => {
            if (event.target === row && (event.key === 'Enter' || event.key === ' ')) {
                event.preventDefault();
                select(state, observationId, row);
            }
        });
        return row;
    }

    function whoCell(createdAt, user, observationId) {
        const text = t(P + 'row.who', ZT.time(createdAt), user || '—');
        // A phone reads it on two lines, the time on 24 hours and the user, in the narrow column it has.
        return el('td', {title: text}, el('a', {class: 'zt-link', href: detailUrl(observationId)},
            el('span', {class: 'zt-long', text}),
            el('span', {class: 'zt-short'}, el('span', {class: 'zt-line', text: ZT.shortTime(createdAt)}),
                el('span', {class: 'zt-line', text: user || '—'}))));
    }

    function actionCell(row) {
        // The source and SHADOW chips are kept for the wider layouts: a phone leaves their room to the target.
        const wide = chip => {
            chip.classList.add('zt-wide');
            return chip;
        };
        return el('td', {class: 'zt-cell-chips'}, ZT.chip(row.action),
            row.source && row.source !== 'MODEL' ? [' ', wide(ZT.statusChip('INFO', known(P + 'source.' + row.source,
                row.source)))] : null,
            row.mode === 'SHADOW' ? [' ', wide(ZT.statusChip('INFO', t(P + 'row.shadow')))] : null);
    }

    function wideCell(node) {
        node.classList.add('zt-wide');
        return node;
    }

    /** @param took whether the time each decision took is a column (the slowest decisions) */
    function decisionTable(state, rows, took) {
        // The target takes the room the others leave; a phone keeps who, target and action (1.4 check 8).
        // the slowest decisions keep the time on a phone in place of the action
        const columns = [{key: 'who'}, {key: 'target'}, {key: 'action', wide: took}];
        if (took) {
            columns.push({key: 'took', number: true});
        }
        columns.push({key: 'hypothesis', wide: true}, {key: 'outcome', wide: true});
        return table(columns, rows.map(row => selectable(state, row.observationId, [
            whoCell(row.createdAt, row.user, row.observationId),
            cell(target(row), {class: 'zt-fill'}),
            took ? wideCell(actionCell(row)) : actionCell(row),
            took ? cell(row.totalMs == null ? '—' : ZT.seconds(row.totalMs), {class: 'zt-num'}) : null,
            cell(hypothesisLabel(row.hypothesis), {class: 'zt-wide'}),
            cell(outcomeLabel(row), {class: 'zt-wide'})].filter(Boolean))));
    }

    function reviewTable(state, items) {
        return table([{key: 'sampleDay', wide: true}, {key: 'who'}, {key: 'target'}, {key: 'action'},
            {key: 'hypothesis', wide: true}],
            items.map(item => selectable(state, item.observationId, [
                cell(ZT.day(item.sampleDay), {class: 'zt-wide'}),
                whoCell(item.createdAt, item.user, item.observationId),
                cell(item.resource || '—', {class: 'zt-fill'}),
                // K17: a decision whose model answer broke a decision rule says so beside its action
                el('td', {class: 'zt-cell-chips'}, item.action ? ZT.chip(item.action) : '—',
                    item.reason === 'RULE_BREACH' ? [' ', ZT.statusChip('WARN', t(P + 'review.reason.RULE_BREACH'))]
                        : item.reason === 'SHADOW_BLOCK'
                            ? [' ', ZT.statusChip('INFO', t(P + 'review.reason.SHADOW_BLOCK'))] : null),
                cell(hypothesisLabel(item.hypothesis), {class: 'zt-wide'})])));
    }

    // ----- the preview of the chosen decision -----

    function previewCard() {
        const body = el('div', {class: 'zt-item'});
        const card = ZT.card(t(P + 'preview.title'), t(P + 'preview.aside'), body);
        const foot = el('div', {class: 'zt-card-foot'});
        card.append(foot);
        body.append(muted(t(P + 'preview.empty')));
        return {card, body, foot, aside: card.querySelector('.zt-aside')};
    }

    function clearPreview(state) {
        state.previewToken++;
        state.preview.body.replaceChildren(muted(t(P + 'preview.empty')));
        state.preview.foot.replaceChildren();
        state.preview.aside.textContent = t(P + 'preview.aside');
    }

    async function select(state, observationId, row) {
        row.parentNode.querySelectorAll('tr[data-selected]').forEach(other => other.removeAttribute('data-selected'));
        row.setAttribute('data-selected', 'true');
        const token = ++state.previewToken;
        const preview = state.preview;
        preview.body.replaceChildren(muted(t(P + 'loading')));
        preview.foot.replaceChildren(el('a', {class: 'zt-link', href: detailUrl(observationId),
            text: t(P + 'preview.open')}));
        try {
            const detail = await ZT.load('/decisions/' + encodeURIComponent(observationId));
            if (token === state.previewToken) {
                preview.aside.textContent = t('zt.console.ui.action.' + detail.action);
                preview.body.replaceChildren(...previewBody(detail));
            }
        } catch (error) {
            if (token !== state.previewToken) {
                return;
            }
            if (error && error.message === '404') {
                preview.body.replaceChildren(muted(t(P + 'preview.notFound')));
            } else {
                ZT.failed(preview.body, error);
            }
        }
    }

    function previewBody(detail) {
        const nodes = [];
        nodes.push(el('div', {class: 'zt-toolbar'}, ZT.chip(detail.action),
            detail.mode === 'SHADOW' ? ZT.statusChip('INFO', t(P + 'row.shadow')) : null));
        nodes.push(el('div', {text: detail.conclusion || '—'}));
        const hypotheses = detail.hypotheses || [];
        if (hypotheses.length) {
            nodes.push(el('div', {class: 'zt-metric-label', text: t(P + 'preview.hypotheses')}),
                ZT.hypothesisBoard(hypotheses, {
                    label: t(P + 'preview.hypotheses'),
                    name: id => hypothesisLabel(id),
                    assessment: code => t(P + 'assessment.' + code),
                    cited: (kind, fact) => t(P + 'cited.' + kind, fact),
                    href: fact => detailUrl(detail.observationId) + '#zt-fact-' + encodeURIComponent(fact)
                }));
        }
        const cited = (detail.reasons || []).filter(reason => reason.fact);
        if (cited.length) {
            nodes.push(el('div', {class: 'zt-metric-label', text: t(P + 'preview.facts')}));
            cited.forEach(reason => nodes.push(el('div', {class: 'zt-fact', text: t(P + 'preview.fact', reason.fact,
                reason.factName ? ZT.factName(reason.factName) : ZT.reasonName(reason.code),
                reason.factValue || '—')})));
        } else if (!detail.explained) {
            nodes.push(muted(t(P + 'preview.unexplained', detail.bundle || '—')));
        }
        const meta = [detail.source ? known(P + 'source.' + detail.source, detail.source) : null,
            detail.timing ? known(P + 'timing.' + detail.timing, detail.timing) : null,
            detail.totalMs != null ? ZT.seconds(detail.totalMs) : null,
            detail.bundle && detail.bundleNumber == null ? t(P + 'preview.bundle', detail.bundle) : null].filter(Boolean);
        if (meta.length) {
            nodes.push(muted(meta.join(' · ')));
        }
        // the version the decision ran opens its version screen
        if (detail.bundle && detail.bundleNumber != null) {
            nodes.push(el('a', {class: 'zt-link', href: '/contexa/admin/prompt-quality/versions/'
                + encodeURIComponent(detail.bundleNumber), text: t(P + 'preview.bundle', detail.bundle)}));
        }
        return nodes;
    }

    ZT.start('/overview', render);
})(window.ZT);
