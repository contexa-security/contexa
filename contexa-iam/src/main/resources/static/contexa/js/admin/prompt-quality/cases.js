/*
 * Prompt quality assurance, the labelled cases (quality plan 3.2, quality P46): what decisions are graded against. The
 * list with the published bundle, whether there are cases enough, the cases by resource grade beside the decisions of
 * the operation, and every case; a case with its answer, its input, its results and the changes of its answer; and the
 * changes themselves (a copy, a case from a sealed decision, a new answer, a confirmation, a deletion, publishing).
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const PV = global.PV;
    const PQA = global.PQA;
    const root = document.getElementById('zt-console');
    const content = document.getElementById('zt-content');
    if (!ZT || !PV || !PQA || !root || !content) {
        return;
    }
    const el = ZT.el;
    const C = ZT.COLORS;
    const m = (key, ...args) => ZT.t('pqa.cases.' + key, ...args);
    const PAGES = '/contexa/admin/prompt-quality/cases';
    const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];
    const CLASSES = ['THREAT', 'NORMAL', 'UNCERTAIN'];
    const KINDS = ['OUTSIDER', 'INSIDER', 'NORMAL_WORK', 'AUTOMATION'];
    const GRADES = ['ORDINARY', 'MUST_CATCH', 'MUST_NOT_BLOCK'];
    const RESOURCE_GRADES = ['CRITICAL', 'SENSITIVE', 'NORMAL', 'PUBLIC'];
    const CLASS_STATUS = {THREAT: 'BAD', NORMAL: 'GOOD', UNCERTAIN: 'WARN'};
    const NOW_STATUS = {HIT: 'GOOD', MISS: 'BAD', OFF: 'WARN', PENDING: 'WARN', NONE: null};
    const COVER_STATUS = {COVERED: 'GOOD', FEW_CASES: 'WARN', NO_CASES: 'BAD', UNUSED: null};
    const ORIGIN_TABS = {contexa: 'CONTEXA', operation: 'OPERATION', customer: 'CUSTOMER'};
    /** The views of the list by the names an address opens them with (view=...); every case has none. */
    const VIEWS = ['contexa', 'operation', 'customer', 'pending'];
    const resourceGrade = key => PQA.word('pqa.cases.resGrade.' + key, key);

    // ----- the list -----

    async function drawList() {
        let view;
        try {
            view = await PQA.get('');
        } catch (error) {
            content.replaceChildren(PQA.failed());
            return;
        }
        PQA.toolbar(PQA.button(m('promote'), 'fa-upload', 'secondary', {'data-pqa-action': 'promote'},
            () => promoteDialog(view)),
        PQA.button(m('create'), 'fa-plus', 'primary', {'data-pqa-action': 'create'}, () => createDialog(view, null)));
        const bundle = view.bundle;
        PQA.band(el('span', {title: bundle ? bundle.version : null, text: bundle
            ? m('band.bundle', shortVersion(bundle.version), ZT.shortTime(bundle.publishedAt), ZT.count(bundle.cases))
            : m('band.noBundle')}),
        bundle ? el('span', {text: m('band.added', ZT.count(view.addedSince))}) : null,
        PQA.button(m('publish'), 'fa-stamp', 'refresh', {disabled: bundle && !view.addedSince ? true : null,
            'data-pqa-action': 'publish'}, () => publishDialog(view)),
        ZT.info(m('band.note')));
        const s = view.sufficiency;
        const cards = PQA.grid(
            PQA.kpi({tone: 'amber', icon: 'fa-hand-paper', label: m('kpi.stop'), value: ZT.shortCount(s.stopRoots),
                sub: m('kpi.target', ZT.count(s.stopTarget), ZT.count(s.stopCases)), title: m('kpi.rootsDef')}),
            PQA.kpi({tone: 'green', icon: 'fa-door-open', label: m('kpi.pass'), value: ZT.shortCount(s.passRoots),
                sub: m('kpi.target', ZT.count(s.passTarget), ZT.count(s.passCases)), title: m('kpi.rootsDef')}),
            PQA.kpi({tone: 'purple', icon: 'fa-search', label: m('kpi.power'),
                value: s.power == null ? null : ZT.percent(s.power, 0),
                sub: s.power == null ? m('kpi.powerNone') : m('kpi.powerSub', ZT.percent(s.powerAtTarget, 0)),
                title: m('kpi.powerDef', ZT.count(s.stopRoots), ZT.percent(s.baseMiss, 1))}),
            PQA.kpi({tone: 'indigo', icon: 'fa-user-check', label: m('kpi.pending'), value: ZT.shortCount(view.counts.pending),
                sub: m(view.twoPerson ? 'kpi.pendingSub' : 'kpi.pendingOff'), title: m('kpi.pendingDef')}));
        const holder = el('div', {class: 'zt-stack'});
        // The view the address names (view=pending opens the cases waiting for confirmation), else every case.
        const asked = PQA.params().get('view');
        const state = {tab: VIEWS.includes(asked) ? asked : '', filters: {}};
        const redraw = () => holder.replaceChildren(...listParts(view, state, redraw));
        redraw();
        content.replaceChildren(cards, coverRow(view), holder, el('p', {class: 'zt-muted pv-foot', text: m('foot')}));
        PQA.fitChips();
    }

    /**
     * Where the cases of the published bundle cover the protected resources: each grade, its share of the distinct
     * roots over its share of the decisions of the operation, its roots to stop and to pass, and a mark where the
     * operation decides and no case, or few, cover it. Right, the resources with the most cases.
     */
    function coverRow(view) {
        const coverage = view.coverage ? view.coverage.coverage : null;
        const grades = coverage ? coverage.classes.filter(row => RESOURCE_GRADES.includes(row.resourceClass)
            || row.cases > 0) : [];
        const roots = grades.reduce((sum, row) => sum + row.stopRoots + row.allowRoots, 0);
        const decisions = grades.reduce((sum, row) => sum + row.operationDecisions, 0);
        const rows = el('div', {class: 'zt-criteria'},
            el('span', {class: 'zt-muted', text: m('cover.grade')}),
            el('span', {class: 'zt-muted', text: m('cover.shares')}),
            el('span', {class: 'zt-muted zt-num', text: m('cover.rootsHead')}),
            el('span', {class: 'zt-muted', text: m('cover.state')}));
        grades.forEach(row => {
            const mark = row.gap !== 'NONE' ? row.gap : row.cases > 0 ? 'COVERED' : 'UNUSED';
            const share = roots ? (row.stopRoots + row.allowRoots) / roots : null;
            rows.append(
                el('span', {title: m('resGrade.def')}, el('div', {text: resourceGrade(row.resourceClass)}),
                    el('div', {class: 'zt-muted', title: ZT.count(row.operationDecisions),
                        text: m('cover.operations', ZT.shortCount(row.operationDecisions))})),
                el('span', {class: 'flex flex-col gap-1'},
                    ZT.bar(share, 1, {color: C.ACCENT, label: resourceGrade(row.resourceClass) + ' ' + ZT.percent(share, 0)}),
                    ZT.bar(decisions ? row.operationDecisions / decisions : null, 1, {color: C.MUTED,
                        label: m('cover.operations', ZT.count(row.operationDecisions))})),
                el('span', {class: 'zt-num', title: ZT.count(row.stopRoots) + ' · ' + ZT.count(row.allowRoots),
                    text: m('cover.roots', ZT.shortCount(row.stopRoots), ZT.shortCount(row.allowRoots))}),
                el('span', {}, ZT.statusChip(COVER_STATUS[mark], m('cover.' + mark))));
        });
        const aside = view.bundle ? m('cover.aside', shortVersion(view.bundle.version)) : m('cover.asideNow');
        const gradeCard = PQA.tipped(ZT.card(m('cover.title'), aside, grades.length ? PQA.form('grade-cover', rows)
            : PQA.form('empty-state', PQA.emptyState(m('list.empty'), 'fa-layer-group'))),
        m('cover.tip', ZT.count(view.coverage ? coverage.minimumRoots : 0)));
        const resources = coverage ? coverage.topResources.slice(0, 5) : [];
        const most = resources.length ? resources[0].cases : 0;
        const resourceCard = ZT.card(m('resources.title'), m('resources.aside', ZT.count(coverage ? coverage.resources : 0)),
            resources.length ? PQA.form('resource-ranks', el('div', {class: 'zt-reason-rows'}, resources.map(row => {
                const name = resourceName(row);
                return el('div', {class: 'zt-reason-row', title: row.resource},
                    el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name pv-cut', text: name}),
                        el('span', {class: 'zt-reason-value', title: ZT.count(row.cases),
                            text: m('resources.count', ZT.shortCount(row.cases))})),
                    ZT.bar(row.cases, most, {label: name}));
            })))
                : PQA.form('empty-state', PQA.emptyState(m('list.empty'), 'fa-layer-group')));
        return PQA.grid(PQA.span(gradeCard, 8), PQA.span(resourceCard, 4));
    }

    function resourceName(row) {
        if (row.urlTemplate) {
            return (row.httpMethod ? row.httpMethod + ' ' : '') + row.urlTemplate;
        }
        const name = row.resource || '—';
        const dot = name.lastIndexOf('.');
        return dot >= 0 ? name.slice(dot + 1) : name;
    }

    function shortVersion(version) {
        return version ? String(version).slice(0, 8) : '—';
    }

    /** The views, the filters and the table of the list; a filter is applied by the search button. */
    function listParts(view, state, redraw) {
        const counts = view.counts;
        const tabs = PQA.viewTabs([
            {key: '', label: m('tab.all'), count: counts.all},
            {key: 'contexa', label: m('origin.CONTEXA'), count: counts.contexa},
            {key: 'operation', label: m('origin.OPERATION'), count: counts.operation},
            {key: 'customer', label: m('origin.CUSTOMER'), count: counts.customer},
            {key: 'pending', label: m('tab.pending'), count: counts.pending}], state.tab, m('tabs'), key => {
            state.tab = key;
            redraw();
        });
        const all = ZT.t('zt.console.ui.decisions.filter.all');
        const choice = (name, values, label, key) => ({name, node: PQA.select(name, [['', all],
            ...values.map(value => [value, label(value)])], state.filters[key], {'data-filter': key})});
        const used = view.usedVersion || '';
        const fields = [
            choice(m('column.class'), CLASSES, value => m('class.' + value), 'classification'),
            choice(m('column.kind'), KINDS, value => m('kind.' + value), 'kind'),
            choice(m('column.caseGrade'), GRADES, value => m('grade.' + value), 'grade'),
            choice(m('filter.resourceGrade'), RESOURCE_GRADES, resourceGrade, 'resourceClass'),
            choice(m('column.now', used), ['HIT', 'MISS', 'OFF', 'NONE'], value => m('now.' + value), 'now')];
        const search = el('input', {type: 'search', class: 'modern-input', placeholder: m('search'),
            'aria-label': m('search'), value: state.filters.text || ''});
        const apply = () => {
            fields.forEach(field => {
                state.filters[field.node.dataset.filter] = field.node.value;
            });
            state.filters.text = search.value.trim();
            redraw();
        };
        search.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();
                apply();
            }
        });
        const box = PQA.filterBox(fields, search,
            PQA.button(ZT.t('zt.console.ui.decisions.filters.search'), 'fa-search', 'primary', null, apply),
            PQA.button(ZT.t('zt.console.ui.decisions.filters.clear'), 'fa-times', 'secondary', null, () => {
                state.filters = {};
                redraw();
            }));
        const pending = state.tab === 'pending';
        const rows = view.rows.filter(row => matches(row, state));
        const list = ZT.card(m(pending ? 'tab.pending' : 'list.title'), m(pending ? 'list.pendingAside' : 'list.aside'));
        if (rows.length) {
            const {body, foot} = PV.paged(rows, row => caseRow(row, view));
            list.querySelector('.zt-card-body').append(PQA.form('case-table', PQA.table([
                {label: m('column.case')}, {label: m('column.resource'), wide: true},
                {label: m('column.classKind')}, {label: m('column.answer'), wide: true},
                {label: m('column.caseGrade'), wide: true}, {label: m('column.now', used), keep: true},
                {label: m('column.work'), wide: true}], body, m('list.title'))));
            PQA.withFoot(list, foot);
        } else {
            list.querySelector('.zt-card-body').append(PQA.form('empty-state', PQA.emptyState(m(pending ? 'list.noPending'
                : view.rows.length ? 'list.noMatch' : 'list.empty'), 'fa-clipboard-check')));
        }
        global.setTimeout(PQA.fitChips, 0);
        return [tabs, box, PQA.grid(PQA.span(list, 12))];
    }

    function matches(row, state) {
        if (state.tab === 'pending' && !row.pending) {
            return false;
        }
        if (ORIGIN_TABS[state.tab] && row.origin !== ORIGIN_TABS[state.tab]) {
            return false;
        }
        const f = state.filters;
        if ((f.classification && row.classification !== f.classification) || (f.kind && row.kind !== f.kind)
            || (f.grade && row.grade !== f.grade) || (f.resourceClass && row.resourceClass !== f.resourceClass)
            || (f.now && row.now !== f.now)) {
            return false;
        }
        const text = (f.text || '').toLowerCase();
        return !text || row.name.toLowerCase().includes(text) || row.key.toLowerCase().includes(text);
    }

    function caseRow(row, view) {
        const open = PQA.page(PAGES + '/' + encodeURIComponent(row.key));
        const actions = el('div', {class: 'pv-row-actions'},
            el('a', {class: 'zt-link pv-row-action', href: open, text: ZT.t('pv.action.view')}));
        if (row.pending) {
            const own = row.labelledBy === view.actor && view.twoPerson;
            actions.append(own ? el('span', {class: 'zt-muted pv-row-action', title: m('confirm.self'),
                text: m('action.confirm')}) : actionLink(m('action.confirm'), () => confirmDialog(row)));
        } else {
            actions.append(actionLink(m('action.copy'), () => createDialog(view, row.key)));
        }
        // Under the name: where the case came from (a lock on the read-only default bundle), when, and its root case.
        const about = [m('origin.' + row.origin), row.at ? ZT.shortTime(row.at) : null,
            row.root ? m('rootOf', row.root) : m('rootSelf')].filter(Boolean).join(' · ');
        return el('tr', {'data-case': row.key},
            el('td', {class: 'zt-fill'}, el('div', {class: 'zt-item'},
                el('a', {class: 'zt-link pv-cut', href: open, title: row.name, text: row.name}),
                el('span', {class: 'zt-muted pv-cut', title: (row.readonly ? m('readonly') + ' · ' : '') + about},
                    row.readonly ? el('i', {class: 'fas fa-lock', 'aria-hidden': 'true', style: {marginRight: '4px'}})
                        : null, about))),
            el('td', {class: 'zt-wide', title: row.resource || ''}, el('div', {class: 'zt-item'},
                el('span', {class: 'pv-cut', text: row.resourceName || '—'}),
                el('span', {class: 'zt-muted pv-cut', text: resourceGrade(row.resourceClass)}))),
            el('td', {class: 'zt-cell-chips'}, ZT.statusChip(CLASS_STATUS[row.classification],
                m('class.' + row.classification)), el('span', {class: 'zt-muted pv-cut', text: m('kind.' + row.kind)})),
            PQA.chipCell(row.allowed, true),
            PQA.cell(m('grade.' + row.grade), {class: 'zt-wide'}),
            el('td', {class: 'zt-cell-chips'}, ZT.statusChip(NOW_STATUS[row.now], m('now.' + row.now))),
            el('td', {class: 'pv-cell-actions zt-wide'}, actions));
    }

    function actionLink(text, onClick) {
        const node = el('a', {class: 'zt-link pv-row-action', href: '#', text});
        node.addEventListener('click', event => {
            event.preventDefault();
            onClick();
        });
        return node;
    }

    // ----- a case -----

    async function drawDetail(key) {
        let d;
        try {
            d = await PQA.get('/' + encodeURIComponent(key));
        } catch (error) {
            PQA.crumbs(PQA.page(PAGES), ZT.t('pqa.nav.cases'), m('detail.none'));
            content.replaceChildren(error.status === 404 ? PQA.emptyState(m('detail.none'), 'fa-clipboard-check')
                : PQA.failed());
            return;
        }
        const row = d.row;
        PQA.crumbs(PQA.page(PAGES), ZT.t('pqa.nav.cases'), row.name);
        PQA.toolbar(
            PQA.button(m('action.delete'), 'fa-trash', 'secondary', {disabled: row.readonly ? true : null,
                title: row.readonly ? m('readonly') : null, 'data-pqa-action': 'delete'}, () => deleteDialog(row)),
            row.readonly ? null : PQA.button(m('action.answer'), 'fa-pen', 'secondary', {'data-pqa-action': 'answer'},
                () => answerDialog(d)),
            d.canConfirm ? PQA.button(m('action.confirm'), 'fa-user-check', 'refresh', {'data-pqa-action': 'confirm'},
                () => confirmDialog(row)) : null,
            PQA.button(m('action.copyNew'), 'fa-copy', 'primary', {'data-pqa-action': 'copy'},
                () => createDialog(null, row.key)));
        PQA.band(ZT.statusChip(CLASS_STATUS[row.classification], m('class.' + row.classification)),
            el('span', {text: m('kind.' + row.kind)}), el('span', {text: m('grade.' + row.grade)}),
            el('span', {text: m('origin.' + row.origin) + (d.submittedBy ? ' · ' + d.submittedBy : '')}),
            el('span', {text: row.root ? m('rootOf', row.root) : m('rootSelf')}),
            row.pending ? ZT.statusChip('WARN', m('now.PENDING')) : null,
            el('span', {text: row.at ? ZT.time(row.at) : m('origin.CONTEXA')}));
        const privacy = d.privacy ? el('div', {class: 'zt-alert max-sm:!grid-cols-1', role: 'note'},
            ZT.statusChip('WARN', m('detail.privacy')), el('span', {text: m('detail.privacyLine')})) : null;
        const lang = document.documentElement.lang || 'en';
        const why = lang === 'ko' ? (d.rationaleKo || d.rationaleEn) : (d.rationaleEn || d.rationaleKo);
        const answer = ZT.card(m('detail.answer'), m('detail.answerAside'),
            PQA.form('answer-set', el('div', {class: 'zt-conclusion'}, row.allowed.map(action => ZT.chip(action)))),
            PQA.form('answer-rows', ZT.valueRows([
                {label: m('detail.best'), value: row.preferred ? ZT.t('zt.console.ui.action.' + row.preferred) : '—'},
                {label: m('column.class'), value: m('class.' + row.classification)},
                {label: m('column.kind'), value: m('kind.' + row.kind)}])),
            ZT.subhead(m('detail.why')),
            el('figure', {class: 'zt-quote'}, el('figcaption', {text: [d.labelledBy, d.labelledAt
                ? ZT.day(d.labelledAt) : null].filter(Boolean).join(' · ') || m('origin.CONTEXA')}),
            el('blockquote', {text: why || '—'})),
            ZT.subhead(m('detail.deciding')),
            d.decidingFacts.length ? d.decidingFacts.map(fact => el('div', {class: 'zt-fact', text: fact}))
                : PQA.muted(m('detail.noDeciding')));
        const input = ZT.tabbedCard(m('detail.input'), m('detail.inputAside'),
            ['request', 'session', 'deviation', 'records', 'unknown'].map(part => ({label: m('detail.tab.' + part),
                node: d.input[part].length ? PQA.form('input-rows', PQA.wrapRows(d.input[part].map(line => ({
                    label: line.name ? PQA.word((part === 'deviation' ? 'pqa.cases.dimension.' : 'pqa.cases.input.')
                        + line.name, line.name) : '·', value: inputValue(part, line)}))))
                    : PQA.emptyState(m('detail.noLines'))})));
        const history = ZT.card(m('detail.results'), m('detail.resultsAside'),
            d.results.length ? PQA.form('result-history', PQA.table([{label: m('detail.version')},
                {label: m('detail.measuredAt'), num: true, wide: true}, {label: m('detail.actions')},
                {label: m('detail.result')}], el('tbody', {}, d.results.map(result => el('tr', {},
                el('td', {class: 'zt-fill'}, el('a', {class: 'zt-link', text: result.version,
                    href: PQA.page('/contexa/admin/prompt-quality/measure/' + result.measureId)})),
                PQA.cell(ZT.shortTime(result.measuredAt), {class: 'zt-num zt-wide'}),
                PQA.chipCell(result.actions),
                el('td', {class: 'zt-cell-chips'}, ZT.statusChip(NOW_STATUS[result.result],
                    m('now.' + result.result))))))))
                : PQA.form('empty-state', PQA.emptyState(m('detail.noResults'))));
        const changes = ZT.card(m('detail.changes'), m('detail.changesAside'),
            d.changes.length ? PQA.form('change-timeline', el('ul', {class: 'zt-rows'}, d.changes.map(change =>
                el('li', {class: 'zt-fact zt-item'},
                    el('span', {class: 'zt-muted', text: ZT.time(change.at) + ' · ' + (change.by || '—')}),
                    el('span', {text: changeText(change)}),
                    change.why ? el('span', {class: 'zt-muted', text: change.why}) : null))))
                : PQA.form('empty-state', PQA.emptyState(m(row.readonly ? 'detail.readonlyChanges' : 'detail.noChanges'),
                    'fa-history')));
        if (d.improvedByEdit) {
            const i = d.improvedByEdit;
            changes.querySelector('.zt-card-body').append(PQA.form('edit-effect', el('div', {class: 'zt-tile zt-metric',
                title: m('detail.improvedDef')},
            el('span', {class: 'zt-metric-label', text: m('detail.improved')}),
            el('span', {class: 'zt-metric-value zt-small', text: ZT.count(i.better)}),
            el('span', {class: 'zt-metric-ratio', text: m('detail.improvedSub', ZT.count(i.worse), ZT.count(i.answers),
                ZT.count(i.measurements))}))));
        }
        content.replaceChildren(...[privacy, PQA.grid(PQA.span(answer, 4), PQA.span(input, 8)),
            PQA.grid(PQA.span(history, 8), PQA.span(changes, 4))].filter(Boolean));
        PQA.fitChips();
    }

    // ----- K197: the values of a case's input in words -----

    const VALUE_WORD = 'pqa.cases.value.';
    const LOGIN_WORD = 'zt.console.ui.decision.value.login.';
    const FACT_WORD = 'zt.console.fact.';
    /**
     * The dictionaries of the engine's codes, in the order a code is looked up: the screen's own words (yes, no, an
     * authorization effect, a level, an approval state), the resource grades, then the words the decision detail of
     * the console reads an action, an operating system, a network zone, a record state and a login by.
     */
    const CODE_WORDS = [VALUE_WORD, 'pqa.cases.resGrade.', 'zt.console.ui.decision.value.action.',
        'zt.console.ui.decision.value.os.', 'zt.console.ui.decision.value.zone.',
        'zt.console.ui.decision.value.recordStatus.', LOGIN_WORD];
    /** The lines of the request, the session and the records that hold codes; the others hold the host's names. */
    const CODED_LINES = ['resourceClass', 'sensitivity', 'action', 'authorization', 'authentication', 'network',
        'device', 'approvalStatus'];
    const YES_NO_LINES = ['mfa', 'newSession', 'newDevice'];
    /** A code as the engine writes it (EXPORT, PASSWORD+ONE_TIME_CODE), set apart from the text around it. */
    const ENGINE_CODE = /(^|[^\w./@#:+-])([A-Z][A-Z0-9_]*(?:\+[A-Z][A-Z0-9_]*)*)(?![\w./@#:+-])/g;

    function knownWord(prefix, code) {
        const key = prefix + code;
        const text = ZT.t(key);
        return text === key ? null : text;
    }

    /**
     * A code in words: a login of several methods by the word of each, else the first dictionary that names it, else,
     * when it is plainly a code of two words or more, in plain words, as the console reads it (ZeroTrustFactWords).
     */
    function codeWord(code) {
        if (code.includes('+')) {
            const methods = code.split('+').map(method => knownWord(LOGIN_WORD, method));
            return methods.every(Boolean) ? methods.join(' + ') : code;
        }
        for (const prefix of CODE_WORDS) {
            const word = knownWord(prefix, code);
            if (word) {
                return word;
            }
        }
        return code.includes('_') ? code.toLowerCase().replace(/_/g, ' ') : code;
    }

    function codesInWords(text) {
        return String(text).replace(ENGINE_CODE, (all, before, code) => before + codeWord(code));
    }

    /**
     * A value of the decision input as the screen shows it (quality plan 3.2): the codes of the engine in words, yes
     * and no in words, the time of the request in the screen's time, a fact the context could not have by its name.
     * A name the host gives (a user, a role, an address, a resource, a record) is shown as it is.
     */
    function inputValue(part, line) {
        const value = line.value;
        if (part === 'deviation' || CODED_LINES.includes(line.name)) {
            return codesInWords(value);
        }
        if (YES_NO_LINES.includes(line.name)) {
            return PQA.word(VALUE_WORD + value, value);
        }
        if (line.name === 'requestedAt') {
            return ZT.time(value);
        }
        if (line.name === 'unknownFact') {
            return PQA.word(FACT_WORD + value, value);
        }
        if (line.name === 'unavailableFact') {
            const at = value.indexOf(': ');
            return at < 0 ? PQA.word(FACT_WORD + value, value)
                : PQA.word(FACT_WORD + value.slice(0, at), value.slice(0, at)) + ': ' + codesInWords(value.slice(at + 2));
        }
        return value;
    }

    function changeText(change) {
        const actions = list => list.map(action => ZT.t('zt.console.ui.action.' + action)).join(', ');
        if (change.kind === 'SUBMITTED') {
            return m('change.submitted', actions(change.allowed), m('grade.' + change.grade));
        }
        if (change.kind === 'CHANGED') {
            return m('change.changed', actions(change.previous), actions(change.allowed), m('grade.' + change.grade));
        }
        return m('change.confirmed');
    }

    // ----- the changes -----

    /** The fields of an answer, filled from a case's answer when one is given. */
    function answerFields(given) {
        const answer = given || {};
        const allowed = new Set(answer.allowed || []);
        const checks = el('div', {class: 'pv-actions'}, ACTIONS.map(action => el('label', {class: 'pv-toggle'},
            el('input', {type: 'checkbox', value: action, checked: allowed.has(action) ? true : null,
                'data-answer': 'allowed'}),
            el('span', {text: ZT.t('zt.console.ui.action.' + action)}))));
        const none = ['', m('form.none')];
        const preferred = PQA.select(m('detail.best'), [none, ...ACTIONS.map(action => [action,
            ZT.t('zt.console.ui.action.' + action)])], answer.preferred || '');
        const classification = PQA.select(m('column.class'), CLASSES.map(value => [value, m('class.' + value)]),
            answer.classification || 'THREAT');
        const kind = PQA.select(m('column.kind'), KINDS.map(value => [value, m('kind.' + value)]),
            answer.kind || 'OUTSIDER');
        const grade = PQA.select(m('column.caseGrade'), GRADES.map(value => [value, m('grade.' + value)]),
            answer.grade || 'ORDINARY');
        const ko = el('textarea', {class: 'modern-input zt-textarea', rows: '2', maxlength: '2000',
            'aria-label': m('form.whyKo'), text: answer.rationaleKo || ''});
        const en = el('textarea', {class: 'modern-input zt-textarea', rows: '2', maxlength: '2000',
            'aria-label': m('form.whyEn'), text: answer.rationaleEn || ''});
        const facts = el('textarea', {class: 'modern-input zt-textarea', rows: '2', maxlength: '4000',
            'aria-label': m('detail.deciding'), placeholder: m('form.factsHint'),
            text: (answer.decidingFacts || []).join('\n')});
        const field = (name, node, wide) => el(wide ? 'div' : 'label', {class: 'zt-filter-field' + (wide ? ' pv-span-all'
            : '')}, el('span', {class: 'zt-filter-name', text: name}), node);
        const node = el('div', {class: 'zt-filter-grid pv-form-grid'},
            field(m('detail.answerAside'), checks, true), field(m('detail.best'), preferred),
            field(m('column.class'), classification), field(m('column.kind'), kind),
            field(m('column.caseGrade'), grade), field(m('form.whyKo'), ko, true), field(m('form.whyEn'), en, true),
            field(m('detail.deciding'), facts, true));
        const read = () => ({
            allowedActions: [...checks.querySelectorAll('input:checked')].map(box => box.value),
            preferred: preferred.value || null, classification: classification.value, kind: kind.value,
            rationaleKo: ko.value.trim() || null, rationaleEn: en.value.trim() || null,
            decidingFacts: facts.value.split('\n').map(line => line.trim()).filter(Boolean), grade: grade.value});
        return {node, read};
    }

    function answerOf(row, d) {
        return {allowed: row.allowed, preferred: row.preferred, classification: row.classification, kind: row.kind,
            grade: row.grade, rationaleKo: d ? d.rationaleKo : null, rationaleEn: d ? d.rationaleEn : null,
            decidingFacts: d ? d.decidingFacts : []};
    }

    /** Sends a change; on success a notice and the screen again, else the reason in the reader's words. */
    async function change(path, body, title, done, after) {
        const result = await PQA.send(path, body);
        if (result.ok) {
            PV.notice('good', done, []);
            if (after) {
                after(result.body);
            }
        } else {
            PV.notice('bad', title, [PQA.refused('pqa.cases.refused.', result)]);
        }
        return result;
    }

    /** Quality plan 3.2: a case of ours made from another case, its input changed or as it is. */
    async function createDialog(view, sourceKey) {
        let source = null;
        if (sourceKey) {
            try {
                source = await PQA.get('/' + encodeURIComponent(sourceKey));
            } catch (error) {
                PV.notice('bad', m('create.failed'), [ZT.t('pv.ui.loadFailed')]);
                return;
            }
        }
        const keys = view ? view.rows.map(row => [row.key, row.name]) : [[sourceKey, source.row.name]];
        const pick = PQA.select(m('create.source'), keys, sourceKey || (keys[0] ? keys[0][0] : ''));
        const fields = answerFields(source ? answerOf(source.row, source) : null);
        const inputText = el('textarea', {class: 'modern-input zt-textarea pv-text', rows: '10',
            'aria-label': m('create.input'), spellcheck: 'false'});
        const fold = el('details', {class: 'pv-prepared'}, el('summary', {class: 'zt-link', text: m('create.input')}));
        let loadedFor = null;
        fold.addEventListener('toggle', async () => {
            if (fold.open && loadedFor !== pick.value) {
                loadedFor = pick.value;
                try {
                    const kept = await PQA.get('/' + encodeURIComponent(pick.value) + '/input');
                    inputText.value = JSON.stringify(kept.input, null, 2);
                    inputText.dataset.original = inputText.value;
                } catch (error) {
                    inputText.value = '';
                }
            }
        });
        PV.fold(fold, el('div', {class: 'zt-stack mt-3'}, PQA.muted(m('create.inputNote')), inputText));
        const answer = await PV.confirm({title: m('create.title'), rows: [], confirmLabel: m('create'), icon: 'fa-plus',
            content: [el('div', {class: 'flex flex-col gap-3 mb-3'},
                el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: m('create.source')}),
                    pick), PQA.muted(m('foot')), fields.node, fold)]});
        if (!answer) {
            return;
        }
        let input = null;
        if (inputText.value && inputText.value !== inputText.dataset.original) {
            try {
                input = JSON.parse(inputText.value);
            } catch (unreadable) {
                PV.notice('bad', m('create.failed'), [m('refused.INVALID')]);
                return;
            }
        }
        await change('', {sourceKey: pick.value, input, answer: fields.read()}, m('create.failed'), m('create.done'),
            saved => global.location.assign(PQA.page(PAGES + '/' + encodeURIComponent(saved.key))));
    }

    /** Quality plan 3.2: a sealed decision as a case of the operation; the person's data is said before it is kept. */
    async function promoteDialog() {
        const id = el('input', {type: 'text', class: 'modern-input', maxlength: '128', 'aria-label': m('promote.id'),
            placeholder: m('promote.idHint')});
        const fields = answerFields(null);
        const answer = await PV.confirm({title: m('promote.title'), rows: [], confirmLabel: m('promote'),
            icon: 'fa-upload', content: [el('div', {class: 'flex flex-col gap-3 mb-3'},
                el('div', {class: 'zt-alert max-sm:!grid-cols-1', role: 'note'}, ZT.statusChip('WARN', m('detail.privacy')),
                    el('span', {text: m('detail.privacyLine')})),
                el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: m('promote.id')}), id),
                fields.node)]});
        if (!answer) {
            return;
        }
        await change('/promote', {packageId: id.value.trim(), answer: fields.read()}, m('promote.failed'),
            m('promote.done'), saved => global.location.assign(PQA.page(PAGES + '/' + encodeURIComponent(saved.key))));
    }

    async function answerDialog(d) {
        const fields = answerFields(answerOf(d.row, d));
        const answer = await PV.confirm({title: m('answer.title', d.row.name), rows: [], confirmLabel: m('action.answer'),
            icon: 'fa-pen', content: [el('div', {class: 'flex flex-col gap-3 mb-3'},
                d.twoPerson ? PQA.muted(m('answer.note')) : null, fields.node)]});
        if (!answer) {
            return;
        }
        await change('/' + encodeURIComponent(d.row.key) + '/answer', fields.read(), m('answer.failed'), m('answer.done'),
            () => drawDetail(d.row.key));
    }

    async function confirmDialog(row) {
        const answer = await PV.confirm({title: m('confirm.title', row.name), rows: [
            [m('column.answer'), row.allowed.map(action => ZT.t('zt.console.ui.action.' + action)).join(', ')],
            [m('column.caseGrade'), m('grade.' + row.grade)], [m('confirm.by'), row.labelledBy || '—']],
        content: [PQA.muted(m('confirm.note'))], confirmLabel: m('action.confirm'), icon: 'fa-user-check'});
        if (!answer) {
            return;
        }
        await change('/' + encodeURIComponent(row.key) + '/confirm', {}, m('confirm.failed'), m('confirm.done'), draw);
    }

    async function deleteDialog(row) {
        const answer = await PV.confirm({title: m('delete.title', row.name), rows: [[m('column.case'), row.key]],
            content: [PQA.muted(m('delete.note'))], confirmLabel: m('action.delete'), icon: 'fa-trash'});
        if (!answer) {
            return;
        }
        await change('/' + encodeURIComponent(row.key) + '/delete', {}, m('delete.failed'), m('delete.done'),
            () => global.location.assign(PQA.page(PAGES)));
    }

    async function publishDialog(view) {
        const answer = await PV.confirm({title: m('publish.title'), rows: [
            [m('publish.before'), view.bundle ? shortVersion(view.bundle.version) : m('band.noBundle')],
            [m('publish.added'), ZT.count(view.addedSince)]],
        content: [PQA.muted(m('band.note'))], confirmLabel: m('publish'), icon: 'fa-stamp'});
        if (!answer) {
            return;
        }
        const result = await PQA.send('/publish', {});
        if (result.ok) {
            PV.notice('good', m(result.body.same ? 'publish.same' : 'publish.done', shortVersion(result.body.bundle.version),
                ZT.count(result.body.bundle.cases)), []);
            drawList();
        } else {
            PV.notice('bad', m('publish.failed'), [PQA.refused('pqa.cases.refused.', result)]);
        }
    }

    function draw() {
        const key = root.dataset.caseKey;
        return key ? drawDetail(key) : drawList();
    }

    global.addEventListener('resize', PQA.fitChips);
    draw();
})(window);
