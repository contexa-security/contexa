/*
 * Prompt quality assurance: the sealed evidence (quality plan 3.7, 3.8), the two sealed prompt screens joined. The list
 * answers which decisions were sealed and whether their record is whole: the band (the period, the sealed count), four
 * key numbers, the filter box and the list with the three checks of the evidence audit. A decision answers what it was
 * made from: "replay" and "add as a case", the decision beside the audit of its record, what went into it (the prompt,
 * the facts, the answer) and its replays. The inspection again, the inspection of a period and the replay are those of
 * the sealed prompt screens. Load after console-common.js and pqa-parts.js.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const P = global.PQA;
    const root = document.getElementById('zt-console');
    if (!ZT || !P || !root) {
        return;
    }
    const el = ZT.el;
    const m = (key, ...args) => ZT.t('pqa.evidence.' + key, ...args);
    const content = document.getElementById('zt-content');
    const band = document.getElementById('zt-band');
    const api = root.dataset.apiBase;
    const pages = root.dataset.pagesBase;
    const inspectionApi = root.dataset.inspectionApi;
    const replayApi = root.dataset.replayApi;
    const packageId = root.dataset.packageId;

    /** The checks of the evidence audit in their order (plan 2.1): the code, the list's column and the key card's icon. */
    const CHECKS = [{code: 'SEAL_INTEGRITY', column: 'integrity', icon: 'fa-fingerprint'},
        {code: 'BUNDLE_TRACE', column: 'trace', icon: 'fa-route'},
        {code: 'SOURCE_TRUTH', column: 'source', icon: 'fa-database'}];
    const RESULT_STATUS = {OK: 'GOOD', MISMATCH: 'BAD', UNCHECKED: 'WARN'};
    const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];
    const RESULTS = ['PROBLEM', 'INTEGRITY', 'TRACE', 'SOURCE', 'UNCHECKED', 'WHOLE'];
    const FILTERS = ['action', 'version', 'result', 'user', 'block', 'entry'];
    const PAGE_SIZE = 20;

    /** The name of a check: one of the audit, or one an earlier inspector ran, as its stored result names it. */
    function checkName(code) {
        const key = 'pqa.evidence.check.' + code;
        return ZT.t(key) !== key ? ZT.t(key) : ZT.t('promptInspection.check.' + code);
    }

    function resultChip(result) {
        return ZT.statusChip(RESULT_STATUS[result] || 'WARN', m('result.' + (result || 'UNCHECKED')));
    }

    function actionChip(action) {
        return action ? ZT.chip(action) : ZT.statusChip(null, '—');
    }

    function target(row) {
        return [row.httpMethod, row.requestPath].filter(Boolean).join(' ') || '—';
    }

    function detailHref(id) {
        return P.scoped(pages + '/' + encodeURIComponent(id));
    }

    // ===== the list =====

    function listKpis(totals) {
        const tone = count => count > 0 ? 'red' : 'green';
        const card = (check, count, filter) => P.span(ZT.kpi({tone: tone(count), icon: check.icon,
            label: m('check.' + check.code), value: ZT.shortCount(count), sub: m('kpi.' + check.code + '.sub'),
            title: m('check.' + check.code + '.def'), href: P.address({result: filter, page: null})}), 3);
        return P.grid(P.span(ZT.kpi({tone: 'indigo', icon: 'fa-stamp', label: m('kpi.sealed'),
            value: ZT.shortCount(totals.sealed), sub: m('kpi.sealedSub', ZT.shortCount(totals.stopped),
                ZT.shortCount(totals.allowed)), title: m('kpi.sealedDef')}), 3),
        card(CHECKS[0], totals.integrity, 'INTEGRITY'), card(CHECKS[1], totals.trace, 'TRACE'),
        card(CHECKS[2], totals.source, 'SOURCE'));
    }

    /** The policy center's filter box: a choice per filter, the search of the request path, and the clearing. */
    function filterBox(page) {
        const params = ZT.query();
        const all = m('filter.all');
        const choice = (name, values, label) => {
            const current = params.get(name) || '';
            const options = values.slice();
            if (current && !options.includes(current)) {
                options.push(current);
            }
            const select = el('select', {class: 'modern-select', name, 'aria-label': m('filter.' + name)},
                el('option', {value: '', text: all}), options.map(value => el('option', {value,
                    text: label ? label(value) : value})));
            select.value = current;
            select.title = current ? select.options[select.selectedIndex].text : '';
            return P.field(m('filter.' + name), select);
        };
        const fields = [choice('action', ACTIONS, action => ZT.t('zt.console.ui.action.' + action)),
            choice('version', page.versions || []), choice('result', RESULTS, result => m('filter.result.' + result)),
            choice('user', [])];
        // The sealed prompt list filtered by a finding in a block, with an entry, or both: typed, as it was.
        const typed = ['block', 'entry'].map(name => el('input', {type: 'text', class: 'modern-input', name,
            maxlength: '128', placeholder: m('filter.' + name + 'Hint'), 'aria-label': m('filter.' + name),
            value: params.get(name) || ''}));
        typed.forEach(input => fields.push(P.field(m('filter.' + input.name), input)));
        const search = el('input', {type: 'search', class: 'modern-input', name: 'q', placeholder: m('filter.q'),
            'aria-label': m('filter.q'), value: params.get('q') || ''});
        const submit = P.button(m('filter.search'), 'fa-search', 'primary', {type: 'submit'});
        const clear = P.button(m('filter.clear'), 'fa-times', 'secondary');
        const formNode = el('form', {class: 'zt-filter-form', 'aria-label': m('filter.title')},
            el('div', {class: 'zt-filter-grid'}, fields), el('div', {class: 'zt-filter-search'}, search, submit, clear));
        formNode.addEventListener('change', event => {
            if (event.target && event.target.tagName === 'SELECT') {
                go({[event.target.name]: event.target.value, page: null});
            }
        });
        formNode.addEventListener('submit', event => {
            event.preventDefault();
            go({q: search.value.trim(), block: typed[0].value.trim(), entry: typed[1].value.trim(), page: null});
        });
        clear.addEventListener('click', () => {
            const cleared = {q: null, page: null};
            FILTERS.forEach(name => cleared[name] = null);
            go(cleared);
        });
        return el('div', {class: 'filter-container zt-filter-box'}, formNode);
    }

    function listTable(page) {
        const result = (value) => el('td', {class: 'zt-cell-chips zt-wide'}, resultChip(value));
        const rows = page.rows.map(row => {
            const who = ZT.time(row.capturedAt) + ' · ' + (row.userId || '—');
            const href = detailHref(row.packageId);
            const line = el('tr', {tabindex: '0', 'data-selectable': true, 'data-package': row.packageId},
                el('td', {title: who}, el('a', {class: 'zt-link', href},
                    el('span', {class: 'zt-long', text: who}),
                    el('span', {class: 'zt-short'}, el('span', {class: 'zt-line', text: ZT.shortTime(row.capturedAt)}),
                        el('span', {class: 'zt-line', text: row.userId || '—'})))),
                el('td', {class: 'zt-fill', title: target(row), text: target(row)}),
                el('td', {class: 'zt-cell-chips'}, actionChip(row.action)),
                el('td', {class: 'zt-wide', title: row.version || '—', text: row.version || '—'}),
                result(row.integrity), result(row.trace), result(row.source));
            line.addEventListener('keydown', event => {
                if (event.key === 'Enter') {
                    global.location.assign(href);
                }
            });
            return line;
        });
        const columns = [m('column.who'), m('column.target'), m('column.action'), m('column.version'),
            m('check.SEAL_INTEGRITY'), m('check.BUNDLE_TRACE'), m('check.SOURCE_TRUTH')];
        return el('div', {class: 'modern-table zt-table-wrap'}, el('table', {class: 'zt-table'},
            el('caption', {class: 'zt-sr-only', text: m('list.title')}),
            el('thead', {}, el('tr', {}, columns.map((label, index) => el('th', {scope: 'col',
                class: index >= 3 ? 'zt-wide' : null, text: label})))),
            el('tbody', {}, rows)));
    }

    function pager(page) {
        const first = page.total ? page.page * page.size + 1 : 0;
        const last = Math.min(page.total, (page.page + 1) * page.size);
        const previous = P.button(m('list.previous'), 'fa-chevron-left', 'secondary',
            {disabled: page.page <= 0 ? true : null});
        const next = el('button', {type: 'button', class: 'modern-btn-secondary',
            disabled: last >= page.total ? true : null}, el('span', {text: m('list.next')}),
        el('i', {class: 'fas fa-chevron-right', 'aria-hidden': 'true'}));
        previous.addEventListener('click', () => go({page: page.page - 1 > 0 ? page.page - 1 : null}));
        next.addEventListener('click', () => go({page: page.page + 1}));
        return el('div', {class: 'zt-card-foot'}, previous, next,
            P.muted(m('list.page', ZT.count(first), ZT.count(last), ZT.count(page.total))));
    }

    function go(changes) {
        global.history.replaceState(null, '', P.address(changes));
        drawList();
    }

    async function drawList() {
        const params = ZT.query();
        const period = P.range();
        const values = {from: period.from, to: period.to, page: params.get('page'), size: PAGE_SIZE,
            q: params.get('q')};
        FILTERS.forEach(name => values[name] = params.get(name));
        let page;
        try {
            page = await P.call(api + P.query(values));
        } catch (error) {
            band.replaceChildren();
            ZT.failed(content, error);
            return;
        }
        band.replaceChildren(el('span', {text: m('band.sealed', ZT.count(page.totals.sealed))}),
            ZT.info(m('band.note')));
        const list = ZT.card(m('list.title'), m('list.aside'), page.rows.length ? P.form('evidence-table',
            listTable(page)) : P.form('empty-state', P.emptyState(m('list.empty'), 'fa-stamp')));
        if (page.rows.length) {
            list.append(pager(page));
        }
        content.replaceChildren(listKpis(page.totals), filterBox(page), P.grid(P.span(list, 12)));
    }

    /** The automatic round inspects the period again; its progress is how many of the period's decisions are left. */
    async function reinspectPeriod(button) {
        const period = P.range();
        button.disabled = true;
        try {
            let status = await P.call(inspectionApi + '/reinspections', {method: 'POST', body: period});
            P.notice('note', m('reinspect.started', ZT.count(status.uninspected)));
            while (status.uninspected > 0) {
                await new Promise(resolve => global.setTimeout(resolve, 5000));
                status = await P.call(inspectionApi + '/reinspections' + P.query(period));
                if (status.uninspected > 0) {
                    P.notice('note', m('reinspect.progress', ZT.count(status.uninspected), ZT.count(status.packages)));
                }
            }
            await drawList();
            P.notice('good', m('reinspect.done', ZT.count(status.packages)));
        } catch (error) {
            P.notice('bad', m('reinspect.failed'));
        } finally {
            button.disabled = false;
        }
    }

    function startList() {
        const again = P.button(m('reinspect.period'), 'fa-sync-alt', 'secondary', {title: m('reinspect.periodTip'),
            'data-pqa-action': 'reinspect-period'});
        again.addEventListener('click', () => reinspectPeriod(again));
        root.querySelector('.zt-toolbar').replaceChildren(again);
        P.periods(document.getElementById('zt-period'), drawList, {custom: true});
        drawList();
    }

    // ===== a sealed decision =====

    // Plan 3.12 D7: the engine says a package of a version this build no longer ships cannot be inspected again; the
    // reader sees it in their words, as the sealed prompt detail showed it.
    const EARLIER_VERSION = '(decision D7)';

    /** The engine's reason of a finding, in the reader's words where the screens have them. */
    function reasonText(reason) {
        return typeof reason === 'string' && reason.includes(EARLIER_VERSION) ? m('finding.earlierVersion') : reason;
    }

    /** Whether a finding is a mismatch or could not be checked, in the reader's words; none for an unknown outcome. */
    function outcomeWord(outcome) {
        const key = 'pqa.evidence.finding.outcome.' + outcome;
        return outcome && ZT.t(key) !== key ? m('finding.outcome.' + outcome) : null;
    }

    function findingText(finding) {
        const place = [finding.block, finding.entry].filter(Boolean).join('.') + (finding.factId
            ? ' [' + finding.factId + ']' : '');
        const parts = [outcomeWord(finding.outcome), checkName(finding.checkCode) + (place ? ' · ' + place : '')]
            .filter(Boolean);
        if (finding.actual != null && finding.actual !== '') {
            parts.push(m('finding.actual', finding.actual));
        }
        if (finding.expected != null && finding.expected !== '') {
            parts.push(m('finding.expected', finding.expected));
        }
        if (finding.sourceRef) {
            parts.push(m('finding.source', finding.sourceRef));
        }
        if (finding.reason) {
            parts.push(m('finding.reason', reasonText(finding.reason)));
        }
        return parts.join(' · ');
    }

    function decisionSentence(detail) {
        const user = detail.userId || '—';
        return m('detail.sentence.' + (ACTIONS.includes(detail.action) ? detail.action : 'NONE'), user, target(detail));
    }

    function decisionCard(detail) {
        const rows = el('div', {class: 'zt-result-rows'}, [
            [m('column.who'), ZT.time(detail.capturedAt) + ' · ' + (detail.userId || '—')],
            [m('column.target'), target(detail) + (detail.resourceId ? ' (' + detail.resourceId + ')' : '')],
            [m('column.version'), detail.version || '—'],
            [m('detail.model'), detail.model || '—']].map(([label, value]) => el('div', {class: 'zt-result-row'},
            el('span', {class: 'zt-result-name', text: label}),
            el('span', {class: 'zt-result-value pv-wrap', text: value}))));
        return ZT.card(m('detail.decision'), m('detail.decisionAside'),
            P.form('decision-line', el('div', {class: 'zt-conclusion'}, actionChip(detail.action),
                el('strong', {class: 'min-w-0', style: {overflowWrap: 'anywhere'}, text: decisionSentence(detail)}))),
            P.form('decision-rows', rows),
            detail.reason ? el('figure', {class: 'zt-quote'}, el('figcaption', {text: m('detail.reason')}),
                el('blockquote', {text: detail.reason})) : null);
    }

    function storedText(inspection) {
        const stored = inspection.stored;
        return !stored ? m('detail.stored.none') : !stored.sameInspector ? m('detail.stored.other', stored.inspectorVersion)
            : stored.sameFindings ? m('detail.stored.same') : m('detail.stored.differs');
    }

    function historyBlock(inspection) {
        const history = inspection.history || [];
        if (!history.length) {
            return null;
        }
        const changes = inspection.changes;
        const table = el('div', {class: 'modern-table zt-table-wrap'}, el('table', {class: 'zt-table'},
            el('thead', {}, el('tr', {}, [[m('history.inspectedAt'), 'zt-num'], [m('history.inspector'), null],
                [m('history.dictionary'), 'zt-wide'], [m('history.verdict'), null], [m('history.mismatch'), 'zt-num'],
                [m('history.unverifiable'), 'zt-num'], [m('history.trigger'), 'zt-wide']].map(([label, cls]) =>
                el('th', {scope: 'col', class: cls, text: label})))),
            el('tbody', {}, history.map(row => el('tr', {},
                el('td', {class: 'zt-num', text: ZT.shortTime(row.inspectedAt)}),
                el('td', {text: row.inspectorVersion || '—'}),
                el('td', {class: 'zt-wide', text: row.dictionaryVersion || '—'}),
                el('td', {text: ZT.t('promptInspection.verdict.' + row.verdict)}),
                el('td', {class: 'zt-num', text: ZT.count(row.mismatchCount)}),
                el('td', {class: 'zt-num', text: ZT.count(row.unverifiableCount)}),
                el('td', {class: 'zt-wide', text: ZT.t('promptInspection.trigger.' + row.trigger)}))))));
        return el('details', {class: 'zt-item'}, el('summary', {class: 'zt-link', text: m('history.title',
            ZT.count(history.length))}), changes ? P.muted(m('history.changes', changes.comparedVersion,
            ZT.count((changes.disappeared || []).length), ZT.count((changes.appeared || []).length))) : null,
        ...(changes ? (changes.disappeared || []).map(finding => el('div', {class: 'zt-fact',
            text: m('history.gone', findingText(finding))})).concat((changes.appeared || []).map(finding =>
            el('div', {class: 'zt-fact', text: m('history.new', findingText(finding))}))) : []), table);
    }

    function wholeCard(detail) {
        const inspection = detail.inspection;
        const rows = el('div', {class: 'zt-result-rows'}, detail.checks.map(check => el('div',
            {class: 'zt-result-row', title: m('check.' + check.code + '.def') + ' ' + m('detail.counts',
                ZT.count(check.matched), ZT.count(check.mismatched), ZT.count(check.unverifiable)),
            'data-check': check.code},
            el('span', {class: 'zt-result-name', text: m('check.' + check.code)}), resultChip(check.result))));
        const notes = detail.checks.flatMap(check => check.findings.map(finding => el('div', {class: 'zt-fact',
            text: findingText(finding)})));
        const card = ZT.card(m('detail.whole'), m('detail.wholeAside'), P.form('check-badges', rows), ...notes,
            P.muted(m('detail.inspector', detail.packageId, inspection.inspectorVersion,
                inspection.dictionaryVersion || '—', inspection.layoutVersion || '—',
                ZT.t('promptInspection.verdict.' + inspection.verdict)) + ' · ' + storedText(inspection)),
            inspection.errorReason ? el('div', {class: 'zt-fact', text: m('detail.error', inspection.errorReason)})
                : null, historyBlock(inspection));
        const again = P.button(m('detail.reinspect'), 'fa-sync-alt', 'secondary', {'data-pqa-action': 'reinspect'});
        again.addEventListener('click', async () => {
            again.disabled = true;
            try {
                await P.call(inspectionApi + '/packages/' + encodeURIComponent(packageId) + '/reinspect',
                    {method: 'POST'});
                P.notice('good', m('detail.reinspected'));
                await drawDetail();
            } catch (error) {
                P.notice('bad', m('detail.reinspectFailed'));
                again.disabled = false;
            }
        });
        return P.foot(card, again);
    }

    /**
     * The lines of the user prompt the audit compared, each with the checks that matched it and the findings on it, as
     * the sealed prompt detail showed them line by line.
     */
    function matchedLines(inspection) {
        const lines = (inspection && inspection.lines ? inspection.lines : []).filter(line =>
            (line.matchedBy || []).length || (line.findings || []).length);
        if (!lines.length) {
            return P.muted(m('detail.noMatchedLines'));
        }
        return el('details', {class: 'zt-item', 'data-form': 'matched-lines'},
            el('summary', {class: 'zt-link', text: m('detail.matchedLines', ZT.count(lines.length))}),
            el('ul', {class: 'zt-rows'}, lines.map(line => el('li', {class: 'zt-fact flex items-start gap-3',
                'data-line': line.number},
            el('span', {class: 'zt-fact-id', text: String(line.number)}),
            el('span', {class: 'zt-item min-w-0'}, el('span', {class: 'zt-fact-value pv-wrap', text: line.text}),
                (line.matchedBy || []).length ? P.muted(m('detail.matchedBy', line.matchedBy.map(checkName).join(', ')))
                    : null,
                ...(line.findings || []).map(finding => el('span', {class: 'zt-muted', text: findingText(finding)})))))));
    }

    function insideCard(detail) {
        const prompt = el('div', {class: 'zt-item', style: {gap: '0.75rem'}},
            P.muted(m('detail.system')), el('pre', {class: 'pv-text', tabindex: '0', text: detail.systemPrompt || '—'}),
            P.muted(m('detail.user')), el('pre', {class: 'pv-text', tabindex: '0', text: detail.userPrompt || '—'}),
            matchedLines(detail.inspection));
        const facts = detail.facts.length ? el('ul', {class: 'zt-rows'}, detail.facts.map(fact => el('li',
            {class: 'zt-fact flex items-start gap-3', 'data-fact': fact.id},
            el('span', {class: 'zt-fact-id', text: fact.id}),
            el('span', {class: 'zt-item'}, el('span', {class: 'zt-fact-value', text: fact.label + ': ' + fact.value}),
                P.muted(m('detail.factBlock', fact.block || '—', ZT.count(fact.line))),
                ...fact.findings.map(finding => el('span', {class: 'zt-muted', text: findingText(finding)}))))))
            : P.emptyState(m('detail.noFacts'), 'fa-list');
        const hypothesis = detail.hypothesis ? ZT.t('zt.console.ui.decisions.hypothesis.' + detail.hypothesis)
            : m('detail.noHypothesis');
        const answer = el('div', {class: 'zt-item', style: {gap: '0.75rem'}},
            el('div', {class: 'zt-conclusion'}, actionChip(detail.action), el('strong', {class: 'min-w-0',
                style: {overflowWrap: 'anywhere'}, text: hypothesis})),
            el('div', {class: 'zt-fact', text: m('detail.cited', detail.citedFacts.length
                ? detail.citedFacts.join(', ') : '—')}),
            detail.reason ? el('figure', {class: 'zt-quote'}, el('figcaption', {text: m('detail.reason')}),
                el('blockquote', {text: detail.reason})) : null);
        return ZT.tabbedCard(m('detail.inside'), m('detail.insideAside'), [
            {label: m('detail.tab.prompt'), node: P.form('prompt-text', prompt)},
            {label: m('detail.tab.facts'), node: P.form('fact-rows', facts)},
            {label: m('detail.tab.answer'), node: P.form('answer-block', answer)}]);
    }

    function replayRow(replay) {
        return el('tr', {}, el('td', {class: 'zt-num', text: ZT.shortTime(replay.at)}),
            el('td', {class: 'zt-fill', title: replay.version || '—', text: replay.version || '—'}),
            el('td', {class: 'zt-cell-chips'}, replay.failure ? ZT.statusChip('BAD', m('replay.failedShort'))
                : actionChip(replay.action)),
            el('td', {class: 'zt-wide', text: replay.same == null ? '—' : m(replay.same ? 'replay.same' : 'replay.differs')}),
            el('td', {class: 'zt-num zt-wide', text: replay.elapsedMs != null ? ZT.seconds(replay.elapsedMs) : '—'}));
    }

    function replaysCard(detail, holder) {
        const body = el('tbody', {}, detail.replays.map(replayRow));
        const table = el('div', {class: 'modern-table zt-table-wrap'}, el('table', {class: 'zt-table'},
            el('caption', {class: 'zt-sr-only', text: m('replay.title')}),
            el('thead', {}, el('tr', {}, [[m('replay.at'), 'zt-num'], [m('column.version'), null],
                [m('column.action'), null], [m('replay.against'), 'zt-wide'], [m('replay.took'), 'zt-num zt-wide']]
                .map(([label, cls]) => el('th', {scope: 'col', class: cls, text: label})))), body));
        const empty = P.emptyState(m('replay.none'), 'fa-redo');
        table.hidden = !detail.replays.length;
        empty.hidden = detail.replays.length > 0;
        const card = ZT.card(m('replay.title'), m('replay.aside'), holder, P.form('replay-table', table), empty);
        const replay = P.button(m('replay.run'), 'fa-redo', 'refresh', {'data-pqa-action': 'replay'});
        replay.addEventListener('click', () => replayDecision(detail, holder, body, table, empty));
        const promote = P.button(m('promote.run'), 'fa-upload', 'secondary', {'data-pqa-action': 'promote-foot'});
        promote.addEventListener('click', () => promoteDecision(detail));
        return P.foot(card, replay, promote, P.muted(m('replay.note')));
    }

    /** The replay's answer as the sealed prompt detail showed it: integrity, action, reasons, model, time, baselines. */
    function replayResult(answer) {
        const result = answer.result || {};
        const telemetry = result.telemetry || {};
        const codes = (result.reasonCodes || []).map(code => [code.code, code.fact].filter(Boolean).join(' '))
            .join('; ');
        const rows = [[m('replay.integrity'), m('replay.integrity.' + answer.integrity)],
            [m('column.action'), result.action ? ZT.t('zt.console.ui.action.' + result.action) : null],
            [m('detail.reason'), result.reason], [m('replay.codes'), codes],
            [m('detail.model'), telemetry.model || telemetry.modelName],
            [m('replay.took'), result.elapsedMs != null ? ZT.seconds(result.elapsedMs) : null],
            [m('replay.baselines'), m('replay.baselines.' + answer.baselines)],
            [m('replay.failure'), result.failure]];
        (result.secondPasses || []).forEach(pass => rows.push([m('replay.secondPass', pass.requestedModel),
            [pass.action, pass.failure].filter(Boolean).join(' - ')]));
        return el('div', {class: 'zt-result-rows', 'data-form': 'replay-result'}, rows.filter(([, value]) => value != null
            && value !== '').map(([label, value]) => el('div', {class: 'zt-result-row'},
            el('span', {class: 'zt-result-name', text: label}),
            el('span', {class: 'zt-result-value pv-wrap', text: String(value)}))));
    }

    async function replayDecision(detail, holder, body, table, empty) {
        let bundles = [];
        try {
            bundles = await P.call(replayApi + '/replay-bundles');
        } catch (error) {
            P.notice('bad', m('replay.unavailable'));
            return;
        }
        const version = el('select', {class: 'modern-select', name: 'bundleVersion'},
            (bundles || []).map(bundle => el('option', {value: bundle, text: bundle})));
        if (detail.version && (bundles || []).includes(detail.version)) {
            version.value = detail.version;
        }
        const models = el('input', {type: 'text', class: 'modern-input', name: 'secondPassModels',
            placeholder: m('replay.modelsHint')});
        const asked = await P.dialog({title: m('replay.confirmTitle'),
            rows: [[m('column.who'), ZT.time(detail.capturedAt) + ' · ' + (detail.userId || '—')],
                [m('replay.original'), detail.action ? ZT.t('zt.console.ui.action.' + detail.action) : '—']],
            content: [el('div', {class: 'zt-filter-grid'}, P.field(m('column.version'), version),
                P.field(m('replay.models'), models)), P.muted(m('replay.confirm'))],
            confirmLabel: m('replay.run'), cancelLabel: m('dialog.cancel'), icon: 'fa-redo',
            check: () => Boolean(version.value)});
        if (!asked) {
            return;
        }
        const secondPassModels = models.value.split(',').map(model => model.trim()).filter(Boolean);
        holder.replaceChildren(P.muted(m('replay.running')));
        try {
            const answer = await P.call(replayApi + '/packages/' + encodeURIComponent(detail.packageId) + '/replay',
                {method: 'POST', body: {bundleVersion: version.value, secondPassModels}});
            holder.replaceChildren(replayResult(answer));
            const result = answer.result || {};
            body.prepend(replayRow({at: new Date().toISOString(), version: version.value, action: result.action,
                same: result.action && detail.action ? result.action === detail.action : null,
                elapsedMs: result.elapsedMs, failure: result.failure}));
            table.hidden = false;
            empty.hidden = true;
        } catch (error) {
            holder.replaceChildren();
            P.notice('bad', m(error.status === 503 ? 'replay.unavailable' : 'replay.failed'));
        }
    }

    /** The right answer of the decision as a labelled case (plan 3.6); a decision that is not sealed is refused. */
    async function promoteDecision(detail) {
        const answer = global.PQA_CASE_ANSWER.fields({action: detail.action});
        const asked = await P.dialog({title: m('promote.title'),
            rows: [[m('column.who'), ZT.time(detail.capturedAt) + ' · ' + (detail.userId || '—')],
                [m('replay.original'), detail.action ? ZT.t('zt.console.ui.action.' + detail.action) : '—']],
            content: [answer.node, P.muted(m('promote.note'))],
            confirmLabel: m('promote.run'), cancelLabel: m('dialog.cancel'), icon: 'fa-upload',
            check: answer.check});
        if (!asked) {
            return;
        }
        try {
            const done = await P.call(api + '/' + encodeURIComponent(detail.packageId) + '/case'
                + P.query({scope: ZT.query().get('scope')}), {method: 'POST', body: answer.read()});
            P.notice('good', m('promote.done'), global.PQA_CASE_ANSWER.doneLines(done));
        } catch (error) {
            P.notice('bad', m('promote.failed'), [global.PQA_CASE_ANSWER.refusal(error.body)]);
        }
    }

    function crumbs(detail) {
        const title = document.getElementById('pv-title');
        const node = el('nav', {class: 'pv-crumbs', id: 'pv-crumbs', 'aria-label': m('crumbs')},
            el('a', {class: 'zt-link', href: P.scoped(pages), text: m('title')}),
            el('span', {class: 'zt-muted', text: ' › ' + (detail ? ZT.time(detail.capturedAt) + ' · '
                + (detail.userId || '—') : m('detail.notFound'))}));
        const known = document.getElementById('pv-crumbs');
        if (known) {
            known.replaceWith(node);
        } else {
            title.before(node);
        }
    }

    async function drawDetail() {
        let detail;
        try {
            detail = await P.call(api + '/' + encodeURIComponent(packageId));
        } catch (error) {
            crumbs(null);
            band.replaceChildren(P.muted(error.status === 404 ? m('detail.notFound') : ''));
            if (error.status === 404) {
                content.replaceChildren(P.emptyState(m('detail.notFound'), 'fa-stamp'));
            } else {
                ZT.failed(content, error);
            }
            return;
        }
        crumbs(detail);
        band.replaceChildren(actionChip(detail.action),
            el('span', {text: m('band.version', detail.version || '—')}),
            el('span', {text: m('band.sealedAt', ZT.time(detail.capturedAt))}),
            detail.stage === 'SHADOW' ? el('span', {class: 'zt-band-note', text: m('band.shadow')}) : null,
            ZT.info(m('band.note')));
        const replay = P.button(m('replay.run'), 'fa-redo', 'refresh', {'data-pqa-action': 'replay-top'});
        const promote = P.button(m('promote.run'), 'fa-upload', 'primary', {'data-pqa-action': 'promote'});
        const holder = el('div', {class: 'zt-item'});
        const replays = replaysCard(detail, holder);
        replay.addEventListener('click', () => replays.querySelector('[data-pqa-action="replay"]').click());
        promote.addEventListener('click', () => promoteDecision(detail));
        root.querySelector('.zt-toolbar').replaceChildren(replay, promote);
        content.replaceChildren(P.grid(P.span(decisionCard(detail), 8), P.span(wholeCard(detail), 4)),
            P.grid(P.span(insideCard(detail), 12)), P.grid(P.span(replays, 12)));
    }

    if (packageId) {
        // A decision is no period: the band holds what it is, without the period buttons.
        document.getElementById('zt-period').hidden = true;
        drawDetail();
    } else {
        startList();
    }
})(window);
