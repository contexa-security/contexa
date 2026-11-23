/*
 * Measure and compare, the wrong cases and their causes (quality plan 3.5): what went wrong and why. The wrong answers of
 * a measurement, with the decisions rated inadequate in operation when asked, put down to the seven causes by the rules
 * of the causes: a tile per cause with its count, where it is fixed and the condition it is computed under; the answers
 * of the cause chosen, with the actions given and the right answer, each put down to another cause by an administrator;
 * and the answers a new prompt version fixes taken beside the version editor. A view of the screen registered in
 * PQA_MEASURE.views. Load after measure.js.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const PV = global.PV;
    const PQA = global.PQA;
    const MEASURE = global.PQA_MEASURE;
    const root = document.getElementById('zt-console');
    const content = document.getElementById('zt-content');
    if (!ZT || !PV || !PQA || !MEASURE || !root || !content) {
        return;
    }
    const el = ZT.el;
    const c = (key, ...args) => ZT.t('pqa.causes.' + key, ...args);
    /** The fix that opens the version editor beside the wrong cases (QualityCauseFix.opensVersionEditor). */
    const EDITOR_FIX = 'PROMPT_VERSION';
    /** The causes an administrator can put an answer down to; only a decision is put down to an input error. */
    const RULED = ['FORMAT_AND_MODEL', 'ENGINE_CHANGED', 'INPUT_ERROR', 'INPUT_SHORTAGE', 'GROUNDING_ERROR', 'UNSTABLE',
        'JUDGEMENT_ERROR'];

    async function drawCauses() {
        const id = root.dataset.measureId;
        const withDecisions = PQA.params().get('decisions') !== 'false';
        const [, view] = await Promise.all([MEASURE.band(), PQA.get((id ? '/' + id : '/run') + '/causes',
            {decisions: withDecisions ? null : 'false'}).catch(error => error)]);
        if (!view || view instanceof Error) {
            content.replaceChildren(view && view.status === 404 ? PQA.emptyState(MEASURE.m('run.empty'),
                'fa-balance-scale') : PQA.failed());
            return;
        }
        const pick = pickBox(view, withDecisions);
        if (!view.rows.length) {
            content.replaceChildren(pick, PQA.emptyState(c('empty'), 'fa-check-circle'));
            return;
        }
        const asked = PQA.params().get('cause');
        const counted = view.tiles.filter(tile => tile.count > 0);
        const first = counted.slice().sort((one, other) => other.count - one.count)[0];
        let selected = view.tiles.some(tile => tile.cause === asked && tile.count > 0) ? asked : first.cause;
        const rowsHolder = el('div', {class: 'zt-stack'});
        const tiles = tilesCard(view, () => selected, key => {
            selected = key;
            global.history.replaceState(null, '', global.location.pathname + PQA.kept({view: 'causes',
                decisions: withDecisions ? null : 'false', cause: key}));
            tiles.querySelectorAll('[data-cause]').forEach(tile => {
                const on = tile.dataset.cause === key;
                tile.classList.toggle('ring-1', on);
                tile.classList.toggle('ring-indigo-400', on);
                tile.setAttribute('aria-current', on ? 'true' : 'false');
            });
            rowsHolder.replaceChildren(PQA.grid(PQA.span(rowsCard(view, key), 12)));
            PQA.fitChips();
        });
        rowsHolder.replaceChildren(PQA.grid(PQA.span(rowsCard(view, selected), 12)));
        content.replaceChildren(pick, PQA.grid(PQA.span(tiles, 12)), rowsHolder);
        PQA.fitChips();
    }

    /** The measurement to read and whether the decisions rated inadequate in operation come with it. */
    function pickBox(view, withDecisions) {
        const options = view.picks.map(pick => [pick.id, MEASURE.m('run.pickOption', pick.version,
            String(pick.caseSetVersion).slice(0, 8), pick.repeats, ZT.shortTime(pick.createdAt))]);
        if (!view.picks.some(pick => pick.id === view.measureId)) {
            options.unshift([view.measureId, MEASURE.m('run.pickOption', view.version,
                String(view.caseSetVersion).slice(0, 8), view.repeats, ZT.shortTime(view.createdAt))]);
        }
        const node = PQA.select(MEASURE.m('run.pick'), options, view.measureId);
        node.addEventListener('change', () => global.location.assign(PQA.page(MEASURE.PAGES + '/' + node.value,
            {view: 'causes', decisions: withDecisions ? null : 'false'})));
        const box = el('input', {type: 'checkbox', checked: withDecisions ? true : null, 'data-pqa': 'with-decisions'});
        box.addEventListener('change', () => global.location.assign(global.location.pathname + PQA.kept({view: 'causes',
            decisions: box.checked ? null : 'false'})));
        const toggle = el('label', {class: 'pv-toggle', title: c('withDecisionsTip', ZT.day(view.decisionsFrom),
            ZT.day(view.decisionsTo))}, box, el('span', {text: withDecisions ? c('withDecisions', ZT.count(view.decisions))
            : c('withDecisionsOff')}));
        return PQA.filterBox([{name: MEASURE.m('run.pick'), node}], toggle,
            view.decisionsWithoutRecord ? PQA.muted(c('withoutRecord', ZT.count(view.decisionsWithoutRecord))) : null);
    }

    /** The condition a cause is computed under, as the view states it (plan 3.5). */
    function condition(tile, view) {
        if (!tile.conditional) {
            return null;
        }
        if (tile.cause === 'FORMAT_AND_MODEL') {
            return view.timeLimitMillis > 0 ? c('cause.FORMAT_AND_MODEL.when', ZT.seconds(view.timeLimitMillis))
                : c('cause.FORMAT_AND_MODEL.whenUnknown');
        }
        return c('cause.' + tile.cause + '.when');
    }

    /** A tile per cause: its name, its count (or that it was not computed), where it is fixed and its condition. */
    function tilesCard(view, current, onPick) {
        const total = view.rows.length;
        const tiles = view.tiles.map(tile => {
            const notComputed = tile.count === 0 && tile.notComputed > 0;
            const chip = notComputed ? ZT.statusChip(null, c('notComputed'))
                : ZT.statusChip(tile.count > 0 ? 'WARN' : 'GOOD', c('count', ZT.shortCount(tile.count)));
            const on = tile.cause === current();
            const node = el(tile.count > 0 ? 'button' : 'div', {type: tile.count > 0 ? 'button' : null,
                class: 'zt-tile flex flex-col items-start gap-2 min-w-0 text-left' + (on ? ' ring-1 ring-indigo-400' : ''),
                'data-cause': tile.cause, 'aria-current': on ? 'true' : 'false', title: c('cause.' + tile.cause + '.def')},
            el('span', {class: 'font-semibold', style: {color: ZT.COLORS.TEXT}, text: c('cause.' + tile.cause)}), chip,
            tile.fix ? el('span', {class: 'zt-muted', text: c('fix', c('fix.' + tile.fix))}) : null,
            condition(tile, view) ? el('span', {class: 'zt-muted', text: condition(tile, view)}) : null,
            tile.notComputed > 0 && !notComputed ? el('span', {class: 'zt-muted', text: c('notComputedLine',
                ZT.count(tile.notComputed))}) : null);
            if (tile.count > 0) {
                node.addEventListener('click', () => onPick(tile.cause));
            }
            return node;
        });
        return ZT.card(c('classes'), c('classesAside', ZT.count(total)), PQA.form('cause-tiles',
            el('div', {class: 'grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3'}, tiles)));
    }

    /** The answers of the cause chosen, each with the actions given, the right answer and the change of its cause. */
    function rowsCard(view, cause) {
        const rows = view.rows.filter(row => row.cause === cause);
        const tile = view.tiles.find(one => one.cause === cause) || {};
        const body = el('tbody', {}, rows.map(row => el('tr', {'data-cause-id': row.id},
            el('td', {class: 'zt-fill', title: row.name}, el('div', {class: 'zt-item'}, nameNode(row),
                row.corrected ? PQA.muted(c('corrected', row.ruleCause ? c('cause.' + row.ruleCause) : '—')) : null)),
            PQA.chipCell(row.given),
            row.allowed.length ? PQA.chipCell(row.allowed, true) : el('td', {class: 'zt-wide zt-muted',
                text: c('noAnswer')}),
            el('td', {class: 'pv-cell-actions zt-wide'}, el('div', {class: 'pv-row-actions'},
                el('a', {class: 'zt-link pv-row-action', href: '#', 'data-pqa': 'reclass',
                    text: c('reclass')}))))));
        body.querySelectorAll('[data-pqa="reclass"]').forEach((link, index) => link.addEventListener('click', event => {
            event.preventDefault();
            reclassDialog(rows[index]);
        }));
        const card = ZT.card(c('cause.' + cause), c('selectedAside', ZT.count(rows.length),
            tile.fix ? c('fix.' + tile.fix) : '—'), PQA.form('cause-cases', PQA.table([{label: c('column.case')},
            {label: c('column.given')}, {label: c('column.answer'), wide: true}, {label: c('column.class'), wide: true}],
        body, c('cause.' + cause))));
        const handoff = tile.fix === EDITOR_FIX && rows.some(row => row.source === 'MEASUREMENT')
            ? PQA.button(c('handoff'), 'fa-pen', 'primary', {href: PQA.page(root.dataset.pagesBase + '/new',
                {base: view.versionNumber, causesOf: view.measureId}), 'data-pqa': 'handoff'}) : null;
        card.append(el('div', {class: 'zt-card-foot'}, handoff, PQA.muted(c('reclassNote'))));
        return card;
    }

    /** A case by its name and run, or a decision of the operation with the way to its detail. */
    function nameNode(row) {
        if (row.source === 'DECISION') {
            return el('div', {class: 'zt-item'}, row.observationId ? el('a', {class: 'zt-link pv-cut',
                href: '/contexa/admin/zero-trust/decisions/' + encodeURIComponent(row.observationId), text: row.name})
                : el('span', {class: 'pv-cut', text: row.name}), PQA.muted(c('fromDecision')));
        }
        return el('span', {class: 'pv-cut', text: row.run && row.run > 1 ? c('caseRun', row.name, row.run) : row.name});
    }

    /** An administrator puts the answer down to another cause; the rules never overwrite it. */
    async function reclassDialog(row) {
        const choices = RULED.filter(cause => row.source === 'DECISION' || cause !== 'INPUT_ERROR');
        const pick = PQA.select(c('reclassTo'), choices.map(cause => [cause, c('cause.' + cause)]), row.cause);
        const answer = await PV.confirm({title: c('reclassTitle', row.name),
            rows: [[c('column.class'), c('cause.' + row.cause)], [c('ruleClass'),
                row.ruleCause ? c('cause.' + row.ruleCause) : '—']],
            content: [el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: c('reclassTo')}),
                pick), PQA.muted(c('reclassNote'))],
            confirmLabel: c('reclass'), icon: 'fa-tag'});
        if (!answer) {
            return;
        }
        const result = await PQA.send('/causes/' + row.id + '/category', {category: pick.value});
        if (result.ok) {
            PV.notice('good', c('reclassDone', c('cause.' + pick.value)), []);
            drawCauses();
        } else {
            PV.notice('bad', c('reclassFailed'), [PQA.refused('pqa.causes.refused.', result)]);
        }
    }

    MEASURE.views.causes = drawCauses;
})(window);
