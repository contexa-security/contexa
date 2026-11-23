/*
 * Prompt quality assurance, measure and compare (quality plan 3.3, 3.8, quality P46): is the new version better than
 * the one in use. The list and the start of the measurements (on the labelled cases, or on the latest sealed decisions,
 * the trial of the version screens), the result of one measurement on both bases and by resource grade, and the
 * comparison of two versions as the quality gate makes it. The views of the screen are its tab bar, which the server
 * draws from its one list of views (PromptQualityMeasureScreen.VIEWS); each view's page is drawn by the function
 * registered under its name in PQA_MEASURE.views, so a view added to the list registers its own here.
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
    const m = (key, ...args) => ZT.t('pqa.measure.' + key, ...args);
    const caseWord = (key, ...args) => ZT.t('pqa.cases.' + key, ...args);
    const PAGES = '/contexa/admin/prompt-quality/measure';
    const RUN_STATUS = {DONE: 'GOOD', RUNNING: 'WARN', INCOMPLETE: 'WARN', QUEUED: null, CANCELLED: null, FAILED: 'BAD'};
    const VERDICT_STATUS = {BETTER: 'GOOD', SAME: null, WORSE: 'BAD', UNDECIDABLE: 'WARN'};
    const SPLIT_STATUS = {NEW_MISS: 'BAD', NEW_CATCH: 'GOOD', NEW_STOP: 'WARN', NEW_PASS: null};
    const STATE_STATUS = {MEASURED: 'GOOD', MISSING: 'WARN', STALE: 'WARN', UNMEASURABLE: 'BAD', BASELINE_PENDING: 'WARN',
        NONE: null};
    const resourceGrade = key => key === 'ALL' ? m('grade.ALL') : PQA.word('pqa.cases.resGrade.' + key, key);
    const versionNumber = name => {
        const found = /^v?(\d+)(\.0)?$/i.exec(String(name || ''));
        return found ? Number(found[1]) : null;
    };

    // ----- numbers: a ratio with its counts and its 95% range -----

    function percentOf(value) {
        return value && value.n ? ZT.percent(value.k / value.n, 1) : '—';
    }

    function countsOf(value) {
        return value && value.n != null ? ZT.shortCount(value.k) + ' / ' + ZT.shortCount(value.n) : '—';
    }

    function rangeOf(value) {
        return value && value.lo != null ? m('range', ZT.percent(value.lo, 1), ZT.percent(value.hi, 1)) : '—';
    }

    /** The line under a key number: its counts and its 95% range (only the upper bound when nothing was counted). */
    function ratioSub(value) {
        if (!value || !value.n) {
            return m('metric.none');
        }
        return value.k === 0 ? m('kpi.upperSub', countsOf(value), ZT.percent(value.hi, 1))
            : m('kpi.rangeSub', countsOf(value), rangeOf(value));
    }

    /** A metric's definition with the roots its 95% range counts (plan 3.3: the range is by distinct root cases). */
    function definitionOf(metric) {
        return m('metric.' + metric.key + '.def') + (metric.roots ? ' ' + m('metric.rootsNote', ZT.count(metric.roots))
            : '');
    }

    function metricKpi(metric, tone, icon) {
        return PQA.kpi({tone, icon, label: m('metric.' + metric.key), value: percentOf(metric), sub: ratioSub(metric),
            title: definitionOf(metric)});
    }

    // ----- the band, the tabs -----

    /**
     * The model setting decisions are measured under, with the note that a measurement waits behind decisions. The
     * model is the one that answers: a layer's own, else the primary chat model's (K196).
     */
    async function band() {
        let b = null;
        try {
            b = await PQA.get('/band');
        } catch (error) {
            b = null;
        }
        PQA.band(b && b.settingsHash ? el('span', {text: m('band.model', b.model || m('modelUnknown'))})
            : el('span', {text: m('band.noRunner')}),
            b && b.minimumAction ? el('span', {text: m('band.minimumAction', b.minimumAction)}) : null,
            b && b.settingsHash ? el('span', {title: b.settingsHash, text: m('band.setting', String(b.settingsHash)
                .slice(0, 8))}) : null,
            ZT.info(m('band.note')));
        return b;
    }

    /** The tabs the server drew open their view's page, with the scope kept. */
    function tabs() {
        document.querySelectorAll('#pqa-views [role="tab"][data-href]').forEach(tab => {
            tab.addEventListener('click', () => global.location.assign(tab.dataset.href));
        });
    }

    // ----- the list and the start -----

    async function drawRuns() {
        const [, view] = await Promise.all([band(), PQA.get('', {page: PQA.params().get('page') || null})
            .catch(() => null)]);
        if (!view) {
            content.replaceChildren(PQA.failed());
            return;
        }
        const parts = [startBox(view)];
        if (view.running.length) {
            parts.push(PQA.grid(PQA.span(runningCard(view.running), 12)));
        }
        parts.push(PQA.grid(PQA.span(listCard(view), 12)));
        content.replaceChildren(...parts);
        const alongside = global.PQA_TRIALS ? await global.PQA_TRIALS.shadowCard() : null;
        if (alongside) {
            content.append(alongside);
        }
    }

    /**
     * The start of a measurement. Its input is the published bundle of labelled cases (graded against the answers) or
     * the latest sealed decisions, the trial of the version screens: the version to try, the one to compare with and
     * 20, 50 or 100 decisions, with the trial's own note.
     */
    function startBox(view) {
        const sealed = PQA.params().get('input') === 'sealed' && global.PQA_TRIALS;
        const inputs = [['cases', m('input.CASES')]];
        if (global.PQA_TRIALS) {
            inputs.push(['sealed', m('input.SEALED')]);
        }
        const inputField = {name: m('start.input'), span: true, node: PQA.pills(m('start.input'), inputs,
            sealed ? 'sealed' : 'cases', key => global.location.assign(PQA.page(PAGES, {input: key === 'sealed'
                ? 'sealed' : null})))};
        const modelField = {name: m('start.model'), node: el('input', {class: 'modern-input', type: 'text', readonly: true,
            value: view.band.model || (view.band.settingsHash ? m('modelUnknown') : '—'),
            'aria-label': m('start.model'), title: view.band.settingsHash || null})};
        if (sealed) {
            return global.PQA_TRIALS.startBox(view, inputField, modelField);
        }
        const s = view.start;
        const versionOptions = s.versions.map(option => [option.number, option.name
            + (option.state === 'USED' ? ' ' + m('start.inUse') : '')]);
        // The version asked (the "measure" button of the version screens), else the newest one not in use.
        const asked = s.versions.find(option => String(option.number) === String(root.dataset.candidate || ''));
        const first = asked || s.versions.find(option => option.state !== 'USED') || s.versions[0];
        const version = PQA.select(m('start.version'), versionOptions, first ? first.number : '');
        const bundle = PQA.select(m('start.bundle'), s.caseSets.map(set => [set.id, m('start.bundleOption',
            String(set.version).slice(0, 8), ZT.count(set.cases))]), s.caseSets.length ? s.caseSets[0].id : '');
        const repeats = PQA.select(m('start.repeats'), s.repeats.map(n => [n, m('start.times', n)]), s.defaultRepeats);
        // Quality P32: measured anew, no kept answer is used again; two such measurements give the gate its noise.
        const anew = el('input', {type: 'checkbox', 'data-pqa-field': 'anew'});
        const anewField = {name: m('start.answers'), node: el('span', {class: 'pv-toggle'}, anew,
            el('span', {text: m('start.anew')}))};
        const note = el('div', {class: 'zt-item'});
        const none = !view.measurable || !s.versions.length;
        const go = PQA.button(m('start.go'), 'fa-play', 'primary', {disabled: none ? true : null,
            'data-pqa-action': 'start'}, async () => {
            go.disabled = true;
            const result = await PQA.send('', {version: Number(version.value), caseSet: bundle.value
                ? Number(bundle.value) : null, repeats: Number(repeats.value), anew: anew.checked});
            go.disabled = false;
            if (result.ok) {
                PV.notice('good', m('start.done'), []);
                drawRuns();
            } else {
                PV.notice('bad', m('start.failed'), [PQA.refused('pqa.measure.refused.', result)]);
            }
        });
        const showEstimate = estimate => {
            note.replaceChildren();
            if (!view.measurable) {
                note.append(PQA.muted(m('start.noRunner')));
                return;
            }
            if (!estimate || none) {
                note.append(PQA.muted(m('start.nothing')));
                return;
            }
            if (estimate.refusal && estimate.refusal !== 'CALL_LIMIT') {
                note.append(PQA.muted(PQA.word('pqa.measure.refused.' + estimate.refusal, m('start.nothing'))));
                go.disabled = true;
                return;
            }
            go.disabled = !estimate.withinLimit;
            note.append(PQA.muted(m('start.calls', ZT.count(estimate.cases), ZT.count(estimate.repeats),
                ZT.count(estimate.replays), ZT.count(estimate.minutes), estimate.callLimit
                    ? ZT.count(estimate.callLimit) : m('start.noLimit'))));
            if (estimate.reusable) {
                note.append(PQA.muted(m('start.reused', ZT.count(estimate.reusable))));
            }
            if (anew.checked) {
                note.append(PQA.muted(m('start.anewNote')));
            }
            if (!estimate.withinLimit) {
                note.append(PQA.muted(m('refused.CALL_LIMIT')));
            }
        };
        const refresh = async () => {
            if (none) {
                showEstimate(null);
                return;
            }
            try {
                showEstimate(await PQA.get('/estimate', {version: version.value, caseSet: bundle.value || null,
                    repeats: repeats.value, anew: anew.checked ? true : null}));
            } catch (error) {
                showEstimate(null);
            }
        };
        [version, bundle, repeats, anew].forEach(node => node.addEventListener('change', refresh));
        showEstimate(s.estimate);
        return PQA.filterBox([inputField, {name: m('start.version'), node: version},
            {name: m('start.bundle'), node: bundle}, {name: m('start.repeats'), node: repeats}, modelField, anewField],
        go, note);
    }

    function runningCard(running) {
        const rows = running.map(r => {
            const label = m('running.label', r.version, String(r.caseSetVersion).slice(0, 8), r.repeats);
            const cancel = PQA.button(m('running.cancel'), 'fa-stop', 'secondary', {'data-pqa-action': 'cancel'},
                async () => {
                    const answer = await PV.confirm({title: m('running.cancelTitle', label), rows: [[m('running.progress'),
                        ZT.count(r.answered) + ' / ' + ZT.count(r.planned)]], confirmLabel: m('running.cancel'),
                    icon: 'fa-stop'});
                    if (!answer) {
                        return;
                    }
                    const result = await PQA.send('/' + r.id + '/cancel', {});
                    if (!result.ok || !result.body || !result.body.cancelled) {
                        PV.notice('bad', m('running.cancelFailed'), [PQA.refused('pqa.measure.refused.', result)]);
                    }
                    drawRuns();
                });
            return el('div', {class: 'zt-stack'}, PQA.form('progress', el('div', {class: 'zt-reason-row'},
                el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: label}),
                    el('span', {class: 'zt-reason-value', title: ZT.count(r.answered) + ' / ' + ZT.count(r.planned),
                        text: m('running.done', ZT.shortCount(r.answered), ZT.shortCount(r.planned),
                            ZT.percent(r.planned ? r.answered / r.planned : null, 0))})),
                ZT.bar(r.answered, r.planned, {label}))),
            el('div', {class: 'zt-card-foot'}, cancel, PQA.muted(r.status === 'QUEUED' ? m('run.QUEUED')
                : m('running.left', ZT.count(r.minutesLeft)))));
        });
        return ZT.card(m('running.title'), m('running.aside'), ...rows);
    }

    function listCard(view) {
        const list = ZT.card(m('list.title'), m('list.aside'));
        const body = list.querySelector('.zt-card-body');
        if (!view.rows.length) {
            body.append(PQA.form('empty-state', PQA.emptyState(m('list.empty'), 'fa-balance-scale')));
            return list;
        }
        body.append(PQA.form('run-table', PQA.table([
            {label: m('column.version')}, {label: m('column.input'), wide: true},
            {label: m('column.status')}, {label: m('column.result')},
            {label: m('column.started'), wide: true}, {label: caseWord('column.work'), wide: true}],
        el('tbody', {}, view.rows.map(runRow)), m('list.title'))));
        return PQA.withFoot(list, pager(view));
    }

    /** The foot of a list read page by page from the server: the previous and next buttons and the rows shown. */
    function pager(view) {
        const firstRow = view.page * view.size + 1;
        const lastRow = view.page * view.size + view.rows.length;
        const previous = PQA.button(ZT.t('pv.ui.previous'), 'fa-chevron-left', 'secondary',
            {disabled: view.page === 0 ? true : null}, () => global.location.assign(PQA.page(PAGES,
                {page: view.page - 1 || null})));
        const next = el('button', {type: 'button', class: 'modern-btn-secondary', disabled: lastRow >= view.total ? true
            : null}, el('span', {text: ZT.t('pv.ui.next')}), el('i', {class: 'fas fa-chevron-right', 'aria-hidden': 'true'}));
        next.addEventListener('click', () => global.location.assign(PQA.page(PAGES, {page: view.page + 1})));
        const foot = el('div', {class: 'zt-card-foot'}, previous, next, PQA.muted(ZT.t('pv.ui.page', ZT.count(firstRow),
            ZT.count(lastRow), ZT.count(view.total))));
        foot.hidden = view.total <= view.size;
        return foot;
    }

    /** A measurement on a bundle shows its misses and false stops, one on sealed decisions what it can. */
    function runRow(run) {
        const incomplete = run.status === 'DONE' && run.incomplete > 0;
        const status = incomplete ? 'INCOMPLETE' : run.status;
        const text = status === 'RUNNING' && run.progress != null ? m('run.RUNNING', ZT.percent(run.progress, 0))
            : status === 'INCOMPLETE' ? m('run.INCOMPLETE', ZT.count(run.incomplete)) : m('run.' + status);
        const sealed = run.kind === 'SEALED';
        let lines = null;
        let whole = null;
        if (sealed && run.pairs) {
            lines = [m('result.same', ZT.count(run.same) + ' / ' + ZT.count(run.pairs)),
                m('result.format', ZT.count(run.formatErrors))];
            whole = ZT.count(run.same) + ' / ' + ZT.count(run.pairs);
        } else if (!sealed && run.miss) {
            lines = [m('result.miss', percentOf(run.miss)), m('result.falseStop', percentOf(run.falseStop))];
            whole = countsOf(run.miss) + ' · ' + countsOf(run.falseStop);
        }
        const actions = el('div', {class: 'pv-row-actions'});
        if (sealed) {
            actions.append(el('a', {class: 'zt-link pv-row-action', href: PQA.page(PAGES + '/trials/' + run.id),
                text: m('action.result')}));
        } else if (lines) {
            actions.append(el('a', {class: 'zt-link pv-row-action', href: PQA.page(PAGES + '/' + run.id),
                text: m('action.result')}), el('a', {class: 'zt-link pv-row-action', href: PQA.page(PAGES + '/compare',
                {candidate: versionNumber(run.version)}), text: m('action.compare')}));
        } else {
            actions.append(PQA.muted('—'));
        }
        // Quality P32: a measurement taken anew is marked, as two of them of one version give the gate its noise.
        const input = sealed ? [m('input.sealedRow', ZT.count(run.requested)), m('input.against', run.reference)]
            : [m('input.casesRow', String(run.caseSetVersion).slice(0, 8)), m('start.times', run.repeats)
                + (run.anew ? ' · ' + m('input.anew') : '')];
        const model = modelOf(run.model);
        return el('tr', {'data-kind': run.kind},
            el('td', {class: 'zt-fill'}, el('div', {class: 'zt-item'},
                el('span', {class: 'pv-cut', title: run.version, text: run.version}),
                el('span', {class: 'zt-muted pv-cut', title: run.model || '', text: model}))),
            el('td', {class: 'zt-wide', title: input.join(' · ')}, el('div', {class: 'zt-item'},
                el('span', {class: 'pv-cut', text: input[0]}), el('span', {class: 'zt-muted pv-cut', text: input[1]}))),
            el('td', {class: 'zt-cell-chips'}, ZT.statusChip(RUN_STATUS[status], text)),
            el('td', {title: whole}, lines ? el('div', {class: 'zt-item'}, el('span', {class: 'pv-cut', text: lines[0]}),
                el('span', {class: 'zt-muted pv-cut', text: lines[1]})) : '—'),
            el('td', {class: 'zt-wide'}, el('div', {class: 'zt-item'},
                el('span', {class: 'pv-cut', text: ZT.shortTime(run.startedAt)}),
                el('span', {class: 'zt-muted pv-cut', title: run.by, text: run.by}))),
            el('td', {class: 'pv-cell-actions zt-wide'}, actions));
    }

    /** The models a model setting names (settings=<hash>;models=<names>), else the setting as it is. */
    function modelOf(setting) {
        if (!setting) {
            return '—';
        }
        const found = /models=([^;]*)/.exec(setting);
        return found ? (found[1] === 'unknown' ? m('modelUnknown') : found[1]) : setting;
    }

    // ----- one measurement -----

    async function drawRun() {
        const id = root.dataset.measureId;
        const [, run] = await Promise.all([band(), PQA.get(id ? '/' + id : '/run').catch(error => error)]);
        if (!run || run instanceof Error) {
            content.replaceChildren(run && run.status === 404 ? PQA.emptyState(m('run.empty'), 'fa-balance-scale')
                : PQA.failed());
            return;
        }
        let basis = 'FIRST';
        const holder = el('div', {class: 'zt-stack'});
        const pickBox = PQA.filterBox([{name: m('run.pick'), node: pickSelect(run)}],
            el('span', {class: 'zt-filter-name', text: m('run.basis')}),
            PQA.pills(m('run.basis'), ['FIRST', 'FINAL'].map(key => [key, m('run.basis.' + key),
                m('run.basis.' + key + '.def')]), basis, key => {
                basis = key;
                holder.replaceChildren(...runParts(run, basis === 'FIRST' ? run.firstAnswer : run.finalAction));
            }),
            ZT.info(m('run.basisTip')));
        holder.replaceChildren(...runParts(run, run.firstAnswer));
        content.replaceChildren(pickBox, holder);
        const grade = PQA.params().get('grade');
        if (grade) {
            const tab = [...content.querySelectorAll('[data-form="metric-card"] .zt-tabs [role="tab"]')]
                .find(node => node.dataset.grade === grade);
            if (tab) {
                tab.click();
            }
        }
    }

    function pickSelect(run) {
        const options = run.picks.map(pick => [pick.id, m('run.pickOption', pick.version, String(pick.caseSetVersion)
            .slice(0, 8), pick.repeats, ZT.shortTime(pick.createdAt))]);
        if (!run.picks.some(pick => pick.id === run.id)) {
            options.unshift([run.id, m('run.pickOption', run.version, String(run.caseSetVersion).slice(0, 8), run.repeats,
                ZT.shortTime(run.createdAt))]);
        }
        const node = PQA.select(m('run.pick'), options, run.id);
        node.addEventListener('change', () => global.location.assign(PQA.page(PAGES + '/' + node.value)));
        return node;
    }

    /** The value of a metric row: a ratio, or the median of a time and of a length, or "—" with its reason. */
    function metricValue(metric) {
        if (metric.none) {
            return '—';
        }
        return metric.key === 'TIME' ? ZT.seconds(metric.median) : percentOf(metric);
    }

    function metricNote(metric) {
        if (metric.none) {
            return m('metric.none.' + metric.none);
        }
        return metric.key === 'TIME' ? m('metric.timeNote', ZT.count(metric.tokens == null ? null
            : Math.round(metric.tokens)), ZT.seconds(metric.p95), ZT.count(metric.tokensP95 == null ? null
            : Math.round(metric.tokensP95))) : null;
    }

    function metricRow(metric) {
        const note = metricNote(metric);
        const time = metric.key === 'TIME';
        return el('tr', {title: definitionOf(metric), 'data-metric': metric.key},
            el('td', {class: 'zt-fill'}, el('div', {class: 'zt-item'},
                el('span', {class: 'pv-cut', text: m('metric.' + metric.key)}),
                note ? el('span', {class: 'zt-muted pv-cut', text: note}) : ZT.bar(metric.n ? metric.k / metric.n : null, 1,
                    {lower: metric.lo, upper: metric.hi, color: C.ACCENT, label: m('metric.' + metric.key) + ' '
                        + percentOf(metric)}))),
            PQA.cell(metricValue(metric), {class: 'zt-num'}),
            PQA.cell(time || metric.none ? '—' : countsOf(metric), {class: 'zt-num'}),
            PQA.cell(time || metric.none ? '—' : rangeOf(metric), {class: 'zt-num zt-wide'}));
    }

    function runParts(run, b) {
        const cards = PQA.grid(metricKpi(b.headline[0], 'red', 'fa-eye-slash'), metricKpi(b.headline[1], 'amber', 'fa-ban'),
            metricKpi(b.headline[2], 'indigo', 'fa-bullseye'), metricKpi(b.headline[3], 'teal', 'fa-quote-right'));
        // The tabs of the card switch the cases the metrics count: all of them, or those that ask for a resource of one
        // grade. A grade no case asks for says so instead of showing an empty table.
        const metricTable = rows => PQA.form('metric-table', PQA.table([{label: m('column.metric')},
            {label: m('column.value'), num: true}, {label: m('column.counts'), num: true},
            {label: m('column.range'), num: true, wide: true}], el('tbody', {}, rows.map(metricRow)), m('run.metrics')));
        const whole = b.grades[0];
        const metrics = PQA.tipped(ZT.tabbedCard(m('run.metrics'), m('run.metricsAside', ZT.count(run.answers),
            ZT.count(whole.roots)) + (run.missingCases.length ? ' · ' + m('run.missing', ZT.count(run.missingCases.length))
            : ''), b.grades.map(grade => ({label: caseWord('tabCount', resourceGrade(grade.key), ZT.shortCount(grade.cases)),
            node: grade.metrics ? metricTable(grade.metrics) : PQA.emptyState(m('run.noGradeCases',
                resourceGrade(grade.key)), 'fa-layer-group')}))), m('run.metricsTip'));
        PQA.form('metric-card', metrics);
        metrics.querySelectorAll('.zt-tabs [role="tab"]').forEach((tab, index) => {
            tab.dataset.grade = b.grades[index].key;
        });
        const splitRow = (key, part) => el('div', {class: 'zt-reason-row'},
            el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: m('split.' + key,
                ZT.count(part.cases))}), el('span', {class: 'zt-reason-value', text: part.miss.n
                ? m('split.miss', countsOf(part.miss), percentOf(part.miss)) : m('split.none')})),
            ZT.bar(part.miss.n ? part.miss.k / part.miss.n : null, 1, {color: C.BAD, lower: part.miss.lo,
                upper: part.miss.hi, label: m('split.' + key, ZT.count(part.cases))}));
        const apart = PQA.tipped(ZT.card(m('split.title'), m('split.aside'),
            PQA.form('split-meters', el('div', {class: 'zt-reason-rows'}, splitRow('CONTEXA', b.split.contexa),
                splitRow('OURS', b.split.ours)))), m('split.tip'));
        const later = b.later;
        const after = PQA.tipped(ZT.card(m('later.title'), m('later.aside'),
            PQA.form('later-tile', el('div', {class: 'zt-tile zt-metric'},
                el('span', {class: 'zt-metric-label', text: m('later.cases', ZT.count(later.cases))}),
                el('span', {class: 'zt-metric-value zt-small' + (later.miss.n ? '' : ' zt-none'),
                    text: later.miss.n ? percentOf(later.miss) : '—'}),
                el('span', {class: 'zt-metric-ratio', text: later.miss.n ? m('later.miss', countsOf(later.miss),
                    percentOf(later.overall)) : run.versionCreatedAt ? m('later.none') : m('later.unknown')}))),
            later.worse ? el('div', {class: 'zt-alert max-sm:!grid-cols-1', role: 'note'}, ZT.statusChip('WARN',
                m('later.worseChip')), el('span', {text: m('later.worse')})) : null), m('later.def'));
        return [cards, PQA.grid(PQA.span(metrics, 12)), PQA.grid(PQA.span(apart, 6), PQA.span(after, 6))];
    }

    // ----- two versions -----

    async function drawCompare() {
        // Two measurements when both are named (a version measured twice), else two versions.
        const asked = {candidate: root.dataset.candidate || null, reference: root.dataset.reference || null,
            candidateMeasure: root.dataset.candidateMeasure || null,
            referenceMeasure: root.dataset.referenceMeasure || null};
        const [, c] = await Promise.all([band(), PQA.get('/compare', asked).catch(() => null)]);
        if (!c) {
            content.replaceChildren(PQA.failed());
            return;
        }
        const options = c.versions.map(option => [option.number, option.name]);
        const choose = (name, value, param) => {
            const node = PQA.select(name, [['', '—'], ...options], value == null ? '' : value);
            node.addEventListener('change', () => global.location.assign(PQA.page(PAGES + '/compare',
                Object.assign({candidate: c.candidate, reference: c.current}, {[param]: node.value || null}))));
            return {name, node};
        };
        const byMeasure = c.candidateMeasure != null && c.referenceMeasure != null;
        const chooseMeasure = (name, value, param) => {
            const options = c.picks.map(pick => [pick.id, m('run.pickOption', pick.version,
                String(pick.caseSetVersion).slice(0, 8), pick.repeats, ZT.shortTime(pick.createdAt))]);
            if (!options.some(([id]) => String(id) === String(value))) {
                options.unshift([value, m('compare.measureId', value)]);
            }
            const node = PQA.select(name, options, value);
            node.addEventListener('change', () => global.location.assign(PQA.page(PAGES + '/compare',
                Object.assign({candidateMeasure: c.candidateMeasure, referenceMeasure: c.referenceMeasure},
                    {[param]: node.value}))));
            return {name, node};
        };
        const pick = PQA.filterBox(byMeasure ? [chooseMeasure(m('compare.referenceMeasure'), c.referenceMeasure,
            'referenceMeasure'), chooseMeasure(m('compare.candidateMeasure'), c.candidateMeasure, 'candidateMeasure')]
            : [choose(m('compare.current'), c.current, 'reference'), choose(m('compare.candidate'), c.candidate,
                'candidate')],
        c.same ? PQA.muted(m('compare.same', String(c.same.caseSetVersion).slice(0, 8), modelOf(c.same.model),
            c.same.repeats)) : null);
        if (!c.comparable) {
            content.replaceChildren(pick, stateNote(c));
            return;
        }
        const metricRows = c.metrics.filter(row => row.key !== 'CONSISTENCY' || c.same.repeats > 1);
        const summary = el('div', {class: 'zt-summary'}, el('p', {class: 'zt-summary-main', text: sentence(c)}),
            el('p', {class: 'zt-summary-sub', text: subSentence(c)}));
        const tile = (key, count, tone, icon) => PQA.kpi({tone, icon, label: m('split.' + key), value: ZT.shortCount(count),
            sub: m('split.' + key + '.sub'), title: m('split.' + key + '.sub') + ' (' + ZT.count(count) + ')'});
        const splits = PQA.grid(tile('NEW_MISS', c.splits.newMiss, 'red', 'fa-eye-slash'),
            tile('NEW_CATCH', c.splits.newCatch, 'green', 'fa-shield-alt'),
            tile('NEW_STOP', c.splits.newStop, 'amber', 'fa-hand-paper'),
            tile('NEW_PASS', c.splits.newPass, 'teal', 'fa-door-open'));
        const current = c.currentSide.version;
        const candidate = c.candidateSide.version;
        // The adoption screen's criteria rows: a name, the two versions' bars one over the other, the values, the verdict.
        const criteria = el('div', {class: 'zt-criteria'},
            el('span', {class: 'zt-muted', text: m('column.metric')}),
            el('span', {class: 'zt-muted', text: m('compare.bars', current, candidate)}),
            el('span', {class: 'zt-muted zt-num', text: m('column.value')}),
            el('span', {class: 'zt-muted', text: m('column.verdict')}));
        metricRows.forEach(row => criteria.append(
            el('span', {title: m('metric.' + row.key + '.def'), text: m('metric.' + row.key)}),
            el('span', {class: 'flex flex-col gap-1'},
                ZT.bar(row.currentValue, 1, {color: C.MUTED, label: current + ' ' + percentOf(row.current)}),
                ZT.bar(row.candidateValue, 1, {color: C.ACCENT, label: candidate + ' ' + percentOf(row.candidate)})),
            el('span', {class: 'zt-num', title: countsOf(row.current) + ' → ' + countsOf(row.candidate),
                text: share(row.currentValue) + ' → ' + share(row.candidateValue)}),
            el('span', {}, ZT.statusChip(VERDICT_STATUS[row.verdict], m('verdict.' + row.verdict)))));
        if (c.time) {
            const most = Math.max(c.time.currentMedian || 0, c.time.candidateMedian || 0);
            criteria.append(el('span', {title: m('metric.TIME.def'), text: m('metric.TIME')}),
                el('span', {class: 'flex flex-col gap-1'},
                    ZT.bar(c.time.currentMedian, most, {color: C.MUTED, label: current + ' ' + ZT.seconds(c.time.currentMedian)}),
                    ZT.bar(c.time.candidateMedian, most, {color: C.ACCENT, label: candidate + ' '
                        + ZT.seconds(c.time.candidateMedian)})),
                el('span', {class: 'zt-num', title: m('compare.tokens', ZT.count(round(c.time.currentTokens)),
                    ZT.count(round(c.time.candidateTokens))),
                text: ZT.seconds(c.time.currentMedian) + ' → ' + ZT.seconds(c.time.candidateMedian)}),
                el('span', {title: m('compare.timeNoVerdict')}, ZT.statusChip(null, '—')));
        }
        // The same rows by resource grade: a grade that got worse shows even where the whole stayed the same.
        const byGrade = el('div', {class: 'zt-criteria'},
            el('span', {class: 'zt-muted', text: caseWord('filter.resourceGrade')}),
            el('span', {class: 'zt-muted', text: m('compare.bars', current, candidate)}),
            el('span', {class: 'zt-muted zt-num', text: m('metric.MISS')}),
            el('span', {class: 'zt-muted', text: m('column.verdict')}));
        c.grades.forEach(grade => byGrade.append(
            el('span', {title: caseWord('resGrade.def')}, el('div', {text: resourceGrade(grade.key)}),
                el('div', {class: 'zt-muted', text: !grade.compared ? caseWord('cover.NO_CASES') : grade.newMisses
                    ? m('compare.gradeChangedMiss', ZT.shortCount(grade.changed), ZT.shortCount(grade.newMisses))
                    : m('compare.gradeChanged', ZT.shortCount(grade.changed))})),
            el('span', {class: 'flex flex-col gap-1'},
                ZT.bar(grade.compared && grade.current ? grade.current.value : null, 1, {color: C.MUTED, label: current}),
                ZT.bar(grade.compared && grade.candidate ? grade.candidate.value : null, 1, {color: C.ACCENT,
                    label: candidate})),
            el('span', {class: 'zt-num', text: grade.compared ? countsOf(grade.current) + ' → ' + countsOf(grade.candidate)
                : '—'}),
            el('span', {}, grade.compared && grade.verdict ? ZT.statusChip(VERDICT_STATUS[grade.verdict],
                m('verdict.' + grade.verdict)) : ZT.statusChip(null, '—'))));
        const metrics = PQA.tipped(ZT.card(m('compare.metrics'), m('compare.metricsAside'),
            PQA.form('compare-criteria', criteria), ZT.subhead(m('compare.byGrade'), m('compare.byGradeTip')),
            PQA.form('grade-criteria', byGrade)), m('compare.metricsTip', noiseText(c)));
        const answers = ZT.card(m('compare.answers'), null, PQA.form('empty-state',
            PQA.emptyState(m('compare.pickCase'))));
        const list = ZT.card(m('compare.list'), m('compare.listAside'));
        if (c.rows.length) {
            const {body, foot} = PV.paged(c.rows, row => {
                const line = el('tr', {tabindex: '0', 'data-selectable': true, 'data-case': row.key},
                    PQA.cell(row.name, {class: 'zt-fill'}),
                    el('td', {class: 'zt-cell-chips'}, ZT.statusChip(SPLIT_STATUS[row.split], m('split.' + row.split))),
                    PQA.chipCell(row.currentActions, true), PQA.chipCell(row.candidateActions, true));
                const open = () => {
                    list.querySelectorAll('tr[data-selected]').forEach(other => other.removeAttribute('data-selected'));
                    line.setAttribute('data-selected', 'true');
                    showAnswers(answers, c, row);
                };
                line.addEventListener('click', open);
                line.addEventListener('keydown', event => {
                    if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        open();
                    }
                });
                return line;
            });
            list.querySelector('.zt-card-body').append(PQA.form('split-table', PQA.table([{label: caseWord('column.case')},
                {label: m('column.split')}, {label: current, wide: true, keep: true},
                {label: candidate, wide: true, keep: true}], body, m('compare.list'))));
            PQA.withFoot(list, foot);
        } else {
            list.querySelector('.zt-card-body').append(PQA.form('empty-state', PQA.emptyState(m('compare.noSplit'))));
        }
        content.replaceChildren(pick, summary, splits, PQA.grid(PQA.span(metrics, 12)),
            PQA.grid(PQA.span(list, 6), PQA.span(answers, 6)));
        const first = list.querySelector('tr[data-case]');
        if (first) {
            first.click();
        }
        PQA.fitChips();
    }

    function share(value) {
        return value == null ? '—' : ZT.percent(value, 1);
    }

    function round(value) {
        return value == null ? null : Math.round(value);
    }

    /** Why two versions are not compared, as the gate reads their measurements. */
    function stateNote(c) {
        const lines = [m('compare.state.' + c.state + '.line', c.candidate ? 'v' + c.candidate + '.0' : '—',
            c.current ? 'v' + c.current + '.0' : '—')];
        if (c.sides.length) {
            lines.push(m('compare.sides', c.sides.map(side => m('compare.side.' + side)).join(', ')));
        }
        if (c.differences.length) {
            lines.push(m('compare.differences', c.differences.map(code => m('compare.difference.' + code)).join(', ')));
        }
        if (c.detail) {
            lines.push(PQA.word('pqa.measure.compare.detail.' + c.detail, c.detail));
        }
        if (c.state === 'MEASURED') {
            lines.push(m('compare.empty'));
        }
        return el('div', {class: 'zt-stack'}, el('div', {class: 'zt-alert max-sm:!grid-cols-1', role: 'note',
            'data-compare-state': c.state}, ZT.statusChip(STATE_STATUS[c.state], m('compare.state.' + c.state)),
        el('div', {class: 'zt-item'}, ...lines.map(line => el('span', {text: line})))),
        PQA.emptyState(m('compare.empty'), 'fa-balance-scale'));
    }

    /** One sentence: what happened to the misses, and a grade that got worse where the whole did not. */
    function sentence(c) {
        const miss = c.metrics.find(row => row.key === 'MISS');
        const worseGrades = c.grades.filter(grade => grade.verdict === 'WORSE').map(grade => resourceGrade(grade.key));
        if (worseGrades.length && miss.verdict !== 'WORSE') {
            return m('compare.sentence.gradeWorse', worseGrades.join(', '));
        }
        const before = miss.current ? ZT.count(miss.current.k) : '—';
        const after = miss.candidate ? ZT.count(miss.candidate.k) : '—';
        if (miss.verdict === 'UNDECIDABLE') {
            const noise = c.noise.some(row => row.key === 'MISS');
            return m('compare.sentence.UNDECIDABLE', c.candidateSide.version, before, after,
                m(noise ? 'compare.reason.cases' : 'compare.reason.noise'));
        }
        return m('compare.sentence.' + miss.verdict, c.candidateSide.version, before, after);
    }

    function subSentence(c) {
        const parts = [m('compare.subChanged', ZT.count(c.rows.length))];
        c.grades.filter(grade => grade.newMisses > 0).forEach(grade => parts.push(m('compare.subNewMiss',
            ZT.count(grade.newMisses), resourceGrade(grade.key))));
        c.metrics.filter(row => row.key !== 'MISS' && (row.verdict === 'BETTER' || row.verdict === 'WORSE'))
            .forEach(row => parts.push(m('compare.subVerdict', m('metric.' + row.key), m('verdict.' + row.verdict))));
        return parts.join(' · ');
    }

    function noiseText(c) {
        const miss = c.noise.find(row => row.key === 'MISS');
        return miss ? m('compare.noise', ZT.percent(miss.width, 1)) : m('compare.noNoise');
    }

    /** The two versions' answers to one case side by side: the actions of the runs and the reason codes cited. */
    async function showAnswers(card, c, row) {
        const body = card.querySelector('.zt-card-body');
        const aside = card.querySelector('.zt-aside') || el('span', {class: 'zt-aside'});
        aside.textContent = row.name;
        card.querySelector('.zt-card-head').append(aside);
        let answers;
        try {
            answers = await PQA.get('/compare/answers', c.candidateMeasure != null && c.referenceMeasure != null
                ? {candidateMeasure: c.candidateMeasure, referenceMeasure: c.referenceMeasure, 'case': row.key}
                : {candidate: c.candidate, reference: c.current, 'case': row.key});
        } catch (error) {
            body.replaceChildren(PQA.failed());
            return;
        }
        const side = (answer, label) => {
            const distinct = [...new Set(answer.actions.filter(Boolean))];
            const reasons = answer.findings.map(finding => finding.code ? PQA.word('zt.console.reasonCode.' + finding.code,
                finding.code) : null).filter(Boolean);
            return el('div', {class: 'zt-item', style: {gap: '0.75rem'}},
                el('span', {class: 'zt-muted', text: m(label, answer.version)}),
                el('div', {class: 'zt-conclusion'}, distinct.length ? distinct.map(action => ZT.chip(action))
                    : PQA.muted('—')),
                el('figure', {class: 'zt-quote'}, el('figcaption', {text: m('compare.reason')}),
                    el('blockquote', {text: reasons.length ? reasons.join(', ') : m('compare.noReason')})),
                answer.findings.filter(finding => finding.fact).map(finding => el('div', {class: 'zt-fact',
                    title: finding.outcome ? m('finding.' + finding.outcome) : null,
                    text: [finding.fact, finding.code ? PQA.word('zt.console.reasonCode.' + finding.code, finding.code)
                        : null, finding.outcome ? m('finding.' + finding.outcome) : null].filter(Boolean).join(' · ')})));
        };
        body.replaceChildren(PQA.form('answers-side-by-side', el('div', {class: 'pv-compare'},
            side(answers.current, 'compare.currentLabel'), side(answers.candidate, 'compare.candidateLabel'))));
    }

    // ----- the views -----

    const views = {runs: drawRuns, run: drawRun, compare: drawCompare};

    global.PQA_MEASURE = {views, m, band, percentOf, countsOf, rangeOf, modelOf, PAGES};

    function draw() {
        tabs();
        // The server opens a view the list of views names; a view whose script is not here opens the page's own.
        const view = root.dataset.view || 'runs';
        const drawView = views[view] || (root.dataset.measureId ? views.run : views.runs);
        drawView();
    }

    global.addEventListener('resize', PQA.fitChips);
    // The scripts of the other views register theirs after this one: the page is drawn once they all have run.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', draw);
    } else {
        global.setTimeout(draw, 0);
    }
})(window);
