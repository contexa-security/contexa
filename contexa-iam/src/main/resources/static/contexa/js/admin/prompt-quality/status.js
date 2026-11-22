/*
 * Prompt quality assurance: the state of quality (quality plan 3.6, 3.8). How right the prompt in use is and what there
 * is to check, from PromptQualityStatus: the band (the period of operation, the version in use and since when, the
 * conditions of the last measurement), one sentence, the four key numbers of the last measurement, what there is to
 * check as a work queue, the version in use as a state board, the other metrics as range bars and the operation as
 * paired bars before and after the version changed. Each area has a visual form of its own (data-form). The quality
 * report is exported from the head. Load after console-common.js and pqa-parts.js.
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
    const C = ZT.COLORS;
    const m = (key, ...args) => ZT.t('pqa.status.' + key, ...args);
    const r = (key, ...args) => ZT.t('pqa.report.ui.' + key, ...args);
    const paths = P.json('pqa-paths');
    const content = document.getElementById('zt-content');
    const band = document.getElementById('zt-band');

    /** The four key numbers, their tone and icon, and the seven others of the last measurement (plan 3.3). */
    const HEADLINE = [['MISS', 'red', 'fa-eye-slash'], ['FALSE_STOP', 'amber', 'fa-ban'],
        ['ACTION_HIT', 'indigo', 'fa-bullseye'], ['CITATION_ACCURACY', 'teal', 'fa-quote-right']];
    const MORE = ['FRICTION', 'OVER_BLOCK', 'DEFERRAL', 'CONSISTENCY', 'REASK', 'MODEL_LESS'];
    /** The rates the scheduled measurement compares, in the order a worse one is named (the gate's). */
    const GATED = ['MISS', 'FALSE_STOP', 'OVER_BLOCK', 'FRICTION', 'DEFERRAL', 'CITATION_ACCURACY'];
    const ICONS = {MEASUREMENT_STALE: 'fa-history', MEASUREMENT_MISSING: 'fa-ruler', BASELINE_PENDING: 'fa-hourglass-half',
        UNMEASURABLE: 'fa-ban', REMEASURE_WORSE: 'fa-chart-line', REMEASURE_CHANGED: 'fa-exchange-alt',
        CASES_PENDING: 'fa-user-check', REVIEW_PENDING: 'fa-clipboard-list'};

    // ----- numbers: a ratio with its counts and its 95% range -----

    function percentOf(rate) {
        return rate && rate.trials ? ZT.percent(rate.events / rate.trials, 1) : '—';
    }

    function countsOf(rate) {
        return rate && rate.trials ? ZT.shortCount(rate.events) + ' / ' + ZT.shortCount(rate.trials) : '—';
    }

    function rangeOf(rate) {
        return rate && rate.lower != null && rate.upper != null
            ? m('range', ZT.percent(rate.lower, 1), ZT.percent(rate.upper, 1)) : '—';
    }

    /** Why a rate has no value: a consistency needs two runs or more, another rate a case of its kind. */
    function noneOf(key, measurement) {
        return key === 'CONSISTENCY' && measurement.repeats < 2 ? m('metric.none.ONE_RUN') : m('metric.none.NO_CASES');
    }

    /** The line under a key number: its counts and its 95% range (only the upper bound when nothing was counted). */
    function ratioSub(key, rate, measurement) {
        if (!rate || !rate.trials) {
            return noneOf(key, measurement);
        }
        return rate.events === 0 && rate.upper != null ? m('kpi.upperSub', countsOf(rate), ZT.percent(rate.upper, 1))
            : m('kpi.rangeSub', countsOf(rate), rangeOf(rate));
    }

    /** A metric's definition with the roots its 95% range counts (plan 3.3: the range is by distinct root cases). */
    function definitionOf(key, rate) {
        return m('metric.' + key + '.def') + (rate && rate.roots ? ' ' + m('metric.rootsNote', ZT.count(rate.roots)) : '');
    }

    // ----- the band, the sentence and the key numbers -----

    function drawBand(status) {
        const operation = status.operation;
        const since = operation ? operation.changedAt || operation.firstSeen : null;
        const measurement = status.measurement;
        band.replaceChildren(
            el('span', {class: 'status-badge zt-mode', 'data-mode': status.version ? 'ENFORCE' : 'DISABLED',
                text: status.version ? (since ? m('band.used', status.version, ZT.day(since))
                    : m('band.usedNoSince', status.version)) : m('band.noVersion')}),
            el('span', {text: measurement ? m('band.measure', ZT.shortTime(measurement.finishedAt),
                measurement.caseSetVersion, measurement.modelSetting, ZT.count(measurement.repeats))
                : m('band.noMeasure')}),
            ZT.info(m('band.note')));
    }

    function sentence(status) {
        const measurement = status.measurement;
        const miss = measurement.firstAnswer.rates.MISS;
        if (!miss || !miss.trials) {
            return m('summary.noStop', measurement.version);
        }
        return m(measurement.repeats > 1 ? 'summary.answers' : 'summary.cases', measurement.version,
            ZT.count(miss.trials), ZT.count(miss.events), ZT.percent(miss.events / miss.trials, 1));
    }

    function summary(status) {
        const todo = status.toCheck || [];
        if (!status.measurement) {
            const key = !status.version ? 'noVersion' : status.state;
            return el('div', {class: 'zt-summary'}, el('p', {class: 'zt-summary-main', text: m('summary.none.' + key)}),
                el('p', {class: 'zt-summary-sub', text: m('summary.none.' + key + '.sub')}));
        }
        return el('div', {class: 'zt-summary'}, el('p', {class: 'zt-summary-main', text: sentence(status)}),
            el('p', {class: 'zt-summary-sub', text: todo.length ? m('summary.todo', ZT.count(todo.length),
                todoText(todo[0], status)) : m('summary.noTodo')}));
    }

    function keyNumbers(measurement) {
        const rates = measurement.firstAnswer.rates;
        return P.grid(...HEADLINE.map(([key, tone, icon]) => P.span(ZT.kpi({tone, icon, label: m('metric.' + key),
            value: percentOf(rates[key]), sub: ratioSub(key, rates[key], measurement),
            title: definitionOf(key, rates[key])}), 3)));
    }

    // ----- what there is to check: the work queue -----

    /** The rate the scheduled measurement found worse first, with its counts before and after. */
    function worseRate(figures) {
        const rates = figures.rates || {};
        const key = GATED.find(name => rates[name] && rates[name].pairedVerdict === 'WORSE');
        return key ? {key, before: (rates[key].before || [])[0], after: (rates[key].after || [])[0]} : null;
    }

    function todoText(item, status) {
        const figures = item.figures || {};
        const version = figures.version || status.version || '—';
        switch (item.kind) {
            case 'REMEASURE_WORSE': {
                const worse = worseRate(figures);
                return worse ? m('todo.REMEASURE_WORSE.text', m('metric.' + worse.key), ZT.count(worse.before),
                    ZT.count(worse.after)) : m('todo.REMEASURE_WORSE.graded',
                    ZT.count((figures.newlyFailedGraded || []).length));
            }
            case 'REMEASURE_CHANGED':
                return m('todo.REMEASURE_CHANGED.text', ZT.count((figures.newlyMissed || []).length
                    + (figures.addedMissed || []).length), ZT.count((figures.newlyStopped || []).length
                    + (figures.addedStopped || []).length));
            case 'CASES_PENDING':
            case 'REVIEW_PENDING':
                return m('todo.' + item.kind + '.text', ZT.count(item.count));
            default:
                return m('todo.' + item.kind + '.text', version);
        }
    }

    function todoRule(item, status) {
        const figures = item.figures || {};
        const version = figures.version || status.version || '—';
        if (item.kind === 'REMEASURE_WORSE' || item.kind === 'REMEASURE_CHANGED') {
            return m('todo.remeasure.rule', ZT.day(figures.comparedAt), version);
        }
        if (item.kind === 'MEASUREMENT_STALE' && figures.measuring) {
            return m('todo.MEASUREMENT_STALE.measuring', version);
        }
        return m('todo.' + item.kind + '.rule', version);
    }

    /** Where a row's button leads: measure again, the comparison, the cases to confirm, the decisions to review. */
    function todoLink(item, status) {
        const figures = item.figures || {};
        switch (item.kind) {
            case 'MEASUREMENT_STALE':
            case 'MEASUREMENT_MISSING':
            case 'BASELINE_PENDING':
                return P.scoped(paths.measure);
            case 'REMEASURE_WORSE':
            case 'REMEASURE_CHANGED':
                return P.scoped(paths.measure + '/compare', {base: figures.comparedMeasureId,
                    candidate: figures.measureId});
            case 'CASES_PENDING':
                return P.scoped(paths.cases, {view: 'pending'});
            case 'REVIEW_PENDING':
                return paths.review;
            default:
                return null;
        }
    }

    function todoCard(status) {
        const todo = status.toCheck || [];
        const card = ZT.card(m('todo.title'), null, todo.length ? P.form('work-queue',
            el('div', {class: 'zt-indicators zt-queue-rows'}, todo.map(item => {
                const to = todoLink(item, status);
                return el('div', {class: 'zt-indicator flex-wrap', 'data-severity': item.severity,
                    'data-kind': item.kind},
                el('div', {class: 'flex items-center gap-3 min-w-0'},
                    el('i', {class: 'fas ' + (ICONS[item.kind] || 'fa-circle'), 'aria-hidden': 'true',
                        style: {color: C.MUTED, width: '20px', textAlign: 'center'}}),
                    el('div', {class: 'zt-indicator-text'},
                        el('span', {class: 'zt-indicator-title', text: todoText(item, status)}),
                        el('span', {class: 'zt-indicator-rule', text: todoRule(item, status)}))),
                el('div', {class: 'zt-queue-act flex items-center gap-3 flex-shrink-0'}, ZT.statusChip(item.severity),
                    to ? el('a', {class: 'modern-btn-secondary', href: to, text: m('todo.' + item.kind + '.go')})
                        : null));
            })))
            : P.form('empty-state', P.emptyState(m('todo.none'), 'fa-check-circle')));
        const counts = ['BAD', 'WARN', 'INFO'].map(severity => [severity,
            todo.filter(item => item.severity === severity).length]).filter(([, n]) => n > 0);
        const chips = () => counts.map(([severity, n]) => ZT.statusChip(severity, m('todo.severity',
            ZT.t('zt.console.ui.status.' + severity), ZT.count(n))));
        card.querySelector('.zt-card-head').append(el('span',
            {class: 'flex items-center gap-2 flex-shrink-0 max-sm:hidden'}, chips()));
        if (counts.length) {
            card.querySelector('.zt-card-body').prepend(el('div', {class: 'flex flex-wrap items-center gap-2 sm:hidden'},
                chips()));
        }
        return card;
    }

    // ----- the version in use: the state board -----

    function changedText(changed) {
        return Object.entries(changed || {}).map(([name, pair]) => name + ': ' + (pair[0] == null ? '—' : pair[0])
            + ' → ' + (pair[1] == null ? '—' : pair[1])).join(', ');
    }

    function boardCard(status) {
        const measurement = status.measurement;
        const chipRow = (name, chipStatus, text, title) => el('div', {class: 'zt-result-row', title: title || null},
            el('span', {class: 'zt-result-name', text: name}), ZT.statusChip(chipStatus, text));
        const valueRow = (name, value, title) => el('div', {class: 'zt-result-row', title: title || null},
            el('span', {class: 'zt-result-name', text: name}),
            el('span', {class: 'zt-result-value pv-wrap', text: value == null || value === '' ? '—' : value}));
        const stale = measurement && !measurement.fresh ? m('board.staleTip', changedText(measurement.changedSettings))
            : null;
        const card = ZT.card(m('board.title'), m('board.aside'), P.form('state-board', el('div', {class: 'zt-result-rows'},
            chipRow(m('board.version'), status.version ? 'GOOD' : null, status.version || m('board.none')),
            chipRow(m('board.measured'), !measurement ? null : measurement.fresh ? 'GOOD' : 'WARN',
                !measurement ? m('board.none') : measurement.fresh ? m('board.fresh') : m('board.stale'), stale),
            valueRow(m('board.bundle'), measurement ? measurement.caseSetVersion : null),
            valueRow(m('board.model'), measurement ? measurement.modelSetting : null, stale),
            valueRow(m('board.repeats'), measurement ? m('board.times', ZT.count(measurement.repeats)) : null,
                m('board.repeatsTip')),
            valueRow(m('board.next'), status.nextScheduled ? ZT.time(status.nextScheduled) : m('board.off')))));
        return P.foot(card, measurement ? P.link(P.scoped(paths.measure + '/' + measurement.id), m('link.run')) : null,
            P.link(P.scoped(paths.versions), m('link.versions')));
    }

    // ----- the other metrics of the last measurement: range bars -----

    function meterRow(key, rate, measurement) {
        const name = m('metric.' + key);
        return el('div', {class: 'zt-reason-row', title: definitionOf(key, rate), 'data-metric': key},
            el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: name}),
                el('span', {class: 'zt-reason-value', text: rate && rate.trials ? m('meter', percentOf(rate),
                    countsOf(rate)) : noneOf(key, measurement)})),
            ZT.bar(rate && rate.trials ? rate.events / rate.trials : null, 1, {lower: rate ? rate.lower : null,
                upper: rate ? rate.upper : null, label: name}),
            el('span', {class: 'zt-muted', text: rate && rate.trials ? m('kpi.range', rangeOf(rate)) : '—'}));
    }

    function timeRow(score) {
        const time = score.decisionMillis || {};
        const tokens = score.answerTokens || {};
        const name = m('metric.TIME');
        return el('div', {class: 'zt-reason-row', title: m('metric.TIME.def'), 'data-metric': 'TIME'},
            el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: name}),
                el('span', {class: 'zt-reason-value', text: time.median != null
                    ? m('metric.timeBoth', ZT.seconds(time.median), ZT.seconds(time.ninetyFifth))
                    : m('metric.none.NO_CASES')})),
            ZT.bar(time.median, time.ninetyFifth || null, {color: C.MUTED, label: name}),
            el('span', {class: 'zt-muted', text: time.median != null ? m('metric.timeP95', ZT.seconds(time.ninetyFifth),
                ZT.count(tokens.ninetyFifth != null ? Math.round(tokens.ninetyFifth) : null)) : '—'}));
    }

    function measuredCard(measurement) {
        const score = measurement.firstAnswer;
        const card = ZT.card(m('measured.title'), m('measured.aside', ZT.count(score.answers)),
            P.form('range-meters', el('div', {class: 'zt-reason-rows'},
                ...MORE.map(key => meterRow(key, score.rates[key], measurement)), timeRow(score))));
        P.foot(card, P.link(P.scoped(paths.measure + '/' + measurement.id), m('link.run')),
            P.link(P.scoped(paths.measure + '/' + measurement.id, {view: 'causes'}), m('link.causes')));
        return P.tipped(card, m('measured.tip'));
    }

    // ----- the operation before and after the version changed: paired bars -----

    function opsCard(status) {
        const operation = status.operation;
        const period = ZT.t('zt.console.ui.period.' + (['day', 'week', 'month', 'quarter'].includes(ZT.query()
            .get('period')) ? ZT.query().get('period') : 'week'));
        const rates = operation ? operation.rates || [] : [];
        const seen = rates.some(rate => rate.beforeTrials > 0 || rate.afterTrials > 0);
        const before = operation && operation.previousVersion ? operation.previousVersion : m('ops.noPrevious');
        const after = operation ? operation.version : '—';
        const side = (events, trials, name, colour) => el('div', {class: 'flex flex-col gap-1 min-w-0'},
            el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name zt-muted', text: name}),
                el('span', {class: 'zt-reason-value', text: trials ? m('meter', ZT.percent(events / trials, 1),
                    ZT.shortCount(events) + ' / ' + ZT.shortCount(trials)) : '—'})),
            ZT.bar(trials ? events / trials : null, 1, {color: colour, label: name}));
        const pair = rate => el('div', {class: 'flex flex-col gap-2', title: m('ops.' + rate.key + '.def'),
            'data-metric': rate.key},
        el('span', {class: 'zt-reason-name', text: m('ops.' + rate.key)}),
        el('div', {class: 'zt-split'}, side(rate.beforeEvents, rate.beforeTrials, before, C.MUTED),
            side(rate.afterEvents, rate.afterTrials, after, C.ACCENT)));
        const card = ZT.card(m('ops.title'), seen ? (operation.previousVersion ? m('ops.aside', before, after, period)
            : m('ops.asideOne', after, period)) : null,
        seen ? P.form('paired-bars', el('div', {class: 'flex flex-col gap-4'}, rates.map(pair)))
            : P.form('empty-state', P.emptyState(m('ops.empty'), 'fa-chart-bar')));
        P.foot(card, P.link(paths.decisions, m('link.decisions')), P.link(P.scoped(paths.evidence), m('link.evidence')));
        return P.tipped(card, m('ops.tip'));
    }

    function render(status) {
        drawBand(status);
        if (!status.measurement) {
            const seen = status.operation && (status.operation.rates || []).some(rate => rate.beforeTrials > 0
                || rate.afterTrials > 0);
            content.replaceChildren(summary(status), P.grid(P.span(todoCard(status), 12)),
                seen ? P.grid(P.span(opsCard(status), 12)) : null);
            return;
        }
        content.replaceChildren(summary(status), keyNumbers(status.measurement),
            P.grid(P.span(todoCard(status), 8), P.span(boardCard(status), 4)),
            P.grid(P.span(measuredCard(status.measurement), 6), P.span(opsCard(status), 6)));
    }

    async function draw() {
        try {
            render(await ZT.load(''));
        } catch (error) {
            band.replaceChildren();
            ZT.failed(content, error);
        }
    }

    // ----- the quality report (quality plan 3.7): its days, then the bundle downloaded -----

    function utcDay(date) {
        return date.toISOString().slice(0, 10);
    }

    function fileName(response) {
        const header = response.headers.get('Content-Disposition') || '';
        const encoded = /filename\*=UTF-8''([^;]+)/i.exec(header);
        if (encoded) {
            return decodeURIComponent(encoded[1]);
        }
        const plain = /filename="?([^";]+)"?/i.exec(header);
        return plain ? plain[1] : 'prompt-quality-report.zip';
    }

    async function exportReport() {
        const today = new Date();
        const first = new Date(today.getTime() - 89 * 24 * 3600 * 1000);
        const from = el('input', {type: 'date', class: 'modern-input', value: utcDay(first), max: utcDay(today),
            required: true, name: 'from'});
        const to = el('input', {type: 'date', class: 'modern-input', value: utcDay(today), max: utcDay(today),
            required: true, name: 'to'});
        const scope = ZT.query().get('scope');
        const answer = await P.dialog({
            title: r('title'),
            rows: [[r('scope'), scope || r('platform')], [r('contents'), r('contentsValue')]],
            content: [el('div', {class: 'zt-filter-grid'}, P.field(r('from'), from), P.field(r('to'), to)),
                P.muted(r('note'))],
            confirmLabel: r('download'), cancelLabel: r('cancel'), icon: 'fa-download',
            check: () => {
                const fine = from.value && to.value && from.value <= to.value;
                from.setAttribute('aria-invalid', String(!fine));
                if (!fine) {
                    from.setCustomValidity(r('invalid'));
                    from.reportValidity();
                } else {
                    from.setCustomValidity('');
                }
                return fine;
            }
        });
        if (!answer) {
            return;
        }
        P.notice('note', r('preparing'));
        try {
            const response = await fetch(paths.report + P.query({scope, from: from.value, to: to.value}),
                {credentials: 'same-origin'});
            if (!response.ok) {
                throw new Error(String(response.status));
            }
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const anchor = el('a', {href: url, download: fileName(response)});
            document.body.append(anchor);
            anchor.click();
            anchor.remove();
            URL.revokeObjectURL(url);
            P.notice('good', r('done'), [r('doneLine', from.value, to.value)]);
        } catch (error) {
            P.notice('bad', r('failed'), [error.message === '400' ? r('refused') : r('failedLine')]);
        }
    }

    const toolbar = root.querySelector('.zt-toolbar');
    const report = P.button(r('button'), 'fa-file-export', 'secondary', {title: r('title'), 'data-pqa-action': 'report'});
    report.addEventListener('click', exportReport);
    toolbar.replaceChildren(report);
    P.periods(document.getElementById('zt-period'), draw);
    draw();
})(window);
