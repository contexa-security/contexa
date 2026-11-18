/*
 * Zero Trust console, overview (console design 6.1): "are we protecting what we should, right now?". Drawn as the
 * admin dashboard draws its first screen: one sentence of the period, four key numbers on gradient cards (each with its
 * daily trend and a link to the screen that explains it), the decisions of each day beside their share by action, and
 * the reasons the stopped requests gave beside the warnings to look at. The detail behind each number (the outcomes,
 * the timing, the burden, the reasons without a decision) stays on the screen the card links to. In SHADOW a stopped
 * request is one ENFORCE would have stopped, and the screen says so.
 */
(function (ZT) {
    'use strict';

    const t = ZT.t;
    const el = ZT.el;
    const C = ZT.COLORS;
    const P = 'zt.console.ui.overview.';
    const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];
    const STOPPED = ['CHALLENGE', 'ESCALATE', 'BLOCK'];
    const DAY_MS = 24 * 60 * 60 * 1000;
    /** The longest calendar the trend is drawn on: the console's longest period is 400 days. */
    const MAX_DAYS = 400;

    let shadow = false;
    let charts = [];
    let drawn = [];

    function m(key, ...args) {
        return t(P + key, ...args);
    }

    /** In SHADOW the "would have been stopped" form of a message, the plain one otherwise. */
    function s(key, ...args) {
        return t(P + key + (shadow ? '.shadow' : ''), ...args);
    }

    /** K110: a card title in the mode's form, with its short form for a phone when it has one. */
    function heading(key, ...args) {
        return ZT.title(P + key + (shadow ? '.shadow' : ''), ...args);
    }

    function span(node, columns) {
        node.classList.add('zt-span-' + columns);
        return node;
    }

    function grid(...cards) {
        return el('div', {class: 'zt-grid'}, ...cards);
    }

    /** The links that stay at the bottom of a card. */
    function foot(card, ...links) {
        card.append(el('div', {class: 'zt-card-foot'}, ...links));
        return card;
    }

    function link(href, text) {
        return el('a', {class: 'zt-link', href, text});
    }

    function decisions(params) {
        return ZT.consoleLink('/decisions', params);
    }

    function ordered(shares, keys) {
        return keys.map(key => (shares || []).find(share => share.key === key) || {key, count: 0, ratio: null});
    }

    // ----- the days of the trend -----

    function localDay(time) {
        const date = new Date(time);
        if (Number.isNaN(date.getTime())) {
            return null;
        }
        const pad = number => String(number).padStart(2, '0');
        return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate());
    }

    function utc(day) {
        return Date.UTC(Number(day.slice(0, 4)), Number(day.slice(5, 7)) - 1, Number(day.slice(8, 10)));
    }

    /**
     * Every day of the period with its trend point, or null for a day the trend does not name: such a day had no
     * decision, so its ratios are missing, never 0.
     */
    function calendar(period, trend) {
        const byDay = new Map(trend.map(point => [point.day, point]));
        const named = trend.map(point => point.day).sort();
        let first = named[0] || null;
        let last = named[named.length - 1] || null;
        const from = period && period.from ? localDay(period.from) : null;
        const to = period && period.to ? localDay(new Date(period.to).getTime() - 1) : null;
        if (from && (!first || from < first)) {
            first = from;
        }
        if (to && (!last || to > last)) {
            last = to;
        }
        const days = [];
        if (!first || !last) {
            return days;
        }
        for (let at = utc(first); at <= utc(last) && days.length < MAX_DAYS; at += DAY_MS) {
            const day = new Date(at).toISOString().slice(0, 10);
            days.push({day, point: byDay.get(day) || null});
        }
        return days;
    }

    function decided(point) {
        return point.allow + point.challenge + point.escalate + point.block;
    }

    function series(days, read) {
        return days.map(day => (day.point ? read(day.point) : null));
    }

    /** The protected calls a decision answered, new or reused, of the day's protected calls (console design 5). */
    function coverageOf(point) {
        if (point.protectedCalls == null || point.protectedCalls === 0) {
            return null;
        }
        // Only the decisions of protected calls answer a protected call (a sign-in step is decided too, no protected call).
        return Math.min(1, ((point.protectedDecisions || 0) + (point.reused || 0)) / point.protectedCalls);
    }

    function stoppedOf(point) {
        const all = decided(point);
        return all === 0 ? null : (point.challenge + point.escalate + point.block) / all;
    }

    /** The protected calls of the day no new decision answered: reused, skipped or failed (design 6.0). */
    function noDecisionOf(point) {
        return point.noDecision + (point.reused || 0) + (point.skipped || 0);
    }

    /** The challenges the account owner passed, of the day's challenges: the pass card's daily trend. */
    function passOf(point) {
        return point.challenge > 0 ? (point.passed || 0) / point.challenge : null;
    }

    function modelOf(point) {
        const all = decided(point);
        return all === 0 ? null : point.model / all;
    }

    // ----- the sentence of the period -----

    function summaryLine(summary) {
        const node = el('div', {class: 'zt-summary'});
        if (!summary.decisions) {
            node.append(el('p', {class: 'zt-summary-main', text: ZT.reason('NO_DECISIONS')}));
            return node;
        }
        node.append(el('p', {class: 'zt-summary-main', text: s('flow.sentence', ZT.count(summary.decisions),
            ZT.count(summary.stopped), ZT.percent(summary.stoppedRatio))}));
        const after = [];
        if (shadow) {
            if (summary.challenges > 0 || summary.blocks > 0) {
                after.push(m('flow.sentence.wouldHave', ZT.count(summary.challenges), ZT.count(summary.blocks)));
            }
        } else {
            if (summary.challenges > 0) {
                after.push(m('flow.sentence.challenges', ZT.count(summary.challenges), ZT.count(summary.challengesPassed),
                    ZT.percent(summary.challengesPassed / summary.challenges)));
            }
            if (summary.blocks > 0) {
                after.push(m('flow.sentence.blocks', ZT.count(summary.blocks), ZT.count(summary.blocksReleased)));
            }
        }
        if (after.length) {
            node.append(el('p', {class: 'zt-summary-sub', text: after.join(' ')}));
        }
        return node;
    }

    // ----- the four key numbers: the dashboard's gradient cards (ZT.kpiMetric) -----

    /**
     * Design 6.1: how a share changed from the period of the same length before, in percentage points; nothing when
     * either period has no value.
     */
    function change(current, previous) {
        if (current == null || previous == null) {
            return null;
        }
        const points = (current - previous) * 100;
        const shown = new Intl.NumberFormat(document.documentElement.lang || 'en', {maximumFractionDigits: 1,
            signDisplay: 'exceptZero'}).format(points);
        return m('kpi.delta', m('kpi.deltaPoints', shown));
    }

    /** A key card of a metric: it opens the screen that explains the number and draws the number's daily trend. */
    function keyCard(tone, icon, value, sub, trendValues, href, before) {
        const metric = value || {};
        const delta = change(metric.value, before);
        sub = delta ? (sub ? sub + ' · ' + delta : delta) : sub;
        return ZT.kpiMetric(metric, {tone, icon, sub, href, trend: trendValues,
            trendLabel: m('kpi.trend', metric.label || '')});
    }

    function keyCards(value, days) {
        const coverage = (value.coverage && value.coverage.coverage) || {};
        const stoppedCard = value.stopped || {};
        const stopped = shadow ? Object.assign({}, stoppedCard.stopped, {label: m('stopped.metric.shadow')})
            : (stoppedCard.stopped || {});
        const byAction = ordered(stoppedCard.byAction, STOPPED);
        const count = key => ZT.count(byAction.find(share => share.key === key).count);
        const pass = (value.impact && value.impact.challengePass && value.impact.challengePass.metric) || {};
        const perUser = (value.impact && value.impact.challengesPerUserWeek) || {};
        const model = (value.trust && value.trust.modelDecided) || {};
        const modelLess = (value.trust && value.trust.modelLess) || {};
        const previous = value.previous || {};
        return ZT.kpiRow(
            keyCard('indigo', 'fa-shield-alt', coverage,
                m('kpi.coverage.sub', ZT.count(coverage.numerator), ZT.count(coverage.denominator)),
                series(days, coverageOf), ZT.consoleLink('/operations'), previous.coverage),
            keyCard('purple', 'fa-hand-paper', stopped,
                m('kpi.stopped.sub', ZT.count(stopped.numerator), count('CHALLENGE'), count('BLOCK')),
                series(days, stoppedOf), ZT.consoleLink('/impact'), previous.stopped),
            keyCard('teal', 'fa-user-check', pass,
                m('kpi.pass.sub', ZT.metricText(perUser)),
                series(days, passOf), ZT.consoleLink('/impact'), previous.challengePass),
            keyCard('green', 'fa-robot', model,
                m('kpi.trust.sub', ZT.metricText(modelLess)),
                series(days, modelOf), ZT.consoleLink('/trust'), previous.modelDecided));
    }

    // ----- the decisions of each day, and their share by action -----

    function trendCard(days) {
        const has = days.some(day => day.point && decided(day.point) + day.point.noDecision > 0);
        const datasets = ACTIONS.map(action => ({type: 'bar', label: t('zt.console.ui.action.' + action),
            data: series(days, point => point[action.toLowerCase()]), backgroundColor: C[action], stack: 'decisions',
            borderRadius: 4, maxBarThickness: 48}));
        // Design 6.0, 6.1: "no decision" is every protected call no new decision answered: a decision reused, an
        // analysis skipped and a technical failure (the counts of the calls are over every tenant).
        datasets.push({type: 'line', label: m('trend.noDecision'), data: series(days, noDecisionOf),
            borderColor: C.MUTED, backgroundColor: C.MUTED, borderDash: [4, 4], pointRadius: 2, stack: 'noDecision'});
        datasets.push({type: 'line', label: m('trend.baseline'), data: series(days, point => point.baselineEstablished),
            yAxisID: 'ratio', borderColor: C.ACCENT, backgroundColor: C.ACCENT, pointRadius: 2, stack: 'baseline'});
        const box = el('div');
        const body = [];
        if (has) {
            body.push(ZT.legend(datasets.map(dataset => ({label: dataset.label, color: dataset.backgroundColor}))));
        }
        body.push(box);
        if (has && shadow) {
            body.push(el('div', {class: 'zt-muted', text: m('trend.shadow')}));
        }
        charts.push(() => ZT.chart(box, 'l', {type: 'bar', label: m('trend.label'),
            data: {labels: days.map(day => ZT.day(day.day)), datasets},
            axes: {x: {stacked: true}, y: {stacked: true}, ratio: true}}, has, 'NO_DECISIONS'));
        return ZT.card(m('trend.title'), m('trend.aside'), ...body);
    }

    /** The decisions of the period by their action: the dashboard's donut with the total in its centre. */
    function resultCard(summary, stoppedCard) {
        if (!summary.decisions) {
            return ZT.card(m('result.title'), null, ZT.empty('NO_DECISIONS'));
        }
        const byAction = ordered(stoppedCard && stoppedCard.byAction, STOPPED);
        const parts = [{key: 'ALLOW', count: Math.max(0, summary.decisions - summary.stopped)}]
            .concat(byAction.map(share => ({key: share.key, count: share.count})))
            .map(part => Object.assign(part, {label: t('zt.console.ui.action.' + part.key), color: C[part.key]}));
        const ring = el('div', {class: 'zt-donut'}, ZT.donut(parts, {label: m('result.title')}),
            el('div', {class: 'zt-donut-centre'}, el('div', {class: 'zt-donut-value', text: ZT.count(summary.decisions)}),
                el('div', {class: 'zt-donut-caption', text: m('result.total')})));
        const rows = el('div', {class: 'zt-result-rows'}, parts.map(part => el('a', {class: 'zt-result-row',
            href: decisions({action: part.key})},
            el('span', {class: 'zt-result-name'}, el('span', {class: 'zt-dot', style: {background: part.color}}), part.label),
            el('span', {class: 'zt-result-value', text: m('countShare', ZT.count(part.count),
                ZT.percent(summary.decisions > 0 ? part.count / summary.decisions : null))}))));
        return ZT.card(m('result.title'), m('result.aside'), el('div', {class: 'zt-result'}, ring, rows));
    }

    // ----- why the requests were stopped, and what to look at -----

    function reasonsCard(groups, summary) {
        const total = groups.reduce((sum, group) => sum + group.count, 0);
        if (!summary.decisions || total === 0) {
            return ZT.card(heading('reasons.title'), null,
                summary.decisions ? ZT.emptyNote(s('reasons.none')) : ZT.empty('NO_DECISIONS'));
        }
        const max = Math.max(...groups.map(group => group.count));
        const rows = el('div', {class: 'zt-reason-rows'}, groups.map((group, index) => {
            const label = ZT.keyLabel('zt.console.reasonGroup.', group.key);
            return el('div', {class: 'zt-reason-row'},
                el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: label}),
                    el('span', {class: 'zt-reason-value', text: m('countShare', ZT.count(group.count),
                        ZT.percent(group.ratio))})),
                ZT.bar(group.count, max, {color: ZT.SERIES[index % ZT.SERIES.length], label}));
        }));
        return foot(ZT.card(heading('reasons.title'), s('reasons.aside', ZT.count(total)), rows),
            link(ZT.consoleLink('/impact'), m('reasons.link')));
    }

    /** The warnings as the dashboard's indicator rows: the colour of its border says how urgent it is. */
    function alertsCard(alerts) {
        const body = alerts.length ? el('div', {class: 'zt-indicators'}, alerts.map(alert => {
            const rule = ZT.keyLabel(P + 'alerts.rule.', alert.key);
            return el('a', {class: 'zt-indicator', 'data-severity': alert.severity || 'INFO',
                href: ZT.keepPeriod(alert.link)},
                el('div', {class: 'zt-indicator-text'}, el('span', {class: 'zt-indicator-title', text: alert.message}),
                    rule !== alert.key ? el('span', {class: 'zt-indicator-rule', text: rule}) : null),
                ZT.statusChip(alert.severity));
        })) : ZT.emptyNote(m('alerts.none'));
        return ZT.card(m('alerts.title'), m('alerts.count', ZT.count(alerts.length)), body);
    }

    function render(content, value) {
        const header = value.header || {};
        shadow = header.mode === 'SHADOW';
        drawn.forEach(chart => chart && chart.destroy());
        drawn = [];
        charts = [];
        const days = calendar(header.period, value.trend || []);
        const summary = value.summary || {};
        content.append(
            summaryLine(summary),
            keyCards(value, days),
            grid(span(trendCard(days), 8), span(resultCard(summary, value.stopped), 4)),
            grid(span(reasonsCard(value.stopReasonGroups || [], summary), 6), span(alertsCard(value.alerts || []), 6)));
        // Chart.js sizes a chart from its box, so the charts are drawn once their boxes are on the page.
        drawn = charts.map(draw => draw());
    }

    ZT.start('/overview', render);
})(window.ZT);
