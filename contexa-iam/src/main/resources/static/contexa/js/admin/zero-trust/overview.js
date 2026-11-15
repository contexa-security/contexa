/*
 * Zero Trust console, overview (console design 6.1): "are we protecting what we should, right now?". The period's
 * protection flow in a sentence and four steps, four key cards with their daily trend, the decisions of each day, the
 * warnings to look at and the reasons the stopped decisions gave. In SHADOW a stopped request is one ENFORCE would
 * have stopped, and the screen says so.
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

    /** A number beside the main one: its definition stays in its tooltip. */
    function minor(value) {
        const node = ZT.metric(value, {small: true, hideDefinition: true});
        if (value && value.description) {
            node.title = value.description;
        }
        return node;
    }

    function minorRanged(range) {
        const node = ZT.ranged(range, {small: true, hideDefinition: true});
        if (range && range.metric && range.metric.description) {
            node.title = range.metric.description;
        }
        return node;
    }

    /** A count of the response (not a ratio) shown as the console shows a metric; "—" and the reason without one. */
    function counted(label, value, reasonCode) {
        return ZT.metric({key: null, label, description: null, value: value == null ? null : value, numerator: null,
            denominator: null, unit: 'COUNT', noDataReason: value == null ? reasonCode : null}, {small: true});
    }

    function countShare(value, whole) {
        return m('countShare', ZT.count(value), ZT.percent(whole > 0 ? value / whole : null));
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

    function modelOf(point) {
        const all = decided(point);
        return all === 0 ? null : point.model / all;
    }

    /** A small trend line of a daily series and its lowest and highest day in words. */
    function trend(name, values, format, color) {
        const present = values.filter(value => value != null);
        if (present.length < 2) {
            return el('div', {class: 'zt-metric-definition', text: m('spark.tooFew', name)});
        }
        const text = m('spark.range', name, format(Math.min(...present)), format(Math.max(...present)));
        return el('div', {class: 'zt-metric'}, ZT.sparkline(values, {label: text, color}),
            el('div', {class: 'zt-metric-definition', text}));
    }

    const ratioText = value => ZT.percent(value);
    const countText = value => ZT.count(value);

    // ----- the protection flow -----

    function verdict(summary) {
        const node = el('div', {class: 'zt-verdict'});
        if (!summary.decisions) {
            node.append(el('p', {text: ZT.reason('NO_DECISIONS')}));
            return node;
        }
        node.append(el('p', {text: s('flow.sentence', ZT.count(summary.decisions), ZT.count(summary.stopped),
            ZT.percent(summary.stoppedRatio))}));
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
            node.append(el('div', {class: 'zt-metric-label', text: after.join(' ')}));
        }
        return node;
    }

    function step(title, ...body) {
        return el('div', {class: 'zt-tile'}, el('div', {class: 'zt-card-body'},
            el('div', {class: 'zt-metric-label', text: title}), ...body));
    }

    function partRows(parts, whole) {
        return ZT.rows(parts, part => [el('span', {text: part.label}),
            part.href ? link(part.href, countShare(part.count, whole)) : el('span', {text: countShare(part.count, whole)})]);
    }

    /** ① The protected calls and the share a decision answered. */
    function protectedStep(coverage) {
        const ratio = coverage.coverage;
        const body = [ZT.metric(ratio, {small: true, hideDefinition: true})];
        if (ratio.value != null) {
            const noDecision = coverage.noDecision && coverage.noDecision.value != null ? coverage.noDecision.value : 0;
            const parts = [{label: m('flow.answered'), count: ratio.numerator, color: C.ACCENT},
                {label: m('flow.noDecision'), count: noDecision, color: C.MUTED}];
            body.push(ZT.stacked(parts), ZT.legend(parts), partRows(parts, ratio.denominator));
        }
        body.push(link(ZT.consoleLink('/operations'), m('flow.noDecisionLink')));
        return step(m('flow.step1'), ...body);
    }

    /** ② The decisions and the share that was stopped. */
    function decidedStep(summary) {
        if (!summary.decisions) {
            return step(m('flow.step2'), counted(m('flow.decisions'), null, 'NO_DECISIONS'));
        }
        const parts = [{label: m('flow.notStopped'), count: summary.decisions - summary.stopped, color: C.ALLOW},
            {label: s('flow.stopped'), count: summary.stopped, color: C.CHALLENGE}];
        return step(m('flow.step2'), counted(m('flow.decisions'), summary.decisions), ZT.stacked(parts),
            ZT.legend(parts), partRows(parts, summary.decisions));
    }

    /** ③ How the stopped requests were stopped: the action chips are the legend. */
    function stoppedStep(card, summary) {
        if (!summary.decisions) {
            return step(s('flow.step3'), counted(s('flow.stopped'), null, 'NO_DECISIONS'));
        }
        const shares = ordered(card.byAction, STOPPED);
        const parts = shares.map(share => ({label: t('zt.console.ui.action.' + share.key), count: share.count,
            color: C[share.key]}));
        return step(s('flow.step3'), counted(s('flow.stopped'), summary.stopped), ZT.stacked(parts),
            ZT.rows(shares, share => [ZT.chip(share.key),
                link(decisions({action: share.key}), countShare(share.count, summary.stopped))]));
    }

    /** ④ What came after: the step-ups the account owner passed, the blocks an administrator released. */
    function afterStep(summary) {
        if (!summary.decisions) {
            return step(m('flow.step4'), counted(m('flow.outcomes'), null, 'NO_DECISIONS'));
        }
        const challenges = [{label: m('flow.passed'), count: summary.challengesPassed, color: C.GOOD,
            href: decisions({action: 'CHALLENGE', outcome: 'CHALLENGE_PASSED'})},
            {label: m('flow.notPassed'), count: Math.max(0, summary.challenges - summary.challengesPassed),
                color: C.CHALLENGE}];
        const blocks = [{label: m('flow.released'), count: summary.blocksReleased, color: C.ACCENT,
            href: decisions({action: 'BLOCK', outcome: 'ADMIN_RELEASED'})},
            {label: m('flow.notReleased'), count: Math.max(0, summary.blocks - summary.blocksReleased), color: C.BLOCK}];
        const body = [ZT.stacked(challenges.concat(blocks)), ZT.legend(challenges.concat(blocks)),
            el('div', {class: 'zt-metric-label', text: m('flow.ofChallenges', ZT.count(summary.challenges))}),
            partRows(challenges, summary.challenges),
            el('div', {class: 'zt-metric-label', text: m('flow.ofBlocks', ZT.count(summary.blocks))}),
            partRows(blocks, summary.blocks)];
        if (shadow) {
            body.push(el('div', {class: 'zt-metric-definition', text: m('flow.after.shadow')}));
        }
        return step(m('flow.step4'), ...body);
    }

    function flowCard(value) {
        const summary = value.summary || {};
        return ZT.card(s('flow.title'), m('flow.aside'), verdict(summary),
            grid(span(protectedStep(value.coverage), 3), span(decidedStep(summary), 3),
                span(stoppedStep(value.stopped, summary), 3), span(afterStep(summary), 3)));
    }

    // ----- the four key cards -----

    function noDecisionReasons(shares) {
        const top = (shares || []).filter(share => share.count > 0).slice(0, 3);
        if (!top.length) {
            return null;
        }
        return ZT.rows(top, share => [el('span', {text: ZT.keyLabel(P + 'noDecisionReason.', share.key)}),
            el('span', {text: m('countShareRatio', ZT.count(share.count), ZT.percent(share.ratio))})]);
    }

    function coverageCard(card, days) {
        return foot(ZT.card(m('coverage.title'), null, ZT.metric(card.coverage),
            trend(m('coverage.trend'), series(days, coverageOf), ratioText, C.ACCENT),
            minor(card.noDecision), noDecisionReasons(card.noDecisionReasons)),
        link(ZT.consoleLink('/operations'), m('coverage.link')));
    }

    function stoppedCard(card, days) {
        const stopped = shadow ? Object.assign({}, card.stopped, {label: m('stopped.metric.shadow')}) : card.stopped;
        return foot(ZT.card(s('stopped.title'), null, ZT.metric(stopped),
            trend(s('stopped.trend'), series(days, stoppedOf), ratioText, C.CHALLENGE), minor(card.beforeResponse)),
        link(ZT.consoleLink('/impact'), m('stopped.link')));
    }

    function impactCard(card, days) {
        const perUser = shadow ? Object.assign({}, card.challengesPerUserWeek, {label: m('impact.perUserWeek.shadow')})
            : card.challengesPerUserWeek;
        return foot(ZT.card(m('impact.title'), null, ZT.metric(perUser),
            trend(s('impact.trend'), series(days, point => point.challenge), countText, C.CHALLENGE),
            el('div', {class: 'zt-split'}, minorRanged(card.challengePass), minor(card.userWaitP95)),
            minorRanged(card.blockRelease)),
        link(ZT.consoleLink('/impact'), m('impact.link')));
    }

    function trustCard(card, days) {
        return foot(ZT.card(m('trust.title'), null, ZT.metric(card.modelDecided),
            trend(m('trust.trend'), series(days, modelOf), ratioText, C.GOOD),
            el('div', {class: 'zt-split'}, minor(card.baselineEstablished), minor(card.modelLess)),
            trend(m('trust.baselineTrend'), series(days, point => point.baselineEstablished), ratioText, C.ACCENT),
            minorRanged(card.reviewValid)),
        link(ZT.consoleLink('/trust'), m('trust.link')));
    }

    // ----- the decisions of each day -----

    function trendCard(days) {
        const has = days.some(day => day.point && decided(day.point) + day.point.noDecision > 0);
        const datasets = ACTIONS.map(action => ({type: 'bar', label: t('zt.console.ui.action.' + action),
            data: series(days, point => point[action.toLowerCase()]), backgroundColor: C[action], stack: 'decisions'}));
        datasets.push({type: 'line', label: m('trend.noDecision'), data: series(days, point => point.noDecision),
            borderColor: C.MUTED, backgroundColor: C.MUTED, borderDash: [4, 4], pointRadius: 2, stack: 'noDecision'});
        const box = el('div');
        const body = [];
        if (has) {
            body.push(ZT.legend(datasets.map(dataset => ({label: dataset.label, color: dataset.backgroundColor}))));
        }
        body.push(box);
        if (has && shadow) {
            body.push(el('div', {class: 'zt-metric-definition', text: m('trend.shadow')}));
        }
        charts.push(() => ZT.chart(box, 'l', {type: 'bar', label: m('trend.label'),
            data: {labels: days.map(day => ZT.day(day.day)), datasets},
            axes: {x: {stacked: true}, y: {stacked: true}}}, has, 'NO_DECISIONS'));
        return ZT.card(m('trend.title'), m('trend.aside'), ...body);
    }

    // ----- what to look at -----

    function alertsCard(alerts) {
        const body = alerts.length ? el('ul', {class: 'zt-rows'}, alerts.map(alert => {
            const rule = ZT.keyLabel(P + 'alerts.rule.', alert.key);
            return el('li', {class: 'zt-alert'}, ZT.statusChip(alert.severity),
                el('div', {class: 'zt-item'}, link(ZT.keepPeriod(alert.link), m('alerts.open', alert.message)),
                    rule !== alert.key ? el('div', {class: 'zt-metric-definition', text: rule}) : null));
        })) : el('div', {class: 'zt-metric-label', text: m('alerts.none')});
        return ZT.card(m('alerts.title'), m('alerts.count', ZT.count(alerts.length)), body);
    }

    // ----- why the requests were stopped -----

    function reasonsCard(groups, summary) {
        const total = groups.reduce((sum, group) => sum + group.count, 0);
        if (!summary.decisions || total === 0) {
            return ZT.card(s('reasons.title'), null,
                summary.decisions ? ZT.emptyNote(s('reasons.none')) : ZT.empty('NO_DECISIONS'));
        }
        const parts = groups.map((group, index) => ({label: ZT.keyLabel('zt.console.reasonGroup.', group.key),
            count: group.count, ratio: group.ratio, color: ZT.SERIES[index % ZT.SERIES.length]}));
        const max = Math.max(...parts.map(part => part.count));
        const table = el('div', {class: 'zt-criteria'}, parts.flatMap(part => [el('span', {text: part.label}),
            ZT.bar(part.count, max, {color: part.color, label: part.label}),
            el('span', {class: 'zt-num', text: ZT.percent(part.ratio)}),
            el('span', {class: 'zt-num', text: ZT.count(part.count)})]));
        return foot(ZT.card(s('reasons.title'), s('reasons.aside', ZT.count(total)), ZT.stacked(parts),
            ZT.legend(parts), table), link(ZT.consoleLink('/impact'), m('reasons.link')));
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
            grid(span(flowCard(value), 12)),
            grid(span(coverageCard(value.coverage, days), 3), span(stoppedCard(value.stopped, days), 3),
                span(impactCard(value.impact, days), 3), span(trustCard(value.trust, days), 3)),
            grid(span(trendCard(days), 8), span(alertsCard(value.alerts || []), 4)),
            grid(span(reasonsCard(value.stopReasonGroups || [], summary), 12)));
        // Chart.js sizes a chart from its box, so the charts are drawn once their boxes are on the page.
        drawn = charts.map(draw => draw());
    }

    ZT.start('/overview', render);
})(window.ZT);
