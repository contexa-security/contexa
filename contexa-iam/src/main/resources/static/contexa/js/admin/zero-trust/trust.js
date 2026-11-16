/*
 * Zero Trust console, decision trust (console design 6.3): "can the decisions be trusted?". Drawn as the admin
 * dashboard draws: four key cards (the model set the action, the baseline was known, the administrators judged it
 * right, the owner passed the step-up), then who set the action and why, how the decisions turned out, whether the
 * evidence was enough (the baseline, the context, the facts the model lacked) and the answers' quality beside each
 * prompt bundle and model. A definition or a caption is a tooltip.
 */
(function (ZT) {
    'use strict';

    const t = ZT.t;
    const el = ZT.el;
    const C = ZT.COLORS;
    const P = 'zt.console.ui.trust.';
    const BASELINES = ['ESTABLISHED', 'PROVISIONAL', 'NONE', 'UNKNOWN'];
    const BASELINE_COLORS = {ESTABLISHED: C.GOOD, PROVISIONAL: C.WARN, NONE: C.MUTED, UNKNOWN: C.TEXT};
    const CONTEXTS = ['ENVIRONMENT_ONLY', 'IDENTITY_AWARE', 'SCOPE_AWARE', 'BUSINESS_AWARE', 'UNKNOWN'];
    const INVALID = ['OVERREACTION', 'FACTS_WRONG', 'MISSED_SIGNAL', 'OTHER'];

    let shadow = false;
    let decided = 0;
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

    function link(href, text) {
        return el('a', {class: 'zt-link', href, text});
    }

    function decisions(params) {
        return ZT.consoleLink('/decisions', params);
    }

    function none(text) {
        return decided ? ZT.emptyNote(text) : ZT.empty('NO_DECISIONS');
    }

    function countShare(value, whole) {
        return m('countShare', ZT.count(value), ZT.percent(whole > 0 ? value / whole : null));
    }

    function find(shares, key) {
        return (shares || []).find(share => share.key === key) || {key, count: 0, ratio: null};
    }

    /** The keys in the order given, then the others the data names. */
    function keysOf(shares, order) {
        const present = (shares || []).map(share => share.key);
        return order.concat(present.filter(key => !order.includes(key)));
    }

    /**
     * A share of the decisions as the console shows a metric, with the name and the definition of its metric in the
     * console's messages (console design 5), so it reads the same as on the overview.
     */
    function shareMetric(key, share, whole) {
        return {key, label: t('zt.console.metric.' + key + '.label'),
            description: t('zt.console.metric.' + key + '.description'),
            value: whole > 0 ? share.count / whole : null, numerator: share.count, denominator: whole, unit: 'RATIO',
            noDataReason: whole > 0 ? null : 'NO_DECISIONS'};
    }

    function rangeText(range) {
        return range && range.metric && range.metric.value != null && range.lower95 != null
            ? t('zt.console.ui.range95', ZT.percent(range.lower95, 0), ZT.percent(range.upper95, 0), ZT.count(range.sample))
            : null;
    }

    // ----- the four key cards -----

    function keyCards(source, evidence, outcomes) {
        const baseline = shareMetric('baselineEstablished', find(evidence.baseline, 'ESTABLISHED'), decided);
        const review = outcomes.reviewValid && outcomes.reviewValid.metric;
        const pass = outcomes.challengePass && outcomes.challengePass.metric;
        return ZT.kpiRow(
            ZT.kpiMetric(source.model, {tone: 'green', icon: 'fa-robot', href: decisions({source: 'MODEL'}),
                sub: m('kpi.model.sub', ZT.metricText(source.engineChanged), ZT.metricText(source.modelLess))}),
            ZT.kpiMetric(baseline, {tone: 'teal', icon: 'fa-user-shield',
                sub: m('baseline.users', ZT.count(evidence.usersEstablished), ZT.count(evidence.users))}),
            ZT.kpiMetric(review, {tone: 'indigo', icon: 'fa-clipboard-check',
                sub: rangeText(outcomes.reviewValid) || m('outcomes.pending', ZT.count(outcomes.reviewPending)),
                href: ZT.consoleLink('/decisions', {view: 'review'})}),
            ZT.kpiMetric(pass, {tone: 'purple', icon: 'fa-user-check',
                sub: m('kpi.release.sub', ZT.metricText(outcomes.blockRelease && outcomes.blockRelease.metric)),
                href: decisions({action: 'CHALLENGE', outcome: 'CHALLENGE_PASSED'})}));
    }

    // ----- who set the action, and why -----

    function causeRows(shares, whole) {
        const items = (shares || []).filter(share => share.count > 0);
        if (!items.length) {
            return ZT.emptyNote(m('source.noCause'));
        }
        return ZT.valueRows(items.map(share => ({label: ZT.causeName(share.key, P + 'cause.'), title: share.key,
            value: countShare(share.count, whole)})));
    }

    function sourceCard(source) {
        const whole = source.model ? source.model.denominator : null;
        if (!whole) {
            return ZT.card(m('source.title'), null, ZT.empty(source.model ? source.model.noDataReason : 'NO_DECISIONS'));
        }
        const parts = [{metric: source.model, color: C.GOOD, href: decisions({source: 'MODEL'})},
            {metric: source.engineChanged, color: C.WARN, href: decisions({source: 'ENGINE_CHANGED'})},
            {metric: source.modelLess, color: C.BAD, href: decisions({source: 'MODEL_LESS'})}]
            .map(part => ({label: part.metric.label, count: part.metric.numerator || 0, color: part.color,
                text: ZT.metricText(part.metric), href: part.href, title: part.metric.description}));
        return ZT.card(m('source.title'), m('source.aside', ZT.count(whole)), ZT.stacked(parts),
            ZT.valueRows(parts.map(part => ({label: part.label, color: part.color, value: part.text, href: part.href,
                title: part.title}))),
            ZT.subhead(m('source.engineCauses')), causeRows(source.engineCauses, source.engineChanged.numerator),
            ZT.subhead(m('source.modelLessCauses')), causeRows(source.modelLessCauses, source.modelLess.numerator),
            el('div', {class: 'zt-card-foot'}, link(decisions({source: 'MODEL_LESS', action: 'BLOCK'}),
                s('source.modelLessBlocks', ZT.count(source.modelLessBlocks)))));
    }

    // ----- how the decisions turned out -----

    function outcomesCard(outcomes) {
        const reasons = keysOf(outcomes.invalidReasons, INVALID).map(key => find(outcomes.invalidReasons, key))
            .filter(share => share.count > 0);
        const metricRow = (range, href) => {
            const metric = (range && range.metric) || {};
            return {label: metric.label || '', value: ZT.metricText(metric), href,
                title: [metric.description, rangeText(range)].filter(Boolean).join(' · ') || null};
        };
        const body = [ZT.valueRows([metricRow(outcomes.challengePass,
            decisions({action: 'CHALLENGE', outcome: 'CHALLENGE_PASSED'})),
        metricRow(outcomes.blockRelease, decisions({action: 'BLOCK', outcome: 'ADMIN_RELEASED'})),
        metricRow(outcomes.reviewValid, ZT.consoleLink('/decisions', {view: 'review'}))])];
        const range = outcomes.reviewValid;
        if (range && range.metric && range.metric.value != null && range.lower95 != null) {
            body.push(ZT.subhead(m('outcomes.reviewRange'), rangeText(range)),
                ZT.bar(range.metric.value, 1, {lower: range.lower95, upper: range.upper95, color: C.GOOD,
                    label: ZT.metricText(range.metric) + ', ' + rangeText(range)}));
        }
        body.push(ZT.subhead(m('outcomes.invalidTitle')), reasons.length
            ? ZT.valueRows(reasons.map(share => ({label: ZT.keyLabel(P + 'invalid.', share.key),
                value: m('countShareRatio', ZT.count(share.count), ZT.percent(share.ratio))})))
            : ZT.emptyNote(m('outcomes.invalidNone')));
        return ZT.withTip(ZT.card(m('outcomes.title'), m('outcomes.pending', ZT.count(outcomes.reviewPending)), ...body),
            [m('outcomes.challengeNote'), m('review.how')].join(' '));
    }

    // ----- was the evidence enough -----

    function baselineCard(evidence) {
        const parts = BASELINES.map(key => ({key, label: ZT.keyLabel(P + 'baseline.', key),
            count: find(evidence.baseline, key).count, color: BASELINE_COLORS[key]}))
            .filter(part => part.count > 0 || part.key !== 'UNKNOWN');
        if (!decided) {
            return ZT.card(m('baseline.title'), null, ZT.empty('NO_DECISIONS'));
        }
        return ZT.card(m('baseline.title'), m('baseline.users', ZT.count(evidence.usersEstablished), ZT.count(evidence.users)),
            ZT.stacked(parts), ZT.valueRows(parts.map(part => ({label: part.label, color: part.color,
                value: countShare(part.count, decided)}))));
    }

    function contextCard(evidence) {
        // A level nothing recorded is left out only when no decision lacks its level.
        const items = keysOf(evidence.context, CONTEXTS).map(key => find(evidence.context, key))
            .filter(share => share.key !== 'UNKNOWN' || share.count > 0);
        const box = el('div');
        const body = [box];
        if (decided > 0) {
            body.push(ZT.valueRows(items.map(share => ({label: ZT.keyLabel(P + 'context.', share.key),
                title: ZT.keyLabel(P + 'context.hint.', share.key), value: countShare(share.count, decided)}))));
        }
        charts.push(() => ZT.chart(box, 'm', {type: 'bar', label: items.map(share => ZT.keyLabel(P + 'context.', share.key)
            + ' ' + ZT.percent(share.ratio)).join(', '),
        data: {labels: items.map(share => ZT.keyLabel(P + 'context.', share.key)),
            datasets: [{label: m('context.series'), data: items.map(share => share.ratio), backgroundColor: C.ACCENT,
                borderRadius: 4, maxBarThickness: 56}]},
        axes: {y: {max: 1}, yFormat: value => ZT.percent(value, 0)},
        options: {plugins: {tooltip: {callbacks: {label: item => m('context.tooltip', ZT.percent(item.raw),
            ZT.count(items[item.dataIndex].count))}}}}}, decided > 0, 'NO_DECISIONS'));
        return ZT.withTip(ZT.card(m('context.title'), m('context.aside'), ...body), m('context.note'));
    }

    /** What to do about a fact the model lacked: connect it, or look at what could not fetch it. */
    function unknownNext(reason) {
        if (reason === 'UNAVAILABLE_NOW') {
            return link(ZT.consoleLink('/operations'), m('unknown.operationsLink'));
        }
        return reason === 'NOT_INTEGRATED' ? el('span', {class: 'zt-muted', text: m('unknown.integrateHint')}) : '—';
    }

    function unknownCard(evidence) {
        const facts = evidence.unknownFacts || [];
        if (!facts.length) {
            return ZT.card(m('unknown.title'), m('unknown.aside'), none(m('unknown.none')));
        }
        const head = el('tr', {}, el('th', {scope: 'col', text: m('unknown.column.fact')}),
            el('th', {scope: 'col', text: m('unknown.column.reason')}),
            el('th', {scope: 'col', class: 'zt-num', text: m('unknown.column.decisions')}),
            el('th', {scope: 'col', class: 'zt-wide', text: m('unknown.column.next')}));
        const body = el('tbody', {}, facts.map(fact => el('tr', {},
            el('td', {class: 'zt-fill', title: fact.fact, text: ZT.factName(fact.fact)}),
            el('td', {text: ZT.keyLabel(P + 'unknownReason.', fact.reason || 'UNKNOWN')}),
            el('td', {class: 'zt-num', text: ZT.count(fact.decisions)}),
            el('td', {class: 'zt-wide'}, unknownNext(fact.reason)))));
        return ZT.card(m('unknown.title'), m('unknown.aside'), el('div', {class: 'modern-table zt-table-wrap'},
            el('table', {class: 'zt-table'}, el('thead', {}, head), body)));
    }

    // ----- the answers' quality and what changed -----

    function qualityCard(quality) {
        const row = metric => ({label: (metric || {}).label || '', value: ZT.metricText(metric),
            title: (metric || {}).description || null});
        return ZT.withTip(ZT.card(m('quality.title'), null, ZT.valueRows([row(quality.corrected),
            row(quality.formatFallback), row(quality.contractFallback)])), m('quality.note'));
    }

    function named(value) {
        return value == null || value === 'NONE' ? m('changes.none') : value;
    }

    function lastDay(iso) {
        const end = Date.parse(iso);
        return Number.isNaN(end) ? iso : new Date(end - 1).toISOString();
    }

    function ratioCell(ratio, whole) {
        if (ratio == null) {
            return el('span', {text: '—'});
        }
        return el('span', {text: ZT.percent(ratio),
            title: m('ratio', ZT.count(Math.round(ratio * whole)), ZT.count(whole))});
    }

    function changesCard(changes) {
        if (!changes.length) {
            return ZT.card(m('changes.title'), null, ZT.empty('NO_DECISIONS'));
        }
        const columns = [{label: m('changes.pair'), fill: true}, {label: m('changes.period'), wide: true},
            {label: m('changes.decisions'), num: true}, {label: s('changes.stopped'), num: true},
            {label: m('changes.modelLess'), num: true, wide: true}];
        const head = el('tr', {}, columns.map(column => el('th', {scope: 'col',
            class: [column.num ? 'zt-num' : '', column.wide ? 'zt-wide' : ''].join(' ').trim() || null,
            text: column.label})));
        const body = el('tbody', {}, changes.map(row => {
            const pair = m('changes.pairValue', named(row.bundle), named(row.model));
            return el('tr', {}, el('td', {class: 'zt-fill', title: pair, text: pair}),
                el('td', {class: 'zt-wide', text: m('changes.span', ZT.day(row.from), ZT.day(row.to ? lastDay(row.to) : null))}),
                el('td', {class: 'zt-num', text: ZT.count(row.decisions)}),
                el('td', {class: 'zt-num'}, ratioCell(row.stoppedRatio, row.decisions)),
                el('td', {class: 'zt-num zt-wide'}, ratioCell(row.modelLessRatio, row.decisions)));
        }));
        return ZT.withTip(ZT.card(m('changes.title'), m('changes.aside'), el('div', {class: 'modern-table zt-table-wrap'},
            el('table', {class: 'zt-table'}, el('thead', {}, head), body))), m('changes.note'));
    }

    function render(content, value) {
        const header = value.header || {};
        shadow = header.mode === 'SHADOW';
        decided = header.decisions || 0;
        drawn.forEach(chart => chart && chart.destroy());
        drawn = [];
        charts = [];
        const source = value.source || {};
        const evidence = value.evidence || {};
        const outcomes = value.outcomes || {};
        content.append(
            keyCards(source, evidence, outcomes),
            grid(span(sourceCard(source), 6), span(outcomesCard(outcomes), 6)),
            grid(span(baselineCard(evidence), 4), span(contextCard(evidence), 8)),
            unknownCard(evidence),
            grid(span(qualityCard(value.quality || {}), 4), span(changesCard(value.changes || []), 8)));
        // Chart.js sizes a chart from its box, so the charts are drawn once their boxes are on the page.
        drawn = charts.map(draw => draw());
    }

    ZT.start('/trust', render);
})(window.ZT);
