/*
 * Zero Trust console, decision trust (console design 6.3): "can the decisions be trusted?". Who set the action (the
 * model, the engine over the model, the engine without the model, and why), whether the evidence was enough (the
 * baseline, the context, the facts the model lacked), how the decisions turned out afterwards (step-ups passed, blocks
 * released, administrator reviews with their 95% ranges), the answers' quality and how each prompt bundle and model
 * decided.
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

    function note(text) {
        return el('div', {class: 'zt-metric-definition', text});
    }

    function label(text) {
        return el('div', {class: 'zt-metric-label', text});
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

    /** A ring of a ratio beside its number: the arc is the numerator's share of the denominator. */
    function ringTile(title, metric, node, color, ...below) {
        if (!metric || metric.value == null) {
            return ZT.card(title, null, node, ...below);
        }
        const ring = ZT.donut([{label: metric.label, count: metric.numerator, color},
            {label: m('ring.rest'), count: Math.max(0, metric.denominator - metric.numerator), color: C.TRACK}],
        {label: metric.label + ' ' + ZT.metricText(metric)});
        return ZT.card(title, null, el('div', {class: 'zt-split'},
            el('div', {class: 'zt-chart zt-chart-s'}, ring), node), ...below);
    }

    // ----- the three key numbers -----

    function modelTile(source) {
        return ringTile(m('model.title'), source.model, ZT.metric(source.model), C.GOOD);
    }

    function baselineTile(evidence) {
        const metric = shareMetric('baselineEstablished', find(evidence.baseline, 'ESTABLISHED'), decided);
        const parts = BASELINES.map(key => ({label: ZT.keyLabel(P + 'baseline.', key), count: find(evidence.baseline, key).count,
            color: BASELINE_COLORS[key]})).filter(part => part.count > 0);
        const below = [label(m('baseline.users', ZT.count(evidence.usersEstablished), ZT.count(evidence.users)))];
        if (decided > 0) {
            below.push(ZT.stacked(parts), ZT.legend(parts.map(part => ({label: m('legendShare', part.label,
                ZT.percent(part.count / decided)), color: part.color}))));
        }
        return ringTile(m('baseline.title'), metric, ZT.metric(metric), C.GOOD, ...below);
    }

    function reviewTile(outcomes) {
        const range = outcomes.reviewValid;
        return ringTile(m('review.title'), range && range.metric, ZT.ranged(range), C.GOOD,
            note(m('review.how')));
    }

    // ----- who set the action -----

    function causeRows(shares, whole) {
        const items = (shares || []).filter(share => share.count > 0);
        if (!items.length) {
            return note(m('source.noCause'));
        }
        return ZT.rows(items, share => [el('span', {text: ZT.causeName(share.key, P + 'cause.'), title: share.key}),
            el('span', {text: countShare(share.count, whole)})]);
    }

    function sourceCard(source) {
        const whole = source.model ? source.model.denominator : null;
        if (!whole) {
            return ZT.card(m('source.title'), null, ZT.empty(source.model ? source.model.noDataReason : 'NO_DECISIONS'));
        }
        const parts = [{metric: source.model, color: C.GOOD}, {metric: source.engineChanged, color: C.WARN},
            {metric: source.modelLess, color: C.BAD}].map(part => ({label: part.metric.label,
            count: part.metric.numerator || 0, color: part.color, text: ZT.metricText(part.metric)}));
        const engine = el('div', {class: 'zt-tile'}, el('div', {class: 'zt-card-body'},
            ZT.metric(source.engineChanged, {small: true}), label(m('source.engineCauses')),
            causeRows(source.engineCauses, source.engineChanged.numerator),
            link(decisions({source: 'ENGINE_CHANGED'}), m('source.engineLink'))));
        const modelLess = el('div', {class: 'zt-tile'}, el('div', {class: 'zt-card-body'},
            ZT.metric(source.modelLess, {small: true}), label(m('source.modelLessCauses')),
            causeRows(source.modelLessCauses, source.modelLess.numerator),
            link(decisions({source: 'MODEL_LESS', action: 'BLOCK'}), s('source.modelLessBlocks',
                ZT.count(source.modelLessBlocks))),
            link(decisions({source: 'MODEL_LESS'}), m('source.modelLessLink'))));
        return ZT.card(m('source.title'), m('source.aside', ZT.count(whole)), ZT.stacked(parts),
            ZT.legend(parts.map(part => ({label: m('legendShare', part.label, part.text), color: part.color}))),
            grid(span(engine, 6), span(modelLess, 6)));
    }

    // ----- was the evidence enough -----

    function contextCard(evidence) {
        // A level nothing recorded is left out only when no decision lacks its level.
        const items = keysOf(evidence.context, CONTEXTS).map(key => find(evidence.context, key))
            .filter(share => share.key !== 'UNKNOWN' || share.count > 0);
        const box = el('div');
        const body = [];
        if (decided > 0) {
            body.push(ZT.legend([{label: m('context.series'), color: C.ACCENT}]));
        }
        body.push(box);
        if (decided > 0) {
            body.push(ZT.rows(items, share => [el('span', {text: m('context.hintLine',
                ZT.keyLabel(P + 'context.', share.key), ZT.keyLabel(P + 'context.hint.', share.key))}),
            el('span', {text: countShare(share.count, decided)})]), note(m('context.note')));
        }
        charts.push(() => ZT.chart(box, 'm', {type: 'bar', label: items.map(share => ZT.keyLabel(P + 'context.', share.key)
            + ' ' + ZT.percent(share.ratio)).join(', '),
        data: {labels: items.map(share => ZT.keyLabel(P + 'context.', share.key)),
            datasets: [{label: m('context.series'), data: items.map(share => share.ratio), backgroundColor: C.ACCENT}]},
        axes: {y: {max: 1}, yFormat: value => ZT.percent(value, 0)},
        options: {plugins: {tooltip: {callbacks: {label: item => m('context.tooltip', ZT.percent(item.raw),
            ZT.count(items[item.dataIndex].count))}}}}}, decided > 0, 'NO_DECISIONS'));
        return ZT.card(m('context.title'), m('context.aside'), ...body);
    }

    /** What to do about a fact the model lacked: connect it, or look at what could not fetch it. */
    function unknownNext(reason) {
        if (reason === 'UNAVAILABLE_NOW') {
            return link(ZT.consoleLink('/operations'), m('unknown.operationsLink'));
        }
        return reason === 'NOT_INTEGRATED' ? note(m('unknown.integrateHint')) : null;
    }

    function unknownCard(evidence) {
        const facts = evidence.unknownFacts || [];
        if (!facts.length) {
            return ZT.card(m('unknown.title'), m('unknown.aside'), none(m('unknown.none')));
        }
        const tiles = facts.map(fact => span(el('div', {class: 'zt-tile'}, el('div', {class: 'zt-card-body'},
            ZT.rows([fact], item => [el('span', {text: ZT.factName(item.fact), title: item.fact}),
                el('span', {text: m('decisionsCount', ZT.count(item.decisions))})]),
            label(ZT.keyLabel(P + 'unknownReason.', fact.reason || 'UNKNOWN')), unknownNext(fact.reason))), 4));
        return ZT.card(m('unknown.title'), m('unknown.aside'), grid(...tiles));
    }

    // ----- how the decisions turned out -----

    function reviewRange(range) {
        if (!range || !range.metric || range.metric.value == null || range.lower95 == null) {
            return [];
        }
        const text = t('zt.console.ui.range95', ZT.percent(range.lower95, 0), ZT.percent(range.upper95, 0),
            ZT.count(range.sample));
        return [label(m('outcomes.reviewRange')),
            ZT.bar(range.metric.value, 1, {lower: range.lower95, upper: range.upper95, color: C.GOOD,
                label: ZT.metricText(range.metric) + ', ' + text}),
            ZT.rows([[ZT.percent(0, 0), ZT.percent(1, 0)]], ends => [el('span', {text: ends[0]}),
                el('span', {text: ends[1]})])];
    }

    function outcomesCard(outcomes) {
        const reasons = keysOf(outcomes.invalidReasons, INVALID).map(key => find(outcomes.invalidReasons, key))
            .filter(share => share.count > 0);
        const body = [ZT.ranged(outcomes.challengePass, {small: true}), note(m('outcomes.challengeNote')),
            ZT.ranged(outcomes.blockRelease, {small: true})].concat(reviewRange(outcomes.reviewValid));
        body.push(label(m('outcomes.invalidTitle')), reasons.length
            ? ZT.rows(reasons, share => [el('span', {text: ZT.keyLabel(P + 'invalid.', share.key)}),
                el('span', {text: m('countShareRatio', ZT.count(share.count), ZT.percent(share.ratio))})])
            : note(m('outcomes.invalidNone')));
        const card = ZT.card(m('outcomes.title'), m('outcomes.aside'), ...body);
        card.append(el('div', {class: 'zt-card-foot'}, label(m('outcomes.pending', ZT.count(outcomes.reviewPending)))));
        return card;
    }

    // ----- the answers' quality and what changed -----

    function qualityCard(quality) {
        return ZT.card(m('quality.title'), null, ZT.metric(quality.corrected, {small: true}),
            ZT.metric(quality.formatFallback, {small: true}), ZT.metric(quality.contractFallback, {small: true}),
            note(m('quality.note')));
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
        return ZT.card(m('changes.title'), m('changes.aside'), el('div', {class: 'zt-table-wrap'},
            el('table', {class: 'zt-table'}, el('thead', {}, head), body)), note(m('changes.note')));
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
            grid(span(modelTile(source), 4), span(baselineTile(evidence), 4), span(reviewTile(outcomes), 4)),
            grid(span(sourceCard(source), 12)),
            grid(span(contextCard(evidence), 6), span(outcomesCard(outcomes), 6)),
            grid(span(unknownCard(evidence), 12)),
            grid(span(qualityCard(value.quality || {}), 6), span(changesCard(value.changes || []), 6)));
        // Chart.js sizes a chart from its box, so the charts are drawn once their boxes are on the page.
        drawn = charts.map(draw => draw());
    }

    ZT.start('/trust', render);
})(window.ZT);
