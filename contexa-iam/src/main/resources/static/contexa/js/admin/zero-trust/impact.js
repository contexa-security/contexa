/*
 * Zero Trust console, threats and business impact (console design 6.2): "what was stopped, and what did it cost?".
 * What was stopped and why (the most likely explanation, when it took effect, where and when), and what the business
 * paid for it (the step-ups and their outcome, the wait, the review holds and blocks, the burden on each user). In
 * SHADOW a stopped request is one ENFORCE would have stopped, and the screen says so.
 */
(function (ZT) {
    'use strict';

    const t = ZT.t;
    const el = ZT.el;
    const C = ZT.COLORS;
    const P = 'zt.console.ui.impact.';
    const STOPPED = ['CHALLENGE', 'ESCALATE', 'BLOCK'];
    const HYPOTHESES = ['H1', 'H2', 'H3', 'H4', 'H5'];
    const HYPOTHESIS_COLORS = {H1: C.GOOD, H2: C.BAD, H3: C.ESCALATE, H4: C.WARN, H5: C.MUTED};
    const CLASSES = ['CRITICAL', 'SENSITIVE', 'CONFIDENTIAL', 'RESTRICTED', 'NORMAL'];
    const TIMINGS = ['BEFORE_RESPONSE', 'NEXT_REQUEST'];
    const WEEKDAYS = ['1', '2', '3', '4', '5', '6', '7'];
    const BANDS = ['0', '1', '2', '3', '4', '5'];
    /** The weekend days (ISO 6 Saturday, 7 Sunday) and the night bands (0 to 4 h, 20 to 24 h). */
    const WEEKEND = ['6', '7'];
    const NIGHT = ['0', '5'];
    const BURDEN = ['0', '1', '2', '3', '4+'];

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

    function minor(value) {
        const node = ZT.metric(value, {small: true, hideDefinition: true});
        if (value && value.description) {
            node.title = value.description;
        }
        return node;
    }

    function note(text) {
        return el('div', {class: 'zt-metric-definition', text});
    }

    function label(text) {
        return el('div', {class: 'zt-metric-label', text});
    }

    /** "—" and why: no decision in the period, or none of the kind the card counts. */
    function none(text) {
        return decided ? ZT.emptyNote(text) : ZT.empty('NO_DECISIONS');
    }

    function countShare(value, whole) {
        return m('countShare', ZT.count(value), ZT.percent(whole > 0 ? value / whole : null));
    }

    /** The keys in the order given, then the others the data names, largest first. */
    function keysOf(present, order) {
        const known = order.filter(key => present.includes(key));
        return known.concat(present.filter(key => !order.includes(key) && key !== 'NONE'),
            present.includes('NONE') ? ['NONE'] : []);
    }

    function hypothesisName(key) {
        return ZT.keyLabel(P + 'hypothesis.', key);
    }

    function className(key) {
        return ZT.keyLabel(P + 'resourceClass.', key);
    }

    function find(shares, key) {
        return (shares || []).find(share => share.key === key) || {key, count: 0, ratio: null};
    }

    /** A table: words left, numbers right; a phone keeps the columns not marked wide. */
    function table(columns, items, cells) {
        const head = el('tr', {}, columns.map(column => el('th', {scope: 'col',
            class: [column.num ? 'zt-num' : '', column.wide ? 'zt-wide' : ''].join(' ').trim() || null,
            text: column.label})));
        const body = el('tbody', {}, items.map(item => el('tr', {}, cells(item).map((cell, index) => {
            const column = columns[index];
            const node = el('td', {class: [column.num ? 'zt-num' : '', column.wide ? 'zt-wide' : '',
                column.fill ? 'zt-fill' : ''].join(' ').trim() || null});
            if (cell instanceof Node) {
                node.append(cell);
            } else {
                node.textContent = cell == null ? '—' : String(cell);
            }
            if (column.fill) {
                node.title = node.textContent;
            }
            return node;
        }))));
        return el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table'}, el('thead', {}, head), body));
    }

    // ----- what was stopped -----

    function hypothesisParts(side) {
        const keys = keysOf((side.hypotheses || []).filter(share => share.count > 0).map(share => share.key), HYPOTHESES);
        return keys.map(key => ({key, label: hypothesisName(key), count: find(side.hypotheses, key).count,
            ratio: find(side.hypotheses, key).ratio, color: HYPOTHESIS_COLORS[key] || C.ACCENT}));
    }

    function hypotheses(side) {
        const parts = hypothesisParts(side);
        if (side.explained === 0 || !parts.length) {
            return [none(m('hypotheses.none'))];
        }
        const list = el('div', {class: 'zt-card-body'}, ZT.legend(parts),
            ZT.rows(parts, part => [el('span', {text: part.label}),
                el('span', {text: m('shareCount', ZT.percent(part.ratio), ZT.count(part.count))})]));
        const body = [el('div', {class: 'zt-split'},
            el('div', {class: 'zt-chart zt-chart-s'}, ZT.donut(parts, {label: parts.map(part => part.label + ' '
                + ZT.percent(part.ratio)).join(', ')})), list),
        note(m('hypotheses.caption', ZT.count(side.explained)))];
        if (find(side.hypotheses, 'H1').count > 0) {
            body.push(note(m('hypotheses.h1Note')));
        }
        return body;
    }

    function stoppedCard(side) {
        if (!side.stopped) {
            return ZT.card(s('stopped.title'), s('stopped.aside', ZT.count(0)), none(s('stopped.none')));
        }
        const body = [label(s('stopped.hypotheses'))].concat(hypotheses(side));
        body.push(label(s('stopped.byAction')), ZT.rows(STOPPED.map(key => find(side.byAction, key)), share => [
            ZT.chip(share.key), link(decisions({action: share.key}), countShare(share.count, side.stopped))]));
        const timing = TIMINGS.concat((side.timing || []).map(share => share.key).filter(key => !TIMINGS.includes(key)))
            .map(key => find(side.timing, key));
        body.push(label(m('stopped.timing')), ZT.rows(timing, share => [
            el('span', {text: ZT.keyLabel(P + 'timing.', share.key)}),
            el('span', {text: countShare(share.count, side.stopped)})]));
        if (find(side.timing, 'NEXT_REQUEST').count > 0) {
            body.push(note(m('timing.nextRequestNote')));
        }
        const classes = keysOf((side.resourceClasses || []).filter(share => share.count > 0).map(share => share.key),
            CLASSES).map((key, index) => ({label: className(key), count: find(side.resourceClasses, key).count,
            color: ZT.SERIES[index % ZT.SERIES.length]}));
        if (classes.length) {
            body.push(label(m('stopped.classes')), ZT.stacked(classes), ZT.legend(classes.map(part => ({
                label: m('legendCount', part.label, ZT.count(part.count)), color: part.color}))));
        }
        return ZT.card(s('stopped.title'), s('stopped.aside', ZT.count(side.stopped)), ...body);
    }

    // ----- what it cost -----

    function funnelBlock(funnel) {
        if (funnel.required === 0) {
            return [none(s('funnel.none'))];
        }
        const code = funnel.codeRequests;
        const body = [ZT.funnel([{label: s('funnel.required'), count: funnel.required, color: C.CHALLENGE},
            {label: code.label, count: code.value, color: C.MUTED},
            {label: m('funnel.passed'), count: funnel.passed, color: C.GOOD}])];
        const missing = note(m('funnel.codeRequests', code.label, ZT.reason(code.noDataReason)));
        if (code.description) {
            missing.title = code.description;
        }
        body.push(missing, ZT.ranged(funnel.passRate, {small: true}),
            ZT.rows([{label: m('funnel.failed'), count: funnel.failed, outcome: 'CHALLENGE_FAILED'},
                {label: m('funnel.expired'), count: funnel.expired, outcome: 'CHALLENGE_EXPIRED'}], row => [
                el('span', {text: row.label}),
                link(decisions({action: 'CHALLENGE', outcome: row.outcome}), countShare(row.count, funnel.required))]),
            note(m('funnel.note')));
        return body;
    }

    function blockBlock(blocks) {
        if (blocks.blocks === 0) {
            return [label(s('blocks.title', ZT.count(0)))];
        }
        return [label(s('blocks.title', ZT.count(blocks.blocks))),
            ZT.rows([{label: m('blocks.released'), count: blocks.released, outcome: 'ADMIN_RELEASED'},
                {label: m('blocks.kept'), count: blocks.kept, outcome: 'BLOCK_KEPT'}], row => [
                el('span', {text: row.label}),
                link(decisions({action: 'BLOCK', outcome: row.outcome}), countShare(row.count, blocks.blocks))]),
            minor(blocks.releaseMedianHours)];
    }

    function costCard(cost) {
        const body = [label(s('funnel.title'))].concat(funnelBlock(cost.challenges));
        if (shadow) {
            body.push(note(m('cost.shadowNote')));
        }
        body.push(label(m('cost.wait')), el('div', {class: 'zt-split'}, minor(cost.userWaitP50), minor(cost.userWaitP95)),
            ZT.rows([{label: s('cost.escalations'), count: cost.escalations}], row => [el('span', {text: row.label}),
                link(decisions({action: 'ESCALATE'}), m('count', ZT.count(row.count)))]));
        return ZT.card(s('cost.title'), m('cost.aside'), ...body.concat(blockBlock(cost.blocks)));
    }

    // ----- where and when -----

    function matrixCard(cells) {
        const used = cells.filter(cell => cell.count > 0);
        if (!used.length) {
            return ZT.card(m('matrix.title'), s('matrix.aside'), none(s('stopped.none')));
        }
        const rows = keysOf([...new Set(used.map(cell => cell.row))], HYPOTHESES);
        const columns = keysOf([...new Set(used.map(cell => cell.column))], CLASSES);
        return ZT.card(m('matrix.title'), s('matrix.aside'),
            el('div', {class: 'zt-heat'}, ZT.heatmap(rows, columns, used, hypothesisName, className)),
            note(m('matrix.caption')));
    }

    function whenCard(cells) {
        const used = cells.filter(cell => cell.count > 0);
        if (!used.length) {
            return ZT.card(s('when.title'), m('when.aside'), none(s('stopped.none')));
        }
        const total = used.reduce((sum, cell) => sum + cell.count, 0);
        const off = used.filter(cell => WEEKEND.includes(cell.row) || NIGHT.includes(cell.column))
            .reduce((sum, cell) => sum + cell.count, 0);
        return ZT.card(s('when.title'), m('when.aside'),
            el('div', {class: 'zt-heat'}, ZT.heatmap(WEEKDAYS, BANDS, used, key => m('weekday.' + key),
                key => m('band.' + key), key => m('bandStart', Number(key) * 4))),
            label(s('when.offHours', ZT.percent(off / total), ZT.count(off), ZT.count(total))),
            note(m('matrix.caption')));
    }

    // ----- the ranked lists -----

    function rankedTable(items, name, href) {
        return table([{label: name, fill: true}, {label: s('column.stopped'), num: true},
            {label: t('zt.console.ui.action.CHALLENGE'), num: true, wide: true},
            {label: t('zt.console.ui.action.ESCALATE'), num: true, wide: true},
            {label: t('zt.console.ui.action.BLOCK'), num: true, wide: true}], items, item => [
            href ? link(href(item), item.item) : item.item, ZT.count(item.count),
            ZT.count((item.byDetail || {}).CHALLENGE || 0), ZT.count((item.byDetail || {}).ESCALATE || 0),
            ZT.count((item.byDetail || {}).BLOCK || 0)]);
    }

    function resourcesCard(side) {
        const items = side.topResources || [];
        return ZT.card(s('resources.title'), items.length ? m('top.aside', ZT.count(items.length)) : null,
            items.length ? rankedTable(items, m('column.resource')) : none(s('stopped.none')));
    }

    function usersCard(side) {
        const items = side.topUsers || [];
        return ZT.card(s('users.title'), items.length ? m('top.aside', ZT.count(items.length)) : null,
            items.length ? rankedTable(items, m('column.user'), item => decisions({q: item.item})) : none(s('stopped.none')));
    }

    function reasonsCard(side) {
        const items = side.topReasons || [];
        if (!items.length) {
            return ZT.card(s('reasons.title'), m('reasons.aside'), none(s('stopped.none')));
        }
        const max = Math.max(...items.map(item => item.count));
        const rows = el('div', {class: 'zt-criteria'}, items.flatMap(item => {
            const name = ZT.reasonName(item.item);
            const title = m('reasons.item', ZT.keyLabel('zt.console.reasonGroup.', item.note || 'OTHER'), name);
            return [el('span', {text: name, title}), ZT.bar(item.count, max, {color: C.ACCENT, label: name}),
                el('span', {class: 'zt-num', text: ZT.percent(side.stopped > 0 ? item.count / side.stopped : null)}),
                el('span', {class: 'zt-num', text: ZT.count(item.count)})];
        }));
        return ZT.card(s('reasons.title'), m('reasons.aside'), rows, note(s('reasons.caption')));
    }

    // ----- the burden on the users -----

    function burdenCard(cost, histogram) {
        const counts = BURDEN.map(key => find(histogram, key).count);
        const total = counts.reduce((sum, value) => sum + value, 0);
        const box = el('div');
        const body = [];
        if (total > 0) {
            body.push(ZT.legend([{label: m('burden.series'), color: C.ACCENT}]));
        }
        body.push(box, el('div', {class: 'zt-split'}, minor(cost.burdenMedianPerWeek), minor(cost.burdenP95PerWeek)));
        charts.push(() => ZT.chart(box, 'm', {type: 'bar', label: BURDEN.map((key, index) => m('burden.bucket.' + key)
            + ' ' + ZT.count(counts[index])).join(', '),
        data: {labels: BURDEN.map(key => m('burden.bucket.' + key)),
            datasets: [{label: m('burden.series'), data: counts, backgroundColor: C.ACCENT}]}}, total > 0,
        'NO_DECISIONS'));
        return ZT.card(s('burden.title'), m('burden.aside'), ...body);
    }

    function challengedCard(users) {
        if (!users.length) {
            return ZT.card(s('challenged.title'), null, none(s('funnel.none')));
        }
        return ZT.card(s('challenged.title'), m('top.aside', ZT.count(users.length)), table([
            {label: m('column.user'), fill: true}, {label: s('column.challenges'), num: true},
            {label: m('column.passed'), num: true}, {label: m('column.mainReason'), wide: true},
            {label: m('column.baseline'), wide: true}], users, user => [
            link(decisions({q: user.user, action: 'CHALLENGE'}), user.user), ZT.count(user.challenges),
            ZT.count(user.passed), ZT.reasonName(user.mainReason),
            user.baseline ? ZT.keyLabel(P + 'baseline.', user.baseline) : '—']));
    }

    function render(content, value) {
        const header = value.header || {};
        shadow = header.mode === 'SHADOW';
        decided = header.decisions || 0;
        drawn.forEach(chart => chart && chart.destroy());
        drawn = [];
        charts = [];
        const side = value.stopped || {};
        const cost = value.cost || {};
        content.append(
            grid(span(stoppedCard(side), 6), span(costCard(cost), 6)),
            grid(span(matrixCard(value.hypothesisByClass || []), 6), span(whenCard(value.whenStopped || []), 6)),
            grid(span(resourcesCard(side), 6), span(burdenCard(cost, value.burdenHistogram || []), 6)),
            grid(span(reasonsCard(side), 6), span(usersCard(side), 6)),
            grid(span(challengedCard(cost.topChallengedUsers || []), 12)));
        // Chart.js sizes a chart from its box, so the charts are drawn once their boxes are on the page.
        drawn = charts.map(draw => draw());
    }

    ZT.start('/impact', render);
})(window.ZT);
