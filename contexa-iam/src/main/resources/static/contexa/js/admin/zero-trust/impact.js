/*
 * Zero Trust console, threats and business impact (console design 6.2): "what was stopped, and what did it cost?".
 * Drawn as the admin dashboard draws: four key cards (the stopped requests, the step-ups the owner passed, the wait,
 * the blocks), then what was suspected, how the step-ups ended and how the requests were stopped, when and why, where
 * and how much each user bore, and the ranked lists under one tab bar. A definition or a caption is a tooltip. In
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
        return el('div', {class: 'modern-table zt-table-wrap'}, el('table', {class: 'zt-table'}, el('thead', {}, head), body));
    }

    // ----- the four key cards -----

    function keyCards(side, cost) {
        const challenges = cost.challenges || {};
        const blocks = cost.blocks || {};
        const pass = challenges.passRate && challenges.passRate.metric;
        return ZT.kpiRow(
            ZT.kpi({tone: 'purple', icon: 'fa-hand-paper', label: s('kpi.stopped.label'), value: ZT.count(side.stopped || 0),
                sub: m('kpi.stopped.sub', ZT.count(find(side.byAction, 'CHALLENGE').count),
                    ZT.count(find(side.byAction, 'ESCALATE').count), ZT.count(find(side.byAction, 'BLOCK').count)),
                href: decisions({})}),
            ZT.kpiMetric(pass, {tone: 'teal', icon: 'fa-user-check',
                sub: m('kpi.pass.sub', ZT.count(challenges.passed || 0), ZT.count(challenges.required || 0)),
                href: decisions({action: 'CHALLENGE', outcome: 'CHALLENGE_PASSED'})}),
            ZT.kpiMetric(cost.userWaitP50, {tone: 'indigo', icon: 'fa-hourglass-half',
                sub: m('kpi.wait.sub', ZT.metricText(cost.userWaitP95))}),
            ZT.kpi({tone: 'red', icon: 'fa-ban', label: t('zt.console.ui.action.BLOCK'), value: ZT.count(blocks.blocks || 0),
                sub: m('kpi.blocks.sub', ZT.count(blocks.released || 0), ZT.count(blocks.kept || 0)),
                title: blocks.releaseMedian ? blocks.releaseMedian.label + ' ' + ZT.metricText(blocks.releaseMedian)
                    + '. ' + blocks.releaseMedian.description : null,
                href: decisions({action: 'BLOCK'})}));
    }

    // ----- what was suspected, how the step-ups ended, how the requests were stopped -----

    function hypothesesCard(side) {
        const keys = keysOf((side.hypotheses || []).filter(share => share.count > 0).map(share => share.key), HYPOTHESES);
        const parts = keys.map(key => ({key, label: hypothesisName(key), count: find(side.hypotheses, key).count,
            ratio: find(side.hypotheses, key).ratio, color: HYPOTHESIS_COLORS[key] || C.ACCENT}));
        if (!side.stopped || side.explained === 0 || !parts.length) {
            return ZT.card(s('stopped.hypotheses'), null, none(m('hypotheses.none')));
        }
        const tip = m('hypotheses.caption', ZT.count(side.explained))
            + (find(side.hypotheses, 'H1').count > 0 ? ' ' + m('hypotheses.h1Note') : '');
        return ZT.withTip(ZT.card(s('stopped.hypotheses'), s('stopped.aside', ZT.count(side.explained)),
            ZT.donutBlock(parts, side.explained, s('stopped.hypotheses'), part => ({label: part.label,
                color: part.color, value: m('shareCount', ZT.percent(part.ratio), ZT.count(part.count)),
                // the number opens the stopped decisions of that explanation
                href: part.key === 'NONE' ? null : decisions({action: 'STOPPED', hypothesis: part.key})}))), tip);
    }

    function challengesCard(cost) {
        const funnel = cost.challenges || {};
        if (!funnel.required) {
            return ZT.card(s('funnel.title'), null, none(s('funnel.none')));
        }
        const code = funnel.codeRequests || {};
        const tip = [m('funnel.codeRequests', code.label, code.value == null ? ZT.reason(code.noDataReason)
            : code.description), m('funnel.note'),
            shadow ? m('cost.shadowNote') : null].filter(Boolean).join(' ');
        return ZT.withTip(ZT.card(s('funnel.title'), null,
            ZT.funnel([{label: s('funnel.required'), count: funnel.required, color: C.CHALLENGE},
                {label: code.label, count: code.value, color: C.MUTED},
                {label: m('funnel.passed'), count: funnel.passed, color: C.GOOD}]),
            ZT.valueRows([{label: m('funnel.failed'), color: C.BAD, value: countShare(funnel.failed, funnel.required),
                href: decisions({action: 'CHALLENGE', outcome: 'CHALLENGE_FAILED'})},
            {label: m('funnel.expired'), color: C.WARN, value: countShare(funnel.expired, funnel.required),
                href: decisions({action: 'CHALLENGE', outcome: 'CHALLENGE_EXPIRED'})}])), tip);
    }

    function stoppedCard(side, cost) {
        if (!side.stopped) {
            return ZT.card(s('stopped.byAction'), null, none(s('stopped.none')));
        }
        const timing = TIMINGS.concat((side.timing || []).map(share => share.key).filter(key => !TIMINGS.includes(key)))
            .map(key => find(side.timing, key));
        const blocks = cost.blocks || {};
        const body = [ZT.valueRows(STOPPED.map(key => find(side.byAction, key)).map(share => ({chip: ZT.chip(share.key),
            value: countShare(share.count, side.stopped), href: decisions({action: share.key})}))),
        ZT.subhead(m('stopped.timing'), find(side.timing, 'NEXT_REQUEST').count > 0 ? m('timing.nextRequestNote') : null),
        ZT.valueRows(timing.map(share => ({label: ZT.keyLabel(P + 'timing.', share.key),
            value: countShare(share.count, side.stopped)})))];
        if (blocks.blocks) {
            body.push(ZT.subhead(s('blocks.title', ZT.count(blocks.blocks))), ZT.valueRows([
                {label: m('blocks.released'), value: countShare(blocks.released, blocks.blocks),
                    href: decisions({action: 'BLOCK', outcome: 'ADMIN_RELEASED'})},
                {label: m('blocks.kept'), value: countShare(blocks.kept, blocks.blocks),
                    href: decisions({action: 'BLOCK', outcome: 'BLOCK_KEPT'})},
                {label: blocks.releaseMedian ? blocks.releaseMedian.label : '',
                    value: blocks.releaseMedian && blocks.releaseMedian.value == null
                        ? ZT.metricText(blocks.releaseMedian) + ' · ' + ZT.reason(blocks.releaseMedian.noDataReason)
                        : ZT.metricText(blocks.releaseMedian),
                    // the definition (design 5): the buckets it is counted in and what it counts
                    title: blocks.releaseMedian ? blocks.releaseMedian.description : null}]));
        }
        body.push(ZT.valueRows([{label: s('cost.escalations'), value: m('count', ZT.count(cost.escalations || 0)),
            href: decisions({action: 'ESCALATE'})}]));
        return ZT.card(s('stopped.byAction'), s('stopped.aside', ZT.count(side.stopped)), ...body);
    }

    // ----- when, and why -----

    function whenCard(cells) {
        const used = cells.filter(cell => cell.count > 0);
        if (!used.length) {
            return ZT.card(s('when.title'), m('when.aside'), none(s('stopped.none')));
        }
        const total = used.reduce((sum, cell) => sum + cell.count, 0);
        const off = used.filter(cell => WEEKEND.includes(cell.row) || NIGHT.includes(cell.column))
            .reduce((sum, cell) => sum + cell.count, 0);
        return ZT.withTip(ZT.card(s('when.title'), m('when.aside'),
            el('div', {class: 'zt-heat'}, ZT.heatmap(WEEKDAYS, BANDS, used, key => m('weekday.' + key),
                key => m('band.' + key), key => m('bandStart', Number(key) * 4),
                (weekday, band) => decisions({action: 'STOPPED', weekday, band}))),
            el('div', {class: 'zt-muted', text: s('when.offHours', ZT.percent(off / total), ZT.count(off),
                ZT.count(total))})), m('matrix.caption'));
    }

    function reasonsCard(side) {
        const items = side.topReasons || [];
        if (!items.length) {
            return ZT.card(s('reasons.title'), m('reasons.aside'), none(s('stopped.none')));
        }
        const max = Math.max(...items.map(item => item.count));
        const rows = el('div', {class: 'zt-reason-rows'}, items.map(item => {
            const name = ZT.reasonName(item.item);
            const title = m('reasons.item', ZT.keyLabel('zt.console.reasonGroup.', item.note || 'OTHER'), name);
            return el('div', {class: 'zt-reason-row', title},
                el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: name}),
                    el('span', {class: 'zt-reason-value', text: m('countShare', ZT.count(item.count),
                        ZT.percent(side.reasoned > 0 ? item.count / side.reasoned : null))})),
                ZT.bar(item.count, max, {color: C.ACCENT, label: name}));
        }));
        // Design 6.2: the shares are of the stopped decisions with a reason code (a bundle that gives none is left out)
        return ZT.withTip(ZT.card(s('reasons.title'), m('reasons.basis', ZT.count(side.reasoned || 0)), rows),
            s('reasons.caption'));
    }

    // ----- where, and how much each user bore -----

    function matrixCard(cells, side) {
        const used = cells.filter(cell => cell.count > 0);
        if (!used.length) {
            return ZT.card(m('matrix.title'), s('matrix.aside'), none(s('stopped.none')));
        }
        const rows = keysOf([...new Set(used.map(cell => cell.row))], HYPOTHESES);
        const columns = keysOf([...new Set(used.map(cell => cell.column))], CLASSES);
        const body = [el('div', {class: 'zt-heat'}, ZT.heatmap(rows, columns, used, hypothesisName, className, null,
            (hypothesis, resourceClass) => hypothesis === 'NONE' || resourceClass === 'NONE' ? null
                : decisions({action: 'STOPPED', hypothesis, resourceClass})))];
        const classes = keysOf((side.resourceClasses || []).filter(share => share.count > 0).map(share => share.key),
            CLASSES).map((key, index) => ({key, label: className(key), count: find(side.resourceClasses, key).count,
            color: ZT.SERIES[index % ZT.SERIES.length]}));
        if (classes.length) {
            body.push(ZT.subhead(m('stopped.classes')), ZT.stacked(classes), ZT.valueRows(classes.map(part => ({
                label: part.label, color: part.color, value: ZT.count(part.count),
                href: part.key === 'NONE' ? null : decisions({action: 'STOPPED', resourceClass: part.key})}))));
        }
        return ZT.withTip(ZT.card(m('matrix.title'), s('matrix.aside'), ...body), m('matrix.caption'));
    }

    function burdenCard(cost, histogram) {
        const counts = BURDEN.map(key => find(histogram, key).count);
        const total = counts.reduce((sum, value) => sum + value, 0);
        const box = el('div');
        charts.push(() => ZT.chart(box, 'm', {type: 'bar', label: BURDEN.map((key, index) => m('burden.bucket.' + key)
            + ' ' + ZT.count(counts[index])).join(', '),
        data: {labels: BURDEN.map(key => m('burden.bucket.' + key)),
            datasets: [{label: m('burden.series'), data: counts, backgroundColor: C.ACCENT, borderRadius: 4,
                maxBarThickness: 56}]}}, total > 0, 'NO_DECISIONS'));
        const median = cost.burdenMedianPerWeek || {};
        const top = cost.burdenP95PerWeek || {};
        const many = find(histogram, '4+').count;
        return ZT.card(s('burden.title'), m('burden.aside'), box, ZT.valueRows([
            {label: median.label || '', value: ZT.metricText(median), title: median.description || null},
            {label: top.label || '', value: ZT.metricText(top), title: top.description || null},
            // Design 6.2: the users challenged four times or more, their challenges in the decision list
            {label: m('burden.many'), value: m('count', ZT.count(many)),
                href: many > 0 ? decisions({action: 'CHALLENGE', challengedAtLeast: 4}) : null}]));
    }

    // ----- the ranked lists, one tab bar -----

    function rankedTable(items, name, href) {
        return table([{label: name, fill: true}, {label: s('column.stopped'), num: true},
            {label: t('zt.console.ui.action.CHALLENGE'), num: true, wide: true},
            {label: t('zt.console.ui.action.ESCALATE'), num: true, wide: true},
            {label: t('zt.console.ui.action.BLOCK'), num: true, wide: true}], items, item => [
            href ? link(href(item), item.item) : item.item, ZT.count(item.count),
            ZT.count((item.byDetail || {}).CHALLENGE || 0), ZT.count((item.byDetail || {}).ESCALATE || 0),
            ZT.count((item.byDetail || {}).BLOCK || 0)]);
    }

    function challengedTable(users) {
        return table([{label: m('column.user'), fill: true}, {label: s('column.challenges'), num: true},
            {label: m('column.passed'), num: true}, {label: m('column.mainReason'), wide: true},
            {label: m('column.baseline'), wide: true}], users, user => [
            link(decisions({q: user.user, action: 'CHALLENGE'}), user.user), ZT.count(user.challenges),
            ZT.count(user.passed), ZT.reasonName(user.mainReason),
            user.baseline ? ZT.keyLabel(P + 'baseline.', user.baseline) : '—']);
    }

    function listsCard(side, cost) {
        const users = side.topUsers || [];
        const resources = side.topResources || [];
        const challenged = cost.topChallengedUsers || [];
        return ZT.tabbedCard(m('lists.title'), m('top.aside', ZT.count(Math.max(users.length, resources.length,
            challenged.length))), [
            {label: s('users.title'), node: users.length
                ? rankedTable(users, m('column.user'), item => decisions({action: 'STOPPED', q: item.item}))
                : none(s('stopped.none'))},
            {label: s('resources.title'), node: resources.length
                ? rankedTable(resources, m('column.resource'), item => decisions({action: 'STOPPED', q: item.item}))
                : none(s('stopped.none'))},
            {label: s('challenged.title'), node: challenged.length ? challengedTable(challenged) : none(s('funnel.none'))}]);
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
            keyCards(side, cost),
            grid(span(hypothesesCard(side), 4), span(challengesCard(cost), 4), span(stoppedCard(side, cost), 4)),
            grid(span(whenCard(value.whenStopped || []), 8), span(reasonsCard(side), 4)),
            grid(span(matrixCard(value.hypothesisByClass || [], side), 6),
                span(burdenCard(cost, value.burdenHistogram || []), 6)),
            listsCard(side, cost));
        // Chart.js sizes a chart from its box, so the charts are drawn once their boxes are on the page.
        drawn = charts.map(draw => draw());
    }

    ZT.start('/impact', render);
})(window.ZT);
