/*
 * Zero Trust console, operations (console design 6.6): "can we carry it?". The parts a decision passes through and
 * their state, the throughput by hour, why protected calls got no decision, the latency of each stage, the failures by
 * kind, the cost and the storage.
 */
(function (ZT) {
    'use strict';

    const {t, el} = ZT;
    const P = 'zt.console.ui.operations.';
    const PAGES = '/contexa/admin/zero-trust';
    const SETTINGS = '/contexa/admin/system-settings';
    const STATES = ['BAD', 'WARN', 'GOOD', 'UNKNOWN'];
    /** The no-decision reasons shown one by one; the rest are summed as "other". */
    const REASONS_SHOWN = 5;
    /** The failure kinds drawn one by one (small multiples on one scale). */
    const KINDS_SHOWN = 6;

    function known(key, fallback) {
        const text = t(key);
        return text === key ? fallback : text;
    }

    function muted(text) {
        return el('div', {class: 'zt-muted', text});
    }

    function grid(...cards) {
        return el('div', {class: 'zt-grid'}, cards);
    }

    function span(card, columns) {
        card.classList.add('zt-span-' + columns);
        return card;
    }

    function link(href, text) {
        return el('a', {class: 'zt-link', href, text});
    }

    function foot(...children) {
        return el('div', {class: 'zt-card-foot'}, children);
    }

    function perMinute(value) {
        return ZT.metricText({value, unit: 'PER_MINUTE'});
    }

    function stateChip(status) {
        const state = STATES.includes(status) ? status : 'UNKNOWN';
        return ZT.statusChip(state, t(P + 'symbol.' + state) + ' ' + t('zt.console.ui.status.' + state));
    }

    /** The decision list of this screen's period with one more filter. */
    function decisionsUrl(filter) {
        const params = new URLSearchParams(filter);
        const current = ZT.query();
        ['period', 'from', 'to', 'tenant'].forEach(name => {
            if (current.get(name)) {
                params.set(name, current.get(name));
            }
        });
        return PAGES + '/decisions?' + params.toString();
    }

    function hourLabel(iso) {
        const date = new Date(iso);
        return date.getHours() === 0 ? ZT.day(iso) : t(P + 'hour', date.getHours());
    }

    // ----- the path a decision takes -----

    function componentValue(component) {
        if (component.value == null) {
            return component.noDataReason ? ZT.reason(component.noDataReason) : '—';
        }
        switch (component.key) {
            case 'PROTECTED_CALLS':
                return t(P + 'component.value.perMinute', perMinute(Number(component.value)));
            case 'ANALYSIS_LINE': {
                const [inLine, limit] = String(component.value).split('/');
                return t(P + 'component.value.line', inLine, limit === '-' || limit == null
                    ? t(P + 'component.value.noLimit') : limit);
            }
            case 'MODEL':
                return t(P + 'component.value.model', ZT.count(Number(component.value)));
            case 'DECISION_STORE':
                return t(P + 'component.value.persist', ZT.seconds(Number(component.value)));
            case 'STATE_STORE':
                return known(P + 'component.value.' + component.value, component.value);
            case 'AGGREGATION':
                return t(P + 'component.value.computed', ZT.time(component.value));
            default:
                return String(component.value);
        }
    }

    function componentsCard(operations) {
        const components = operations.components || [];
        const counts = STATES.map(state => [state, components.filter(component => component.status === state).length])
            .filter(([, count]) => count > 0)
            .map(([state, count]) => t(P + 'components.count', t('zt.console.ui.status.' + state), ZT.count(count)));
        const list = el('ol', {class: 'zt-rows'});
        components.forEach(component => {
            const name = known(P + 'component.' + component.key, component.key);
            const value = componentValue(component);
            list.append(el('li', {class: 'zt-item'},
                el('div', {class: 'zt-row'}, el('strong', {text: name, title: name}), stateChip(component.status)),
                el('div', {class: 'zt-muted', text: value, title: value})));
        });
        return ZT.card(t(P + 'components.title'), counts.join(' · ') || null,
            components.length ? list : ZT.empty('NOT_RECORDED'));
    }

    // ----- throughput -----

    function throughputCard(operations) {
        const throughput = operations.throughput || {};
        const hourly = operations.hourly || [];
        const peak = hourly.reduce((largest, point) => Math.max(largest, point.decisions), 0);
        const inLine = {key: 'inLine', label: t(P + 'throughput.inLine'), value: throughput.inLine, unit: 'COUNT',
            description: t(P + 'throughput.inLineDefinition'),
            noDataReason: throughput.inLine == null ? 'NOT_RECORDED' : null};
        const metrics = el('div', {class: 'zt-grid'},
            [ZT.metric(throughput.protectedPerMinute, {small: true}), ZT.metric(throughput.decisionsPerMinute,
                {small: true}), ZT.metric(inLine, {small: true})].map(node => {
                node.classList.add('zt-span-4');
                return node;
            }));
        const box = el('div');
        const hasData = hourly.some(point => point.decisions > 0);
        ZT.chart(box, 'm', {
            type: 'line',
            data: {labels: hourly.map(point => hourLabel(point.hour)), datasets: [{
                label: t(P + 'throughput.decisions'), data: hourly.map(point => point.decisions),
                borderColor: ZT.COLORS.ACCENT, backgroundColor: ZT.COLORS.ACCENT, pointRadius: 0, borderWidth: 2}]},
            label: t(P + 'throughput.label', perMinute(peak / 60)),
            axes: {yFormat: ZT.compact},
            options: {plugins: {tooltip: {callbacks: {
                title: items => items.length ? ZT.time(hourly[items[0].dataIndex].hour) : '',
                afterLabel: item => {
                    const calls = hourly[item.dataIndex].protectedCalls;
                    return calls == null ? '' : t(P + 'throughput.protectedCalls', ZT.count(calls));
                }
            }}}}
        }, hasData, 'NO_DECISIONS');
        return ZT.card(t(P + 'throughput.title'), hasData ? t(P + 'throughput.peak', perMinute(peak / 60)) : null,
            metrics, hasData ? ZT.legend([{label: t(P + 'throughput.decisions'), color: ZT.COLORS.ACCENT}]) : null, box);
    }

    // ----- protected calls without a decision -----

    function noDecisionCard(operations) {
        const shares = (operations.noDecisionReasons || []).filter(share => share.count > 0);
        const total = shares.reduce((sum, share) => sum + share.count, 0);
        const title = t(P + 'noDecision.title', ZT.count(total));
        if (total === 0) {
            const tenant = operations.header && operations.header.tenant;
            return ZT.card(title, null, ZT.empty(tenant ? 'TENANT_FILTERED' : 'NO_DECISIONS'));
        }
        const shown = shares.slice(0, REASONS_SHOWN);
        const rest = shares.slice(REASONS_SHOWN);
        const parts = shown.map((share, index) => ({label: known(P + 'noDecisionReason.' + share.key, share.key),
            count: share.count, color: ZT.SERIES[index % (ZT.SERIES.length - 1)]}));
        if (rest.length) {
            parts.push({label: t(P + 'noDecision.other'), count: rest.reduce((sum, share) => sum + share.count, 0),
                color: ZT.COLORS.MUTED, title: rest.map(share => known(P + 'noDecisionReason.' + share.key, share.key)
                    + ' ' + ZT.count(share.count)).join(', ')});
        }
        const list = ZT.rows(parts, part => [ZT.legend([{label: part.label, color: part.color}]),
            el('span', {text: t(P + 'share', ZT.count(part.count), ZT.percent(part.count / total, 0))})]);
        parts.forEach((part, index) => {
            if (part.title) {
                list.children[index].setAttribute('title', part.title);
            }
        });
        return ZT.card(title, t(P + 'noDecision.aside'), ZT.stacked(parts), list, muted(t(P + 'noDecision.note')));
    }

    // ----- latency of each stage: the bar reaches the 95th percentile, its mark is the median; one scale -----

    function latencyCard(operations) {
        const stages = operations.latency || [];
        const measured = stages.filter(stage => stage.measured > 0 && stage.p95Ms != null);
        if (!measured.length) {
            return ZT.card(t(P + 'latency.title'), null, ZT.empty('NO_DECISIONS'));
        }
        const max = Math.max(...measured.map(stage => stage.p95Ms));
        const list = el('div', {class: 'zt-rows', role: 'img', 'aria-label': measured.map(stage =>
            t(P + 'stage.' + stage.stage) + ' ' + t(P + 'latency.range', ZT.seconds(stage.p50Ms),
                ZT.seconds(stage.p95Ms))).join(', ')});
        stages.forEach(stage => {
            const name = known(P + 'stage.' + stage.stage, stage.stage);
            const has = stage.measured > 0 && stage.p95Ms != null;
            const text = has ? t(P + 'latency.range', ZT.seconds(stage.p50Ms), ZT.seconds(stage.p95Ms))
                : t(P + 'latency.notMeasured');
            list.append(el('div', {class: 'zt-row', title: has ? t(P + 'latency.measured', ZT.count(stage.measured)) : null},
                stage.stage === 'TOTAL' ? el('strong', {text: name}) : el('span', {text: name}),
                el('span', {text})));
            list.append(ZT.bar(has ? stage.p95Ms : null, max, {color: ZT.COLORS.ACCENT,
                mark: has ? stage.p50Ms : null, label: name + ' ' + text}));
        });
        return ZT.card(t(P + 'latency.title'), t(P + 'latency.aside'), list, muted(t(P + 'latency.note')));
    }

    // ----- the analysis time of the decisions, by bucket -----

    function bucketLabel(key) {
        const match = /^([<>]=?)(\d+)(ms|s)$/.exec(String(key));
        if (!match) {
            return String(key);
        }
        const ms = Number(match[2]) * (match[3] === 's' ? 1000 : 1);
        return t(P + (match[1] === '<=' ? 'bucket.upTo' : 'bucket.over'), ZT.seconds(ms));
    }

    function histogramCard(operations) {
        const buckets = operations.analysisTimeBuckets || [];
        const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
        const box = el('div');
        ZT.chart(box, 'm', {
            type: 'bar',
            data: {labels: buckets.map(bucket => bucketLabel(bucket.key)), datasets: [{
                label: t(P + 'histogram.decisions'), data: buckets.map(bucket => bucket.count),
                backgroundColor: ZT.COLORS.ACCENT}]},
            axes: {yFormat: ZT.compact},
            label: t(P + 'histogram.label', ZT.count(total))
        }, total > 0, 'NO_DECISIONS');
        return ZT.card(t(P + 'histogram.title'), total > 0 ? t(P + 'histogram.aside', ZT.count(total)) : null,
            total > 0 ? ZT.legend([{label: t(P + 'histogram.decisions'), color: ZT.COLORS.ACCENT}]) : null, box);
    }

    // ----- the 95th percentile of the whole decision, day by day -----

    function p95Card(operations) {
        const days = operations.trend || [];
        const values = days.map(point => point.totalP95Ms);
        const present = values.filter(value => value != null);
        const box = el('div');
        ZT.chart(box, 'm', {
            type: 'line',
            data: {labels: days.map(point => ZT.day(point.day)), datasets: [{
                label: t(P + 'p95.series'), data: values, borderColor: ZT.COLORS.ACCENT,
                backgroundColor: ZT.COLORS.ACCENT, pointRadius: 2, borderWidth: 2, spanGaps: false}]},
            axes: {yFormat: value => ZT.seconds(value)},
            label: t(P + 'p95.label', ZT.count(days.length))
        }, present.length > 0, 'NO_DECISIONS');
        let aside = null;
        if (present.length) {
            const highest = Math.max(...present);
            aside = t(P + 'p95.aside', ZT.day(days[values.indexOf(highest)].day), ZT.seconds(highest));
        }
        return ZT.card(t(P + 'p95.title'), aside,
            present.length ? ZT.legend([{label: t(P + 'p95.series'), color: ZT.COLORS.ACCENT}]) : null, box);
    }

    // ----- failures by kind: small multiples on one scale -----

    function kindLabel(key) {
        const [prefix, cause] = String(key).split(':');
        return t(P + 'failure.kind', known(P + 'failure.prefix.' + prefix, prefix), ZT.causeName(cause));
    }

    function failureCard(operations) {
        const failureDays = operations.failureTrend || [];
        const dayKeys = Array.from(new Set((operations.trend || []).map(point => point.day)
            .concat(failureDays.map(point => point.day)))).sort();
        const byDay = new Map(failureDays.map(point => [point.day, point.byKind || {}]));
        const totals = new Map();
        failureDays.forEach(point => Object.entries(point.byKind || {}).forEach(([kind, count]) => {
            totals.set(kind, (totals.get(kind) || 0) + count);
        }));
        const kinds = Array.from(totals.entries()).sort((one, other) => other[1] - one[1] || one[0].localeCompare(other[0]));
        const total = kinds.reduce((sum, [, count]) => sum + count, 0);
        const links = foot(link(decisionsUrl({action: 'NO_DECISION'}), t(P + 'failure.openNoDecision')),
            link(decisionsUrl({source: 'MODEL_LESS'}), t(P + 'failure.openModelLess')));
        let body;
        if (!kinds.length) {
            const decided = operations.header ? operations.header.decisions : 0;
            body = decided > 0 ? muted(t(P + 'failure.none')) : ZT.empty('NO_DECISIONS');
        } else {
            const series = kinds.slice(0, KINDS_SHOWN).map(([kind]) => dayKeys.map(day => (byDay.get(day) || {})[kind] || 0));
            const max = Math.max(1, ...series.flat());
            body = el('div', {class: 'zt-split'}, kinds.slice(0, KINDS_SHOWN).map(([kind, count], index) => {
                const values = series[index];
                const peak = Math.max(...values);
                const name = kindLabel(kind);
                return el('div', {class: 'zt-tile zt-item'},
                    el('div', {class: 'zt-row'}, el('span', {text: name, title: name}), el('strong', {text: ZT.count(count)})),
                    ZT.sparkline(values, {min: 0, max, color: ZT.COLORS.ACCENT, label: t(P + 'failure.label', name,
                        ZT.count(count))}),
                    muted(t(P + 'failure.peak', ZT.day(dayKeys[values.indexOf(peak)]), ZT.count(peak))));
            }));
        }
        const card = ZT.card(t(P + 'failure.title'), kinds.length ? t(P + 'failure.aside', ZT.count(total)) : null, body,
            kinds.length > KINDS_SHOWN ? muted(t(P + 'failure.more', ZT.count(kinds.length - KINDS_SHOWN))) : null,
            muted(t(P + 'failure.note')));
        card.append(links);
        return card;
    }

    function failedPathsCard(operations) {
        const paths = operations.failedPaths || [];
        let body;
        if (paths.length) {
            const rows = paths.map(item => {
                // The detail of a failed path is its failure type, else its attempt (TIMEOUT, REJECTED).
                const detail = Object.entries(item.byDetail || {}).map(([cause, count]) => ZT.causeName(cause)
                    + ' ' + ZT.count(count)).join(', ');
                return el('tr', {}, el('td', {title: detail ? item.item + ' · ' + detail : item.item, text: item.item}),
                    el('td', {class: 'zt-num', text: ZT.count(item.count)}));
            });
            body = el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table'},
                el('thead', {}, el('tr', {}, el('th', {scope: 'col', text: t(P + 'failedPaths.path')}),
                    el('th', {scope: 'col', class: 'zt-num', text: t(P + 'failedPaths.count')}))),
                el('tbody', {}, rows)));
        } else {
            body = muted(t(P + 'failedPaths.none'));
        }
        return ZT.card(t(P + 'failedPaths.title'), paths.length ? t(P + 'failedPaths.aside', ZT.count(paths.length))
            : null, body);
    }

    // ----- cost and model -----

    function costCard(operations) {
        const cost = operations.cost || {};
        const price = ZT.metric(cost.costPerDay, {small: true});
        if (cost.costPerDay && cost.costPerDay.value != null && cost.currency) {
            price.append(el('div', {class: 'zt-metric-ratio', text: t(P + 'cost.currency', cost.currency)}));
        }
        const metrics = el('div', {class: 'zt-grid'}, [ZT.metric(cost.tokensPerDecision, {small: true}),
            ZT.metric(cost.callsPerDecision, {small: true}), price].map(node => {
            node.classList.add('zt-span-4');
            return node;
        }));
        const days = operations.trend || [];
        const hasData = days.some(point => point.tokens > 0);
        const box = el('div');
        ZT.chart(box, 's', {
            type: 'bar',
            data: {labels: days.map(point => ZT.day(point.day)), datasets: [{
                label: t(P + 'cost.tokens'), data: days.map(point => point.tokens), backgroundColor: ZT.COLORS.ACCENT}]},
            axes: {yFormat: ZT.compact},
            label: t(P + 'cost.label', ZT.count(days.reduce((sum, point) => sum + point.tokens, 0)))
        }, hasData, 'NO_DECISIONS');
        return ZT.card(t(P + 'cost.title'), hasData ? t(P + 'cost.aside',
            ZT.count(days.reduce((sum, point) => sum + point.tokens, 0))) : null, metrics,
            hasData ? ZT.legend([{label: t(P + 'cost.tokens'), color: ZT.COLORS.ACCENT}]) : null, box,
            muted(t(P + 'cost.note')));
    }

    function usageCard(operations) {
        const usage = operations.usage || [];
        let body;
        if (usage.length) {
            // [key, number, wide]: the bundle and its model take the room the others leave; a phone keeps them, the
            // decisions and the share set without the model (1.4 check 8).
            const columns = [['bundleModel', false, false], ['span', false, true], ['decisions', true, false],
                ['stopped', true, true], ['modelLess', true, false]];
            const rows = usage.map(row => {
                const spanText = t(P + 'usage.spanValue', ZT.day(row.from), ZT.day(row.to));
                const name = (row.bundle || '—') + ' · ' + (row.model || '—');
                return el('tr', {}, el('td', {class: 'zt-fill', title: name, text: name}),
                    el('td', {class: 'zt-wide', text: spanText}),
                    el('td', {class: 'zt-num', text: ZT.count(row.decisions)}),
                    el('td', {class: 'zt-num zt-wide', text: ZT.percent(row.stoppedRatio)}),
                    el('td', {class: 'zt-num', text: ZT.percent(row.modelLessRatio)}));
            });
            body = el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table'},
                el('thead', {}, el('tr', {}, columns.map(([key, number, wide]) => el('th', {scope: 'col',
                    class: [number ? 'zt-num' : '', wide ? 'zt-wide' : ''].join(' ').trim() || null,
                    text: t(P + 'usage.' + key)})))),
                el('tbody', {}, rows)));
        } else {
            body = ZT.empty('NO_DECISIONS');
        }
        return ZT.card(t(P + 'usage.title'), usage.length ? t(P + 'usage.aside', ZT.count(usage.length)) : null, body);
    }

    // ----- storage -----

    function storageCard(operations) {
        const storage = operations.storage || {};
        const card = ZT.card(t(P + 'storage.title'), null,
            ZT.rows([[t(P + 'storage.decisions'), t(P + 'storage.days', ZT.count(storage.decisionRetentionDays))],
                [t(P + 'storage.aggregates'), t(P + 'storage.days', ZT.count(storage.aggregateRetentionDays))]],
            ([name, value]) => [el('span', {text: name}), el('span', {text: value})]),
            storage.standalone ? el('div', {class: 'zt-warning', role: 'note', text: t('zt.console.ui.band.standalone')})
                : null);
        card.append(foot(link(SETTINGS, t(P + 'storage.settings'))));
        return card;
    }

    function render(content, operations) {
        content.append(
            grid(span(componentsCard(operations), 4), span(throughputCard(operations), 8)),
            grid(span(noDecisionCard(operations), 6), span(latencyCard(operations), 6)),
            grid(span(histogramCard(operations), 6), span(p95Card(operations), 6)),
            grid(span(failureCard(operations), 8), span(failedPathsCard(operations), 4)),
            grid(span(costCard(operations), 6), span(usageCard(operations), 6)),
            grid(span(storageCard(operations), 12)));
    }

    ZT.start('/operations', render);
})(window.ZT);
