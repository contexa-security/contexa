/*
 * Zero Trust console, adoption (console design 6.5, decision 11.5): "can we move to ENFORCE?". Drawn as the admin
 * dashboard draws: four key cards (the verdict of the SHADOW trial, the criteria met, what enforcing would have
 * stopped and the accounts it would have blocked), then the verdict in words beside the criteria's ring, each criterion
 * against its recommended bound, the days of the trial beside the burden it would have put on the users, and the mode
 * history. The bounds are recommendations, not guarantees; the mode is changed in the system settings, not here. A
 * caption is a tooltip.
 */
(function (ZT) {
    'use strict';

    const {t, el} = ZT;
    const P = 'zt.console.ui.adoption.';
    const PAGES = '/contexa/admin/zero-trust';
    const SETTINGS = '/contexa/admin/system-settings';
    /** The axis of an open-ended bar reaches past the larger of value and bound, so both stay inside the track. */
    const HEADROOM = 1.25;
    const STOPPED = ['CHALLENGE', 'ESCALATE', 'BLOCK'];
    /**
     * Design 6.5: an unmet criterion opens the screen that shows what holds it back; the period is the SHADOW trial's.
     */
    const CRITERION_SCREENS = {modelDecided: '/trust', modelLess: '/trust', baselineEstablished: '/trust',
        reviewValid: '/decisions?view=review', burdenP95: '/impact', userWaitP95: '/operations',
        businessContext: '/trust'};

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

    function statusColor(status) {
        switch (status) {
            case 'MET':
                return ZT.COLORS.GOOD;
            case 'UNMET':
                return ZT.COLORS.BAD;
            case 'INSUFFICIENT':
                return ZT.COLORS.WARN;
            default:
                return ZT.COLORS.ACCENT;
        }
    }

    // ----- the recommended bounds, read from the server's threshold strings -----

    /** ">=0.95" -> 0.95, "<=0.05" -> 0.05, "3.0" -> 3, "10000" -> 10000; null when there is none. */
    function bound(threshold) {
        if (threshold == null) {
            return null;
        }
        const value = parseFloat(String(threshold).replace(/^[<>]=/, ''));
        return Number.isFinite(value) ? value : null;
    }

    /** "14d/5000" -> [14, 5000]; "0.9/30" -> [0.9, 30]. */
    function pair(threshold, separator) {
        const parts = String(threshold || '').split(separator).map(part => parseFloat(part));
        return parts.length === 2 && parts.every(Number.isFinite) ? parts : [null, null];
    }

    function openMax(value, limit) {
        return Math.max(value || 0, limit || 0) * HEADROOM;
    }

    /**
     * One criterion as the table shows it: its name, its recommended bound in words, its current value in words and
     * its bar (value, axis, mark at the bound).
     */
    function view(criterion, adoption) {
        const current = criterion.current || {};
        const value = current.value;
        const name = known(P + 'criterion.' + criterion.key, current.label || criterion.key);
        const shown = ZT.metricText(current);
        switch (criterion.key) {
            case 'observed': {
                const [days, decisions] = pair(criterion.threshold, 'd/');
                return {name, bound: t(P + 'threshold.observed', ZT.count(days), ZT.count(decisions)),
                    text: t(P + 'current.observed', ZT.count(adoption.observedDays), ZT.count(value)),
                    bar: {value, max: openMax(value, decisions), mark: decisions}};
            }
            case 'modelDecided':
            case 'modelLess':
            case 'baselineEstablished': {
                const limit = bound(criterion.threshold);
                const atLeast = String(criterion.threshold || '').startsWith('>=');
                return {name, bound: t(P + (atLeast ? 'threshold.atLeast' : 'threshold.atMost'), ZT.percent(limit)),
                    text: shown, bar: {value, max: 1, mark: limit}};
            }
            case 'reviewValid': {
                const [lower, sample] = pair(criterion.threshold, '/');
                return {name, bound: t(P + 'threshold.reviewValid', ZT.percent(lower), ZT.count(sample)),
                    text: value == null ? shown : t(P + 'current.reviewValid', ZT.percent(value),
                        ZT.count(current.denominator)),
                    bar: {value, max: 1, mark: lower}};
            }
            case 'burdenP95': {
                const limit = bound(criterion.threshold);
                return {name, bound: t(P + 'threshold.burden', ZT.metricText({value: limit, unit: 'PER_USER_WEEK'})),
                    text: value == null ? shown : t(P + 'current.perWeek', shown),
                    bar: {value, max: openMax(value, limit), mark: limit}};
            }
            case 'userWaitP95': {
                const limit = bound(criterion.threshold);
                return {name, bound: t(P + 'threshold.userWait', ZT.seconds(limit)), text: shown,
                    bar: {value, max: openMax(value, limit), mark: limit}};
            }
            case 'businessContext':
                return {name, bound: t(P + 'threshold.info'), text: shown, bar: {value, max: 1, mark: null}};
            default:
                return {name, bound: criterion.threshold || '—', text: shown,
                    bar: {value, max: openMax(value, bound(criterion.threshold)), mark: bound(criterion.threshold)}};
        }
    }

    // ----- the four key cards -----

    const VERDICT_TONES = {RECOMMENDED: 'green', CONDITIONS_UNMET: 'amber', DATA_INSUFFICIENT: 'red'};

    function keyCards(adoption, weighed) {
        const verdict = adoption.verdict || 'DATA_INSUFFICIENT';
        const met = weighed.filter(criterion => criterion.status === 'MET').length;
        const unmet = weighed.filter(criterion => criterion.status === 'UNMET').length;
        const insufficient = weighed.filter(criterion => criterion.status === 'INSUFFICIENT').length;
        const would = adoption.wouldHave || {};
        return ZT.kpiRow(
            ZT.kpi({tone: VERDICT_TONES[verdict] || 'indigo', icon: 'fa-flag-checkered', label: t(P + 'verdict.title'),
                value: t('zt.console.ui.status.' + verdict), sub: observation(adoption),
                title: t(P + 'verdict.recommendation')}),
            ZT.kpi({tone: 'indigo', icon: 'fa-tasks', label: t(P + 'gauge.title'),
                value: t(P + 'gauge.centre', met, weighed.length),
                sub: t(P + 'kpi.criteriaSub', ZT.count(unmet), ZT.count(insufficient))}),
            ZT.kpi({tone: 'purple', icon: 'fa-hand-paper', label: t(P + 'wouldHave.stopped'),
                value: would.stopped == null ? null : ZT.count(would.stopped),
                sub: t(P + 'kpi.usersSub', would.users == null ? '—' : ZT.count(would.users)),
                title: t(P + 'wouldHave.stoppedDefinition'), href: stoppedUrl(adoption)}),
            ZT.kpi({tone: 'red', icon: 'fa-user-lock', label: t(P + 'wouldHave.blockedAccounts'),
                value: would.blockedAccounts == null ? null : ZT.count(would.blockedAccounts),
                sub: t(P + 'links.shadowBlocks'), href: shadowBlocksUrl(adoption),
                title: t(P + 'wouldHave.blockedAccountsDefinition')}));
    }

    // ----- the verdict and the gauge of the criteria -----

    function observation(adoption) {
        if (adoption.observedMode === 'SHADOW' && adoption.observedSince) {
            return t(P + 'observing', ZT.count(adoption.observedDays), ZT.day(adoption.observedSince));
        }
        if (adoption.observedSince) {
            return t(P + 'observedBefore', ZT.count(adoption.observedDays), ZT.day(adoption.observedSince));
        }
        return t(P + 'notObserved');
    }

    function gaugeCard(weighed) {
        const met = weighed.filter(criterion => criterion.status === 'MET').length;
        let body;
        if (weighed.length) {
            body = [ZT.legend(['MET', 'UNMET', 'INSUFFICIENT'].map(status => ({
                label: t('zt.console.ui.status.' + status), color: statusColor(status)}))),
                el('div', {class: 'zt-chart zt-chart-m'}, ZT.gauge(weighed.map(criterion => ({status: criterion.status})),
                    t(P + 'gauge.centre', met, weighed.length), t(P + 'gauge.caption')))];
        } else {
            body = [ZT.empty('NO_DECISIONS')];
        }
        return ZT.card(t(P + 'gauge.title'), t(P + 'gauge.aside', ZT.count(met), ZT.count(weighed.length)), ...body);
    }

    function verdictCard(adoption, criteria) {
        const names = status => criteria.filter(criterion => criterion.status === status)
            .map(criterion => view(criterion, adoption).name);
        const unmet = names('UNMET');
        const insufficient = names('INSUFFICIENT');
        const verdict = adoption.verdict || 'DATA_INSUFFICIENT';
        const card = ZT.card(t(P + 'verdict.title'), observation(adoption),
            el('div', {class: 'zt-verdict'}, el('div', {class: 'zt-toolbar'}, ZT.statusChip(verdict)),
                el('p', {text: t(P + 'verdict.' + verdict, ZT.count(adoption.unmet))})),
            unmet.length ? el('div', {text: t(P + 'verdict.unmetList', unmet.join(' · '))}) : null,
            insufficient.length ? el('div', {text: t(P + 'verdict.insufficientList', insufficient.join(' · '))}) : null);
        card.append(foot(link(PAGES + '/decisions?view=review', t(P + 'links.review')),
            link(SETTINGS, t(P + 'links.switchMode'))));
        return ZT.withTip(card, t(P + 'verdict.recommendation'));
    }

    // ----- the criteria against their recommended bounds -----

    function criteriaCard(adoption) {
        const criteria = adoption.criteria || [];
        const table = el('div', {class: 'zt-criteria'});
        ['name', 'bar', 'current', 'status'].forEach(key => table.append(el('span', {class: 'zt-muted'
            + (key === 'current' ? ' zt-num' : ''), text: t(P + 'criteria.head.' + key)})));
        criteria.forEach(criterion => {
            const shown = view(criterion, adoption);
            const current = criterion.current || {};
            const reason = current.value == null && current.noDataReason ? ZT.reason(current.noDataReason) : null;
            table.append(
                el('span', {title: reason ? shown.name + ' · ' + reason : shown.name}, el('div', {}, shown.name,
                    criterion.status === 'UNMET' || criterion.status === 'INSUFFICIENT' ? criterionLink(criterion) : null),
                    el('div', {class: 'zt-muted', text: t(P + 'criteria.recommended', shown.bound), title: shown.bound})),
                el('span', {}, ZT.bar(shown.bar.value, shown.bar.max, {mark: shown.bar.mark,
                    color: statusColor(criterion.status), label: shown.name + ' ' + shown.text + ' / ' + shown.bound})),
                el('span', {class: 'zt-num', text: shown.text, title: shown.text}),
                el('span', {}, ZT.statusChip(criterion.status)));
        });
        const card = ZT.card(t(P + 'criteria.title'), t(P + 'criteria.aside'),
            criteria.length ? table : ZT.empty('NO_DECISIONS'));
        card.append(foot(link(SETTINGS, t(P + 'links.bounds'))));
        return ZT.withTip(card, t(P + 'criteria.note'));
    }

    /** The "›" of an unmet criterion, to the screen that explains it (none for the observation itself). */
    function criterionLink(criterion) {
        const screen = CRITERION_SCREENS[criterion.key];
        return screen ? [' ', el('a', {class: 'zt-link', href: ZT.keepPeriod(PAGES + screen), text: '›',
            'aria-label': t(P + 'criteria.open', known(P + 'criterion.' + criterion.key, criterion.key))})] : null;
    }

    // ----- what SHADOW would have stopped -----

    function trendCard(adoption) {
        const days = adoption.trend || [];
        const box = el('div');
        const total = days.reduce((sum, point) => sum + point.challenge + point.escalate + point.block, 0);
        const hasData = total > 0;
        const datasets = STOPPED.map(action => ({
            label: t('zt.console.ui.action.' + action),
            data: days.map(point => point[action.toLowerCase()]),
            backgroundColor: ZT.COLORS[action],
            stack: 'stopped'
        }));
        ZT.chart(box, 'm', {
            type: 'bar',
            data: {labels: days.map(point => ZT.day(point.day)), datasets},
            axes: {x: {stacked: true}, y: {stacked: true}, yFormat: ZT.compact},
            label: t(P + 'trend.label', ZT.count(days.length), ZT.count(total))
        }, hasData, 'NO_DECISIONS');
        const shares = days.map(point => point.baselineEstablished);
        const present = shares.filter(share => share != null);
        const baseline = present.length >= 2 ? el('div', {class: 'zt-item'},
            el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: t(P + 'trend.baseline')}),
                el('span', {class: 'zt-reason-value', text: t(P + 'trend.baselineChange', ZT.percent(present[0], 0),
                    ZT.percent(present[present.length - 1], 0))})),
            ZT.sparkline(shares, {min: 0, max: 1, color: ZT.COLORS.GOOD,
                label: t(P + 'trend.baseline')})) : null;
        return ZT.card(ZT.title(P + 'trend.title'), t(P + 'trend.aside', ZT.count(total)),
            hasData ? ZT.legend(STOPPED.map(action => ({label: t('zt.console.ui.action.' + action),
                color: ZT.COLORS[action]}))) : null,
            box, baseline);
    }

    /**
     * Design 6.5 (G18): a block SHADOW would have made blocks nobody, so the accounts it would have blocked are
     * reviewed in the review queue, which holds those blocks for it.
     */
    function shadowBlocksUrl() {
        return PAGES + '/decisions?view=review&reason=SHADOW_BLOCK';
    }

    /** The requests SHADOW would have stopped, in the decision list of the trial's period. */
    function stoppedUrl(adoption) {
        const params = new URLSearchParams({mode: 'SHADOW', action: 'STOPPED'});
        const period = adoption.header && adoption.header.period;
        if (period && period.from) {
            // K87: the trial's own period from the moment it starts (the list reads it from that hour, as the
            // number counts it) to today.
            params.set('period', 'custom');
            params.set('from', String(period.from));
        }
        if (adoption.header && adoption.header.tenant) {
            params.set('tenant', adoption.header.tenant);
        }
        return PAGES + '/decisions?' + params.toString();
    }

    function wouldHaveCard(adoption) {
        const would = adoption.wouldHave || {};
        const count = (key, value) => ({label: t(P + 'wouldHave.' + key), value: value == null ? '—' : ZT.count(value),
            title: t(P + 'wouldHave.' + key + 'Definition')});
        const median = would.burdenMedianPerWeek || {};
        const top = would.burdenP95PerWeek || {};
        return ZT.card(t(P + 'wouldHave.title'), t(P + 'wouldHave.aside'), ZT.valueRows([
            Object.assign(count('stopped', would.stopped), {href: stoppedUrl(adoption)}), count('users', would.users),
            Object.assign(count('blockedAccounts', would.blockedAccounts), {href: shadowBlocksUrl(adoption)}),
            {label: median.label || '', value: ZT.metricText(median), title: median.description || null},
            {label: top.label || t(P + 'wouldHave.burdenP95', ''), value: ZT.metricText(top),
                title: top.description || null}]));
    }

    // ----- the mode history -----

    function modeName(mode) {
        return mode ? known(P + 'mode.' + mode, mode) : t(P + 'mode.unknown');
    }

    function historyCard(adoption) {
        const history = adoption.modeHistory || [];
        const body = history.length ? ZT.valueRows(history.map(change => {
            // design 6.5: the change with the reason its operator gave
            const text = t(P + 'history.change', modeName(change.from), modeName(change.to), change.by || '—')
                + (change.reason ? ' · ' + t(P + 'history.reason', change.reason) : '');
            return {label: text, title: text, value: ZT.time(change.at)};
        })) : ZT.emptyNote(t(P + 'history.none'));
        const card = ZT.card(t(P + 'history.title'), history.length ? t(P + 'history.aside', ZT.count(history.length))
            : null, body);
        card.append(foot(link(SETTINGS, t(P + 'links.settings'))));
        return ZT.withTip(card, t(P + 'history.note'));
    }

    // ----- the AI monitor's past measuring windows (console plan 5-2 ⑤) -----

    function pastWindowsCard(windows) {
        // [key, class]: a phone keeps the window, its decisions and its failure rate
        const head = el('tr', {}, [['span', null], ['decisions', 'zt-num'], ['failureRate', 'zt-num'],
            ['timeoutRate', 'zt-num zt-wide'], ['p95', 'zt-num zt-wide'], ['recommendation', 'zt-wide']]
            .map(([key, kind]) => el('th', {scope: 'col', class: kind, text: t(P + 'past.column.' + key)})));
        const rows = windows.map(past => {
            const when = t(P + 'past.span', ZT.time(past.startedAt), ZT.time(past.endedAt));
            const closed = t(P + 'past.closed', past.closedBy || '—', past.reason || '—');
            return el('tr', {}, el('td', {class: 'zt-fill', title: when + ' · ' + closed, text: when}),
                el('td', {class: 'zt-num', text: ZT.count(past.decisions)}),
                el('td', {class: 'zt-num', text: ZT.percent(past.failureRate)}),
                el('td', {class: 'zt-num zt-wide', text: ZT.percent(past.timeoutRate)}),
                el('td', {class: 'zt-num zt-wide', text: past.p95LatencyMs == null ? '—'
                    : ZT.seconds(past.p95LatencyMs)}),
                el('td', {class: 'zt-wide', text: known(P + 'past.recommendation.' + past.recommendation,
                    t(P + 'past.recommendation.other'))}));
        });
        return ZT.withTip(ZT.card(t(P + 'past.title'), t(P + 'past.aside', ZT.count(windows.length)),
            el('div', {class: 'modern-table zt-table-wrap'}, el('table', {class: 'zt-table'}, el('thead', {}, head),
                el('tbody', {}, rows)))), t(P + 'past.note'));
    }

    function render(content, adoption) {
        const criteria = adoption.criteria || [];
        const weighed = criteria.filter(criterion => criterion.status !== 'INFO');
        const windows = adoption.pastWindows || [];
        content.append(
            keyCards(adoption, weighed),
            grid(span(verdictCard(adoption, criteria), 8), span(gaugeCard(weighed), 4)),
            criteriaCard(adoption),
            grid(span(trendCard(adoption), 8), span(wouldHaveCard(adoption), 4)),
            historyCard(adoption));
        if (windows.length) {
            content.append(pastWindowsCard(windows));
        }
    }

    ZT.start('/adoption', render);
})(window.ZT);
