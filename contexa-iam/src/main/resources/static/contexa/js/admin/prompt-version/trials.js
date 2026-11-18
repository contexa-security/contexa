/*
 * Prompt versions, the trials (plan 3.10, screen 4): the latest sealed decisions decided again with two versions,
 * nothing applied; the share that kept its action, the format errors, the decision time and the answer length, the
 * actions of each version, and the decisions that changed. The results of a version running alongside the decisions
 * are read here as well.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const PV = global.PV;
    const el = ZT.el;
    const t = ZT.t;
    const root = document.getElementById('zt-console');
    const content = document.getElementById('zt-content');
    const trialId = root.dataset.trialId ? Number(root.dataset.trialId) : null;
    const POLL_MS = 3000;
    let poll = null;

    async function draw() {
        global.clearTimeout(poll);
        let start;
        let list;
        try {
            [start, list] = await Promise.all([PV.get('/trials'), PV.get('')]);
        } catch (error) {
            content.replaceChildren(el('div', {class: 'pc-empty', role: 'alert'},
                el('i', {class: 'fas fa-exclamation-triangle', 'aria-hidden': 'true'}),
                el('p', {text: '— ' + t('pv.ui.loadFailed')})));
            return;
        }
        PV.band(list, {page: PV.PAGES + '/trials'});
        PV.toolbar();
        if (!start.offered) {
            content.replaceChildren(el('div', {class: 'pc-empty', role: 'note'},
                el('i', {class: 'fas fa-info-circle', 'aria-hidden': 'true'}),
                el('p', {text: '— ' + t('pv.trial.notOffered')})));
            return;
        }
        const nodes = [startCard(start, list)];
        if (trialId) {
            nodes.unshift(await resultBlock(list));
        }
        nodes.push(recentCard(start), await shadowCard());
        content.replaceChildren(...nodes.filter(Boolean));
    }

    // ----- the start -----

    function startCard(start, list) {
        const asked = Number(PV.params().get('candidate')) || null;
        const shown = start.versions;
        const unused = shown.filter(row => row.state !== 'USED');
        const candidate = select('pv-trial-candidate', t('pv.trial.candidate'), shown,
            asked || (unused.length ? unused[0].number : null));
        const current = shown.find(row => row.state === 'USED');
        const reference = select('pv-trial-reference', t('pv.trial.reference'), shown,
            current ? current.number : shown.length > 1 ? shown[1].number : null, true);
        let count = start.counts[0];
        const counts = el('div', {class: 'zt-period', role: 'group', 'aria-label': t('pv.trial.count')},
            ...start.counts.map(value => {
                const button = el('button', {type: 'button', 'aria-pressed': String(value === count),
                    text: t('pv.trial.countValue', value)});
                button.addEventListener('click', () => {
                    count = value;
                    counts.querySelectorAll('button').forEach(other => other.setAttribute('aria-pressed',
                        String(other === button)));
                });
                return button;
            }));
        const go = PV.button(t('pv.trial.start'), 'fa-play', async () => {
            const body = {candidate: Number(candidate.querySelector('select').value),
                reference: Number(reference.querySelector('select').value), count};
            if (body.candidate === body.reference) {
                PV.notice('bad', t('pv.trial.startFailed'), [t('pv.refused.TRIAL_VERSION')]);
                return;
            }
            go.disabled = true;
            const result = await PV.send('/trials', body);
            go.disabled = false;
            if (result.ok) {
                global.location.assign(PV.page('/trials/' + result.body.id));
            } else {
                PV.notice('bad', t('pv.trial.startFailed'), PV.refusedLines(result));
            }
        }, {primary: true, name: 'start-trial', disabled: !list.writable});
        return ZT.card(t('pv.trial.new'), t('pv.trial.newAside'),
            el('div', {class: 'zt-filter-grid pv-form-grid'}, candidate, reference,
                el('div', {class: 'zt-filter-field pv-span-all'}, el('span', {class: 'zt-filter-name',
                    text: t('pv.trial.count')}), counts)),
            el('p', {class: 'zt-muted', text: t('pv.trial.startNote')}),
            el('div', {class: 'pv-actions'}, go));
    }

    function select(id, label, rows, selected, current) {
        const node = el('select', {class: 'modern-select', id, 'aria-label': label});
        rows.forEach(row => node.append(el('option', {value: String(row.number), selected: row.number === selected
            ? true : null, text: PV.versionLabel(row) + (current && row.state === 'USED' ? ' ' + t('pv.trial.now') : '')})));
        return el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: label}), node);
    }

    // ----- the result -----

    async function resultBlock(list) {
        let view;
        try {
            view = await PV.get('/trials/' + trialId);
        } catch (error) {
            return el('div', {class: 'pc-empty', role: 'alert'}, el('i', {class: 'fas fa-exclamation-triangle',
                'aria-hidden': 'true'}), el('p', {text: '— ' + t(error.status === 404 ? 'pv.trial.missing'
                : 'pv.ui.loadFailed')}));
        }
        const result = view.result;
        const trial = result.trial;
        const open = trial.status === 'QUEUED' || trial.status === 'RUNNING';
        if (open) {
            poll = global.setTimeout(draw, POLL_MS);
        }
        const decision = list.decisionPrompt;
        const wrap = el('div', {class: 'zt-stack', id: 'pv-trial-result'});
        wrap.append(statusCard(view, open));
        if (result.pairs === 0) {
            return wrap;
        }
        const same = result.sameAction;
        wrap.append(
            el('div', {class: 'zt-verdict', role: 'status'}, el('p', {text: verdict(result)})),
            ZT.kpiRow(
                ZT.kpi({tone: 'green', icon: 'fa-equals', label: t('pv.trial.same'),
                    value: ZT.count(same) + ' / ' + ZT.count(result.pairs),
                    sub: ZT.percent(result.pairs ? same / result.pairs : null, 0), title: t('pv.trial.sameHelp')}),
                ZT.kpi({tone: 'indigo', icon: 'fa-file-code', label: t('pv.trial.format'),
                    value: ZT.count(result.candidate.formatErrors),
                    sub: t('pv.trial.formatSub', result.reference.name, ZT.count(result.reference.formatErrors)),
                    title: t('pv.trial.formatHelp')}),
                ZT.kpi({tone: 'purple', icon: 'fa-stopwatch', label: t('pv.trial.time'),
                    value: ZT.seconds(result.candidate.averageMs),
                    sub: t('pv.trial.vsSub', result.reference.name, ZT.seconds(result.reference.averageMs))}),
                ZT.kpi({tone: 'teal', icon: 'fa-text-width', label: t('pv.trial.length'),
                    value: PV.tokens(result.candidate.averageAnswerTokens),
                    sub: t('pv.trial.vsSub', result.reference.name, PV.tokens(result.reference.averageAnswerTokens))})),
            distributionCard(result),
            changedCard(result),
            open ? null : nextActions(view, decision));
        return wrap;
    }

    function statusCard(view, open) {
        const trial = view.result.trial;
        const done = trial.replayed;
        const total = trial.replays;
        const lines = [t('pv.trial.statusLine', trial.candidateName, trial.referenceName, ZT.time(trial.createdAt),
            trial.createdBy || '—')];
        if (trial.actual != null && trial.actual < trial.requested) {
            lines.push(t('pv.trial.fewer', ZT.count(trial.requested), ZT.count(trial.actual)));
        }
        if (trial.failure) {
            lines.push(t('pv.trial.failure'));
        }
        const cancel = open && view.writable ? PV.button(t('pv.trial.cancel'), 'fa-stop', async () => {
            const answer = await PV.confirm({title: t('pv.trial.cancelTitle'), rows: [[t('pv.trial.progress'),
                ZT.count(done) + ' / ' + ZT.count(total)]], confirmLabel: t('pv.trial.cancel'), icon: 'fa-stop'});
            if (answer) {
                const result = await PV.send('/trials/' + trial.id + '/cancel', {});
                if (!result.ok) {
                    PV.notice('bad', t('pv.trial.cancelFailed'), PV.refusedLines(result));
                }
                draw();
            }
        }, {name: 'cancel-trial'}) : null;
        return ZT.card(t('pv.trial.result'), PV.word('pv.trial.status.' + trial.status),
            el('div', {class: 'zt-item'}, ...lines.map(line => el('span', {class: 'zt-muted', text: line}))),
            open ? el('div', {class: 'zt-item'}, ZT.bar(done, total, {label: t('pv.trial.progress')}),
                el('span', {class: 'zt-num zt-muted', text: t('pv.trial.progressLine', ZT.count(done), ZT.count(total))}))
                : null,
            cancel ? el('div', {class: 'pv-actions'}, cancel) : null);
    }

    function verdict(result) {
        const changed = result.pairs - result.sameAction;
        const errors = result.candidate.formatErrors;
        return t('pv.trial.verdict', ZT.count(result.pairs), ZT.count(result.sameAction), ZT.count(changed))
            + ' ' + (errors ? t('pv.trial.verdictErrors', ZT.count(errors)) : t('pv.trial.verdictNoErrors'));
    }

    function distributionCard(result) {
        const head = el('tr', {}, el('th', {scope: 'col', text: t('pv.trial.version')}),
            ...PV.ACTIONS.map(action => el('th', {scope: 'col', class: 'zt-num', text: PV.actionName(action)})),
            el('th', {scope: 'col', class: 'zt-num', text: t('pv.trial.noAnswer')}));
        const row = (side, label) => el('tr', {}, el('td', {class: 'zt-fill', text: side.name + ' ' + label}),
            ...PV.ACTIONS.map(action => el('td', {class: 'zt-num', text: ZT.count(side.actions[action] || 0)})),
            el('td', {class: 'zt-num', text: ZT.count(side.noAnswer)}));
        // A phone cannot hold the six columns: it shows the same numbers as one bar per version.
        const bars = [result.reference, result.candidate].map((side, index) => el('div', {class: 'zt-item'},
            el('strong', {text: side.name + ' ' + t(index === 0 ? 'pv.trial.referenceTag' : 'pv.trial.candidateTag')}),
            PV.actionBar(side.actions, side.answered),
            side.noAnswer ? el('span', {class: 'zt-muted', text: t('pv.trial.noAnswer') + ' ' + ZT.count(side.noAnswer)})
                : null));
        return ZT.card(t('pv.trial.distribution'), t('pv.trial.distributionAside', ZT.count(result.pairs)),
            el('div', {class: 'zt-table-wrap pv-desk'}, el('table', {class: 'zt-table modern-table'},
                el('thead', {}, head), el('tbody', {}, row(result.reference, t('pv.trial.referenceTag')),
                    row(result.candidate, t('pv.trial.candidateTag'))))),
            el('div', {class: 'zt-stack pv-phone'}, ...bars));
    }

    function changedCard(result) {
        if (!result.changed.length) {
            return ZT.card(t('pv.trial.changed', ZT.count(0)), null, el('div', {class: 'pc-empty', role: 'note'},
                el('i', {class: 'fas fa-check', 'aria-hidden': 'true'}), el('p', {text: '— ' + t('pv.trial.noChange')})));
        }
        const {body, foot} = PV.paged(result.changed, change => el('tr', {},
            el('td', {}, el('div', {class: 'zt-item'}, el('span', {class: 'zt-num', text: ZT.shortTime(change.capturedAt)}),
                el('span', {class: 'zt-muted pv-cut', title: change.userId || null, text: change.userId || '—'}))),
            el('td', {class: 'zt-fill'}, el('div', {class: 'zt-item'}, change.requestId ? el('a', {class: 'zt-link pv-cut',
                href: '/contexa/admin/zero-trust/decisions/request/' + encodeURIComponent(change.requestId),
                title: [change.method, change.path].filter(Boolean).join(' ') || change.requestId,
                text: [change.method, change.path].filter(Boolean).join(' ') || change.requestId})
                : el('span', {class: 'pv-cut', text: [change.method, change.path].filter(Boolean).join(' ') || '—'}),
            el('span', {class: 'pv-cut pv-narrow', text: PV.actionName(change.referenceAction) + ' → '
                + PV.actionName(change.candidateAction)}),
            el('span', {class: 'zt-muted pv-cut pv-narrow', title: change.candidateReason || '',
                text: change.candidateReason || ''}))),
            el('td', {class: 'zt-cell-chips pv-wide'}, ZT.chip(change.referenceAction, PV.actionName(change.referenceAction))),
            el('td', {class: 'zt-cell-chips pv-wide'}, ZT.chip(change.candidateAction, PV.actionName(change.candidateAction))),
            el('td', {class: 'pv-wide'}, el('span', {class: 'pv-cut', title: change.candidateReason || '',
                text: change.candidateReason || '—'}))));
        return withFoot(foot, ZT.card(t('pv.trial.changed', ZT.count(result.changed.length)), t('pv.trial.changedAside'),
            el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table modern-table'},
                el('thead', {}, el('tr', {}, ...['when', 'target', 'reference', 'candidate', 'reason'].map(column =>
                    el('th', {scope: 'col', class: (column === 'reason' || column === 'reference' || column === 'candidate'
                        ? 'pv-wide ' : '') + 'pv-keep-case',
                        text: t('pv.trial.column.' + column, result.reference.name, result.candidate.name)})))),
                body))));
    }

    /** A card with the pager of its table below it. */
    function withFoot(foot, card) {
        card.append(foot);
        return card;
    }

    function nextActions(view, decision) {
        const trial = view.result.trial;
        if (trial.status !== 'DONE' || !view.writable) {
            return null;
        }
        return el('div', {class: 'pv-actions pv-end'},
            PV.button(t('pv.trial.canary'), 'fa-users', null, {href: PV.page('/advanced', {canary: trial.candidate}),
                name: 'to-canary'}),
            PV.button(t('pv.trial.use', trial.candidateName), 'fa-check-circle',
                () => PV.useVersion(trial.candidate, decision, draw), {primary: true, name: 'use'}));
    }

    // ----- the recent trials and the results alongside -----

    function recentCard(start) {
        if (!start.recent.length) {
            return null;
        }
        const body = el('tbody');
        start.recent.forEach(trial => body.append(el('tr', {},
            el('td', {}, el('a', {class: 'zt-link', href: PV.page('/trials/' + trial.id), text: ZT.time(trial.createdAt)})),
            el('td', {text: trial.candidateName + ' ↔ ' + trial.referenceName}),
            el('td', {class: 'zt-num', text: ZT.count(trial.actual != null ? trial.actual : trial.requested)}),
            el('td', {class: 'zt-cell-chips'}, el('span', {class: 'status-badge zt-chip', 'data-pv-trial': trial.status,
                text: PV.word('pv.trial.status.' + trial.status)})),
            el('td', {text: trial.createdBy || '—'}))));
        return ZT.card(t('pv.trial.recent'), null, el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table modern-table'},
            el('thead', {}, el('tr', {}, ...['started', 'versions', 'count', 'status', 'by'].map(column =>
                el('th', {scope: 'col', class: column === 'count' ? 'zt-num' : null, text: t('pv.trial.recentColumn.' + column)})))),
            body)));
    }

    /** The sealed package of a run, opened on the prompt inspection screen where its inspection is. */
    const EVIDENCE = '/contexa/admin/prompt-inspection/packages/';
    const SHADOW_DAYS = [1, 7, 30, 90];
    const OUTCOME_COLUMNS = ['version', 'stage', 'action', 'packages', 'failed', 'passed', 'notInspected'];
    const COUNT_COLUMNS = ['packages', 'failed', 'passed', 'notInspected'];
    /**
     * K115: a phone keeps the version and the counts to act on (failed, not inspected) inside the card: the stage and
     * the action read under the version, the sealed and the passed counts stay in the wider layouts.
     */
    const WIDE_COLUMNS = ['stage', 'action', 'packages', 'passed'];

    /** A count in a narrow column: shortened in place on a phone (1.3), the whole count in its tooltip. */
    function countCell(value, column) {
        return el('td', {class: 'zt-num' + (WIDE_COLUMNS.includes(column) ? ' zt-wide' : ''), title: ZT.count(value)},
            el('div', {class: 'zt-long', text: ZT.count(value)}), el('div', {class: 'zt-short', text: ZT.shortCount(value)}));
    }

    function resultRow(name, value) {
        return el('div', {class: 'zt-result-row'}, el('span', {class: 'zt-result-name', text: name}),
            el('span', {class: 'zt-result-value', text: ZT.count(value)}));
    }

    function versionLink(name) {
        const number = String(name || '').replace(/^v/, '').split('.')[0];
        return /^[0-9]+$/.test(number) ? el('a', {class: 'zt-link pv-keep-case', href: PV.page('/' + number), text: name})
            : el('span', {class: 'pv-keep-case', text: name || '—'});
    }

    function actionCell(action) {
        return el('td', {class: 'zt-cell-chips'}, action ? ZT.chip(action, PV.actionName(action)) : '—');
    }

    function table(head, body) {
        return el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table modern-table'}, el('thead', {},
            el('tr', {}, ...head)), body));
    }

    /**
     * Plan 3.9: the shadow runs of a period paired with the decisions of their requests, the sealed decisions of the
     * period per version, stage and action with their latest inspection, and each pair with its sealed packages: what
     * the release comparison showed.
     */
    async function shadowCard(days) {
        const period = SHADOW_DAYS.includes(days) ? days : 7;
        let shadow;
        try {
            shadow = await PV.get('/shadow/results', {days: period});
        } catch (error) {
            return null;
        }
        const holder = el('div', {class: 'zt-stack'});
        const choose = el('div', {class: 'zt-period', role: 'group', 'aria-label': t('pv.shadow.period')},
            ...SHADOW_DAYS.map(value => {
                const button = el('button', {type: 'button', 'aria-pressed': String(value === period),
                    text: t('pv.shadow.days', value)});
                button.addEventListener('click', async () => {
                    const next = await shadowCard(value);
                    if (next) {
                        card.replaceWith(next);
                    }
                });
                return button;
            }));
        const card = ZT.card(t('pv.shadow.results'), t('pv.shadow.resultsAside', ZT.count(period), shadow.shadow || '—'),
            el('div', {class: 'zt-stack'}, choose, holder));
        const outcomes = shadow.outcomes || [];
        if (!shadow.shadow && !shadow.shadows && !outcomes.length) {
            holder.append(el('div', {class: 'pc-empty', role: 'note'},
                el('i', {class: 'fas fa-inbox', 'aria-hidden': 'true'}),
                el('p', {text: '— ' + t('pv.shadow.none', ZT.count(period))})));
            return card;
        }
        holder.append(el('div', {class: 'zt-result-rows'}, resultRow(t('pv.shadow.runs'), shadow.shadows),
            resultRow(t('pv.shadow.paired'), shadow.paired), resultRow(t('pv.shadow.changed'), shadow.changed)));
        if (shadow.changes.length) {
            const changes = el('tbody');
            shadow.changes.forEach(change => changes.append(el('tr', {},
                el('td', {class: 'zt-cell-chips zt-fill'}, ZT.chip(change.decisionAction, PV.actionName(change.decisionAction))),
                actionCell(change.shadowAction),
                el('td', {class: 'zt-num', text: ZT.count(change.requests)}))));
            holder.append(table([el('th', {scope: 'col', text: t('pv.shadow.decision')}),
                el('th', {scope: 'col', text: t('pv.shadow.alongside')}),
                el('th', {scope: 'col', class: 'zt-num', text: t('pv.shadow.requests')})], changes));
        }
        if (outcomes.length) {
            const body = el('tbody');
            outcomes.forEach(outcome => {
                const stage = t('pv.shadow.stage.' + outcome.stage);
                const action = actionCell(outcome.action);
                action.classList.add('zt-wide');
                const line = stage + ' · ' + (outcome.action ? PV.actionName(outcome.action) : '—');
                body.append(el('tr', {},
                    el('td', {class: 'zt-fill'}, versionLink(outcome.version),
                        el('div', {class: 'zt-short zt-muted', title: line, text: line})),
                    el('td', {class: 'zt-wide', title: stage, text: stage}),
                    action,
                    ...COUNT_COLUMNS.map(column => countCell(outcome[column], column))));
            });
            holder.append(el('div', {class: 'zt-subhead', text: t('pv.shadow.outcomes')}),
                table(OUTCOME_COLUMNS.map(column => el('th', {scope: 'col',
                    class: [COUNT_COLUMNS.includes(column) ? 'zt-num' : '', WIDE_COLUMNS.includes(column) ? 'zt-wide' : '']
                        .join(' ').trim() || null, text: t('pv.shadow.outcome.' + column)})), body));
        }
        if ((shadow.cases || []).length) {
            const body = el('tbody');
            // K115: a phone reads each side as a line under the request, and each seal by its side's short word
            const side = (version, action) => (version || '—') + ' · ' + (action ? PV.actionName(action) : '—');
            const seal = (id, key) => id ? el('a', {class: 'zt-link', href: EVIDENCE + encodeURIComponent(id), title: t(key)},
                el('span', {class: 'zt-long', text: t(key)}), el('span', {class: 'zt-short', text: t(key + '.short')})) : null;
            shadow.cases.forEach(item => {
                const decision = side(item.decisionVersion, item.decisionAction);
                const alongside = '→ ' + side(item.shadowVersion, item.shadowAction);
                body.append(el('tr', {},
                    el('td', {class: 'zt-fill'}, el('span', {class: 'pv-cut', title: item.requestId, text: item.requestId}),
                        el('div', {class: 'zt-muted', text: ZT.time(item.capturedAt)}),
                        el('div', {class: 'zt-short zt-muted', title: decision, text: decision}),
                        el('div', {class: 'zt-short zt-muted', title: alongside, text: alongside})),
                    el('td', {class: 'zt-cell-chips zt-wide'}, versionLink(item.decisionVersion), ' ',
                        item.decisionAction ? ZT.chip(item.decisionAction, PV.actionName(item.decisionAction)) : null),
                    el('td', {class: 'zt-cell-chips zt-wide'}, versionLink(item.shadowVersion), ' ',
                        item.shadowAction ? ZT.chip(item.shadowAction, PV.actionName(item.shadowAction)) : null),
                    el('td', {class: 'pv-row-action'}, seal(item.decisionPackageId, 'pv.shadow.decisionSeal'), ' ',
                        seal(item.shadowPackageId, 'pv.shadow.shadowSeal'))));
            });
            holder.append(el('div', {class: 'zt-subhead', text: t('pv.shadow.cases', ZT.count(shadow.cases.length))}),
                table(['request', 'decision', 'alongside', 'evidence'].map(column => el('th', {scope: 'col',
                    class: column === 'decision' || column === 'alongside' ? 'zt-wide' : null,
                    text: t('pv.shadow.case.' + column)})), body));
        }
        return card;
    }

    draw();
})(window);
