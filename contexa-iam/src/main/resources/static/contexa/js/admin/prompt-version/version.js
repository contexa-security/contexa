/*
 * Prompt versions, a version (plan 3.10, screen 2): its parts in order with what it changed against its base, the user
 * blocks, the finished prompt with the values of the latest real decision, its size and the decisions it made, and
 * what can be done to it.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const PV = global.PV;
    const el = ZT.el;
    const t = ZT.t;
    const root = document.getElementById('zt-console');
    const content = document.getElementById('zt-content');
    const number = Number(root.dataset.versionNumber);

    async function draw() {
        let view;
        let list;
        try {
            [view, list] = await Promise.all([PV.get('/' + number), PV.get('')]);
        } catch (error) {
            content.replaceChildren(el('div', {class: 'pc-empty', role: 'alert'},
                el('i', {class: 'fas fa-exclamation-triangle', 'aria-hidden': 'true'}),
                el('p', {text: '— ' + t(error.status === 404 ? 'pv.version.missing' : 'pv.ui.loadFailed')})));
            return;
        }
        const decision = view.decisionPrompt;
        const row = view.version;
        PV.band(list, {page: PV.PAGES});
        document.getElementById('pv-crumbs').replaceChildren(el('a', {class: 'zt-link', href: PV.page(''),
            text: t('pv.ui.title.list')}), el('span', {class: 'zt-muted', text: ' › ' + row.name}));
        document.getElementById('pv-title').textContent = PV.versionLabel(row);
        document.getElementById('pv-question').textContent = [
            row.basedOn ? t('pv.list.basedOn', row.basedOn) : t('pv.version.product'),
            row.provider === 'CONTEXA' ? t('pv.provider.CONTEXA') : t('pv.provider.ORGANIZATION'), PV.origin(row),
            ZT.time(row.createdAt) + ' ' + PV.maker(row), PV.stateText(row.state, decision)
        ].join(' · ');
        PV.toolbar(...tools(view, decision));
        PV.fill(content,
            ZT.kpiRow(changesCard(view), sizeCard(view), timeCard(view), formatCard(view)),
            partsCard(view),
            decisionsCard(view, decision));
    }

    function tools(view, decision) {
        const row = view.version;
        const nodes = [];
        if (decision && view.trialsOffered && row.state !== 'USED' && !row.hidden) {
            nodes.push(PV.button(t('pv.action.trial'), 'fa-vial', null, {href: PV.page('/trials', {candidate: row.number}),
                name: 'trial'}));
        }
        nodes.push(downloadMenu(row));
        if (view.canBase) {
            nodes.push(PV.button(t('pv.action.new'), 'fa-plus', null, {href: PV.page('/new', {base: row.number}),
                name: 'new-from'}));
        }
        if (row.state !== 'USED' && !row.hidden && view.writable) {
            nodes.push(PV.button(PV.useLabel(decision), 'fa-check-circle', () => PV.useVersion(row.number, decision, draw),
                {primary: true, name: 'use'}));
        }
        if (row.state === 'UNUSED' && !row.hidden) {
            nodes.push(PV.button(t('pv.action.hide'), 'fa-eye-slash', () => hide(row), {name: 'hide'}));
        }
        return nodes;
    }

    /** Plan 3.6: the changes (importable on another server) or the whole version (to read). */
    function downloadMenu(row) {
        const menu = el('details', {class: 'pv-menu'}, el('summary', {class: 'modern-btn-secondary'},
            el('i', {class: 'fas fa-file-download', 'aria-hidden': 'true'}), el('span', {text: t('pv.action.download')})));
        return PV.fold(menu, el('div', {class: 'pv-menu-list'},
            el('a', {class: 'zt-link', href: PV.api('/' + row.number + '/export', {form: 'diff'}),
                text: t('pv.download.diff')}),
            el('a', {class: 'zt-link', href: PV.api('/' + row.number + '/export', {form: 'full'}),
                text: t('pv.download.full')})));
    }

    async function hide(row) {
        const answer = await PV.confirm({title: t('pv.hide.title', row.name), rows: [[t('pv.hide.what'), t('pv.hide.line')]],
            confirmLabel: t('pv.action.hide'), icon: 'fa-eye-slash'});
        if (!answer) {
            return;
        }
        const result = await PV.send('/' + row.number + '/hide', {});
        if (result.ok) {
            PV.notice('good', t('pv.hide.done', row.name), []);
            draw();
        } else {
            PV.notice('bad', t('pv.hide.failed'), PV.refusedLines(result));
        }
    }

    function changesCard(view) {
        const changes = view.changes || {};
        const total = (changes.CHANGED || 0) + (changes.DELETED || 0) + (changes.ADDED || 0) + (changes.INCLUDED || 0);
        return ZT.kpi({tone: 'indigo', icon: 'fa-pen', label: t('pv.version.changes'),
            value: view.version.basedOn ? ZT.count(total) : '—',
            sub: view.version.basedOn ? t('pv.version.changesSub', ZT.count(changes.CHANGED || 0),
                ZT.count(changes.DELETED || 0), ZT.count((changes.ADDED || 0) + (changes.INCLUDED || 0)))
                : t('pv.version.product')});
    }

    /** K69: the system prompt and the blocks the version adds to the user prompt, with their headers. */
    function sizeCard(view) {
        const size = view.size || {};
        const added = size.addedUserTokens || 0;
        const delta = size.baseSystemTokens != null
            ? size.systemTokens + added - size.baseSystemTokens - (size.baseAddedUserTokens || 0) : null;
        const signedDelta = delta == null ? null : PV.signed(delta, value => PV.tokens(value));
        return ZT.kpi({tone: 'teal', icon: 'fa-ruler-horizontal', label: t('pv.version.size'),
            value: PV.tokens(size.systemTokens + added),
            sub: delta == null ? t('pv.version.sizeProduct')
                : added ? t('pv.version.sizeDeltaBlocks', view.version.basedOn, signedDelta, PV.tokens(added))
                    : t('pv.version.sizeDelta', view.version.basedOn, signedDelta),
            title: t('pv.version.sizeHelp')});
    }

    function timeCard(view) {
        const made = view.decisions;
        const estimate = view.size && view.size.estimatedDeltaMs != null && view.version.basedOn
            ? PV.signed(view.size.estimatedDeltaMs, value => ZT.seconds(value)) : null;
        return ZT.kpi({tone: 'purple', icon: 'fa-stopwatch', label: t('pv.version.time'),
            value: made && made.medianMs != null ? ZT.seconds(made.medianMs) : '—',
            sub: made
                ? estimate ? t('pv.version.timeSubEstimate', ZT.count(made.decisions), view.version.basedOn, estimate)
                    : t('pv.version.timeSub', ZT.count(made.decisions))
                : estimate ? t('pv.version.timeEstimate', view.version.basedOn, estimate) : t('pv.version.noDecisions'),
            title: t('pv.version.timeHelp')});
    }

    function formatCard(view) {
        const made = view.decisions;
        return ZT.kpi({tone: 'green', icon: 'fa-check-double', label: t('pv.version.format'),
            value: made && made.malformedRatio != null ? ZT.percent(made.malformedRatio) : '—',
            sub: made && made.retriedRatio != null ? t('pv.version.retried', ZT.percent(made.retriedRatio))
                : t('pv.version.noDecisions'), title: t('pv.version.formatHelp')});
    }

    // ----- the parts -----

    function partsCard(view) {
        const views = [
            {label: t('pv.version.tab.system', ZT.count(view.system.length)), node: systemParts(view)},
            {label: t('pv.version.tab.user', ZT.count(view.user.length)), node: userBlocks(view)}];
        if (view.decisionPrompt || (view.preview && view.preview.example)) {
            views.push({label: t('pv.version.tab.preview'), node: preview(view)});
        }
        return ZT.tabbedCard(t('pv.version.parts'), t('pv.version.partsAside'), views);
    }

    /** The system parts in order; Contexa's fixed parts that follow one another fold into one row. */
    function systemParts(view) {
        const list = el('ol', {class: 'pv-parts', 'aria-label': t('pv.version.tab.system', '')});
        groups(view.system).forEach(group => list.append(group.length > 1 ? lockedGroup(group) : part(view, group[0])));
        return el('div', {class: 'zt-stack'}, el('p', {class: 'zt-muted', text: t('pv.version.systemNote')}), list);
    }

    /** Runs of fixed parts in the same group, folded; any other part stands alone. */
    function groups(parts) {
        const result = [];
        parts.forEach(part => {
            const last = result[result.length - 1];
            if (last && part.mark === 'LOCKED' && last[0].mark === 'LOCKED'
                && (last[0].group === 'judgment') === (part.group === 'judgment')) {
                last.push(part);
            } else {
                result.push([part]);
            }
        });
        return result;
    }

    function lockedGroup(group) {
        const user = group[0].list === 'USER';
        const format = !user && group[0].group !== 'judgment';
        const titles = group.map(part => part.position + ' ' + PV.partName(part)).join(' · ');
        const details = el('details', {class: 'pv-part', 'data-pv-mark': 'LOCKED'},
            el('summary', {class: 'pv-part-head'}, el('span', {class: 'pv-part-lead'},
                el('span', {class: 'pv-part-title pv-cut', text: titles}),
                el('span', {class: 'zt-muted pv-part-summary', text: t(user ? 'pv.version.lockedUser'
                    : format ? 'pv.version.lockedEnd' : 'pv.version.lockedRun')})),
                mark('LOCKED')));
        PV.fold(details, el('div', {class: 'pv-part-body'}, ...group.map(part => el('div', {class: 'zt-item'},
            el('strong', {text: part.position + ' ' + PV.partName(part)}), partText(part)))));
        return el('li', {}, details);
    }

    function part(view, one) {
        const details = el('details', {class: 'pv-part', 'data-pv-mark': one.mark, 'data-pv-part': one.key},
            // K106: the title and the summary lead the head, so the marks of the parts share one column
            el('summary', {class: 'pv-part-head'}, el('span', {class: 'pv-part-lead'},
                el('span', {class: 'pv-part-title pv-cut', text: one.position + ' ' + PV.partName(one)}),
                el('span', {class: 'zt-muted pv-part-summary pv-cut', text: summary(one)})),
                mark(one.mark, one.when)));
        const body = el('div', {class: 'pv-part-body'});
        if (one.mark === 'CHANGED' && one.baseText != null) {
            body.append(el('div', {class: 'pv-compare'},
                el('div', {class: 'zt-item'}, el('strong', {text: t('pv.version.compareBase', view.baseName || '')}),
                    PV.textBox(one.baseText)),
                el('div', {class: 'zt-item'}, el('strong', {text: t('pv.version.compareThis', view.version.name)}),
                    PV.textBox(one.text))));
        } else if (one.mark === 'DELETED') {
            body.append(el('p', {class: 'zt-muted', text: t('pv.version.deletedLine')}),
                one.baseText != null ? PV.textBox(one.baseText) : null);
        } else {
            body.append(partText(one));
        }
        PV.fold(details, body);
        return el('li', {}, details);
    }

    function partText(one) {
        if (one.items && one.items.length) {
            return el('dl', {class: 'pv-items'}, ...one.items.flatMap(item => [el('dt', {class: 'zt-num', text: item.key}),
                el('dd', {text: item.text || ''})]));
        }
        return PV.textBox(one.text);
    }

    function summary(one) {
        if (one.mark === 'DELETED') {
            return t('pv.version.deletedSummary');
        }
        if (one.mark === 'SAME') {
            return t('pv.version.sameSummary');
        }
        if (one.mark === 'DEFAULT') {
            return t('pv.version.defaultSummary');
        }
        if (one.items && one.items.length) {
            return t('pv.version.itemsSummary', ZT.count(one.items.length));
        }
        return (one.text || '').replace(/\s+/g, ' ').trim();
    }

    function mark(code, when) {
        const label = PV.word('pv.mark.' + code) + (when ? ' · ' + t('pv.mark.when') : '');
        return el('span', {class: 'status-badge zt-chip pv-mark', 'data-pv-mark': code, text: label});
    }

    function userBlocks(view) {
        const list = el('ol', {class: 'pv-parts', 'aria-label': t('pv.version.tab.user', '')});
        view.user.forEach(one => list.append(part(view, one)));
        return el('div', {class: 'zt-stack'}, el('p', {class: 'zt-muted', text: t('pv.version.userNote')}), list);
    }

    /** The finished prompt: the system text this version draws, the output format, the latest real user prompt. */
    function preview(view) {
        const shown = view.preview || {};
        if (shown.example) {
            // Plan 3.11: a prompt other than the security decision, drawn with its fixed example input.
            return el('div', {class: 'zt-stack'},
                el('p', {class: 'zt-muted', text: t('pv.preview.example')}),
                shown.system ? el('div', {class: 'zt-item'}, el('strong', {text: t('pv.preview.system')}),
                    PV.textBox(shown.system, t('pv.preview.system'))) : null,
                el('div', {class: 'zt-item'}, el('strong', {text: t('pv.preview.user')}),
                    PV.textBox(shown.user, t('pv.preview.user'))));
        }
        const nodes = [el('div', {class: 'zt-item'}, el('strong', {text: t('pv.preview.system')}),
            PV.textBox(shown.system, t('pv.preview.system'))),
        el('div', {class: 'zt-item'}, el('strong', {text: t('pv.preview.format')}),
            PV.textBox(shown.format, t('pv.preview.format')))];
        if (shown.user) {
            // Plan 3.10 (2): a decision another version drew is drawn again with this one; when it cannot be, why.
            const notDrawn = shown.notDrawn === 'UNAVAILABLE' ? t('pv.preview.notDrawn.unavailable')
                : shown.notDrawn ? t('pv.preview.notDrawn.failed') : null;
            nodes.push(el('div', {class: 'zt-item'}, el('strong', {text: t('pv.preview.user')}),
                el('span', {class: 'zt-muted', text: shown.drawnAgain
                    ? t('pv.preview.userDrawn', ZT.time(shown.capturedAt))
                    : shown.drawnWithThisVersion
                        ? t('pv.preview.userSame', ZT.time(shown.capturedAt))
                        : t('pv.preview.userOther', ZT.time(shown.capturedAt), shown.drawnWith || '—')}),
                notDrawn ? el('span', {class: 'zt-muted', text: notDrawn}) : null,
                // K71: the state of the sealed package the user prompt comes from, as the replay screen tells it.
                shown.integrity ? el('span', {class: 'zt-muted', 'data-pv-integrity': shown.integrity,
                    text: t('pv.preview.integrity.' + shown.integrity)}) : null,
                PV.textBox(shown.user, t('pv.preview.user'))));
            if (!shown.drawnWithThisVersion && shown.addedBlocks && shown.addedBlocks.length) {
                nodes.push(el('div', {class: 'zt-item'}, el('strong', {text: t('pv.preview.added')}),
                    ...shown.addedBlocks.map(block => el('div', {class: 'zt-fact'}, el('strong', {text: block.title || ''}),
                        PV.textBox(block.text)))));
            }
        } else {
            nodes.push(el('p', {class: 'zt-muted', text: t('pv.preview.noDecision')}));
        }
        return el('div', {class: 'zt-stack'}, ...nodes);
    }

    function decisionsCard(view, decision) {
        const made = view.decisions;
        if (!made || !made.decisions) {
            return ZT.card(t(decision ? 'pv.version.made' : 'pv.version.made.other'), null,
                el('div', {class: 'pc-empty', role: 'note'}, el('i', {class: 'fas fa-inbox', 'aria-hidden': 'true'}),
                    el('p', {text: '— ' + t('pv.version.noDecisionsLine')})));
        }
        return ZT.card(t(decision ? 'pv.version.made' : 'pv.version.made.other'),
            t('pv.version.madeAside', ZT.day(made.from), ZT.count(made.decisions)),
            PV.actionBar(made.actions, made.decisions));
    }

    draw();
})(window);
