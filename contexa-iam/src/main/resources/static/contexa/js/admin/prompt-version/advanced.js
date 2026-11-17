/*
 * Prompt versions, the advanced screen (plan 3.10, screen 5), for the operators: the document folder, the import and
 * the download of a version, a canary of a version for some users, a version running alongside the decisions, the
 * history, and the emergency rollback another operator approves.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const PV = global.PV;
    const el = ZT.el;
    const t = ZT.t;
    const content = document.getElementById('zt-content');

    async function draw() {
        let view;
        let list;
        try {
            [view, list] = await Promise.all([PV.get('/advanced'), PV.get('')]);
        } catch (error) {
            PV.fill(content,el('div', {class: 'pc-empty', role: 'alert'},
                el('i', {class: 'fas fa-exclamation-triangle', 'aria-hidden': 'true'}),
                el('p', {text: '— ' + t('pv.ui.loadFailed')})));
            return;
        }
        PV.band(list, {page: PV.PAGES + '/advanced'});
        PV.toolbar();
        const decision = view.decisionPrompt;
        PV.fill(content,
            el('div', {class: 'zt-grid'},
                el('div', {class: 'zt-span-6'}, folderCard(view)),
                el('div', {class: 'zt-span-6'}, documentsCard(view))),
            decision ? el('div', {class: 'zt-grid'},
                el('div', {class: 'zt-span-6'}, canaryCard(view)),
                el('div', {class: 'zt-span-6'}, shadowCard(view))) : null,
            historyCard(view),
            decision ? rollbackCard(view) : null);
    }

    function options(view, selected, filter) {
        const select = el('select', {class: 'modern-select'});
        view.versions.filter(filter || (() => true)).forEach(row => select.append(el('option', {value: String(row.number),
            selected: row.number === selected ? true : null, text: PV.versionLabel(row)})));
        return select;
    }

    function field(label, node) {
        return el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: label}), node);
    }

    function choice(values, selected, unit, label) {
        let current = selected;
        const group = el('div', {class: 'zt-period', role: 'group', 'aria-label': label},
            ...values.map(value => {
                const button = el('button', {type: 'button', 'aria-pressed': String(value === current),
                    text: t(unit, value)});
                button.addEventListener('click', () => {
                    current = value;
                    group.querySelectorAll('button').forEach(other => other.setAttribute('aria-pressed',
                        String(other === button)));
                });
                return button;
            }));
        group.value = () => current;
        return group;
    }

    async function act(path, body, done, failed) {
        const result = await PV.send(path, body);
        if (result.ok) {
            PV.notice('good', done, []);
            draw();
        } else {
            PV.notice('bad', failed, PV.refusedLines(result));
        }
        return result;
    }

    // ----- the document folder -----

    function folderCard(view) {
        const folder = view.folder;
        const latest = folder.scans[0];
        const rows = [
            [t('pv.folder.path'), folder.setting || t('pv.folder.notSet')],
            [t('pv.folder.setting'), 'contexa.prompt.versions.directory'],
            [t('pv.folder.lastRead'), latest ? t('pv.folder.lastReadValue', ZT.time(latest.scannedAt),
                ZT.count(latest.documents), latest.node) : '—'],
            [t('pv.folder.lastRegistered'), folder.lastRegistered ? t('pv.folder.lastRegisteredValue',
                folder.lastRegistered.name, folder.lastRegistered.originName || '') : '—']];
        const errors = folder.scans.flatMap(scan => scan.errors.map(error => scan.node + ': ' + error));
        const rescan = PV.button(t('pv.folder.rescan'), 'fa-sync', async () => {
            rescan.disabled = true;
            const result = await PV.send('/folder/rescan', {});
            rescan.disabled = false;
            if (result.ok) {
                PV.notice(result.body.errors.length ? 'bad' : 'good', t('pv.folder.rescanned',
                    ZT.count(result.body.documents), ZT.count(result.body.registered)), result.body.errors);
                draw();
            } else {
                PV.notice('bad', t('pv.folder.rescanFailed'), PV.refusedLines(result));
            }
        }, {name: 'rescan', disabled: !folder.enabled});
        return ZT.card(t('pv.folder.title'), t('pv.folder.aside'),
            el('div', {class: 'zt-result-rows'}, ...rows.map(([label, value]) => el('div', {class: 'zt-result-row'},
                el('span', {class: 'zt-result-name', text: label}),
                el('span', {class: 'zt-result-value pv-wrap', title: value, text: value})))),
            errors.length ? el('div', {class: 'zt-alert', role: 'alert'}, el('span', {class: 'status-badge zt-chip',
                'data-status': 'BAD', text: t('pv.folder.errors', ZT.count(errors.length))}),
            el('div', {class: 'zt-item'}, ...errors.slice(0, 10).map(error => el('span', {class: 'pv-cut', text: error}))))
                : null,
            el('div', {class: 'zt-card-foot'}, rescan, folder.enabled ? null
                : el('span', {class: 'zt-muted', text: t('pv.folder.disabled')})));
    }

    // ----- the import and the download -----

    function documentsCard(view) {
        const file = el('input', {type: 'file', accept: '.yaml,.yml,text/yaml,text/plain', id: 'pv-import-file',
            class: 'modern-input'});
        const upload = PV.button(t('pv.documents.import'), 'fa-file-upload', async () => {
            const chosen = file.files && file.files[0];
            if (!chosen) {
                file.focus();
                return;
            }
            const text = await chosen.text();
            await act('/import', {fileName: chosen.name, text}, t('pv.documents.imported', chosen.name),
                t('pv.documents.importFailed'));
        }, {name: 'import'});
        const version = options(view, view.versions.length ? view.versions[0].number : null);
        const form = el('div', {class: 'zt-period', role: 'radiogroup', 'aria-label': t('pv.documents.form')});
        let chosenForm = 'diff';
        ['diff', 'full'].forEach(value => {
            const button = el('button', {type: 'button', role: 'radio', 'aria-pressed': String(value === chosenForm),
                'aria-checked': String(value === chosenForm), text: t('pv.download.' + value)});
            button.addEventListener('click', () => {
                chosenForm = value;
                form.querySelectorAll('button').forEach(other => {
                    other.setAttribute('aria-pressed', String(other === button));
                    other.setAttribute('aria-checked', String(other === button));
                });
            });
            form.append(button);
        });
        const download = PV.button(t('pv.documents.download'), 'fa-file-download', () => {
            global.location.assign(PV.api('/' + version.value + '/export', {form: chosenForm}));
        }, {name: 'download', disabled: !view.versions.length});
        return ZT.card(t('pv.documents.title'), t('pv.documents.aside'),
            field(t('pv.documents.upload'), file),
            el('div', {class: 'pv-actions'}, upload),
            el('div', {class: 'zt-filter-grid pv-form-grid'}, field(t('pv.documents.version'), version),
                el('div', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.documents.form')}),
                    form)),
            el('div', {class: 'zt-card-foot'}, download, el('span', {class: 'zt-muted', text: t('pv.documents.formNote')})));
    }

    // ----- canary and shadow -----

    function canaryCard(view) {
        const running = view.running || {};
        const asked = Number(PV.params().get('canary')) || null;
        const version = options(view, asked || (view.versions.find(row => row.state !== 'USED') || {}).number,
            row => row.state !== 'USED');
        const percent = choice(view.canaryPercents, view.canaryPercents[0], 'pv.unit.percent', t('pv.canary.share'));
        const tenants = el('input', {type: 'text', class: 'modern-input', maxlength: '2000',
            placeholder: t('pv.canary.tenantsPlaceholder')});
        const paths = el('input', {type: 'text', class: 'modern-input', maxlength: '2000',
            placeholder: t('pv.canary.pathsPlaceholder')});
        const now = running.canary ? t('pv.canary.now', running.canary, running.canaryPercent == null ? '—'
            : running.canaryPercent, running.canaryTenants || t('pv.canary.all'), running.canaryPaths || t('pv.canary.all'))
            : t('pv.canary.none');
        const start = PV.button(t('pv.canary.start'), 'fa-play', async () => {
            const answer = await PV.confirm({title: t('pv.canary.confirm'), rows: [
                [t('pv.canary.version'), version.options[version.selectedIndex] ? version.options[version.selectedIndex].text
                    : '—'],
                [t('pv.canary.share'), t('pv.unit.percent', percent.value())],
                [t('pv.canary.tenants'), tenants.value || t('pv.canary.all')],
                [t('pv.canary.paths'), paths.value || t('pv.canary.all')]], reason: true,
            confirmLabel: t('pv.canary.start'), icon: 'fa-play'});
            if (answer) {
                await act('/canary/start', {number: Number(version.value), percent: percent.value(), tenants: tenants.value,
                    paths: paths.value, reason: answer.reason}, t('pv.canary.started'), t('pv.canary.failed'));
            }
        }, {primary: true, name: 'canary-start', disabled: !view.writable || !version.options.length});
        const stop = PV.button(t('pv.canary.stop'), 'fa-stop', async () => {
            const answer = await PV.confirm({title: t('pv.canary.stopConfirm', running.canary),
                rows: [[t('pv.canary.version'), running.canary]], reason: true, confirmLabel: t('pv.canary.stop'),
                icon: 'fa-stop'});
            if (answer) {
                await act('/canary/stop', {reason: answer.reason}, t('pv.canary.stopped'), t('pv.canary.failed'));
            }
        }, {name: 'canary-stop', disabled: !view.writable || !running.canary});
        return ZT.card(t('pv.canary.title'), now,
            el('div', {class: 'zt-filter-grid pv-form-grid'}, field(t('pv.canary.version'), version),
                el('div', {class: 'zt-filter-field pv-span-all'}, el('span', {class: 'zt-filter-name',
                    text: t('pv.canary.share')}), percent),
                field(t('pv.canary.tenants'), tenants), field(t('pv.canary.paths'), paths)),
            el('p', {class: 'zt-muted', text: t('pv.canary.note')}),
            el('div', {class: 'zt-card-foot'}, start, stop));
    }

    function shadowCard(view) {
        const running = view.running || {};
        const version = options(view, (view.versions.find(row => row.state !== 'USED') || {}).number,
            row => row.state !== 'USED');
        const sample = choice(view.shadowPercents, view.shadowPercents[0], 'pv.unit.percent', t('pv.shadow.sample'));
        const daily = el('input', {type: 'number', class: 'modern-input', min: '1', max: '10000', step: '1', value: '200',
            'aria-label': t('pv.shadow.daily')});
        const now = running.shadow ? t('pv.shadow.now', running.shadow, running.shadowSamplePercent == null ? '—'
            : running.shadowSamplePercent, running.shadowDailyLimit == null ? '—' : ZT.count(running.shadowDailyLimit))
            : t('pv.shadow.idle');
        const start = PV.button(t('pv.shadow.start'), 'fa-play', async () => {
            const answer = await PV.confirm({title: t('pv.shadow.confirm'), rows: [
                [t('pv.shadow.version'), version.options[version.selectedIndex] ? version.options[version.selectedIndex].text
                    : '—'],
                [t('pv.shadow.sample'), t('pv.unit.percent', sample.value())], [t('pv.shadow.daily'), daily.value]],
            content: [el('p', {class: 'zt-muted', text: t('pv.shadow.cost')})], reason: true,
            confirmLabel: t('pv.shadow.start'), icon: 'fa-play'});
            if (answer) {
                await act('/shadow/start', {number: Number(version.value), samplePercent: sample.value(),
                    dailyLimit: Number(daily.value), reason: answer.reason}, t('pv.shadow.started'), t('pv.shadow.failed'));
            }
        }, {primary: true, name: 'shadow-start', disabled: !view.writable || !version.options.length});
        const stop = PV.button(t('pv.shadow.stop'), 'fa-stop', async () => {
            const answer = await PV.confirm({title: t('pv.shadow.stopConfirm', running.shadow),
                rows: [[t('pv.shadow.version'), running.shadow]], reason: true, confirmLabel: t('pv.shadow.stop'),
                icon: 'fa-stop'});
            if (answer) {
                await act('/shadow/stop', {reason: answer.reason}, t('pv.shadow.stopped'), t('pv.shadow.failed'));
            }
        }, {name: 'shadow-stop', disabled: !view.writable || !running.shadow});
        return ZT.card(t('pv.shadow.title'), now,
            el('div', {class: 'zt-filter-grid pv-form-grid'}, field(t('pv.shadow.version'), version),
                el('div', {class: 'zt-filter-field pv-span-all'}, el('span', {class: 'zt-filter-name',
                    text: t('pv.shadow.sample')}), sample),
                field(t('pv.shadow.daily'), daily)),
            el('p', {class: 'zt-muted', text: t('pv.shadow.cost')}),
            el('div', {class: 'zt-card-foot'}, start,
                PV.button(t('pv.shadow.compare'), 'fa-balance-scale', null, {href: PV.page('/trials'), name: 'shadow-results'}),
                stop));
    }

    // ----- the history and the emergency rollback -----

    function historyCard(view) {
        if (!view.history.length) {
            return ZT.card(t('pv.history.title'), t('pv.history.aside'), el('div', {class: 'pc-empty', role: 'note'},
                el('i', {class: 'fas fa-inbox', 'aria-hidden': 'true'}), el('p', {text: '— ' + t('pv.history.none')})));
        }
        const {body, foot} = PV.paged(view.history, row => el('tr', {},
            el('td', {class: 'zt-num', text: ZT.shortTime(row.at)}),
            el('td', {class: 'pv-wide', text: actorOf(row.actor)}),
            el('td', {class: 'zt-fill'}, el('div', {class: 'zt-item'}, el('span', {class: 'pv-cut', text: t('pv.history.action',
                PV.word('pv.history.' + row.action, t('pv.history.other')), row.version || '—')}),
            el('span', {class: 'zt-muted pv-cut pv-narrow', text: actorOf(row.actor) + ' · ' + reasonOf(row)}))),
            el('td', {class: 'pv-wide'}, el('span', {class: 'pv-cut', title: reasonOf(row), text: reasonOf(row)}))));
        return withFoot(foot, ZT.card(t('pv.history.title'), t('pv.history.aside'), el('div', {class: 'zt-table-wrap'},
            el('table', {class: 'zt-table modern-table'}, el('thead', {}, el('tr', {}, ...['at', 'actor', 'action', 'reason']
                .map(column => el('th', {scope: 'col', class: column === 'actor' || column === 'reason' ? 'pv-wide' : null,
                    text: t('pv.history.column.' + column)})))), body))));
    }

    /** A card with the pager of its table below it. */
    function withFoot(foot, card) {
        card.append(foot);
        return card;
    }

    /** The reason of a history row; a version made says where it came from in words (the record keeps the code). */
    function reasonOf(row) {
        const reason = row.reason || '';
        const origin = /^(SCREEN|IMPORT|FOLDER|PRODUCT)(?:\s+(.*))?$/.exec(reason.trim());
        if (row.action === 'PROMPT_VERSION_CREATED' && origin) {
            const name = origin[2] && !/^(screen|import):/.test(origin[2]) ? origin[2] : '';
            return t('pv.history.origin.' + origin[1], name);
        }
        return reason || '—';
    }

    function actorOf(actor) {
        return actor === 'system' ? t('pv.maker.install') : actor || '—';
    }

    function rollbackCard(view) {
        const waiting = view.rollbacks.filter(row => row.status === 'AWAITING_APPROVAL');
        const version = options(view, (view.versions.find(row => row.state !== 'USED') || {}).number,
            row => row.state !== 'USED');
        const roll = PV.button(t('pv.rollback.start'), 'fa-history', async () => {
            const answer = await PV.confirm({title: t('pv.rollback.confirm'), rows: [
                [t('pv.use.now'), view.current || '—'],
                [t('pv.rollback.to'), version.options[version.selectedIndex] ? version.options[version.selectedIndex].text
                    : '—']],
            content: [el('p', {class: 'zt-muted', text: t('pv.rollback.note')})], reason: true, reasonRequired: true,
            confirmLabel: t('pv.rollback.start'), icon: 'fa-history'});
            if (answer) {
                await act('/rollback', {number: Number(version.value), reason: answer.reason}, t('pv.rollback.done'),
                    t('pv.rollback.failed'));
            }
        }, {primary: true, name: 'rollback', disabled: !view.writable || !version.options.length});
        // A rollback awaiting approval stands above the table with its approval, on every width.
        const pending = waiting.map(row => el('div', {class: 'zt-alert', role: 'note', 'data-pv-rollback': row.executionKey},
            el('span', {class: 'status-badge zt-chip', 'data-pv-rollback': row.status,
                text: PV.word('pv.rollback.status.' + row.status)}),
            el('div', {class: 'zt-item'},
                el('strong', {text: (row.from || '—') + ' → ' + (row.to || '—')}),
                el('span', {class: 'zt-muted', text: t('pv.rollback.pendingLine', row.actor || '—',
                    row.executedAt ? ZT.shortTime(row.executedAt) : '—', row.reason || '—')}),
                view.writable ? el('div', {class: 'pv-actions'}, PV.button(t('pv.rollback.approve'), 'fa-user-check',
                    async () => {
                        const answer = await PV.confirm({title: t('pv.rollback.approveConfirm'), rows: [
                            [t('pv.rollback.from'), row.from], [t('pv.rollback.to'), row.to],
                            [t('pv.rollback.by'), row.actor], [t('pv.confirm.reason'), row.reason]],
                        confirmLabel: t('pv.rollback.approve'), icon: 'fa-user-check'});
                        if (answer) {
                            await act('/rollback/' + encodeURIComponent(row.executionKey) + '/approve', {},
                                t('pv.rollback.approved'), t('pv.rollback.failed'));
                        }
                    }, {name: 'approve'})) : null)));
        const rows = el('tbody');
        view.rollbacks.slice(0, 20).forEach(row => {
            rows.append(el('tr', {},
                el('td', {class: 'zt-num', text: row.executedAt ? ZT.shortTime(row.executedAt) : '—'}),
                el('td', {class: 'zt-fill'}, el('div', {class: 'zt-item'},
                    el('span', {class: 'pv-cut', text: (row.from || '—') + ' → ' + (row.to || '—')}),
                    el('span', {class: 'zt-muted pv-cut pv-narrow', text: (row.actor || '—') + ' · '
                        + (row.approvedBy || '—')}),
                    el('span', {class: 'pv-narrow'}, el('span', {class: 'status-badge zt-chip',
                        'data-pv-rollback': row.status, text: PV.word('pv.rollback.status.' + row.status)})))),
                el('td', {class: 'pv-wide', text: row.actor || '—'}),
                el('td', {class: 'zt-cell-chips pv-wide'}, el('span', {class: 'status-badge zt-chip',
                    'data-pv-rollback': row.status, text: PV.word('pv.rollback.status.' + row.status)})),
                el('td', {class: 'pv-wide'}, el('span', {class: 'zt-muted', text: row.approvedBy || '—'}))));
        });
        return ZT.card(t('pv.rollback.title'), t('pv.rollback.waiting', ZT.count(waiting.length)),
            el('p', {class: 'zt-muted', text: t('pv.rollback.note')}),
            ...pending,
            el('div', {class: 'zt-filter-grid pv-form-grid'}, field(t('pv.rollback.to'), version)),
            el('div', {class: 'pv-actions'}, roll),
            view.rollbacks.length ? el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table modern-table'},
                el('thead', {}, el('tr', {}, ...['at', 'versions', 'actor', 'status', 'approval'].map(column =>
                    el('th', {scope: 'col', class: column === 'actor' || column === 'approval' || column === 'status'
                        ? 'pv-wide' : null, text: t('pv.rollback.column.' + column)})))), rows)) : null);
    }

    draw();
})(window);
