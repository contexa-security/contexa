/*
 * Prompt versions, a new version (plan 3.10, screen 3): the base's parts, the fixed ones folded and the others open to
 * change or delete; parts and reference blocks to add; prepared parts to put in; the checks before saving as the text
 * changes; and the save, with "use it for decisions at once" or a trial after it.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const PV = global.PV;
    const el = ZT.el;
    const t = ZT.t;
    const content = document.getElementById('zt-content');
    const CHECK_DELAY_MS = 600;

    /** What the operator did to the base: changes and deletions by part, additions, and the prepared parts put in. */
    const state = {draft: null, edits: {}, added: [], included: new Set(), title: '', description: '', checkTimer: null,
        checkRun: 0, lastCheck: null, saving: false};

    async function draw() {
        const params = PV.params();
        let draft;
        let list;
        try {
            [draft, list] = await Promise.all([PV.get('/draft', {base: params.get('base'), carry: params.get('carry')}),
                PV.get('')]);
        } catch (error) {
            content.replaceChildren(el('div', {class: 'pc-empty', role: 'alert'},
                el('i', {class: 'fas fa-exclamation-triangle', 'aria-hidden': 'true'}),
                el('p', {text: '— ' + t(error.status === 404 ? 'pv.new.noBase' : 'pv.ui.loadFailed')})));
            return;
        }
        state.draft = draft;
        carry(draft);
        PV.band(list, {page: PV.PAGES});
        document.getElementById('pv-crumbs').replaceChildren(el('a', {class: 'zt-link', href: PV.page(''),
            text: t('pv.ui.title.list')}), el('span', {class: 'zt-muted', text: ' › ' + t('pv.ui.title.new')}));
        document.getElementById('pv-question').textContent = t('pv.new.question', draft.baseName, draft.nextName);
        PV.toolbar();
        if (draft.baseFromDocument) {
            content.replaceChildren(el('div', {class: 'zt-alert', role: 'alert'},
                el('span', {class: 'status-badge zt-chip', 'data-status': 'BAD', text: t('pv.notice.bad')}),
                el('span', {text: t('pv.new.fromDocument', draft.baseName)})));
            return;
        }
        PV.fill(content,
            aboutCard(draft, list),
            draft.carried && draft.carried.length ? carriedNotice(draft) : null,
            systemCard(draft),
            userCard(draft),
            checkCard(),
            saveCard(draft));
        check();
    }

    /** Plan 3.3: the changes of the version in use, carried onto the newer base where it can take them. */
    function carry(draft) {
        (draft.carried || []).filter(change => change.movable).forEach(change => {
            if (change.action === 'ADD') {
                state.added.push({list: change.list, key: change.key, title: change.title || '', text: change.text || '',
                    addAfter: change.addAfter});
            } else if (change.action === 'INCLUDE') {
                state.included.add(change.key);
            } else {
                state.edits[change.list + ':' + change.key] = {action: change.action, title: change.title,
                    text: change.text};
            }
        });
    }

    function aboutCard(draft, list) {
        const title = el('input', {type: 'text', class: 'modern-input', id: 'pv-title-input', maxlength: '256',
            placeholder: t('pv.new.titlePlaceholder'), value: state.title});
        title.addEventListener('input', () => {
            state.title = title.value;
            scheduleCheck();
        });
        const description = el('textarea', {class: 'modern-input zt-textarea', id: 'pv-description', rows: '2',
            maxlength: '2000', placeholder: t('pv.new.descriptionPlaceholder')});
        description.value = state.description;
        description.addEventListener('input', () => {
            state.description = description.value;
        });
        const base = el('select', {class: 'modern-select', id: 'pv-base', 'aria-label': t('pv.new.base')});
        (list.versions || []).filter(row => !row.fromDocument && !row.hidden).forEach(row => {
            const option = el('option', {value: String(row.number), text: PV.versionLabel(row)});
            if (row.number === draft.base) {
                option.selected = true;
            }
            base.append(option);
        });
        base.addEventListener('change', async () => {
            if (changed()) {
                const answer = await PV.confirm({title: t('pv.new.baseChangeTitle'),
                    rows: [[t('pv.new.base'), base.options[base.selectedIndex].text]],
                    content: [el('p', {class: 'zt-muted', text: t('pv.new.baseChangeLine')})],
                    confirmLabel: t('pv.new.baseChange'), icon: 'fa-exchange-alt'});
                if (!answer) {
                    base.value = String(draft.base);
                    return;
                }
            }
            global.location.assign(PV.page('/new', {base: base.value}));
        });
        return ZT.card(t('pv.new.about'), null, el('div', {class: 'zt-filter-grid pv-form-grid'},
            el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.new.title')}), title),
            el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.new.base')}), base)),
        el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.new.description')}),
            description));
    }

    function carriedNotice(draft) {
        const moved = draft.carried.filter(change => change.movable);
        const left = draft.carried.filter(change => !change.movable);
        return el('div', {class: 'zt-alert', role: 'note', 'data-pv-notice': 'carried'},
            el('span', {class: 'status-badge zt-chip', 'data-status': left.length ? 'WARN' : 'GOOD',
                text: t('pv.new.carried')}),
            el('div', {class: 'zt-item'}, el('span', {text: t('pv.new.carriedLine', draft.carriedFrom, draft.baseName,
                ZT.count(moved.length), ZT.count(left.length))}),
            ...left.map(change => el('span', {class: 'zt-muted', text: t('pv.new.carriedLeft',
                PV.partName(change),
                PV.word('pv.mark.' + carriedMark(change.action)))}))));
    }

    function carriedMark(action) {
        return {CHANGE: 'CHANGED', DELETE: 'DELETED', ADD: 'ADDED', INCLUDE: 'INCLUDED'}[action] || 'CHANGED';
    }

    // ----- the system prompt -----

    function systemCard(draft) {
        const holder = el('div', {class: 'zt-stack', id: 'pv-system'});
        drawSystem(draft, holder);
        return ZT.card(t('pv.new.system'), t('pv.new.systemAside'), holder);
    }

    function drawSystem(draft, holder) {
        holder.replaceChildren();
        const list = el('ol', {class: 'pv-parts'});
        let run = [];
        const flush = () => {
            if (run.length) {
                list.append(lockedRun(run));
                run = [];
            }
        };
        draft.system.forEach((part, index) => {
            if (part.included) {
                flush();
                list.append(includedInBase(part, index + 1));
            } else if (!part.editable) {
                run.push({part, position: index + 1});
            } else {
                flush();
                list.append(editor('SYSTEM', part, index + 1));
            }
            state.added.filter(add => add.list === 'SYSTEM' && add.addAfter === part.key)
                .forEach(add => {
                    flush();
                    list.append(addedEditor(add, draft.systemPlaces, 'SYSTEM'));
                    appendAddedAfter(list, add, draft.systemPlaces, 'SYSTEM');
                });
            if (state.included.size && draft.prepared.some(prepared => state.included.has(prepared.key))
                    && index === lastJudgment(draft)) {
                flush();
                draft.prepared.filter(prepared => state.included.has(prepared.key))
                    .forEach(prepared => list.append(includedRow(prepared)));
            }
        });
        flush();
        holder.append(list, addBar('SYSTEM', draft.systemPlaces, draft), preparedBox(draft));
    }

    /** Added parts placed after another added part, in the order they were added. */
    function appendAddedAfter(list, add, places, kind) {
        state.added.filter(other => other.list === kind && other.addAfter === add.key).forEach(other => {
            list.append(addedEditor(other, places, kind));
            appendAddedAfter(list, other, places, kind);
        });
    }

    function lastJudgment(draft) {
        let last = 0;
        draft.system.forEach((part, index) => {
            if (part.group === 'judgment') {
                last = index;
            }
        });
        return last;
    }

    /** Plan 3.5: a prepared part the base put in stays in the next version unless it is taken out again. */
    function includedInBase(part, position) {
        const key = 'SYSTEM:' + part.key;
        const out = state.edits[key] && state.edits[key].action === 'DELETE';
        const details = el('details', {class: 'pv-part', 'data-pv-part': part.key, 'data-pv-mark': out ? 'DELETED' : 'INCLUDED'},
            // K106: the title and the summary lead the head, so the marks of the parts share one column
            el('summary', {class: 'pv-part-head'}, el('span', {class: 'pv-part-lead'},
                el('span', {class: 'pv-part-title pv-cut', text: position + ' ' + PV.partName(part)}),
                el('span', {class: 'zt-muted pv-part-summary', text: t(out ? 'pv.new.takenOut' : 'pv.new.includedInBase')})),
                el('span', {class: 'status-badge zt-chip pv-mark', 'data-pv-mark': out ? 'DELETED' : 'INCLUDED',
                    text: t(out ? 'pv.mark.DELETED' : 'pv.mark.INCLUDED')})));
        PV.fold(details, el('div', {class: 'pv-part-body'}, PV.textBox(part.text),
            el('div', {class: 'pv-actions'}, PV.button(out ? t('pv.new.putBack') : t('pv.new.takeOutNext'),
                out ? 'fa-undo' : 'fa-minus', () => {
                    if (out) {
                        delete state.edits[key];
                    } else {
                        state.edits[key] = {action: 'DELETE'};
                    }
                    redraw();
                }, {name: 'take-out'}))));
        return el('li', {}, details);
    }

    function lockedRun(run) {
        const user = run[0].part.list === 'USER';
        const format = !user && run.every(item => item.part.group !== 'judgment');
        const titles = run.map(item => item.position + ' ' + PV.partName(item.part)).join(' · ');
        const details = el('details', {class: 'pv-part', 'data-pv-mark': 'LOCKED'},
            el('summary', {class: 'pv-part-head'}, el('span', {class: 'pv-part-lead'},
                el('span', {class: 'pv-part-title pv-cut', text: titles}),
                el('span', {class: 'zt-muted pv-part-summary', text: t(user ? 'pv.version.lockedUser'
                    : format ? 'pv.version.lockedEnd' : 'pv.new.lockedRun')})),
                el('span', {class: 'status-badge zt-chip pv-mark', 'data-pv-mark': 'LOCKED', text: t('pv.mark.LOCKED')})));
        PV.fold(details, el('div', {class: 'pv-part-body'}, ...run.map(item => el('div', {class: 'zt-item'},
            el('strong', {text: item.position + ' ' + PV.partName(item.part) + (item.part.when ? ' · '
                + t('pv.mark.when') : '')}),
            item.part.items && item.part.items.length ? el('span', {class: 'zt-muted',
                text: t('pv.version.itemsSummary', ZT.count(item.part.items.length))}) : PV.textBox(item.part.text)))));
        return el('li', {}, details);
    }

    function editor(kind, part, position) {
        const key = kind + ':' + part.key;
        const edit = state.edits[key];
        const deleted = edit && edit.action === 'DELETE';
        const text = el('textarea', {class: 'modern-input zt-textarea pv-editor-text', rows: '5',
            'aria-label': PV.partName(part), disabled: deleted ? true : null});
        text.value = edit && edit.action === 'CHANGE' && edit.text != null ? edit.text : part.text || '';
        const chip = el('span', {class: 'status-badge zt-chip pv-mark'});
        const back = PV.button(t('pv.new.backToProduct'), 'fa-undo', () => {
            text.value = part.productText;
            update();
        }, {name: 'product-default'});
        const remove = PV.button(deleted ? t('pv.new.restore') : t('pv.new.delete'), deleted ? 'fa-trash-restore'
            : 'fa-trash', () => {
            if (state.edits[key] && state.edits[key].action === 'DELETE') {
                delete state.edits[key];
            } else {
                state.edits[key] = {action: 'DELETE'};
            }
            redraw();
        }, {name: 'delete-part'});
        const update = () => {
            if (text.value === (part.text || '')) {
                delete state.edits[key];
            } else {
                state.edits[key] = {action: 'CHANGE', text: text.value};
            }
            paint();
            scheduleCheck();
        };
        const paint = () => {
            const current = state.edits[key];
            const code = !current ? 'SAME' : current.action === 'DELETE' ? 'DELETED' : 'CHANGED';
            chip.dataset.pvMark = code;
            chip.textContent = t('pv.mark.' + code);
            back.hidden = !part.productText || text.value === part.productText || deleted;
        };
        text.addEventListener('input', update);
        paint();
        return el('li', {}, el('div', {class: 'pv-editor', 'data-pv-part': part.key},
            el('div', {class: 'pv-part-head'}, el('span', {class: 'pv-part-title pv-cut',
                text: position + ' ' + PV.partName(part)}), chip,
            el('div', {class: 'pv-actions'}, back, remove)),
            deleted ? el('p', {class: 'zt-muted', text: t('pv.new.deletedLine')}) : text));
    }

    function addedEditor(add, places, kind) {
        const title = el('input', {type: 'text', class: 'modern-input', maxlength: '256', value: add.title,
            placeholder: t(kind === 'SYSTEM' ? 'pv.new.addedTitle' : 'pv.new.blockTitle'), 'aria-label': t('pv.new.addedTitleLabel')});
        const text = el('textarea', {class: 'modern-input zt-textarea pv-editor-text', rows: '4',
            placeholder: t('pv.new.addedText'), 'aria-label': t('pv.new.addedTextLabel')});
        text.value = add.text;
        const place = placeSelect(places, add.addAfter, kind, add.key);
        title.addEventListener('input', () => {
            add.title = title.value;
            scheduleCheck();
        });
        text.addEventListener('input', () => {
            add.text = text.value;
            scheduleCheck();
        });
        place.addEventListener('change', () => {
            add.addAfter = place.value;
            redraw();
        });
        return el('li', {}, el('div', {class: 'pv-editor', 'data-pv-part': add.key, 'data-pv-mark': 'ADDED'},
            el('div', {class: 'pv-part-head'}, el('span', {class: 'pv-part-title', text: t(kind === 'SYSTEM'
                ? 'pv.new.addedPart' : 'pv.new.addedBlock')}),
            el('span', {class: 'status-badge zt-chip pv-mark', 'data-pv-mark': 'ADDED', text: t('pv.mark.ADDED')}),
            el('div', {class: 'pv-actions'}, PV.button(t('pv.new.delete'), 'fa-trash', () => {
                state.added = state.added.filter(other => other !== add);
                state.added.filter(other => other.addAfter === add.key).forEach(other => {
                    other.addAfter = add.addAfter;
                });
                redraw();
            }, {name: 'delete-added'}))),
        el('div', {class: 'zt-filter-grid pv-form-grid'},
            el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.new.addedTitleLabel')}),
                title),
            el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.new.place')}), place)),
        text));
    }

    function placeSelect(places, selected, kind, self) {
        const select = el('select', {class: 'modern-select', 'aria-label': t('pv.new.place')});
        const parts = kind === 'SYSTEM' ? state.draft.system : state.draft.user;
        const names = {};
        parts.forEach((part, index) => {
            names[part.key] = (index + 1) + ' ' + PV.partName(part);
        });
        places.forEach(key => select.append(el('option', {value: key, selected: key === selected ? true : null,
            text: t('pv.new.after', names[key] || key)})));
        state.added.filter(add => add.list === kind && add.key !== self).forEach(add => select.append(el('option', {
            value: add.key, selected: add.key === selected ? true : null,
            text: t('pv.new.after', add.title || t('pv.new.addedPart'))})));
        return select;
    }

    function addBar(kind, places, draft) {
        const place = placeSelect(places, places[places.length - 1], kind, null);
        return el('div', {class: 'pv-add-bar'},
            PV.button(t(kind === 'SYSTEM' ? 'pv.new.addPart' : 'pv.new.addBlock'), 'fa-plus', () => {
                state.added.push({list: kind, key: newKey(kind), title: '', text: '', addAfter: place.value});
                redraw();
            }, {name: kind === 'SYSTEM' ? 'add-part' : 'add-block'}),
            el('label', {class: 'zt-filter-field pv-inline'}, el('span', {class: 'zt-filter-name', text: t('pv.new.place')}),
                place),
            el('span', {class: 'zt-muted', text: t(kind === 'SYSTEM' ? 'pv.new.addPartNote' : 'pv.new.addBlockNote')}));
    }

    function newKey(kind) {
        const taken = new Set([...state.draft.system, ...state.draft.user].map(part => part.key)
            .concat(state.added.map(add => add.key)));
        let index = 1;
        while (taken.has((kind === 'SYSTEM' ? 'org-part-' : 'org-block-') + index)) {
            index++;
        }
        return (kind === 'SYSTEM' ? 'org-part-' : 'org-block-') + index;
    }

    /** Plan 3.5 (decision D6): the parts Contexa prepared and leaves out, with what their measurement found. */
    function preparedBox(draft) {
        if (!draft.prepared || !draft.prepared.length) {
            return null;
        }
        const rows = draft.prepared.map(prepared => {
            const included = state.included.has(prepared.key);
            const measured = PV.word('pv.prepared.measured.' + prepared.key, '');
            return el('div', {class: 'zt-alert', role: 'note', 'data-pv-prepared': prepared.key},
                el('span', {class: 'status-badge zt-chip', 'data-status': PV.word('pv.prepared.tone.' + prepared.key,
                    'WARN'), text: PV.word('pv.prepared.verdict.' + prepared.key, t('pv.prepared.verdict'))}),
                el('div', {class: 'zt-item'}, el('strong', {text: PV.partName(prepared)}),
                measured ? el('span', {class: 'zt-muted', text: measured}) : null,
                el('div', {class: 'pv-actions'}, PV.button(included ? t('pv.new.takeOut') : t('pv.new.putIn'),
                    included ? 'fa-minus' : 'fa-plus', () => {
                        if (included) {
                            state.included.delete(prepared.key);
                        } else {
                            state.included.add(prepared.key);
                        }
                        redraw();
                    }, {name: 'prepared'}))));
        });
        return PV.fold(el('details', {class: 'pv-prepared'}, el('summary', {class: 'zt-link',
            text: t('pv.new.prepared', ZT.count(draft.prepared.length))})), el('div', {class: 'zt-stack'}, ...rows));
    }

    function includedRow(prepared) {
        return el('li', {}, el('div', {class: 'pv-editor', 'data-pv-part': prepared.key, 'data-pv-mark': 'INCLUDED'},
            el('div', {class: 'pv-part-head'}, el('span', {class: 'pv-part-title pv-cut', text: PV.partName(prepared)}),
                el('span', {class: 'status-badge zt-chip pv-mark', 'data-pv-mark': 'INCLUDED', text: t('pv.mark.INCLUDED')}),
                el('div', {class: 'pv-actions'}, PV.button(t('pv.new.takeOut'), 'fa-minus', () => {
                    state.included.delete(prepared.key);
                    redraw();
                }, {name: 'take-out'}))),
            PV.textBox(prepared.text)));
    }

    // ----- the user prompt -----

    function userCard(draft) {
        const holder = el('div', {class: 'zt-stack', id: 'pv-user'});
        drawUser(draft, holder);
        return ZT.card(t('pv.new.user'), t('pv.new.userAside'), holder);
    }

    function drawUser(draft, holder) {
        holder.replaceChildren();
        const list = el('ol', {class: 'pv-parts'});
        let run = [];
        const flush = () => {
            if (run.length) {
                list.append(lockedRun(run));
                run = [];
            }
        };
        draft.user.forEach((part, index) => {
            if (part.editable) {
                flush();
                list.append(editor('USER', part, index + 1));
            } else {
                run.push({part, position: index + 1});
            }
            state.added.filter(add => add.list === 'USER' && add.addAfter === part.key).forEach(add => {
                flush();
                list.append(addedEditor(add, draft.userPlaces, 'USER'));
                appendAddedAfter(list, add, draft.userPlaces, 'USER');
            });
        });
        flush();
        holder.append(list, addBar('USER', draft.userPlaces, draft));
    }

    function redraw() {
        drawSystem(state.draft, document.getElementById('pv-system'));
        drawUser(state.draft, document.getElementById('pv-user'));
        scheduleCheck();
    }

    // ----- the checks before saving -----

    function form(extra) {
        const parts = kind => {
            const list = [];
            Object.entries(state.edits).filter(([key]) => key.startsWith(kind + ':')).forEach(([key, edit]) => {
                list.push({key: key.slice(kind.length + 1), action: edit.action,
                    title: edit.action === 'CHANGE' ? edit.title || null : null,
                    text: edit.action === 'CHANGE' ? edit.text : null, addAfter: null});
            });
            state.added.filter(add => add.list === kind).forEach(add => list.push({key: add.key, action: 'ADD',
                title: add.title, text: add.text, addAfter: add.addAfter}));
            if (kind === 'SYSTEM') {
                state.included.forEach(key => list.push({key, action: 'INCLUDE', title: null, text: null, addAfter: null}));
            }
            return list;
        };
        return Object.assign({prompt: state.draft.prompt, base: state.draft.base, title: state.title,
            description: state.description, system: parts('SYSTEM'), user: parts('USER')}, extra || {});
    }

    function changed() {
        return Object.keys(state.edits).length > 0 || state.added.length > 0 || state.included.size > 0;
    }

    function scheduleCheck() {
        global.clearTimeout(state.checkTimer);
        state.checkTimer = global.setTimeout(check, CHECK_DELAY_MS);
    }

    async function check() {
        const run = ++state.checkRun;
        const result = await PV.send('/check', form());
        if (run !== state.checkRun) {
            return;
        }
        state.lastCheck = result.ok ? result.body : null;
        drawCheck(result);
    }

    function checkCard() {
        return ZT.card(t('pv.new.check'), t('pv.new.checkAside'), el('div', {class: 'zt-stack', id: 'pv-check'},
            el('p', {class: 'zt-muted', text: t('pv.new.checking')})));
    }

    function drawCheck(result) {
        const holder = document.getElementById('pv-check');
        if (!holder) {
            return;
        }
        if (!result.ok) {
            holder.replaceChildren(el('div', {class: 'zt-alert', role: 'alert'},
                el('span', {class: 'status-badge zt-chip', 'data-status': 'BAD', text: t('pv.notice.bad')}),
                el('div', {class: 'zt-item'}, ...PV.refusedLines(result).map(line => el('span', {text: line})))));
            paintSave();
            return;
        }
        const view = result.body;
        // Without the model's context the length cannot be checked: the row says so instead of passing.
        const rows = view.checks.map(row => {
            const unknown = row.key === 'LENGTH' && view.contextTokens == null;
            return el('div', {class: 'zt-result-row', 'data-pv-check': row.key},
                el('span', {class: 'zt-result-name', text: unknown ? t('pv.check.LENGTH.unknown')
                    : t('pv.check.' + row.key, ZT.count(view.contextTokens))}),
                el('span', {class: 'status-badge zt-chip', 'data-status': unknown ? 'WARN' : row.passed ? 'GOOD' : 'BAD',
                    text: t(unknown ? 'pv.check.unknown' : row.passed ? 'pv.check.passed' : 'pv.check.failed')}));
        });
        // K64: the size counts the blocks added to the user prompt with the system prompt.
        const delta = view.systemTokens + (view.addedUserTokens || 0)
            - view.baseSystemTokens - (view.baseAddedUserTokens || 0);
        rows.push(el('div', {class: 'zt-result-row', 'data-pv-check': 'SIZE'},
            el('span', {class: 'zt-result-name', text: t('pv.check.size', state.draft.baseName,
                PV.signed(delta, value => PV.tokens(value)), view.estimatedDeltaMs == null ? '—'
                    : PV.signed(view.estimatedDeltaMs, value => ZT.seconds(value)))}),
            el('span', {class: 'status-badge zt-chip', 'data-status': 'WARN', text: t('pv.check.note')})));
        PV.fill(holder, el('div', {class: 'zt-result-rows'}, ...rows),
            view.problems.length ? el('div', {class: 'zt-alert', role: 'alert'},
                el('span', {class: 'status-badge zt-chip', 'data-status': 'BAD', text: t('pv.check.problems',
                    ZT.count(view.problems.length))}),
                el('div', {class: 'zt-item'}, ...view.problems.map(problem => el('span', {text: PV.problemText(problem)}))))
                : null,
            state.draft.decisionPrompt ? el('p', {class: 'zt-muted', text: t('pv.check.trialAdvice')}) : null);
        paintSave();
    }

    // ----- the save -----

    function saveCard(draft) {
        const useNow = el('input', {type: 'checkbox', id: 'pv-use-now'});
        const reason = el('input', {type: 'text', class: 'modern-input', id: 'pv-use-reason', maxlength: '1000',
            placeholder: t('pv.confirm.reasonOptional'), disabled: true});
        useNow.addEventListener('change', () => {
            reason.disabled = !useNow.checked;
        });
        const save = PV.button(t('pv.new.save'), 'fa-save', () => submit('view'), {primary: true, name: 'save'});
        const saveTrial = draft.decisionPrompt ? PV.button(t('pv.new.saveTrial'), 'fa-vial', () => submit('trial'),
            {name: 'save-trial'}) : null;
        const cancel = PV.button(t('pv.new.cancel'), null, null, {href: PV.page(''), name: 'cancel'});
        return ZT.card(t('pv.new.saveTitle'), null,
            el('label', {class: 'pv-toggle'}, useNow, el('span', {text: t(draft.decisionPrompt ? 'pv.new.useNow'
                : 'pv.new.useNow.other')})),
            el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.confirm.reasonLabel')}),
                reason),
            el('div', {class: 'pv-actions', id: 'pv-save-actions'}, save, saveTrial, cancel));
    }

    function paintSave() {
        const ready = state.lastCheck && state.lastCheck.passed && changed() && !state.saving;
        document.querySelectorAll('#pv-save-actions [data-pv-action="save"], #pv-save-actions [data-pv-action="save-trial"]')
            .forEach(node => {
                node.disabled = !ready;
                node.title = ready ? '' : changed() ? t('pv.new.saveBlocked') : t('pv.new.nothingChanged');
            });
    }

    async function submit(next) {
        if (state.saving) {
            return;
        }
        state.saving = true;
        paintSave();
        const useNow = document.getElementById('pv-use-now').checked;
        const result = await PV.send('', form({useNow, reason: document.getElementById('pv-use-reason').value}));
        state.saving = false;
        if (!result.ok) {
            PV.notice('bad', t('pv.new.saveFailed'), PV.refusedLines(result));
            paintSave();
            return;
        }
        const saved = result.body;
        if (saved.used && !saved.used.applied) {
            PV.notice('bad', t('pv.new.savedNotUsed', saved.name), (saved.used.blockers || []).map(PV.blockerText));
            return;
        }
        global.location.assign(next === 'trial' ? PV.page('/trials', {candidate: saved.number})
            : PV.page('/' + saved.number, {saved: '1'}));
    }

    draw();
})(window);
