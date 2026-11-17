/*
 * Prompt version screens (plan 3.10): what the five screens share, on top of the Zero Trust console's components
 * (window.ZT). The prompt and the scope travel in the address, so a link keeps them; every change is a POST with the
 * console's CSRF header; a code the server sends is shown in the reader's words, never as it is.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const el = ZT.el;
    const t = ZT.t;
    const root = document.getElementById('zt-console');
    const API = root ? root.dataset.apiBase : '/contexa/admin/api/prompt-quality/versions';
    const PAGES = root ? root.dataset.pagesBase : '/contexa/admin/prompt-quality/versions';
    const KEPT = ['prompt', 'scope'];
    const ACTIONS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];

    function params() {
        return new URLSearchParams(global.location.search);
    }

    /** The parameters every link and call keeps (the prompt and the scope), with the extra ones. */
    function kept(extra) {
        const current = params();
        const next = new URLSearchParams();
        KEPT.forEach(name => {
            if (current.get(name)) {
                next.set(name, current.get(name));
            }
        });
        Object.entries(extra || {}).forEach(([name, value]) => {
            if (value == null || value === '') {
                next.delete(name);
            } else {
                next.set(name, value);
            }
        });
        const search = next.toString();
        return search ? '?' + search : '';
    }

    function page(path, extra) {
        return PAGES + (path || '') + kept(extra);
    }

    function api(path, extra) {
        return API + (path || '') + kept(extra);
    }

    async function get(path, extra) {
        const response = await fetch(api(path, extra), {headers: {Accept: 'application/json'},
            credentials: 'same-origin'});
        if (!response.ok) {
            const error = new Error(String(response.status));
            error.status = response.status;
            throw error;
        }
        return response.json();
    }

    /** A POST of the screens: {ok, status, body}; a body the server could not give is null. */
    async function send(path, body, extra) {
        const headers = {'Content-Type': 'application/json', Accept: 'application/json'};
        if (root && root.dataset.csrfToken) {
            headers[root.dataset.csrfHeader || 'X-CSRF-TOKEN'] = root.dataset.csrfToken;
        }
        const response = await fetch(api(path, extra), {method: 'POST', headers, credentials: 'same-origin',
            body: JSON.stringify(body == null ? {} : body)});
        const text = await response.text();
        let parsed = null;
        try {
            parsed = text ? JSON.parse(text) : null;
        } catch (unreadable) {
            parsed = null;
        }
        return {ok: response.ok, status: response.status, body: parsed};
    }

    // ----- words -----

    /** A message, or the fallback when the screens have none for the key (a code is never shown as it is). */
    function word(key, fallback, ...args) {
        const text = t(key, ...args);
        return text === key ? (fallback != null ? fallback : t('pv.ui.unknown')) : text;
    }

    function promptName(key) {
        return word('pv.prompt.' + key, t('pv.prompt.other'));
    }

    function stateText(state, decision) {
        return word('pv.state.' + state + (decision || state !== 'USED' ? '' : '.other'));
    }

    function stateChip(state, decision) {
        return el('span', {class: 'status-badge zt-chip', 'data-pv-state': state, text: stateText(state, decision)});
    }

    function useLabel(decision) {
        return t(decision ? 'pv.action.use' : 'pv.action.use.other');
    }

    function actionName(action) {
        return action ? word('zt.console.ui.action.' + action, t('pv.ui.unknown')) : t('pv.trial.noAnswer');
    }

    /** Where a version came from: Contexa or the organization, the screen, a document's name or the installation. */
    function origin(row) {
        if (row.provider === 'CONTEXA') {
            return t('pv.origin.contexa');
        }
        if (row.origin === 'FOLDER') {
            return t('pv.origin.folder', row.originName || '');
        }
        if (row.origin === 'IMPORT') {
            return t('pv.origin.import', row.originName || '');
        }
        return t('pv.origin.screen');
    }

    /** Who made a version: the person, the document folder, or the installation. */
    function maker(row) {
        if (row.provider === 'CONTEXA') {
            return t('pv.maker.install');
        }
        if (row.origin === 'FOLDER') {
            return t('pv.maker.folder');
        }
        return row.createdBy || '—';
    }

    /** A part's name in the reader's words: Contexa's parts by their key, an added part by the title it was given. */
    function partName(part) {
        return word('pv.part.' + part.key, part.title || t('pv.part.untitled'));
    }

    function versionLabel(row) {
        return row ? row.name + (row.title && row.title !== row.name ? ' · ' + row.title : '') : '—';
    }

    function problemText(problem) {
        return word('pv.problem.' + problem.code, t('pv.problem.other'), problem.where || '', problem.detail || '');
    }

    /** A code of the release gate or of a rollback, before any detail it carries. */
    function codeOf(value) {
        return String(value == null ? '' : value).split(/[:\s]/)[0];
    }

    function blockerText(blocker) {
        return word('pv.blocker.' + codeOf(blocker), t('pv.blocker.other', String(blocker)));
    }

    function refusalText(code) {
        return word('pv.refusal.' + codeOf(code), t('pv.refusal.other'));
    }

    /** What a refused POST answered, as sentences: its problems, its blockers, its refusals or its code. */
    function refusedLines(result) {
        const body = result && result.body ? result.body : {};
        if (Array.isArray(body.problems) && body.problems.length) {
            return body.problems.map(problemText);
        }
        if (Array.isArray(body.blockers) && body.blockers.length) {
            return body.blockers.map(blockerText);
        }
        if (Array.isArray(body.refusals) && body.refusals.length) {
            return body.refusals.map(refusalText);
        }
        if (body.code) {
            return [word('pv.refused.' + body.code, t('pv.refused.other'))];
        }
        if (result && result.status === 403) {
            return [t('pv.refused.FORBIDDEN')];
        }
        return [t('pv.refused.other')];
    }

    // ----- the band: the prompt and the scope -----

    /**
     * The choice of the prompt and, with two scopes or more, of the scope, in the filter box; changing one opens the
     * screen again on it.
     */
    function band(view, options) {
        const box = document.getElementById('pv-band');
        if (!box || !view) {
            return;
        }
        box.replaceChildren();
        const promptSelect = el('select', {class: 'modern-select', id: 'pv-prompt', 'aria-label': t('pv.ui.prompt')});
        (view.prompts || []).forEach(choice => {
            const option = el('option', {value: choice.key, text: promptName(choice.key)});
            if (choice.key === view.prompt) {
                option.selected = true;
            }
            promptSelect.append(option);
        });
        promptSelect.addEventListener('change', () => go({prompt: promptSelect.value}, options));
        box.append(el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.ui.prompt')}),
            promptSelect));
        if ((view.scopes || []).length > 1) {
            const scopeSelect = el('select', {class: 'modern-select', id: 'pv-scope', 'aria-label': t('pv.ui.scope')});
            view.scopes.forEach(name => {
                const option = el('option', {value: name, text: name === 'PLATFORM_GLOBAL' ? t('pv.ui.scope.platform')
                    : name});
                if (name === view.scope) {
                    option.selected = true;
                }
                scopeSelect.append(option);
            });
            scopeSelect.addEventListener('change', () => go({scope: scopeSelect.value}, options));
            box.append(el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: t('pv.ui.scope')}),
                scopeSelect));
        }
        if (options && options.note) {
            box.append(el('span', {class: 'zt-band-info', title: options.note, tabindex: '0', role: 'note',
                'aria-label': options.note}, el('i', {class: 'fas fa-info-circle', 'aria-hidden': 'true'})));
        }
        tabs(view);
    }

    function go(change, options) {
        const target = options && options.page ? options.page : global.location.pathname;
        const current = params();
        Object.entries(change).forEach(([name, value]) => current.set(name, value));
        if (change.prompt) {
            current.delete('scope');
        }
        global.location.assign(target + '?' + current.toString());
    }

    /**
     * The tab bar keeps the prompt and the scope; the trials are the security decision's (plan 3.11), the advanced
     * screen holds the folder, the documents and the history of every prompt.
     */
    function tabs(view) {
        document.querySelectorAll('a[data-pv-tab]').forEach(link => {
            const target = new URL(link.getAttribute('href'), global.location.origin);
            link.setAttribute('href', target.pathname + kept());
            const only = link.dataset.pvTab === 'trials';
            link.hidden = only && view && view.decisionPrompt === false;
            // The version list tab counts the versions shown, as the policy center's tabs count theirs.
            if (link.dataset.pvTab === 'list' && view && view.counts) {
                let count = link.querySelector('.tab-count');
                if (!count) {
                    count = el('span', {class: 'tab-count'});
                    link.append(count);
                }
                count.textContent = ZT.count(view.counts.total);
            }
        });
    }

    /**
     * Plan 1.0: the rows of a list 20 a page, with the previous and next buttons of the decision records below the
     * table; the foot shows only when there is more than one page.
     */
    function paged(rows, drawRow, size) {
        const step = size || 20;
        const body = el('tbody');
        const previous = el('button', {type: 'button', class: 'modern-btn-secondary'},
            el('i', {class: 'fas fa-chevron-left', 'aria-hidden': 'true'}), t('pv.ui.previous'));
        const next = el('button', {type: 'button', class: 'modern-btn-secondary'},
            t('pv.ui.next'), el('i', {class: 'fas fa-chevron-right', 'aria-hidden': 'true'}));
        const page = el('span', {class: 'zt-muted'});
        const foot = el('div', {class: 'zt-card-foot'}, previous, next, page);
        let first = 0;
        const show = () => {
            body.replaceChildren(...rows.slice(first, first + step).map(drawRow));
            previous.disabled = first === 0;
            next.disabled = first + step >= rows.length;
            page.textContent = t('pv.ui.page', ZT.count(first + 1), ZT.count(Math.min(first + step, rows.length)),
                ZT.count(rows.length));
        };
        previous.addEventListener('click', () => {
            first = Math.max(0, first - step);
            show();
        });
        next.addEventListener('click', () => {
            if (first + step < rows.length) {
                first += step;
                show();
            }
        });
        show();
        foot.hidden = rows.length <= step;
        return {body, foot};
    }

    // ----- the toolbar, the notices, the confirmation -----

    function toolbar(...nodes) {
        const box = root ? root.querySelector('.zt-toolbar') : null;
        if (box) {
            box.replaceChildren(...nodes.filter(Boolean));
        }
    }

    function button(label, icon, onClick, options = {}) {
        const node = el(options.href ? 'a' : 'button', {type: options.href ? null : 'button',
            class: options.primary ? 'modern-btn-primary' : 'modern-btn-secondary', href: options.href || null,
            disabled: options.disabled ? true : null, title: options.title || null, 'data-pv-action': options.name || null},
        icon ? el('i', {class: 'fas ' + icon, 'aria-hidden': 'true'}) : null, el('span', {text: label}));
        if (onClick && !options.href) {
            node.addEventListener('click', onClick);
        }
        return node;
    }

    /** A notice above the screen: done (good), refused (bad) or a note; its lines under its title. */
    function notice(kind, title, lines) {
        const box = document.getElementById('pv-notice');
        if (!box) {
            return;
        }
        const node = el('div', {class: 'zt-alert', role: kind === 'bad' ? 'alert' : 'status', 'data-pv-notice': kind},
            el('span', {class: 'status-badge zt-chip', 'data-status': kind === 'good' ? 'GOOD' : kind === 'bad' ? 'BAD'
                : 'WARN', text: t('pv.notice.' + kind)}),
            el('div', {class: 'zt-item'}, el('strong', {text: title}),
                ...(lines || []).map(line => el('span', {class: 'zt-muted', text: line}))));
        box.replaceChildren(node);
        node.scrollIntoView({block: 'nearest'});
    }

    function clearNotice() {
        const box = document.getElementById('pv-notice');
        if (box) {
            box.replaceChildren();
        }
    }

    /**
     * The confirmation of the admin console (the policy center's): a title, rows of label and value, more content,
     * an optional reason (required when options.reasonRequired), and the confirm and cancel buttons. Resolves to
     * {reason} on confirm, null on cancel.
     */
    function confirm(options) {
        const overlay = document.getElementById('pv-confirm-overlay');
        const modal = overlay ? overlay.querySelector('.ai-confirm-modal') : null;
        if (!overlay || !modal) {
            return Promise.resolve(global.confirm(options.title) ? {reason: ''} : null);
        }
        return new Promise(resolve => {
            const close = value => {
                overlay.classList.add('hidden');
                modal.replaceChildren();
                document.removeEventListener('keydown', escape);
                resolve(value);
            };
            const escape = event => {
                if (event.key === 'Escape') {
                    close(null);
                }
            };
            const rows = el('div', {class: 'ai-confirm-summary'}, ...(options.rows || []).map(([label, value]) =>
                el('div', {class: 'ai-confirm-row'}, el('span', {class: 'ai-confirm-label', text: label}),
                    el('span', {class: 'ai-confirm-value', text: value == null ? '—' : String(value)}))));
            let reason = null;
            if (options.reason) {
                reason = el('textarea', {class: 'modern-input zt-textarea', id: 'pv-confirm-reason', rows: '2',
                    maxlength: '1000', placeholder: options.reasonRequired ? t('pv.confirm.reasonRequired')
                        : t('pv.confirm.reasonOptional')});
            }
            const confirmButton = button(options.confirmLabel || t('pv.confirm.ok'), options.icon || 'fa-check-circle',
                () => {
                    const text = reason ? reason.value.trim() : '';
                    if (options.reasonRequired && !text) {
                        reason.focus();
                        reason.setAttribute('aria-invalid', 'true');
                        return;
                    }
                    close({reason: text});
                }, {primary: true, name: 'confirm'});
            modal.replaceChildren(
                el('button', {type: 'button', class: 'modal-close-x', 'aria-label': t('pv.confirm.cancel'), text: '×'}),
                el('h4', {class: 'pv-confirm-title', id: 'pv-confirm-title', text: options.title}),
                rows, ...(options.content || []),
                reason ? el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name',
                    text: options.reasonRequired ? t('pv.confirm.reason') : t('pv.confirm.reasonLabel')}), reason) : null,
                el('div', {class: 'ai-confirm-actions'}, confirmButton,
                    button(t('pv.confirm.cancel'), null, () => close(null), {name: 'cancel'})));
            modal.querySelector('.modal-close-x').addEventListener('click', () => close(null));
            overlay.setAttribute('aria-labelledby', 'pv-confirm-title');
            overlay.classList.remove('hidden');
            document.addEventListener('keydown', escape);
            (reason || confirmButton).focus();
        });
    }

    // ----- "use for decisions", shared by the list, a version and a trial -----

    /** The confirmation of using a version (plan 3.4), with the gate's answer and the latest trial, then the move. */
    async function useVersion(number, decision, after) {
        let check;
        try {
            check = await get('/' + number + '/use-check');
        } catch (error) {
            notice('bad', t('pv.use.failed'), [t('pv.ui.loadFailed')]);
            return;
        }
        const content = [];
        if (!check.ready && check.blockers && check.blockers.length) {
            content.push(el('div', {class: 'zt-alert', role: 'note'}, el('span', {class: 'status-badge zt-chip',
                'data-status': 'BAD', text: t('pv.use.blocked')}), el('div', {class: 'zt-item'},
                ...check.blockers.map(blocker => el('span', {text: blockerText(blocker)})))));
        }
        if (decision) {
            const trial = check.latestTrial;
            content.push(el('div', {class: 'zt-alert', role: 'note'}, el('span', {class: 'status-badge zt-chip',
                'data-status': trial ? 'GOOD' : 'WARN', text: t(trial ? 'pv.use.trialDone' : 'pv.use.noTrial')}),
            el('span', {text: trial ? t('pv.use.trialLine', trial.referenceName, ZT.time(trial.finishedAt),
                ZT.count(trial.actual)) : t('pv.use.trialAdvice')})));
        }
        const answer = await confirm({
            title: t(decision ? 'pv.use.title' : 'pv.use.title.other', check.version),
            rows: [[t('pv.use.now'), check.current || '—'], [t('pv.use.next'), check.version],
                [t('pv.use.reflect'), t('pv.use.reflectValue')]],
            content, reason: true, confirmLabel: useLabel(decision), icon: 'fa-check-circle'
        });
        if (!answer) {
            return;
        }
        const result = await send('/' + number + '/use', {reason: answer.reason});
        if (result.ok) {
            notice('good', t('pv.use.done', check.version), [t('pv.use.reflectValue')]);
        } else {
            notice('bad', t('pv.use.failed'), refusedLines(result));
        }
        if (after) {
            after(result);
        }
    }

    // ----- small parts -----

    /** Puts the children in the node in place of what it held; an absent child (null, false) is left out. */
    function fill(node, ...children) {
        node.replaceChildren(...children.flat().filter(child => child != null && child !== false));
        return node;
    }

    /**
     * A folding part: its body is out of the page until it is opened, as a closed details still lays its content out
     * in some browsers; it comes back each time the part opens.
     */
    function fold(details, body) {
        body.hidden = !details.open;
        details.addEventListener('toggle', () => {
            body.hidden = !details.open;
        });
        details.append(body);
        return details;
    }

    /** The decisions per action as the console's 100% stacked bar, with a row per action. */
    function actionBar(actions, total) {
        const parts = ACTIONS.map(action => ({label: actionName(action), count: (actions || {})[action] || 0,
            color: ZT.COLORS[action]}));
        return el('div', {class: 'zt-stack pv-actions-bar'}, ZT.stacked(parts),
            ZT.valueRows(parts.map(part => ({label: part.label, color: part.color,
                value: ZT.count(part.count) + ' · ' + ZT.percent(total ? part.count / total : null, 0)}))));
    }

    /** A text of the prompt as it is: kept whole, wrapped, in the console's monospace box. */
    function textBox(text, label) {
        return el('pre', {class: 'pv-text', tabindex: '0', 'aria-label': label || null, text: text == null ? '' : text});
    }

    function tokens(value) {
        return value == null ? '—' : t('pv.unit.tokens', ZT.count(value));
    }

    function signed(value, unit) {
        if (value == null) {
            return '—';
        }
        const sign = value > 0 ? '+' : value < 0 ? '−' : '±';
        return sign + unit(Math.abs(value));
    }

    global.PV = {
        API, PAGES, ACTIONS, params, page, api, get, send, word, promptName, stateText, stateChip, useLabel, actionName,
        origin, maker, partName, versionLabel, problemText, blockerText, refusalText, refusedLines, band, tabs, toolbar, button,
        notice, clearNotice, confirm, useVersion, fill, fold, actionBar, textBox, tokens, signed, paged
    };
})(window);
