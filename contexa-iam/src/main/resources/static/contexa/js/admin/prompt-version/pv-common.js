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
    /** Measure and compare (quality plan 3.8), where the trials moved: a version is measured and compared there. */
    const MEASURE = root && root.dataset.measureBase ? root.dataset.measureBase
        : '/contexa/admin/prompt-quality/measure';
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

    /** A page of measure and compare, with the prompt and the scope kept as the version screens keep them. */
    function measurePage(path, extra) {
        return MEASURE + (path || '') + kept(extra);
    }

    /** The number of a version by its name (v3.0 is 3); null for a name that is no version's. */
    function numberOf(name) {
        const match = /^v(\d+)(?:\.|$)/.exec(String(name == null ? '' : name));
        return match ? Number(match[1]) : null;
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
     * Quality plan 3.8: the menu bar of the prompt quality assurance group stands where the version screens' tabs
     * stood. The server keeps the scope on its links; the menu of the versions keeps the prompt too, so it opens the
     * versions of the prompt the screen shows. The bar's counts are the server's, the same on every screen of the group.
     */
    function tabs() {
        const own = document.querySelector('a[data-pqa-tab="versions"]');
        if (own) {
            own.setAttribute('href', PAGES + kept());
        }
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
     * The confirmation of the admin console (the policy center's): a title, rows of label and value (a third value is
     * the row's tooltip), more content, an optional box to tick before confirming (options.check: its label and what
     * to say when it is not ticked), an optional reason (required when options.reasonRequired, with what to say when it
     * is left blank), and the confirm and cancel buttons. Resolves to {reason} on confirm, null on cancel.
     */
    function confirm(options) {
        const overlay = confirmOverlay();
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
            const rows = el('div', {class: 'ai-confirm-summary'}, ...(options.rows || []).map(([label, value, tip]) =>
                el('div', {class: 'ai-confirm-row'}, el('span', {class: 'ai-confirm-label', text: label}),
                    el('span', {class: 'ai-confirm-value'}, value == null ? '—' : String(value),
                        tip ? el('span', {class: 'zt-band-info ml-2', title: tip, tabindex: '0', role: 'note',
                            'aria-label': tip}, el('i', {class: 'fas fa-info-circle', 'aria-hidden': 'true'}))
                            : null))));
            let ticked = null;
            if (options.check) {
                ticked = el('input', {type: 'checkbox', id: 'pv-confirm-check'});
            }
            let reason = null;
            if (options.reason) {
                reason = el('textarea', {class: 'modern-input zt-textarea', id: 'pv-confirm-reason', rows: '2',
                    maxlength: '1000', placeholder: options.reasonRequired ? t('pv.confirm.reasonRequired')
                        : t('pv.confirm.reasonOptional')});
            }
            const problem = el('p', {class: 'zt-muted', id: 'pv-confirm-problem', role: 'alert'});
            problem.hidden = true;
            const refuse = (field, words) => {
                field.focus();
                field.setAttribute('aria-invalid', 'true');
                problem.textContent = words || '';
                problem.hidden = !words;
            };
            const confirmButton = button(options.confirmLabel || t('pv.confirm.ok'), options.icon || 'fa-check-circle',
                () => {
                    const text = reason ? reason.value.trim() : '';
                    if (ticked && !ticked.checked) {
                        refuse(ticked, options.check.missing);
                        return;
                    }
                    if (options.reasonRequired && !text) {
                        refuse(reason, options.reasonMissing);
                        return;
                    }
                    close({reason: text});
                }, {primary: true, name: 'confirm'});
            modal.replaceChildren(
                el('button', {type: 'button', class: 'modal-close-x', 'aria-label': t('pv.confirm.cancel'), text: '×'}),
                el('h4', {class: 'pv-confirm-title', id: 'pv-confirm-title', text: options.title}),
                rows, ...(options.content || []),
                ticked ? el('label', {class: 'pv-toggle mb-3'}, ticked, el('span', {text: options.check.label})) : null,
                reason ? el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name',
                    text: options.reasonRequired ? t('pv.confirm.reason') : t('pv.confirm.reasonLabel')}), reason) : null,
                problem,
                el('div', {class: 'ai-confirm-actions'}, confirmButton,
                    button(t('pv.confirm.cancel'), null, () => close(null), {name: 'cancel'})));
            modal.querySelector('.modal-close-x').addEventListener('click', () => close(null));
            overlay.setAttribute('aria-labelledby', 'pv-confirm-title');
            overlay.classList.remove('hidden');
            modal.scrollTop = 0;
            document.addEventListener('keydown', escape);
            (reason || confirmButton).focus({preventScroll: true});
        });
    }

    /**
     * K173: the confirmation stands over the window, not over the page card. The card's backdrop filter makes it the
     * box a fixed element is placed in, so a confirmation inside the card sits on the card, out of view on a long page.
     * It is moved once to the end of the body, in a box of the console's own page styles, the card left as it is.
     */
    function confirmOverlay() {
        const overlay = document.getElementById('pv-confirm-overlay');
        if (overlay && !overlay.parentElement.hasAttribute('data-pv-confirm-host')) {
            const host = el('div', {class: 'zt-page', 'data-pv-confirm-host': ''});
            document.body.append(host);
            host.append(overlay);
        }
        return overlay;
    }

    // ----- the quality gate of "use for decisions" and of a canary (quality plan 3.4) -----

    /** The release gate's blocker of a blocking quality gate, which the gate part of the confirmation shows itself. */
    const QUALITY_GATE_BLOCKED = 'QUALITY_GATE_BLOCKED';
    const GATE_CHIPS = {PASSED: 'GOOD', WARNING: 'WARN', BLOCKED: 'BAD', NOT_EVALUATED: null};
    /** The folded lines, in the order they stand under the open rows. */
    const GATE_FOLDS = ['WARNING', 'NOT_EVALUATED', 'PASSED'];
    const GATE_STOPPING = ['FALSE_STOP', 'OVER_BLOCK', 'FRICTION', 'DEFERRAL'];
    const GATE_LATER = ['MISS', 'FALSE_STOP', 'OVER_BLOCK', 'FRICTION'];
    /** The case keys a row names at most; the rest are counted. */
    const GATE_CASES = 5;

    /** A row's result as the gate applies it: while the first measurement of the version in use waits, row 1 warns. */
    function gateRowStatus(row, quality) {
        return quality.measurement === 'BASELINE_PENDING' && row.condition === 'COMPARABLE_MEASUREMENTS'
            && row.status === 'BLOCKED' ? 'WARNING' : row.status;
    }

    /**
     * Which of the seven pictures of the gate the confirmation draws: all passed, a rollback, a warning, blocked, and
     * the states of the measurements that are not "measured" (missing, cannot be measured, the version in use waiting
     * for its first one, stale).
     */
    function gateState(quality) {
        if (quality.rollback) {
            return 'rollback';
        }
        const measurement = {UNMEASURABLE: 'unmeasurable', BASELINE_PENDING: 'pending', STALE: 'stale',
            MISSING: 'missing'}[quality.measurement];
        if (measurement) {
            return measurement;
        }
        return quality.applied === 'BLOCKED' ? 'block' : quality.applied === 'WARNING' ? 'warn' : 'pass';
    }

    function figure(row, name) {
        const value = row.figures ? row.figures[name] : null;
        return value == null ? null : value;
    }

    /**
     * The words of the versions a state of the measurements is about, by the key ending CANDIDATE, CURRENT or BOTH;
     * the candidate is {0}, the version in use {1}, and more words after them.
     */
    function sidesText(key, quality, check, ...more) {
        const list = quality.measurementSides || [];
        const side = list.includes('CANDIDATE') && list.includes('CURRENT') ? 'BOTH'
            : list.includes('CURRENT') ? 'CURRENT' : 'CANDIDATE';
        return t(key + side, check.version || '—', check.current || '—', ...more);
    }

    /** The details the use check read beside the verdict (the case set, the models, a measurement that runs). */
    function gateDetails(quality) {
        return quality.details || {};
    }

    /** The case set as the screens of the group name it: the start of its version. */
    function caseSetText(details) {
        return details.caseSetVersion ? t('pv.gate.ev.caseSet', String(details.caseSetVersion).slice(0, 8)) : null;
    }

    /** The measurement of the version in use that waits or runs, when the details have it. */
    function baselineProgress(details, check) {
        const measuring = details.measuring;
        return measuring && measuring.version === check.current ? measuring : null;
    }

    /** Whether the model setting changed between a stale measurement and the server now, by their models. */
    function modelsChanged(details) {
        return details.modelsBefore && details.modelsNow && details.modelsBefore !== details.modelsNow;
    }

    /** A difference of two rates in percentage points, to one decimal: 0.267 is 26.7. */
    function points(ratio) {
        return ratio == null ? '—' : ZT.count(Math.round(ratio * 1000) / 10);
    }

    function rateText(comparison) {
        return t('pv.gate.ev.rate', word('pv.gate.metric.' + comparison.metric), ZT.percent(comparison.currentValue),
            ZT.percent(comparison.candidateValue));
    }

    function verdictText(comparison) {
        const noise = comparison.noiseWidth == null ? t('pv.gate.ev.noNoise')
            : t('pv.gate.ev.noise', ZT.percent(comparison.noiseWidth));
        return word('pv.gate.ev.verdict.' + comparison.verdict) + ' (' + noise + ')';
    }

    /** The cases a row names, by the names the details give them (their keys when not given); the rest counted. */
    function caseList(keys, details) {
        const list = keys || [];
        if (!list.length) {
            return null;
        }
        const names = {};
        (details.caseNames || []).forEach(item => {
            names[item.key] = item.name;
        });
        return {names: list.slice(0, GATE_CASES).map(key => names[key] || key),
            more: list.length > GATE_CASES ? t('pv.gate.ev.more', ZT.count(list.length - GATE_CASES)) : null};
    }

    /** The numbers behind a row, in the reader's words (plan 3.4: every row with its result and its numbers). */
    function gateEvidence(row, status, state, check) {
        const quality = check.quality;
        if (status === 'NOT_EVALUATED') {
            return t('pv.gate.ev.wait.' + ({unmeasurable: 'unmeasurable', pending: 'pending', stale: 'stale'}[state]
                || 'missing'));
        }
        const comparisons = row.comparisons || [];
        switch (row.condition) {
            case 'COMPARABLE_MEASUREMENTS': {
                if (state === 'missing' && status === 'BLOCKED') {
                    return sidesText('pv.gate.line.missing.', quality, check);
                }
                const details = gateDetails(quality);
                if (state === 'stale' && status === 'BLOCKED') {
                    return details.modelsBefore
                        ? sidesText('pv.gate.ev.staleModel.', quality, check, details.modelsBefore)
                        : sidesText('pv.gate.ev.stale.', quality, check);
                }
                if (state === 'pending') {
                    const progress = baselineProgress(details, check);
                    return progress ? t('pv.gate.ev.pendingProgress', check.current || '—',
                        ZT.count(progress.answered), ZT.count(progress.planned), check.version || '—')
                        : t('pv.gate.ev.pending', check.current || '—');
                }
                if (status === 'PASSED') {
                    return [t('pv.gate.ev.pairOf', check.current || '—', check.version || '—'), caseSetText(details),
                        details.models || null, figure(row, 'candidateRepeats') != null
                            ? t('pv.gate.ev.runs', ZT.count(figure(row, 'candidateRepeats'))) : null]
                        .filter(Boolean).join(' · ');
                }
                const parts = [];
                const sameSet = figure(row, 'sameCaseSetVersion');
                const sameModel = figure(row, 'sameModelSetting');
                if (sameSet != null) {
                    parts.push(t(sameSet ? 'pv.gate.ev.sameSet' : 'pv.gate.ev.otherSet'));
                }
                if (sameModel != null) {
                    parts.push(t(sameModel ? 'pv.gate.ev.sameModel' : 'pv.gate.ev.otherModel'));
                }
                const current = figure(row, 'currentRepeats');
                const candidate = figure(row, 'candidateRepeats');
                if (current != null && candidate != null) {
                    parts.push(current === candidate ? t('pv.gate.ev.repeats', ZT.count(current))
                        : t('pv.gate.ev.repeatsTwo', ZT.count(current), ZT.count(candidate)));
                }
                parts.push(t('pv.gate.ev.answers', ZT.count(figure(row, 'currentScoredAnswers') || 0),
                    ZT.count(figure(row, 'candidateScoredAnswers') || 0)));
                return parts.join(' · ');
            }
            case 'MUST_CATCH_NEVER_ALLOWED':
            case 'MUST_NOT_BLOCK_NEVER_BLOCKED': {
                const graded = figure(row, 'gradedCases') || 0;
                if (!graded) {
                    return t('pv.gate.ev.noGraded');
                }
                const unmeasured = figure(row, 'unmeasuredCases') || 0;
                return t('pv.gate.ev.graded.' + row.condition, ZT.count(graded),
                    ZT.count(figure(row, 'failedCases') || 0), ZT.count(figure(row, 'failedAnswers') || 0))
                    + (unmeasured ? ' · ' + t('pv.gate.ev.unmeasured', ZT.count(unmeasured)) : '');
            }
            case 'MUST_CATCH_NOT_WEAKENED': {
                // Quality P35: the cases newly answered outside their allowed actions block; those the version in use
                // answers so too only warn.
                const graded = figure(row, 'gradedCases') || 0;
                if (!graded) {
                    return t('pv.gate.ev.noGraded');
                }
                const weakened = figure(row, 'weakenedCases') || 0;
                const before = figure(row, 'currentAlsoOutsideCases') || 0;
                const unmeasured = figure(row, 'unmeasuredCases') || 0;
                return [t('pv.gate.ev.weakened', ZT.count(graded), ZT.count(weakened),
                    ZT.count(figure(row, 'weakenedAnswers') || 0)),
                weakened && figure(row, 'comparedWithCurrent') === 0 ? t('pv.gate.ev.weakenedUncompared') : null,
                before ? t('pv.gate.ev.weakenedBefore', ZT.count(before)) : null,
                unmeasured ? t('pv.gate.ev.unmeasured', ZT.count(unmeasured)) : null].filter(Boolean).join(' · ');
            }
            case 'MISS_NOT_INCREASED':
                return comparisons.map(comparison => rateText(comparison) + ' · ' + verdictText(comparison))
                    .join(' · ');
            case 'STOPPING_NOT_INCREASED': {
                const read = GATE_STOPPING.map(metric => comparisons.find(comparison => comparison.metric === metric))
                    .filter(Boolean);
                const named = verdict => read.filter(comparison => comparison.verdict === verdict)
                    .map(comparison => word('pv.gate.metric.' + comparison.metric)).join(', ');
                return [read.map(rateText).join(' · '),
                    named('WORSE') ? t('pv.gate.ev.worse', named('WORSE')) : null,
                    named('UNDECIDABLE') ? t('pv.gate.ev.undecidable', named('UNDECIDABLE')) : null]
                    .filter(Boolean).join(' · ');
            }
            case 'FRICTION_INCREASE_WITHIN_LIMIT': {
                // Quality P8: the rise of the friction against its limit, whatever the significance.
                if (!figure(row, 'pairedCases')) {
                    return t('pv.gate.ev.noAllowCases');
                }
                const increase = figure(row, 'increase');
                const current = ZT.percent(figure(row, 'currentRate'));
                const candidate = ZT.percent(figure(row, 'candidateRate'));
                const limit = points(figure(row, 'limit'));
                return [increase != null && Math.round(increase * 1000) > 0
                    ? t('pv.gate.ev.frictionUp', current, candidate, points(increase), limit)
                    : t('pv.gate.ev.frictionNotUp', current, candidate, limit),
                status === 'BLOCKED' ? t('pv.gate.ev.frictionSetting') : null].filter(Boolean).join(' · ');
            }
            case 'MODEL_USED_AND_CITATIONS_ACCURATE': {
                const citations = comparisons.find(comparison => comparison.metric === 'CITATION_ACCURACY');
                return [t('pv.gate.ev.modelLess', ZT.count(figure(row, 'modelLessAnswers') || 0),
                    ZT.count(figure(row, 'answers') || 0), ZT.percent(figure(row, 'modelLessLimit'))),
                citations ? rateText(citations) + ' · ' + verdictText(citations) : null].filter(Boolean).join(' · ');
            }
            case 'NO_NEWLY_MISSED_OR_STOPPED_CASES':
                return t('pv.gate.ev.changed', ZT.count(figure(row, 'newlyMissedCases') || 0),
                    ZT.count(figure(row, 'newlyStoppedCases') || 0));
            case 'ENOUGH_CASES': {
                const short = (figure(row, 'stopRootsShort') || 0) + (figure(row, 'allowRootsShort') || 0) > 0;
                const undecidable = figure(row, 'undecidableRates') || 0;
                const noNoise = figure(row, 'ratesWithoutNoise') || 0;
                return [(short ? t('pv.gate.ev.undecided') + ' ' : '') + t('pv.gate.ev.enough',
                    ZT.count(figure(row, 'stopRoots') || 0), ZT.count(figure(row, 'stopRootsNeeded') || 0),
                    ZT.count(figure(row, 'allowRoots') || 0), ZT.count(figure(row, 'allowRootsNeeded') || 0)),
                undecidable ? t('pv.gate.ev.undecidableRates', ZT.count(undecidable)) : null,
                noNoise ? t('pv.gate.ev.noNoiseRates', ZT.count(noNoise)) : null].filter(Boolean).join(' · ');
            }
            case 'NOT_WORSE_ON_LATER_CASES_ONLY': {
                const later = figure(row, 'laterCases') || 0;
                if (!later) {
                    return t('pv.gate.ev.noLater');
                }
                if (!figure(row, 'earlierCases')) {
                    return t('pv.gate.ev.noEarlier', ZT.count(later));
                }
                const rates = GATE_LATER.filter(metric => figure(row, metric + '.laterRate') != null)
                    .filter(metric => status !== 'WARNING'
                        || figure(row, metric + '.laterRate') > figure(row, metric + '.earlierRate'))
                    .slice(0, status === 'WARNING' ? GATE_LATER.length : 1)
                    .map(metric => t('pv.gate.ev.laterRate', word('pv.gate.metric.' + metric),
                        ZT.percent(figure(row, metric + '.laterRate')),
                        ZT.percent(figure(row, metric + '.earlierRate'))));
                return t('pv.gate.ev.later', ZT.count(later), rates.join(' · ') || '—');
            }
            default:
                return '';
        }
    }

    /** What the alert of the gate says: the state, why, and what the mode or the operator can do about it. */
    function gateLine(state, quality, check, blocking, warnings, override) {
        const blocked = quality.applied === 'BLOCKED';
        const sentences = [];
        if (state === 'warn') {
            sentences.push(blocking.length ? t('pv.gate.line.block', ZT.count(blocking.length))
                : t('pv.gate.line.warn', ZT.count(warnings.length)));
        } else if (state === 'block') {
            sentences.push(t('pv.gate.line.block', ZT.count(blocking.length)));
        } else if (state === 'missing') {
            sentences.push(sidesText('pv.gate.line.missing.', quality, check));
        } else if (state === 'pending') {
            const progress = baselineProgress(gateDetails(quality), check);
            sentences.push(progress ? t('pv.gate.line.pendingProgress', check.current || '—',
                ZT.count(progress.answered), ZT.count(progress.planned))
                : t('pv.gate.line.pending', check.current || '—'));
        } else if (state === 'stale') {
            const details = gateDetails(quality);
            sentences.push(modelsChanged(details) ? sidesText('pv.gate.line.staleModels.', quality, check,
                details.modelsBefore, details.modelsNow) : sidesText('pv.gate.line.stale.', quality, check));
        } else {
            sentences.push(t('pv.gate.line.' + state, ZT.count((quality.rows || []).length)));
        }
        // The sentence of the waiting baseline says already that it is being measured.
        if (quality.measurementDetail && !(state === 'pending' && quality.measurementDetail === 'MEASURING')) {
            const detail = word('pv.gate.detail.' + quality.measurementDetail, '');
            if (detail) {
                sentences.push(detail);
            }
        }
        if (blocked) {
            sentences.push(t(override ? 'pv.gate.override' : 'pv.gate.noOverride'));
        } else if (blocking.length) {
            sentences.push(t('pv.gate.softened', ZT.count(blocking.length)));
        }
        return sentences.join(' ');
    }

    /**
     * Quality plan 3.4 and the approved mockup: what the confirmation shows of the quality gate. When the verdict
     * blocks, the blocking rows alone stay open and the warnings fold into "N warnings", whether the gate blocks or,
     * in the warning mode, applies the verdict as a warning; otherwise the rows that warn stay open. The rows the gate
     * could not look at and the rows that passed fold into a line each. The newly missed cases are not listed
     * in the confirmation: a link opens the comparison of the two versions. A blocked gate takes a reason when a reason
     * overrides it (it blocks on quality alone). Pure: it reads the use check and returns what the confirmation draws.
     *
     * @param kind "use" or "canary": the move the gate looks at
     */
    function gatePlan(check, kind) {
        const quality = check ? check.quality : null;
        if (!quality) {
            return null;
        }
        const state = gateState(quality);
        const blocked = quality.applied === 'BLOCKED';
        const override = blocked && quality.overridable === true;
        const rows = (quality.rows || []).map(row => ({row, status: gateRowStatus(row, quality)}));
        const blocking = rows.filter(item => item.status === 'BLOCKED');
        const warnings = rows.filter(item => item.status === 'WARNING');
        // The verdict as the gate computes it, its rule for the first row while the baseline waits applied.
        const blockedVerdict = blocking.length > 0;
        const isOpen = item => (blockedVerdict ? item.status === 'BLOCKED' : item.status === 'WARNING');
        const details = gateDetails(quality);
        const compareHref = measurePage('/compare', {candidate: numberOf(check.version),
            reference: numberOf(check.current)});
        const describe = item => {
            const row = item.row;
            const described = {condition: row.condition, status: item.status, chip: GATE_CHIPS[item.status] || null,
                result: word('pv.gate.result.' + item.status), title: word('pv.gate.row.' + row.condition),
                evidence: gateEvidence(row, item.status, state, check), cases: null, compare: null};
            if (row.condition === 'NO_NEWLY_MISSED_OR_STOPPED_CASES') {
                const missed = figure(row, 'newlyMissedCases') || 0;
                const stopped = figure(row, 'newlyStoppedCases') || 0;
                if (missed + stopped > 0) {
                    described.compare = {href: compareHref, label: missed ? t('pv.gate.compare.missed', ZT.count(missed))
                        : t('pv.gate.compare.stopped', ZT.count(stopped))};
                }
            } else if (item.status !== 'PASSED' && item.status !== 'NOT_EVALUATED') {
                described.cases = caseList(row.cases, details);
            }
            return described;
        };
        const open = rows.filter(isOpen).map(describe);
        const folds = GATE_FOLDS.map(status => rows.filter(item => item.status === status && !isOpen(item)))
            .filter(items => items.length)
            .map(items => ({status: items[0].status, label: t('pv.gate.fold.' + items[0].status, ZT.count(items.length)),
                rows: items.map(describe)}));
        const changed = open.find(row => row.condition === 'NO_NEWLY_MISSED_OR_STOPPED_CASES' && row.compare);
        const repeats = rows.length ? figure(rows[0].row, 'candidateRepeats') : null;
        const staleSide = (quality.measurementSides || []).includes('CURRENT') ? check.current : check.version;
        return {
            state, kind: kind || 'use', chip: GATE_CHIPS[quality.applied] || null,
            label: t('pv.gate.state.' + state),
            line: gateLine(state, quality, check, blocking, warnings, override),
            subhead: [t('pv.gate.title'), caseSetText(details), details.models || null,
                repeats != null ? t('pv.gate.ev.runs', ZT.count(repeats)) : null].filter(Boolean).join(' · '),
            modeTip: [word('pv.gate.mode.' + quality.mode, ''), word('pv.gate.modeTip.' + quality.mode, '')]
                .filter(Boolean).join(': '),
            open, folds, override, seen: !blockedVerdict && changed != null,
            remeasure: state === 'stale' && quality.measurementDetail !== 'MEASURING' && numberOf(staleSide) != null
                ? measurePage('', {candidate: numberOf(staleSide)}) : null
        };
    }

    function gateRows(rows) {
        return el('div', {class: 'zt-indicators'}, rows.map(row => {
            const chip = ZT.statusChip(row.chip, row.chip ? row.result : '—');
            chip.setAttribute('title', row.result);
            return el('div', {class: 'zt-indicator', 'data-severity': row.chip, 'data-gate-row': row.condition},
                el('div', {class: 'zt-indicator-text'}, el('span', {class: 'zt-indicator-title', text: row.title}),
                    row.evidence ? el('span', {class: 'zt-indicator-rule', text: row.evidence}) : null,
                    row.cases ? el('ul', {class: 'zt-rows', style: {marginTop: '0.25rem'}},
                        row.cases.names.map(name => el('li', {class: 'zt-row flex-wrap'}, el('span', {text: name}))),
                        row.cases.more ? el('li', {class: 'zt-muted', text: row.cases.more}) : null) : null,
                    row.compare ? el('a', {class: 'zt-link', href: row.compare.href, 'data-pv-action': 'gate-compare',
                        text: row.compare.label}) : null),
                chip);
        }));
    }

    /** The gate part of the confirmation, as the plan says to draw it. */
    function gateNode(plan) {
        const alert = el('div', {class: 'zt-alert max-sm:!grid-cols-1', role: 'note', 'data-gate-state': plan.state},
            ZT.statusChip(plan.chip, plan.label),
            el('div', {class: 'zt-item'}, el('span', {text: plan.line}),
                plan.remeasure ? el('div', {class: 'pv-actions'}, button(t('pv.gate.remeasure'), 'fa-redo', null,
                    {href: plan.remeasure, name: 'gate-remeasure'})) : null));
        const parts = [alert];
        if (plan.open.length || plan.folds.length) {
            parts.push(el('div', {class: 'zt-subhead', title: plan.modeTip || null, text: plan.subhead}));
        }
        if (plan.open.length) {
            parts.push(gateRows(plan.open));
        }
        plan.folds.forEach(item => parts.push(fold(el('details', {class: 'pv-prepared', 'data-gate-fold': item.status},
            el('summary', {class: 'zt-link', text: item.label})), el('div', {class: 'mt-3'}, gateRows(item.rows)))));
        return el('div', {class: 'flex flex-col gap-3 mb-3', 'data-gate': plan.state}, parts);
    }

    /**
     * The confirmation of a move the release gate looks at (using a version for decisions, starting a canary): the
     * blockers apart from the quality gate, the quality gate as gatePlan draws it, and a reason the gate takes to be
     * overridden when it blocks on quality alone. Resolves to the body the move sends ({reason} and the override's
     * reason when there is one) or null.
     *
     * @param options the confirmation's title, rows, the label and icon of its confirm button, the move ("use" or
     *                "canary"), and the content to show where there is no quality gate
     */
    async function gateConfirm(check, options) {
        const plan = gatePlan(check, options.kind);
        const blockers = (check.blockers || []).filter(blocker => !(plan && codeOf(blocker) === QUALITY_GATE_BLOCKED));
        const content = [];
        if (!check.ready && blockers.length) {
            content.push(el('div', {class: 'zt-alert', role: 'note'}, el('span', {class: 'status-badge zt-chip',
                'data-status': 'BAD', text: t('pv.use.blocked')}), el('div', {class: 'zt-item'},
                ...blockers.map(blocker => el('span', {text: blockerText(blocker)})))));
        }
        content.push(...(plan ? [gateNode(plan)] : options.withoutGate || []));
        const answer = await confirm({
            title: options.title, rows: options.rows, content, reason: true,
            reasonRequired: plan != null && plan.override,
            reasonMissing: plan != null && plan.override
                ? refusedLines({body: {code: 'OVERRIDE_REASON_REQUIRED'}})[0] : null,
            check: plan != null && plan.seen ? {label: t('pv.gate.seen'), missing: t('pv.gate.seenMissing')} : null,
            confirmLabel: plan != null && plan.override ? t('pv.gate.confirm.' + (options.kind || 'use'))
                : options.confirmLabel,
            icon: plan != null && plan.override ? 'fa-unlock' : options.icon
        });
        if (!answer) {
            return null;
        }
        const body = {reason: answer.reason};
        if (plan != null && plan.override) {
            body.overrideReason = answer.reason;
        }
        return body;
    }

    // ----- "use for decisions", shared by the list, a version and a trial -----

    /**
     * The confirmation of using a version (plan 3.4), with the release gate's answer and, for the security decision,
     * its quality gate (quality plan 3.4), then the move; a blocked gate is overridden with the reason given.
     */
    async function useVersion(number, decision, after) {
        let check;
        try {
            check = await get('/' + number + '/use-check');
        } catch (error) {
            notice('bad', t('pv.use.failed'), [t('pv.ui.loadFailed')]);
            return;
        }
        // Without a quality gate (it could not be read) the latest trial is all there is to show of the version.
        const trial = check.latestTrial;
        const withoutGate = decision ? [el('div', {class: 'zt-alert', role: 'note'},
            el('span', {class: 'status-badge zt-chip', 'data-status': trial ? 'GOOD' : 'WARN',
                text: t(trial ? 'pv.use.trialDone' : 'pv.use.noTrial')}),
            el('span', {text: trial ? t('pv.use.trialLine', trial.referenceName, ZT.time(trial.finishedAt),
                ZT.count(trial.actual)) : t('pv.use.trialAdvice')}))] : [];
        const body = await gateConfirm(check, {
            kind: 'use', title: t(decision ? 'pv.use.title' : 'pv.use.title.other', check.version),
            // The words of how a move applies stand in the tooltip of the version it moves to.
            rows: [[t('pv.use.now'), check.current || '—'], [t('pv.use.next'), check.version,
                t('pv.use.reflect') + ': ' + t('pv.use.reflectValue')]],
            withoutGate, confirmLabel: useLabel(decision), icon: 'fa-check-circle'
        });
        if (!body) {
            return;
        }
        const result = await send('/' + number + '/use', body);
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
        API, PAGES, MEASURE, ACTIONS, params, page, measurePage, numberOf, api, get, send, word, promptName, stateText,
        stateChip, useLabel, actionName, origin, maker, partName, versionLabel, problemText, blockerText, refusalText,
        refusedLines, band, tabs, toolbar, button, notice, clearNotice, confirm, gatePlan, gateNode, gateConfirm,
        useVersion, fill, fold, actionBar, textBox, tokens, signed, paged
    };
})(window);
