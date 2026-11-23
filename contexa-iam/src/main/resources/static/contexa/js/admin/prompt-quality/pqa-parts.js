/*
 * Prompt quality assurance: the parts the quality status and the sealed evidence share (quality plan 3.6 to 3.8), made
 * of the admin console's own components (window.ZT of console-common.js, the policy center's buttons, filter box,
 * pager and confirmation); the screens have no stylesheet of their own. Load after console-common.js.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    if (!ZT) {
        return;
    }
    const el = ZT.el;
    const root = document.getElementById('zt-console');

    /** A button of the admin console: primary (purple), refresh (the blue action) or secondary. */
    function button(label, icon, kind, attributes) {
        const to = attributes && attributes.href;
        return el(to ? 'a' : 'button', Object.assign({type: to ? null : 'button',
            class: 'modern-btn-' + (kind || 'secondary')}, attributes || {}),
        icon ? el('i', {class: 'fas ' + icon, 'aria-hidden': 'true'}) : null, el('span', {text: label}));
    }

    function link(to, text) {
        return el('a', {class: 'zt-link', href: to, text});
    }

    function muted(text) {
        return el('span', {class: 'zt-muted', text});
    }

    /** A card's foot: its links and buttons under its body. */
    function foot(card, ...nodes) {
        card.append(el('div', {class: 'zt-card-foot'}, ...nodes.filter(Boolean)));
        return card;
    }

    /** A card's share of the twelve columns of the grid. */
    function span(node, columns) {
        node.classList.add('zt-span-' + columns);
        return node;
    }

    function grid(...cards) {
        return el('div', {class: 'zt-grid'}, ...cards.filter(Boolean));
    }

    /** Names the visual form of a part, so no two areas of a screen are built alike. */
    function form(name, node) {
        node.setAttribute('data-form', name);
        return node;
    }

    /** A card with its definition mark; its aside stays beside the mark. */
    function tipped(card, text) {
        const aside = card.querySelector('.zt-card-head .zt-aside');
        if (aside) {
            aside.classList.add('ml-auto');
        }
        return ZT.withTip(card, text);
    }

    /** The policy center's empty state: an icon and one sentence. */
    function emptyState(text, icon) {
        return el('div', {class: 'pc-empty', role: 'note'}, el('i', {class: 'fas ' + (icon || 'fa-inbox'),
            'aria-hidden': 'true'}), el('p', {text: '— ' + text}));
    }

    /** The data a page carries for its script, as JSON in a script element. */
    function json(id) {
        const node = document.getElementById(id);
        try {
            return node ? JSON.parse(node.textContent || '{}') : {};
        } catch (unreadable) {
            return {};
        }
    }

    /** The address of the page with the parameters changed (null or '' removes one), the others kept. */
    function address(changes) {
        const params = ZT.query();
        Object.entries(changes || {}).forEach(([name, value]) => {
            if (value == null || value === '') {
                params.delete(name);
            } else {
                params.set(name, value);
            }
        });
        const search = params.toString();
        return global.location.pathname + (search ? '?' + search : '');
    }

    /** An address of the group with the scope of the page kept, so the screen it opens shows the same scope. */
    function scoped(path, extra) {
        const target = new URL(path, global.location.origin);
        const scope = ZT.query().get('scope');
        if (scope) {
            target.searchParams.set('scope', scope);
        }
        Object.entries(extra || {}).forEach(([name, value]) => {
            if (value != null && value !== '') {
                target.searchParams.set(name, value);
            }
        });
        return target.pathname + target.search;
    }

    const PERIODS = ['day', 'week', 'month', 'quarter'];
    const HOURS = {day: 24, week: 24 * 7, month: 24 * 30, quarter: 24 * 90};

    /**
     * The console's period buttons, the chosen one kept in the address (design 6.0): the last 24 hours, 7, 30 or 90
     * days and, when the screen reads any days (options.custom), the days an operator chooses.
     */
    function periods(container, onChange, options) {
        const current = ZT.query().get('period') || 'week';
        const pick = (chosen, change) => {
            const params = ZT.query();
            change(params);
            params.delete('page');
            global.history.replaceState(null, '', global.location.pathname + '?' + params.toString());
            container.querySelectorAll('button[data-period]').forEach(other => other.setAttribute('aria-pressed',
                String(other === chosen)));
            onChange();
        };
        const days = [];
        PERIODS.forEach(key => {
            const node = el('button', {type: 'button', 'data-period': key, 'aria-pressed': String(key === current
                || (key === 'week' && !PERIODS.includes(current) && current !== 'custom')),
            text: ZT.t('zt.console.ui.period.' + key)});
            node.addEventListener('click', () => {
                days.forEach(field => field.hidden = true);
                pick(node, params => {
                    params.set('period', key);
                    params.delete('from');
                    params.delete('to');
                });
            });
            container.append(node);
        });
        if (!options || !options.custom) {
            return;
        }
        const custom = current === 'custom';
        const today = new Date().toISOString().slice(0, 10);
        const day = value => value ? String(value).slice(0, 10) : '';
        const from = el('input', {type: 'date', class: 'modern-input', max: today, required: true,
            'aria-label': ZT.t('zt.console.ui.period.from'), value: custom ? day(ZT.query().get('from')) : ''});
        const to = el('input', {type: 'date', class: 'modern-input', max: today,
            'aria-label': ZT.t('zt.console.ui.period.to'), value: custom ? day(ZT.query().get('to')) : ''});
        const apply = el('button', {type: 'button', text: ZT.t('zt.console.ui.period.apply')});
        const choose = el('button', {type: 'button', 'data-period': 'custom', 'aria-pressed': String(custom),
            text: ZT.t('zt.console.ui.period.custom')});
        days.push(from, to, apply);
        days.forEach(field => field.hidden = !custom);
        choose.addEventListener('click', () => {
            days.forEach(field => field.hidden = false);
            from.focus();
        });
        apply.addEventListener('click', () => {
            if (!from.value || (to.value && to.value < from.value)) {
                from.reportValidity();
                return;
            }
            pick(choose, params => {
                params.set('period', 'custom');
                params.set('from', from.value);
                if (to.value) {
                    params.set('to', to.value);
                } else {
                    params.delete('to');
                }
            });
        });
        container.append(choose, from, to, apply);
    }

    /**
     * The moments of the period in the address: the last hours of a period key, or the chosen days in the reader's
     * time zone, the last day in it (the sealed prompt list read its days the same way).
     */
    function range() {
        const params = ZT.query();
        const period = params.get('period') || 'week';
        const now = new Date();
        if (period === 'custom' && params.get('from')) {
            const first = new Date(String(params.get('from')).slice(0, 10) + 'T00:00:00');
            const last = params.get('to') ? new Date(String(params.get('to')).slice(0, 10) + 'T00:00:00') : null;
            const end = last ? new Date(last.getTime()) : now;
            if (last) {
                end.setDate(end.getDate() + 1);
            }
            if (!Number.isNaN(first.getTime()) && !Number.isNaN(end.getTime())) {
                return {from: first.toISOString(), to: (end > now ? now : end).toISOString()};
            }
        }
        const hours = HOURS[period] || HOURS.week;
        return {from: new Date(now.getTime() - hours * 3600 * 1000).toISOString(), to: now.toISOString()};
    }

    /** Calls an admin API at its address; a failed call throws an error carrying its status and its body. */
    async function call(url, options) {
        const method = String((options && options.method) || 'GET').toUpperCase();
        const headers = {Accept: 'application/json'};
        if (method !== 'GET') {
            headers['Content-Type'] = 'application/json';
            if (root && root.dataset.csrfToken) {
                headers[root.dataset.csrfHeader || 'X-CSRF-TOKEN'] = root.dataset.csrfToken;
            }
        }
        const response = await fetch(url, {method, headers, credentials: 'same-origin',
            body: options && options.body !== undefined ? JSON.stringify(options.body) : undefined});
        const text = await response.text();
        let body = null;
        try {
            body = text ? JSON.parse(text) : null;
        } catch (unreadable) {
            body = null;
        }
        if (!response.ok) {
            const error = new Error(String(response.status));
            error.status = response.status;
            error.body = body;
            throw error;
        }
        return body;
    }

    /** The query of the values that have one, for an API address. */
    function query(values) {
        const params = new URLSearchParams();
        Object.entries(values).forEach(([name, value]) => {
            if (value != null && String(value).trim() !== '') {
                params.set(name, String(value).trim());
            }
        });
        const text = params.toString();
        return text ? '?' + text : '';
    }

    /**
     * The confirmation of the admin console (the policy center's): a title, rows of label and value, more content, and
     * the confirm and cancel buttons. options.check(), when given, says whether the content may be sent (it marks what
     * is missing); the promise resolves to true on confirm and null on cancel.
     */
    function dialog(options) {
        const overlay = document.getElementById('pqa-confirm-overlay');
        const modal = overlay ? overlay.querySelector('.ai-confirm-modal') : null;
        if (!overlay || !modal) {
            return Promise.resolve(global.confirm(options.title) ? true : null);
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
            const rows = (options.rows || []).length ? el('div', {class: 'ai-confirm-summary'},
                ...options.rows.map(([label, value]) => el('div', {class: 'ai-confirm-row'},
                    el('span', {class: 'ai-confirm-label', text: label}),
                    el('span', {class: 'ai-confirm-value', text: value == null ? '—' : String(value)})))) : null;
            const confirm = button(options.confirmLabel, options.icon || 'fa-check-circle', 'primary');
            confirm.addEventListener('click', () => {
                if (!options.check || options.check()) {
                    close(true);
                }
            });
            const cancel = button(options.cancelLabel, null, 'secondary');
            cancel.addEventListener('click', () => close(null));
            const shut = el('button', {type: 'button', class: 'modal-close-x', 'aria-label': options.cancelLabel,
                text: '×'});
            shut.addEventListener('click', () => close(null));
            modal.replaceChildren(shut, el('h4', {class: 'pv-confirm-title', id: 'pqa-confirm-title',
                text: options.title}), rows, ...(options.content || []),
            el('div', {class: 'ai-confirm-actions'}, confirm, cancel));
            overlay.setAttribute('aria-labelledby', 'pqa-confirm-title');
            overlay.classList.remove('hidden');
            document.addEventListener('keydown', escape);
            const first = modal.querySelector('input, select, textarea');
            (first || confirm).focus();
        });
    }

    /** A labelled field of the filter box's form grid. */
    function field(label, control) {
        return el('label', {class: 'zt-filter-field'}, el('span', {class: 'zt-filter-name', text: label}), control);
    }

    /** A notice above the screen, as the version screens show one: done (good), refused (bad) or a note (info). */
    function notice(kind, title, lines) {
        const box = document.getElementById('pqa-notice');
        if (!box) {
            return;
        }
        if (!kind) {
            box.replaceChildren();
            return;
        }
        const node = el('div', {class: 'zt-alert', role: kind === 'bad' ? 'alert' : 'status'},
            ZT.statusChip(kind === 'good' ? 'GOOD' : kind === 'bad' ? 'BAD' : 'INFO'),
            el('div', {class: 'zt-item'}, el('strong', {text: title}),
                ...(lines || []).filter(Boolean).map(line => muted(line))));
        box.replaceChildren(node);
        node.scrollIntoView({block: 'nearest'});
    }

    global.PQA = {button, link, muted, foot, span, grid, form, tipped, emptyState, json, address, scoped, periods,
        range, call, query, dialog, field, notice};
})(window);
