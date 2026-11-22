/*
 * Prompt quality assurance (quality plan 3.8): what the screens of the labelled cases and of measure and compare share,
 * on top of the Zero Trust console's components (window.ZT) and the prompt version screens' (window.PV: the policy
 * center's confirmation, the notices, the pager of a list). The scope travels in the address, so a link keeps it; every
 * change is a POST with the console's CSRF header; a code the server sends is shown in the reader's words.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const el = ZT.el;
    const t = ZT.t;
    const root = document.getElementById('zt-console');
    const API = root ? root.dataset.pqaApi : '';
    const KEPT = ['scope'];

    function params() {
        return new URLSearchParams(global.location.search);
    }

    /** The parameters every link and call keeps (the scope), with the extra ones. */
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

    /** A page of the group with the scope kept. */
    function page(path, extra) {
        return path + kept(extra);
    }

    async function get(path, extra) {
        const response = await fetch(API + (path || '') + kept(extra), {headers: {Accept: 'application/json'},
            credentials: 'same-origin'});
        if (!response.ok) {
            const error = new Error(String(response.status));
            error.status = response.status;
            throw error;
        }
        return response.json();
    }

    /** A POST of the screen: {ok, status, body}; a body the server could not give is null. */
    async function send(path, body, extra) {
        const headers = {'Content-Type': 'application/json', Accept: 'application/json'};
        if (root && root.dataset.csrfToken) {
            headers[root.dataset.csrfHeader || 'X-CSRF-TOKEN'] = root.dataset.csrfToken;
        }
        const response = await fetch(API + (path || '') + kept(extra), {method: 'POST', headers,
            credentials: 'same-origin', body: JSON.stringify(body == null ? {} : body)});
        const text = await response.text();
        let parsed = null;
        try {
            parsed = text ? JSON.parse(text) : null;
        } catch (unreadable) {
            parsed = null;
        }
        return {ok: response.ok, status: response.status, body: parsed};
    }

    /** A message of the prefix, or the fallback when there is none for the key (a code is never shown as it is). */
    function word(key, fallback, ...args) {
        const text = t(key, ...args);
        return text === key ? (fallback != null ? fallback : t('pv.ui.unknown')) : text;
    }

    /** What a refused POST answered, as a sentence: its code in the screen's words. */
    function refused(prefix, result) {
        const body = result && result.body ? result.body : {};
        if (body.code) {
            return word(prefix + body.code, t('pv.refused.other'));
        }
        if (result && result.status === 403) {
            return t('pv.refused.FORBIDDEN');
        }
        return t('pv.refused.other');
    }

    // ----- the parts of the screens (the mockups' components, from the console's) -----

    function span(node, columns) {
        node.classList.add('zt-span-' + columns);
        return node;
    }

    function grid(...cards) {
        return el('div', {class: 'zt-grid'}, ...cards.filter(Boolean));
    }

    /** Every visual form names itself, so no two cards are built alike. */
    function form(name, node) {
        node.setAttribute('data-form', name);
        return node;
    }

    function link(to, text) {
        return el('a', {class: 'zt-link', href: to, text});
    }

    function muted(text) {
        return el('span', {class: 'zt-muted', text});
    }

    /** A button of the admin console: primary (purple), refresh (the blue action) or secondary. */
    function button(label, icon, kind, attributes, onClick) {
        const to = attributes && attributes.href;
        const node = el(to ? 'a' : 'button', Object.assign({type: to ? null : 'button',
            class: 'modern-btn-' + (kind || 'secondary')}, attributes || {}),
        icon ? el('i', {class: 'fas ' + icon, 'aria-hidden': 'true'}) : null, el('span', {text: label}));
        if (onClick && !to) {
            node.addEventListener('click', onClick);
        }
        return node;
    }

    /** The policy center's empty state: an icon and one sentence. */
    function emptyState(text, icon, role) {
        return el('div', {class: 'pc-empty', role: role || 'note'}, el('i', {class: 'fas ' + (icon || 'fa-inbox'),
            'aria-hidden': 'true'}), el('p', {text: '— ' + text}));
    }

    function failed() {
        return emptyState(t('pv.ui.loadFailed'), 'fa-exclamation-triangle', 'alert');
    }

    /** A table of the console: its columns ({label, num, wide, keep}) and its body. */
    function table(columns, body, caption) {
        return el('div', {class: 'modern-table zt-table-wrap'}, el('table', {class: 'zt-table'},
            caption ? el('caption', {class: 'zt-sr-only', text: caption}) : null,
            el('thead', {}, el('tr', {}, columns.map(column => el('th', {scope: 'col',
                class: [column.num ? 'zt-num' : '', column.wide ? 'zt-wide' : '', column.keep ? 'pv-keep-case' : '']
                    .join(' ').trim() || null, text: column.label})))),
            body));
    }

    function cell(text, attributes) {
        return el('td', Object.assign({title: text, text}, attributes || {}));
    }

    /** A cell of action badges: up to three stay on one line from a desktop's width (fitChips), more wrap. */
    function chipCell(actions, wide) {
        const list = (actions || []).filter(Boolean);
        return el('td', {class: 'zt-cell-chips' + (wide ? ' zt-wide' : ''),
            'data-fit': list.length > 1 && list.length <= 3 ? 'line' : null}, list.map(action => ZT.chip(action)));
    }

    /**
     * Gives a cell of two or three badges the width they need side by side, measured from the badges as drawn, from a
     * desktop's width up; below it the badges wrap as the console's cells of badges do.
     */
    function fitChips() {
        const desktop = global.innerWidth >= 1280;
        document.querySelectorAll('td[data-fit="line"]').forEach(node => {
            node.style.minWidth = '';
        });
        if (!desktop) {
            return;
        }
        const cells = [...document.querySelectorAll('td[data-fit="line"]')];
        new Set(cells.map(node => node.closest('table'))).forEach(table => {
            const own = cells.filter(node => node.closest('table') === table);
            const widths = own.map(node => {
                const style = getComputedStyle(node);
                const badges = [...node.querySelectorAll('.status-badge')];
                const needed = badges.reduce((sum, badge) => sum + badge.getBoundingClientRect().width
                    + parseFloat(getComputedStyle(badge).marginRight), 0);
                return Math.ceil(needed + parseFloat(style.paddingLeft) + parseFloat(style.paddingRight) + 2);
            });
            own.forEach((node, index) => {
                node.style.minWidth = widths[index] + 'px';
            });
            const fill = table.querySelector('td.zt-fill');
            if (table.getBoundingClientRect().width > table.parentElement.clientWidth + 1
                || (fill && fill.getBoundingClientRect().width < 160)) {
                own.forEach(node => {
                    node.style.minWidth = '';
                });
            }
        });
    }

    /** A card with its definition mark; its aside stays beside the mark. */
    function tipped(card, text) {
        const aside = card.querySelector('.zt-card-head .zt-aside');
        if (aside) {
            aside.classList.add('ml-auto');
        }
        return ZT.withTip(card, text);
    }

    function toolbar(...nodes) {
        const box = root ? root.querySelector('.zt-toolbar') : null;
        if (box) {
            box.replaceChildren(...nodes.filter(Boolean));
        }
    }

    function band(...nodes) {
        const box = document.getElementById('zt-band');
        if (box) {
            box.replaceChildren(...nodes.flat().filter(Boolean));
        }
    }

    /** The way back above the title of a screen opened from a list, as the version screens show it. */
    function crumbs(to, list, here) {
        const node = document.getElementById('pv-crumbs');
        if (node) {
            node.replaceChildren(el('a', {class: 'zt-link', href: to, text: list}),
                el('span', {class: 'zt-muted', text: ' › ' + here}));
        }
    }

    /** The views of a screen: the console's smaller tab bar, a count beside a name as the decision records show it. */
    function viewTabs(tabs, current, label, onPick) {
        const node = el('div', {class: 'zt-tabs', role: 'tablist', 'aria-label': label});
        tabs.forEach(tab => {
            const item = el('button', {type: 'button', role: 'tab', 'aria-selected': String(tab.key === current),
                'data-view': tab.key, text: tab.count == null ? tab.label
                    : t('pqa.cases.tabCount', tab.label, ZT.shortCount(tab.count))});
            item.addEventListener('click', () => {
                if (tab.to) {
                    global.location.assign(tab.to);
                } else if (onPick) {
                    node.querySelectorAll('[role="tab"]').forEach(other => other.setAttribute('aria-selected',
                        String(other === item)));
                    onPick(tab.key);
                }
            });
            node.append(item);
        });
        return node;
    }

    /** A box of labelled choices, the policy center's filter box as the decision records fill it. */
    function filterBox(fields, ...last) {
        // A field of buttons takes a row of the form (the version screens' form grid), so its buttons stay on one line.
        const rows = fields.some(field => field.span);
        const choices = el('div', {class: 'zt-filter-grid' + (rows ? ' pv-form-grid' : '')}, fields.map(field =>
            el(field.span ? 'div' : 'label', {class: 'zt-filter-field' + (field.span ? ' pv-span-all' : '')},
                el('span', {class: 'zt-filter-name', text: field.name}), field.node)));
        return el('div', {class: 'filter-container zt-filter-box'}, el('form', {class: 'zt-filter-form'}, choices,
            last.filter(Boolean).length ? el('div', {class: 'zt-filter-search'}, ...last.filter(Boolean)) : null));
    }

    /** A choice among options [value, words]; the first is chosen unless one is named. */
    function select(label, options, chosen, attributes) {
        const node = el('select', Object.assign({class: 'modern-select', 'aria-label': label}, attributes || {}));
        options.forEach(([value, words]) => node.append(el('option', {value: String(value), text: words,
            selected: String(value) === String(chosen) ? true : null})));
        return node;
    }

    /** The pills of a choice among a few, as the console's period pills. */
    function pills(label, items, chosen, onPick) {
        const node = el('div', {class: 'zt-period', role: 'group', 'aria-label': label});
        items.forEach(([key, words, title]) => {
            const item = el('button', {type: 'button', 'aria-pressed': String(key === chosen), 'data-pick': key,
                text: words, title: title || null});
            item.addEventListener('click', () => {
                node.querySelectorAll('button').forEach(other => other.setAttribute('aria-pressed',
                    String(other === item)));
                if (onPick) {
                    onPick(key);
                }
            });
            node.append(item);
        });
        return node;
    }

    function kpi(options) {
        return span(ZT.kpi(options), 3);
    }

    /** Rows of a value whose value may run long (a path, a sentence): it wraps beside its name. */
    function wrapRows(rows) {
        return el('div', {class: 'zt-result-rows'}, rows.map(row => el('div', {class: 'zt-result-row'},
            el('span', {class: 'zt-result-name', text: row.label}),
            el('span', {class: 'zt-result-value pv-wrap', text: row.value}))));
    }

    /** A card with the pager of its table below it. */
    function withFoot(card, foot) {
        if (foot) {
            card.append(foot);
        }
        return card;
    }

    global.PQA = {
        API, params, kept, page, get, send, word, refused, span, grid, form, link, muted, button, emptyState, failed,
        table, cell, chipCell, fitChips, tipped, toolbar, band, crumbs, viewTabs, filterBox, select, pills, kpi,
        wrapRows, withFoot
    };
})(window);
