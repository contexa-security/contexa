/*
 * Prompt versions, the list (plan 3.10, screen 1): the version in use, how many versions there are, what runs beside
 * it, a newer product version, and every version with what can be done to it.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    const PV = global.PV;
    const el = ZT.el;
    const t = ZT.t;
    const content = document.getElementById('zt-content');
    const PAGE_SIZE = 20;

    async function draw() {
        let view;
        try {
            view = await PV.get('', {hidden: PV.params().get('hidden') === 'true' ? 'true' : null});
        } catch (error) {
            content.replaceChildren(el('div', {class: 'pc-empty', role: 'alert'},
                el('i', {class: 'fas fa-exclamation-triangle', 'aria-hidden': 'true'}),
                el('p', {text: '— ' + t('pv.ui.loadFailed')})));
            return;
        }
        const decision = view.decisionPrompt;
        PV.band(view, {note: t('pv.list.bandNote')});
        const used = view.used || {};
        const usedNumber = used.version ? Number(String(used.version).replace(/^v/, '').split('.')[0]) : null;
        PV.toolbar(view.versions.length && usedNumber ? PV.button(t('pv.action.new'), 'fa-plus', null,
            {primary: true, href: PV.page('/new', {base: usedNumber}), name: 'new'}) : null);
        const cards = ZT.kpiRow(usedCard(view, used), countCard(view), runningCard(view));
        cards.classList.add('pv-kpi-3');
        PV.fill(content,
            cards,
            view.newProduct ? newProductNotice(view.newProduct) : null,
            versionsCard(view, decision),
            el('p', {class: 'zt-muted pv-foot', text: t(decision ? 'pv.list.foot' : 'pv.list.foot.other')}));
    }

    function usedCard(view, used) {
        const sub = used.version ? [
            used.since ? t('pv.list.since', ZT.time(used.since)) : t('pv.list.source.' + (used.source || 'NONE')),
            used.basedOn ? t('pv.list.basedOn', used.basedOn) : null,
            used.changes ? t('pv.list.changes', ZT.count(used.changes)) : null,
            used.createdBy ? t('pv.list.by', used.createdBy) : null
        ].filter(Boolean).join(' · ') : t('pv.list.noVersion');
        return ZT.kpi({tone: 'green', icon: 'fa-check-circle',
            label: t(view.decisionPrompt ? 'pv.list.used' : 'pv.list.used.other'),
            value: used.version || '—',
            sub: used.version && used.title && used.title !== used.version ? used.title + ' · ' + sub : sub,
            title: t('pv.list.usedHelp'),
            href: used.version ? PV.page('/' + used.version.replace(/^v/, '').split('.')[0]) : null});
    }

    function countCard(view) {
        return ZT.kpi({tone: 'indigo', icon: 'fa-layer-group', label: t('pv.list.versions'),
            value: ZT.count(view.counts.total),
            sub: t('pv.list.versionsSub', ZT.count(view.counts.contexa), ZT.count(view.counts.organization))
                + (view.counts.hidden ? ' · ' + t('pv.list.hiddenCount', ZT.count(view.counts.hidden)) : '')});
    }

    function runningCard(view) {
        const running = view.running || {};
        const parts = [];
        if (running.canary) {
            parts.push(t('pv.list.canary', running.canary, running.canaryPercent == null ? '—' : running.canaryPercent));
        }
        if (running.shadow) {
            parts.push(t('pv.list.shadow', running.shadow));
        }
        if (running.trial) {
            parts.push(t('pv.list.trial', running.trial.candidateName));
        }
        return ZT.kpi({tone: 'purple', icon: 'fa-vial', label: t('pv.list.running'),
            value: parts.length ? ZT.count(parts.length) : t('pv.list.runningNone'),
            sub: parts.length ? parts.join(' · ') : t(view.decisionPrompt ? 'pv.list.runningOff' : 'pv.list.runningOff.other'),
            href: running.trial ? PV.page('/trials/' + running.trial.id)
                : view.decisionPrompt ? PV.page('/advanced') : null});
    }

    /** Plan 3.3: a newer product version; the version in use keeps running until its changes are carried over. */
    function newProductNotice(product) {
        const base = product.number;
        const used = Number(String(product.usedVersion).replace(/^v/, '').split('.')[0]);
        return el('div', {class: 'zt-alert', role: 'note', 'data-pv-notice': 'product'},
            el('span', {class: 'status-badge zt-chip', 'data-status': 'WARN', text: t('pv.list.newProduct')}),
            el('div', {class: 'zt-item'},
                el('span', {text: t('pv.list.newProductLine', product.version, product.usedVersion)}),
                el('div', {class: 'pv-actions'},
                    PV.button(t('pv.list.newProductView'), 'fa-eye', null, {href: PV.page('/' + base),
                        name: 'product-view'}),
                    PV.button(t('pv.list.newProductCarry'), 'fa-share', null, {primary: true,
                        href: PV.page('/new', {base, carry: used}), name: 'product-carry'}))));
    }

    function versionsCard(view, decision) {
        const showHidden = PV.params().get('hidden') === 'true';
        const toggle = el('label', {class: 'pv-toggle'}, el('input', {type: 'checkbox', id: 'pv-show-hidden',
            checked: showHidden ? true : null}), el('span', {text: t('pv.list.showHidden')}));
        toggle.querySelector('input').addEventListener('change', event => {
            const params = PV.params();
            if (event.target.checked) {
                params.set('hidden', 'true');
            } else {
                params.delete('hidden');
            }
            global.history.replaceState(null, '', global.location.pathname + (params.toString() ? '?' + params : ''));
            draw();
        });
        if (!view.versions.length) {
            return ZT.card(t('pv.list.table'), null, el('div', {class: 'pc-empty', role: 'note'},
                el('i', {class: 'fas fa-inbox', 'aria-hidden': 'true'}), el('p', {text: '— ' + t('pv.list.empty')})),
            el('div', {class: 'zt-card-foot'}, toggle));
        }
        const pages = Math.max(1, Math.ceil(view.versions.length / PAGE_SIZE));
        const current = Math.min(pages, Math.max(1, Number(PV.params().get('page')) || 1));
        const body = el('tbody');
        view.versions.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE)
            .forEach(row => body.append(versionRow(view, row, decision)));
        const table = el('div', {class: 'zt-table-wrap'}, el('table', {class: 'zt-table modern-table'},
            el('caption', {class: 'zt-sr-only', text: t('pv.list.table')}),
            el('thead', {}, el('tr', {}, ...['number', 'title', 'origin', 'base', 'made', 'state', 'work']
                .map(column => el('th', {scope: 'col', class: WIDE.includes(column) ? 'pv-wide' : null,
                    text: t('pv.list.column.' + column)})))),
            body));
        return ZT.card(t('pv.list.table'), t('pv.list.tableAside', ZT.count(view.versions.length)), table,
            el('div', {class: 'zt-card-foot'}, toggle, pages > 1 ? pager(current, pages) : null));
    }

    /** The pages of the table, twenty rows each (plan 1.0); the page is kept in the address. */
    function pager(current, pages) {
        const go = page => {
            const params = PV.params();
            params.set('page', String(page));
            global.history.replaceState(null, '', global.location.pathname + '?' + params);
            draw();
        };
        return el('nav', {class: 'pv-pager', 'aria-label': t('pv.list.pages')},
            PV.button(t('pv.list.previous'), 'fa-chevron-left', () => go(current - 1),
                {disabled: current <= 1, name: 'previous'}),
            el('span', {class: 'zt-muted zt-num', text: t('pv.list.page', current, pages)}),
            PV.button(t('pv.list.next'), 'fa-chevron-right', () => go(current + 1),
                {disabled: current >= pages, name: 'next'}));
    }

    /** The columns a narrow screen leaves out: their words go under the description, on a short line. */
    const WIDE = ['origin', 'base', 'made', 'state'];

    /** A link of the actions cell: the table keeps its width, the actions stack under one another. */
    function action(label, href, onClick, name) {
        const node = el(href ? 'a' : 'button', {class: 'zt-link pv-row-action', href: href || null,
            type: href ? null : 'button', 'data-pv-action': name, text: label});
        if (onClick) {
            node.addEventListener('click', onClick);
        }
        return node;
    }

    function versionRow(view, row, decision) {
        const actions = el('div', {class: 'pv-row-actions'}, action(t('pv.action.view'), PV.page('/' + row.number), null,
            'view'));
        if (decision && view.trialsOffered && row.state !== 'USED' && !row.hidden) {
            actions.append(action(t('pv.action.trial'), PV.page('/trials', {candidate: row.number}), null, 'trial'));
        }
        if (row.state !== 'USED' && !row.hidden && view.writable) {
            actions.append(action(PV.useLabel(decision), null, () => PV.useVersion(row.number, decision, draw), 'use'));
        }
        if (!row.fromDocument && !row.hidden) {
            actions.append(action(t('pv.action.new'), PV.page('/new', {base: row.number}), null, 'new-from'));
        }
        const provider = row.provider === 'CONTEXA' ? t('pv.provider.CONTEXA') : t('pv.provider.ORGANIZATION');
        const short = [provider, row.basedOn ? t('pv.list.basedOn', row.basedOn) : null, ZT.shortTime(row.createdAt)]
            .filter(Boolean).join(' · ');
        return el('tr', {'data-pv-version': row.number},
            el('td', {}, el('a', {class: 'zt-link', href: PV.page('/' + row.number), text: row.name})),
            el('td', {class: 'zt-fill'}, el('div', {class: 'zt-item'},
                el('span', {class: 'pv-cut', title: row.title || null, text: row.title || '—'}),
                row.description ? el('span', {class: 'zt-muted pv-cut', title: row.description, text: row.description})
                    : null,
                el('span', {class: 'zt-muted pv-cut pv-narrow', title: short, text: short}),
                el('span', {class: 'pv-narrow'}, PV.stateChip(row.state, decision)))),
            el('td', {class: 'pv-wide'}, el('div', {class: 'zt-item'}, el('span', {text: provider}),
                el('span', {class: 'zt-muted pv-cut', title: PV.origin(row), text: PV.origin(row)}))),
            el('td', {class: 'pv-wide', text: row.basedOn || '—'}),
            el('td', {class: 'pv-wide'}, el('div', {class: 'zt-item'}, el('span', {class: 'zt-num', text: ZT.time(row.createdAt)}),
                el('span', {class: 'zt-muted pv-cut', text: PV.maker(row)}))),
            el('td', {class: 'zt-cell-chips pv-wide'}, PV.stateChip(row.state, decision)),
            el('td', {class: 'pv-cell-actions'}, actions));
    }

    draw();
})(window);
