/*
 * The admin dashboard (plan step 9, approved mockup v4): the state of every admin area and the work to do now, drawn
 * from /contexa/admin/api/dashboard with the admin console's components (console-common.js) and Tailwind utilities
 * only. Each area card wears its area's state in its head; three cards gather what no single screen shows: the users to
 * look at across the menus, the recent admin changes and the most refused access. Every visual form names itself in
 * data-form, so no two cards are built alike. The prompt quality card holds its place until its content is settled.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    if (!ZT) {
        return;
    }
    const el = ZT.el;
    const t = ZT.t;
    const C = ZT.COLORS;
    const d = (key, ...args) => t('dashboard.ui.' + key, ...args);
    const o = (key, ...args) => t('zt.console.ui.overview.' + key, ...args);
    const A = '/contexa/admin';
    const Z = A + '/zero-trust';
    const RANK = {BAD: 0, WARN: 1, INFO: 2};
    const TODO_SHOWN = 8;
    const PERIODS = ['day', 'week', 'month', 'quarter'];
    /** The security event log reads a period in hours (D2: the same period as the dashboard). */
    const HOURS = {day: 24, week: 168, month: 720, quarter: 2160};

    /**
     * The seven areas: the left menu's icon of each (its own drawing, read from the menu) and one colour of each, a
     * second mark beside the icon and the name. The system has no top menu: it takes the version screens' sliders.
     */
    const AREAS = {
        iam: {color: '#22d3ee', menu: 'iam', href: A + '/users'},
        policy: {color: '#34d399', menu: 'policy', href: A + '/policy-center'},
        security: {color: '#a78bfa', menu: 'security', href: A + '/security-monitor'},
        agents: {color: '#60a5fa', menu: 'agents', href: A + '/agents'},
        zeroTrust: {color: '#818cf8', menu: 'ai-monitor', href: Z},
        prompt: {color: '#fb923c', menu: 'prompt-quality', href: A + '/prompt-quality/versions'},
        system: {color: '#94a3b8', menu: null, href: A + '/system-settings'}
    };
    /** The areas whose state is not shown yet: the prompt quality card holds its place only. */
    const NO_STATE = ['prompt'];

    // ----- the data of the current draw -----

    let D = null;
    let zt = null;
    let mode = null;
    let off = false;
    let shadow = false;
    let periodKey = 'week';
    let periodName = '';
    let ITEMS = [];
    const charts = [];
    const drawnCharts = [];

    function currentPeriod() {
        const value = ZT.query().get('period');
        return PERIODS.includes(value) ? value : 'week';
    }

    // ----- small helpers -----

    function short(value) {
        return ZT.shortCount(value);
    }

    function whole(value) {
        return value != null && Math.abs(value) >= 10000 ? ZT.count(value) : null;
    }

    function ratio(part, total) {
        return total > 0 ? part / total : null;
    }

    function span(node, columns) {
        node.classList.add('zt-span-' + columns);
        return node;
    }

    function grid(...cards) {
        return el('div', {class: 'zt-grid'}, ...cards);
    }

    function link(href, text) {
        return el('a', {class: 'zt-link', href, text});
    }

    function foot(card, ...nodes) {
        card.append(el('div', {class: 'zt-card-foot'}, ...nodes));
        return card;
    }

    function form(name, node) {
        node.setAttribute('data-form', name);
        return node;
    }

    function countOf(shares, key) {
        return ((shares || []).find(share => share.key === key) || {}).count || 0;
    }

    /**
     * The security event log over the dashboard's period, of a category when one is given; from (K103) names the
     * moment it starts at when a count starts elsewhere than the last hours.
     */
    function events(category, from) {
        return A + '/security-monitor?' + (category ? 'category=' + encodeURIComponent(category) + '&' : '')
            + 'hours=' + HOURS[periodKey] + (from ? '&from=' + encodeURIComponent(from) : '');
    }

    /**
     * K103: the start of the hour the period starts in, as the hourly counts read the period (DashboardQueries.hour:
     * the instant cut to its hour); null when the period names no start.
     */
    function periodHour() {
        const start = D.period && D.period.from ? Date.parse(D.period.from) : NaN;
        return Number.isNaN(start) ? null : new Date(Math.floor(start / 3_600_000) * 3_600_000).toISOString();
    }

    /** The left menu's own icon of a group (its drawing, or its font icon), as its markup; null when the menu has none. */
    function menuIcon(group) {
        if (!group) {
            return null;
        }
        const icon = document.querySelector('.admin-sidebar .main-menu-link[data-group="' + group + '"] .main-menu-icon > *');
        return icon ? icon.outerHTML : null;
    }

    /** An area's icon in its colour: the left menu's own drawing, or the sliders for the system. */
    function areaIcon(area, size) {
        const meta = AREAS[area];
        const node = el('span', {class: 'inline-flex items-center justify-center flex-shrink-0', 'aria-hidden': 'true',
            style: {color: meta.color, width: size + 'px', height: size + 'px'}});
        const icon = menuIcon(meta.menu);
        if (icon) {
            node.innerHTML = icon.replace(/width="24"/, 'width="' + size + '"').replace(/height="24"/, 'height="' + size + '"');
        } else {
            node.append(el('i', {class: 'fas fa-sliders-h'}));
        }
        return node;
    }

    /** A card of an area: its menu icon before its title, its state beside the title. */
    function areaCard(area, title, aside, ...body) {
        const card = ZT.card(title, aside, ...body);
        card.id = 'area-' + area;
        card.setAttribute('data-area', area);
        const heading = card.querySelector('.zt-card-head h2');
        heading.classList.add('flex', 'items-center', 'gap-2');
        heading.prepend(areaIcon(area, 20));
        if (!NO_STATE.includes(area)) {
            // The state beside the title, not in it: a phone puts it on the second head line with the aside.
            const state = areaState(area, ITEMS).chip;
            state.classList.add('flex-shrink-0', 'mr-auto');
            heading.after(state);
        }
        return card;
    }

    // ----- the band: the period chips, the mode, the policy combining, the definition mark -----

    function periodChips(redraw) {
        const container = document.getElementById('zt-period');
        if (!container) {
            return;
        }
        container.replaceChildren();
        PERIODS.forEach(key => {
            const button = el('button', {type: 'button', 'data-period': key, 'aria-pressed': String(key === currentPeriod()),
                text: t('zt.console.ui.period.' + key)});
            button.addEventListener('click', () => {
                const params = ZT.query();
                params.set('period', key);
                global.history.replaceState(null, '', global.location.pathname + '?' + params.toString());
                container.querySelectorAll('button[data-period]').forEach(other => other.setAttribute('aria-pressed',
                    String(other === button)));
                redraw();
            });
            container.append(button);
        });
    }

    function band() {
        const node = document.getElementById('zt-band');
        node.replaceChildren();
        const s = D.system;
        node.append(el('span', {class: 'status-badge zt-mode', 'data-mode': off ? 'DISABLED' : mode},
            (mode === 'ENFORCE' ? '● ' : shadow ? '◐ ' : '○ ') + t('zt.console.ui.mode.' + (off ? 'DISABLED' : mode)),
            !off && s.modeSince ? ' · ' + t('zt.console.ui.since', ZT.day(s.modeSince)) : ''));
        node.append(el('span', {text: d('band.combining',
            t('admin.system.settings.combining.algorithm.' + s.combining.toLowerCase()))}));
        node.append(el('span', {class: 'zt-band-info', title: d('band.note'), tabindex: '0', role: 'note',
            'aria-label': d('band.note')}, el('i', {class: 'fas fa-info-circle', 'aria-hidden': 'true'})));
        if (shadow) {
            node.append(el('span', {class: 'zt-band-note', text: t('zt.console.ui.band.shadow')}));
        }
        if (s.standalone) {
            node.append(el('span', {class: 'zt-warning', role: 'note', text: t('zt.console.ui.band.standalone')}));
        }
    }

    // ----- what to do: every menu's open work, the worst first -----

    function todoItems() {
        const items = [];
        // guide (K90): work done elsewhere: the row says where (text), its link leads to the area's list (link)
        const add = (area, severity, text, href, rule, guide) => items.push({area, severity, text, href, rule, guide});
        const iam = D.iam;
        const policy = D.policy;
        const security = D.security;
        if (iam.adminsWithoutMfa > 0) {
            add('iam', 'BAD', d('todo.adminsWithoutMfa', ZT.count(iam.adminsWithoutMfa)), A + '/users',
                d('todo.adminsWithoutMfa.rule'));
        }
        if (security.sealMismatch > 0) {
            // K103: the log opens from the hour the seal count starts at, so it lists the records counted
            add('security', 'BAD', d('todo.sealBroken', ZT.count(security.sealMismatch)),
                events('SECURITY_DECISION', periodHour()), d('todo.sealBroken.rule'));
        }
        if (policy.healthStatus === 'CRITICAL') {
            add('policy', 'BAD', d('todo.policyConflicts', ZT.count(policy.conflictCount), ZT.count(policy.duplicateCount)),
                A + '/policy-center?tab=list', d('todo.policyConflicts.rule'));
        }
        (zt.alerts || []).filter(alert => alert.severity === 'WARN').forEach(alert => add('zeroTrust', 'WARN',
            alert.message, ZT.keepPeriod(alert.link), t('zt.console.ui.overview.alerts.rule.' + alert.key)));
        if (zt.reviewPending > 0) {
            add('zeroTrust', 'WARN', d('todo.reviewQueue', ZT.count(zt.reviewPending)), Z + '/decisions?view=review',
                d('todo.reviewQueue.rule'));
        }
        const requests = countOf(D.blocked.byLatestStatus, 'UNBLOCK_REQUESTED');
        if (requests > 0) {
            add('security', 'WARN', d('todo.unblockRequests', ZT.count(requests)),
                A + '/blacklist?filter=unblock_requested', d('todo.unblockRequests.rule'));
        }
        if (policy.pendingApproval > 0) {
            add('policy', 'WARN', d('todo.pendingPolicies', ZT.count(policy.pendingApproval)),
                A + '/policy-center?tab=list&approvalStatus=PENDING', d('todo.pendingPolicies.rule'));
        }
        if (policy.healthStatus !== 'CRITICAL' && (policy.conflictCount > 0 || policy.duplicateCount > 0)) {
            add('policy', 'WARN', d('todo.policyConflicts', ZT.count(policy.conflictCount),
                ZT.count(policy.duplicateCount)), A + '/policy-center?tab=list', d('todo.policyConflicts.rule'));
        }
        if (D.agents.confirmations > 0) {
            // K90: a sponsor confirms an agent's request from the mail, not here: the row says so and leads to the agents
            add('agents', 'WARN', d('todo.agentConfirmations', ZT.count(D.agents.confirmations)), A + '/agents',
                d('todo.agentConfirmations.rule'), {text: d('agents.confirmByMail'), link: d('agents.link.list')});
        }
        if (iam.locked > 0) {
            add('iam', 'WARN', d('todo.lockedAccounts', ZT.count(iam.locked)), A + '/users', d('todo.lockedAccounts.rule'));
        }
        if (off) {
            add('zeroTrust', 'INFO', d('todo.ztOff'), A + '/system-settings', d('todo.ztOff.rule'));
        }
        if (shadow && zt.adoption && zt.adoption.unmet > 0) {
            add('zeroTrust', 'INFO', d('todo.adoption', ZT.count(zt.adoption.unmet)), Z + '/adoption',
                d('todo.adoption.rule'));
        }
        if (iam.usersWithoutFactor > 0) {
            add('iam', 'INFO', d('todo.usersWithoutFactor', ZT.count(iam.usersWithoutFactor)), A + '/users',
                d('todo.usersWithoutFactor.rule'));
        }
        if (D.system.missingMethodDecision === 'PERMIT') {
            add('system', 'INFO', d('todo.missingMethodPermit'), A + '/system-settings',
                d('todo.missingMethodPermit.rule'));
        }
        (zt.alerts || []).filter(alert => alert.severity === 'INFO').forEach(alert => add('zeroTrust', 'INFO',
            alert.message, ZT.keepPeriod(alert.link), t('zt.console.ui.overview.alerts.rule.' + alert.key)));
        if (!iam.activeHierarchies) {
            add('iam', 'INFO', d('todo.roleHierarchy'), A + '/role-hierarchies');
        }
        return items.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
    }

    function severityChip(severity, count) {
        return ZT.statusChip(severity, d('todo.severity', t('zt.console.ui.status.' + severity), ZT.count(count)));
    }

    // ----- an area's state in words: the worst of its work, or off, none, observing -----

    function areaState(area, items) {
        const mine = items.filter(item => item.area === area);
        const worst = mine.length ? mine[0].severity : null;
        if (area === 'zeroTrust' && off) {
            return {mine, chip: ZT.statusChip(null, d('areas.status.OFF'))};
        }
        if (area === 'agents' && D.agents.byStatus.length === 0) {
            return {mine, chip: ZT.statusChip(null, d('areas.status.NONE'))};
        }
        if (area === 'zeroTrust' && shadow && !worst) {
            return {mine, chip: ZT.statusChip(null, d('areas.status.SHADOW'))};
        }
        return {mine, chip: ZT.statusChip(worst || 'GOOD')};
    }

    // ----- the work queue: the head counts by severity, a row per piece of work with its area and its button -----

    /**
     * K101: a row's link in the button's place, as wide as the button: an unseen button of the same words keeps the
     * room and the link lies over it, its words wrapping inside.
     */
    function guideLink(item) {
        return el('span', {class: 'zt-action-slot'},
            el('span', {class: 'modern-btn-secondary', 'aria-hidden': 'true', text: d('todo.process')}),
            el('a', {class: 'zt-link', href: item.href, text: item.guide.link}));
    }

    function queueCard(items) {
        // K101: the rows share their columns (zt-queue-rows): every severity badge at one x, every action in one place.
        const card = ZT.card(d('todo.title'), null, items.length ? form('work-queue', el('div', {class: 'zt-indicators zt-queue-rows'},
            items.slice(0, TODO_SHOWN).map(item => el('div', {class: 'zt-indicator flex-wrap', 'data-severity': item.severity,
                title: item.rule || null},
            el('div', {class: 'flex items-center gap-3 min-w-0'}, areaIcon(item.area, 20),
                el('div', {class: 'zt-indicator-text'}, el('span', {class: 'zt-indicator-title', text: item.text}),
                    el('span', {class: 'zt-indicator-rule', text: d('area.' + item.area)}),
                    item.guide ? el('span', {class: 'zt-indicator-rule', text: item.guide.text}) : null)),
            el('div', {class: 'zt-queue-act flex items-center gap-3 flex-shrink-0'}, ZT.statusChip(item.severity),
                item.guide ? guideLink(item) : el('a', {class: 'modern-btn-secondary', href: item.href,
                    text: d('todo.process')}))))))
            : ZT.emptyNote(d('todo.none')));
        card.id = 'dash-queue';
        const counts = ['BAD', 'WARN', 'INFO'].map(severity => [severity,
            items.filter(item => item.severity === severity).length]).filter(([, n]) => n > 0);
        // The counts by severity beside the title; on a phone under it, at the top of the body, on as many lines as
        // their words need (K89: a head keeps its two lines in every language).
        card.querySelector('.zt-card-head').append(el('span', {class: 'flex items-center gap-2 flex-shrink-0 max-sm:hidden'},
            counts.map(([severity, n]) => severityChip(severity, n))));
        if (counts.length) {
            card.querySelector('.zt-card-body').prepend(el('div', {class: 'flex flex-wrap items-center gap-2 sm:hidden'},
                counts.map(([severity, n]) => severityChip(severity, n))));
        }
        if (items.length > TODO_SHOWN) {
            foot(card, el('span', {class: 'zt-muted', text: d('todo.more', TODO_SHOWN, items.length - TODO_SHOWN)}));
        }
        return card;
    }

    // ----- the opening sentence and the four headline numbers (in the area colours) -----

    function summary(items) {
        const s = zt.summary;
        const inForce = D.blocked.inForce;
        const main = off ? d('summary.off', ZT.count(inForce))
            : d(shadow ? 'summary.shadow' : 'summary.main', periodName, ZT.count(s.decisions), ZT.count(s.stopped),
                ZT.percent(s.stoppedRatio), ZT.count(inForce));
        return el('div', {class: 'zt-summary'},
            el('p', {class: 'zt-summary-main', text: main}),
            el('p', {class: 'zt-summary-sub', text: items.length ? d('summary.todo', ZT.count(items.length), items[0].text)
                : d('summary.noTodo')}));
    }

    function keyCards() {
        const coverage = zt.coverage.coverage;
        const days = zt.trend || [];
        const blocked = D.blocked;
        const iam = D.iam;
        const p = D.policy;
        const counted = p.resourcePolicyConnected + p.resourcePermissionCreated + p.resourceNeedsDefinition;
        const card = options => span(ZT.kpi(options), 3);
        return grid(
            card({tone: 'indigo', icon: 'fa-shield-alt', label: coverage.label, href: Z,
                value: off || coverage.value == null ? null : ZT.metricText(coverage),
                title: off ? coverage.description : d('kpi.full', coverage.description, ZT.count(coverage.numerator),
                    ZT.count(coverage.denominator)),
                sub: off ? d('kpi.coverage.off') : d('kpi.coverage.sub', short(coverage.numerator),
                    short(coverage.denominator)),
                trend: off ? [] : days.map(day => ratio((day.protectedDecisions || 0) + (day.reused || 0),
                    day.protectedCalls))}),
            card({tone: 'purple', icon: 'fa-user-slash', label: d('kpi.blocked.label'), href: '#area-security',
                value: short(blocked.inForce),
                title: d('kpi.blocked.def') + (whole(blocked.inForce) ? ' (' + whole(blocked.inForce) + ')' : ''),
                sub: blocked.inForce ? d('kpi.blocked.sub', short(countOf(blocked.byLatestStatus, 'UNBLOCK_REQUESTED')),
                    short(countOf(blocked.byLatestStatus, 'MFA_FAILED'))) : d('kpi.blocked.none')}),
            card({tone: 'teal', icon: 'fa-user-shield', label: d('kpi.mfa.label'), href: '#area-iam',
                value: ZT.percent(ratio(iam.mfaEnabled, iam.activeAccounts)),
                title: d('kpi.full', d('kpi.mfa.def'), ZT.count(iam.mfaEnabled), ZT.count(iam.activeAccounts)),
                sub: d('kpi.mfa.sub', short(iam.mfaEnabled), short(iam.activeAccounts))}),
            card({tone: 'green', icon: 'fa-sitemap', label: d('kpi.resources.label'), href: '#area-policy',
                value: counted ? ZT.percent(ratio(p.resourcePolicyConnected, counted)) : null,
                title: counted ? d('kpi.full', d('kpi.resources.def'), ZT.count(p.resourcePolicyConnected),
                    ZT.count(counted)) : d('kpi.resources.def'),
                sub: counted ? d('kpi.resources.sub', short(p.resourcePolicyConnected), short(counted))
                    : d('kpi.resources.none')}));
    }

    // ----- IAM: a ring meter of one ratio, account hygiene tiles, the scale as icon counts -----

    function iamCard() {
        const iam = D.iam;
        const colour = AREAS.iam.color;
        const mfa = ratio(iam.mfaEnabled, iam.activeAccounts);
        const without = Math.max(0, iam.activeAccounts - iam.mfaEnabled);
        const ring = form('ring-meter', el('div', {class: 'zt-result'},
            el('div', {class: 'zt-donut'}, ZT.donut([
                {label: d('iam.ringCaption'), count: iam.mfaEnabled, color: colour},
                {label: d('iam.ringCaption'), count: without, color: C.TRACK}],
            {label: d('iam.ringCaption') + ' ' + ZT.percent(mfa)}),
            el('div', {class: 'zt-donut-centre'}, el('div', {class: 'zt-donut-value', text: ZT.percent(mfa, 0)}),
                el('div', {class: 'zt-donut-caption', text: d('iam.ringCaption')}))),
            el('div', {class: 'zt-muted', text: d('iam.ringLegend', short(iam.mfaEnabled), short(without))})));
        // The decision screen's fact cell: the number, then the mark and the name (0 calm, more in the warning colour).
        const hygieneTile = (value, label, href) => el('a', {class: 'zt-fact flex flex-col gap-1 min-w-0', href},
            el('span', {class: 'text-lg font-bold', style: {color: value > 0 ? C.WARN : C.TEXT}, text: short(value),
                title: whole(value)}),
            el('span', {class: 'zt-muted break-keep'}, el('i', {class: 'fas ' + (value > 0 ? 'fa-exclamation-triangle' : 'fa-check'),
                'aria-hidden': 'true', style: {color: value > 0 ? C.WARN : C.GOOD, marginRight: '4px'}}), label));
        const hygiene = form('hygiene-tiles', el('div', {class: 'grid grid-cols-1 sm:grid-cols-3 gap-2'},
            hygieneTile(iam.locked, d('iam.lockedShort'), A + '/users'),
            hygieneTile(iam.dormant, d('iam.dormantShort'), A + '/users'),
            hygieneTile(iam.expired, d('iam.expiredShort'), A + '/password-policy')));
        const countItem = (icon, value, label, href) => el('a', {class: 'flex flex-col items-center gap-1 min-w-0', href},
            el('i', {class: 'fas ' + icon, 'aria-hidden': 'true', style: {color: colour}}),
            el('span', {class: 'text-sm font-bold', text: short(value), title: whole(value)}),
            el('span', {class: 'zt-muted', text: label}));
        const counts = form('icon-counts', el('div', {class: 'grid grid-cols-5 gap-2'},
            countItem('fa-user', iam.userCount, d('iam.users'), A + '/users'),
            countItem('fa-layer-group', iam.groupCount, d('iam.groups'), A + '/groups'),
            countItem('fa-user-tag', iam.roleCount, d('iam.roles'), A + '/roles'),
            countItem('fa-key', iam.permissionCount, d('iam.permissions'), A + '/permissions'),
            countItem('fa-user-cog', iam.admins, d('iam.admins'), A + '/users')));
        return foot(areaCard('iam', d('area.iam'), d('iam.aside'), ring, ZT.subhead(d('iam.hygiene')), hygiene,
            ZT.subhead(d('iam.scale')), counts),
        link(A + '/users', d('iam.link.users')), link(A + '/access-center', d('iam.link.access')),
        link(A + '/password-policy', d('iam.link.password')));
    }

    // ----- policy: the protection of the resources as one tall segmented bar, the approval flow, a week of changes -----

    function policyCard() {
        const p = D.policy;
        const week = t('zt.console.ui.period.week');
        const counted = p.resourcePolicyConnected + p.resourcePermissionCreated + p.resourceNeedsDefinition;
        const parts = [
            {label: d('policy.connected'), count: p.resourcePolicyConnected, color: C.GOOD},
            {label: d('policy.permissionOnly'), count: p.resourcePermissionCreated, color: C.WARN},
            {label: d('policy.needsDefinition'), count: p.resourceNeedsDefinition, color: C.BAD}];
        const bar = el('div', {class: 'zt-stacked', style: {height: '2rem'}, role: 'img',
            'aria-label': parts.map(part => part.label + ' ' + ZT.count(part.count)).join(', ')});
        if (counted) {
            parts.filter(part => part.count > 0).forEach(part => {
                const share = part.count / counted;
                bar.append(el('span', {class: 'flex items-center justify-center text-xs font-semibold',
                    title: part.label + ' ' + ZT.count(part.count),
                    style: {width: (share * 100) + '%', background: part.color, color: '#0f172a', display: 'flex',
                        alignItems: 'center', justifyContent: 'center'},
                    text: share >= 0.12 ? ZT.percent(share, 0) : ''}));
            });
        }
        const segmented = form('segmented-bar', el('div', {class: 'flex flex-col gap-2'}, bar,
            ZT.legend(parts.map(part => ({label: part.label + ' ' + short(part.count), color: part.color})))));
        const step = (value, label, href) => el('a', {class: 'zt-tile flex flex-col gap-1 flex-1 min-w-0', href},
            el('span', {class: 'text-2xl font-bold', text: short(value), title: whole(value)}),
            el('span', {class: 'zt-muted', text: label}));
        const arrow = () => el('i', {class: 'fas fa-arrow-right zt-muted max-sm:hidden', 'aria-hidden': 'true'});
        // A policy check that could not run counts nothing: its badges say "—", in no state's colour.
        const checked = p.conflictCount != null && p.duplicateCount != null;
        const flow = form('approval-flow', el('div', {class: 'flex flex-col gap-3'},
            el('div', {class: 'grid grid-cols-1 gap-3 sm:flex sm:items-center min-w-0'},
                step(p.pendingApproval, d('policy.flow.pending'), A + '/policy-center?tab=list&approvalStatus=PENDING'),
                arrow(), step(p.approved, d('policy.flow.approved'), A + '/policy-center?tab=list&approvalStatus=APPROVED'),
                arrow(), step(p.activePolicies, d('policy.flow.active'), A + '/policy-center?tab=list')),
            el('div', {class: 'flex flex-wrap items-center gap-2'},
                ZT.statusChip(!checked ? null : p.conflictCount ? 'WARN' : 'GOOD',
                    d('policy.badge.conflicts', short(p.conflictCount))),
                ZT.statusChip(!checked ? null : p.duplicateCount ? 'WARN' : 'GOOD',
                    d('policy.badge.duplicates', short(p.duplicateCount))),
                ZT.statusChip(null, d('policy.flow.rejected', short(p.rejected))))));
        const days = p.changesByDay.map(day => day.day);
        // The console's heat map: the days across on a wide card, down on a phone (7 columns hold no 7-digit count there).
        const cells = p.changesByDay.map(day => ({row: 'changes', column: day.day, count: day.count}));
        const heat = form('heat-strip', el('div', {class: 'zt-heat'},
            el('div', {class: 'max-sm:hidden'}, ZT.heatmap(['changes'], days, cells, () => d('policy.changesRow'),
                day => ZT.day(day))),
            el('div', {class: 'sm:hidden'}, ZT.heatmap(days, ['changes'], cells.map(cell => ({row: cell.column,
                column: cell.row, count: cell.count})), day => ZT.day(day), () => d('policy.changesRow')))));
        const card = areaCard('policy', d('area.policy'), d('policy.aside', week),
            ZT.subhead(d('policy.protection')), segmented, ZT.subhead(d('policy.flow')), flow,
            ZT.subhead(d('policy.changesByDay', week)), heat);
        ZT.withTip(card, d('policy.excludedTip', short(p.resourceTotal - counted)));
        return foot(card, link(A + '/policy-center', d('policy.link.center')),
            link(A + '/policy-center?tab=resources', d('policy.link.resources')), link(A + '/permissions',
                d('policy.unusedPermissions') + ' ' + short(p.unusedPermissions) + ' ›'));
    }

    // ----- security: the week of failed authentications as bars, the blocked users now as the console's donut -----

    const BLOCK_COLOURS = {BLOCKED: C.BLOCK, UNBLOCK_REQUESTED: C.CHALLENGE, MFA_FAILED: C.ESCALATE,
        TIMEOUT_RESPONDED: C.MUTED};

    function securityCard() {
        const s = D.security;
        const b = D.blocked;
        const week = t('zt.console.ui.period.week');
        const box = el('div');
        const has = s.failuresByDay.some(day => day.count > 0);
        charts.push(() => ZT.chart(box, 'l', {type: 'bar', label: d('security.failuresLabel'),
            data: {labels: s.failuresByDay.map(day => ZT.day(day.day)), datasets: [{label: d('security.authFailures'),
                data: s.failuresByDay.map(day => day.count), backgroundColor: AREAS.security.color, borderRadius: 4,
                maxBarThickness: 32}]}},
        has, 'NO_DECISIONS'));
        const trend = form('bar-trend', el('div', {class: 'flex flex-col gap-3 min-w-0'},
            ZT.subhead(d('security.failuresByDay', week)), box));
        if (!has) {
            box.replaceWith(ZT.emptyNote(d('security.noFailures')));
        }
        const parts = ['BLOCKED', 'UNBLOCK_REQUESTED', 'MFA_FAILED', 'TIMEOUT_RESPONDED'].map(key => ({key,
            label: d('blocks.status.' + key), count: countOf(b.byLatestStatus, key), color: BLOCK_COLOURS[key]}));
        const ring = el('div', {class: 'zt-donut'}, ZT.donut(parts, {label: d('security.blockedTitle')}),
            el('div', {class: 'zt-donut-centre'}, el('div', {class: 'zt-donut-value', text: short(b.inForce),
                title: whole(b.inForce)}), el('div', {class: 'zt-donut-caption', text: d('security.blockedCaption')})));
        const legend = el('div', {class: 'zt-result-rows'}, parts.map(part => el('a', {class: 'zt-result-row',
            href: A + '/blacklist'}, el('span', {class: 'zt-result-name'}, el('span', {class: 'zt-dot',
            style: {background: part.color}}), part.label), el('span', {class: 'zt-result-value', text: short(part.count),
            title: whole(part.count)}))));
        const donut = form('status-donut', el('div', {class: 'flex flex-col gap-3 min-w-0'},
            ZT.subhead(d('security.blockedTitle')), el('div', {class: 'zt-result'}, ring, legend)));
        const facts = form('facts', el('div', {class: 'zt-facts'}, [
            [d('security.ipDeny'), s.ipDeny], [d('security.sessions'), s.recentSessions],
            [d('security.overrides'), s.overrides], [d('security.sealBroken'), s.sealMismatch]].map(([name, value]) =>
            el('div', {class: 'zt-facts-item'}, el('span', {class: 'zt-facts-name', text: name}),
                el('span', {class: 'zt-facts-value', text: short(value), title: whole(value)})))));
        return foot(areaCard('security', d('area.security'), d('security.aside', periodName),
            el('div', {class: 'zt-split'}, trend, donut), facts),
        link(events(null), d('security.link.events')), link(A + '/blacklist', d('security.link.blocked')),
        link(A + '/session-management', d('security.link.sessions')), link(A + '/ip-management', d('security.link.ip')));
    }

    // ----- agents: the queue waiting for a person as the hero, the states as a meter list, the alarms as events -----

    const ALARMS = [['callLimit', 'fa-tachometer-alt'], ['denialAlarm', 'fa-ban'], ['narrowed', 'fa-compress-alt'],
        ['stoppedDelegations', 'fa-pause-circle']];

    function agentsCard() {
        const a = D.agents;
        const links = [link(A + '/agents', d('agents.link.list')), link(A + '/blacklist/agents', d('agents.link.stops'))];
        if (!a.byStatus.length) {
            return foot(areaCard('agents', d('area.agents'), d('agents.aside', periodName),
                form('empty-state', ZT.emptyNote(d('agents.none')))), ...links);
        }
        // K90: the counts stay the hero; a sponsor confirms from the mail, so in place of a button the tile says so. The
        // card's foot leads to the agents in every state, the empty one too.
        const hero = form('hero-queue', el('div', {class: 'zt-tile flex flex-wrap items-end justify-between gap-3'},
            el('div', {class: 'zt-metric'}, el('span', {class: 'zt-metric-label', text: d('agents.queue')}),
                el('span', {class: 'zt-metric-value', text: d('unitCount', short(a.confirmations)),
                    title: whole(a.confirmations)}),
                el('span', {class: 'zt-metric-ratio', style: {color: a.confirmationsOverdue ? C.WARN : null},
                    text: d('agents.overdue', short(a.confirmationsOverdue))})),
            el('span', {class: 'zt-muted text-right min-w-0', text: d('agents.confirmByMail')})));
        const total = a.byStatus.reduce((sum, share) => sum + share.count, 0);
        const colours = {ACTIVE: AREAS.agents.color, SUSPENDED: C.BLOCK, DEREGISTERED: C.MUTED};
        const meters = form('meter-list', el('div', {class: 'zt-reason-rows'},
            ['ACTIVE', 'SUSPENDED', 'DEREGISTERED'].map(key => {
                const value = countOf(a.byStatus, key);
                return el('a', {class: 'zt-reason-row', href: A + '/agents?filter=' + key.toLowerCase()},
                    el('div', {class: 'zt-reason-head'}, el('span', {class: 'zt-reason-name', text: d('agents.status.' + key)}),
                        el('span', {class: 'zt-reason-value', text: d('agents.statusValue', short(value), short(total))})),
                    ZT.bar(value, total, {color: colours[key], label: d('agents.status.' + key)}));
            })));
        const lastAt = a.lastAt || {};
        const alarms = form('event-list', el('ul', {class: 'zt-rows'}, ALARMS.map(([key, icon]) => el('li',
            {class: 'zt-row'}, el('span', {class: 'flex items-center gap-2 min-w-0'},
                el('i', {class: 'fas ' + icon, 'aria-hidden': 'true', style: {color: a[key] ? C.WARN : C.MUTED}}),
                el('span', {class: 'flex flex-col min-w-0'},
                    el('span', {text: d(key === 'stoppedDelegations' ? 'agents.stoppedDelegations' : 'agents.' + key)}),
                    el('span', {class: 'zt-muted', text: d('agents.lastAt', a[key] && lastAt[key] ? ZT.shortTime(lastAt[key]) : '—')}))),
            el('span', {text: d('unitCount', short(a[key])), title: whole(a[key])})))));
        return foot(areaCard('agents', d('area.agents'), d('agents.aside', periodName), hero,
            ZT.subhead(d('agents.statusTitle')), meters, ZT.subhead(d('agents.alarms', periodName)), alarms), ...links);
    }

    // ----- Zero Trust: the console's stacked trend -----

    function zeroTrustCard() {
        const links = [link(ZT.consoleLink('', {period: periodKey}), d('zt.link.overview')),
            link(ZT.consoleLink('/decisions', {period: periodKey}), d('zt.link.decisions')),
            link(Z + '/adoption', d('zt.link.adoption'))];
        if (off) {
            return foot(areaCard('zeroTrust', d('zt.title'), d('zt.aside', periodName),
                form('empty-state', ZT.emptyNote(d('zt.off')))), link(A + '/system-settings', d('zt.link.settings')), ...links);
        }
        const s = zt.summary;
        const days = zt.trend || [];
        const actions = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'];
        const datasets = actions.map(action => ({type: 'bar', label: t('zt.console.ui.action.' + action),
            data: days.map(p => p[action.toLowerCase()]), backgroundColor: C[action], stack: 'decisions',
            borderRadius: 4, maxBarThickness: 48}));
        datasets.push({type: 'line', label: o('trend.noDecision'), data: days.map(p => p.noDecision),
            borderColor: C.MUTED, backgroundColor: C.MUTED, borderDash: [4, 4], pointRadius: 2, stack: 'noDecision'});
        const box = el('div');
        const has = days.some(p => p.allow + p.challenge + p.escalate + p.block + p.noDecision > 0);
        charts.push(() => ZT.chart(box, 'l', {type: 'bar', label: o('trend.label'),
            data: {labels: days.map(p => ZT.day(p.day)), datasets},
            axes: {x: {stacked: true}, y: {stacked: true}}}, has, 'NO_DECISIONS'));
        const stopped = zt.stopped.stopped;
        const pass = zt.impact.challengePass.metric;
        const model = zt.trust.modelDecided;
        const factItems = [[d('zt.decisions'), short(s.decisions), whole(s.decisions)],
            [shadow ? o('stopped.metric.shadow') : stopped.label, ZT.metricText(stopped), stopped.description],
            [pass.label, ZT.metricText(pass), pass.description],
            [model.label, ZT.metricText(model), model.description],
            [zt.coverage.noDecision.label, short(zt.coverage.noDecision.value), whole(zt.coverage.noDecision.value)]];
        const body = [form('facts', el('div', {class: 'zt-facts'}, factItems.map(([name, value, title]) =>
            el('div', {class: 'zt-facts-item'}, el('span', {class: 'zt-facts-name', text: name}),
                el('span', {class: 'zt-facts-value', text: value, title: title || null}))))),
        form('stacked-chart', el('div', {class: 'flex flex-col gap-3 min-w-0'},
            ZT.legend(datasets.map(dataset => ({label: dataset.label, color: dataset.backgroundColor}))), box))];
        if (shadow) {
            body.push(el('div', {class: 'zt-muted', text: o('trend.shadow')}));
        }
        return foot(areaCard('zeroTrust', d('zt.title'), d('zt.aside', periodName), ...body), ...links);
    }

    // ----- prompt quality: the card's place and head only, until its content is settled -----

    function promptCard() {
        return areaCard('prompt', d('area.prompt'), null, form('empty-state', ZT.emptyNote(d('prompt.pending'))));
    }

    // ----- system: the settings as key and value, a badge where the value is a state -----

    function systemCard() {
        const s = D.system;
        const components = D.operations.components.filter(component => component.status !== 'UNKNOWN');
        const good = components.filter(component => component.status === 'GOOD').length;
        const worst = components.some(component => component.status === 'BAD') ? 'BAD'
            : components.some(component => component.status === 'WARN') ? 'WARN' : 'GOOD';
        const chipRow = (name, status, text, href, title) => el('a', {class: 'zt-result-row', href, title: title || null},
            el('span', {class: 'zt-result-name', text: name}), ZT.statusChip(status, text));
        const valueRow = (name, value, href, title) => el('a', {class: 'zt-result-row', href, title: title || null},
            el('span', {class: 'zt-result-name', text: name}), el('span', {class: 'zt-result-value', text: value}));
        const rows = form('kv-badges', el('div', {class: 'zt-result-rows'},
            chipRow(d('system.mode'), off ? null : shadow ? 'WARN' : 'GOOD',
                t('zt.console.ui.mode.' + (off ? 'DISABLED' : mode)), A + '/system-settings'),
            valueRow(d('system.lastChange'), s.lastModeChange ? ZT.day(s.lastModeChange.at) : '—', Z + '/adoption',
                s.lastModeChange ? s.lastModeChange.by : null),
            valueRow(d('system.combining'), t('admin.system.settings.combining.algorithm.' + s.combining.toLowerCase()),
                A + '/system-settings'),
            chipRow(d('system.missingMethod'), s.missingMethodDecision === 'PERMIT' ? 'WARN' : 'GOOD',
                d('system.decision.' + s.missingMethodDecision), A + '/system-settings', d('todo.missingMethodPermit.rule')),
            chipRow(d('system.noMatchingUrl'), s.noMatchingUrlDecision === 'PERMIT' ? 'WARN' : 'GOOD',
                d('system.decision.' + s.noMatchingUrlDecision), A + '/system-settings'),
            valueRow(d('system.retention'), d('system.retentionValue', s.auditRetentionDays), A + '/system-settings'),
            chipRow(d('system.engine'), components.length ? worst : null,
                components.length ? d('system.engineValue', good, components.length) : '—', Z + '/operations')));
        return foot(areaCard('system', d('area.system'), d('system.aside'), rows),
            link(A + '/system-settings', d('system.link.settings')), link(Z + '/operations', d('system.link.operations')));
    }

    // ----- A: the users to look at across the menus: a user per row, the signals as chips, the way to open them -----

    const SIGNAL_STATUS = {BLOCKED: 'BAD', MFA_FAILED: 'BAD', TIMEOUT_RESPONDED: 'BAD', ADMIN_NO_MFA: 'BAD',
        REPEATED: 'BAD', UNBLOCK_REQUESTED: 'WARN', LOCKED: 'WARN', LOGIN_FAILURES: 'WARN', CHALLENGES: 'WARN'};

    function attentionCard() {
        const a = D.attention;
        const links = [link(A + '/users', d('attention.link.users')), link(A + '/blacklist', d('attention.link.blocked'))];
        if (!a.rows.length) {
            return foot(ZT.withTip(ZT.card(d('attention.title'), d('attention.aside', 0, 0),
                form('empty-state', ZT.emptyNote(d('attention.none')))), d('attention.tip')), ...links);
        }
        const chip = signal => {
            const node = ZT.statusChip(SIGNAL_STATUS[signal.kind], d('attention.signal.' + signal.kind, short(signal.count)));
            node.title = d('attention.signal.' + signal.kind, ZT.count(signal.count));
            return node;
        };
        // A block opens its decision; step-ups open the user's step-ups of the period in the decision records (K80, K94:
        // by the records' exact user filter, never another user whose path holds the name); the other signals open the
        // user.
        const openOf = row => row.requestId ? Z + '/decisions/request/' + encodeURIComponent(row.requestId)
            : row.signals.some(signal => signal.kind === 'CHALLENGES') ? Z + '/decisions?action=CHALLENGE&user='
                + encodeURIComponent(row.user) + '&period=' + periodKey
                : A + '/users?keyword=' + encodeURIComponent(row.user);
        const head = el('thead', {}, el('tr', {},
            el('th', {scope: 'col', text: d('attention.column.user')}),
            el('th', {scope: 'col', text: d('attention.column.signals')}),
            el('th', {scope: 'col', class: 'zt-num zt-wide', text: d('attention.column.last')}),
            el('th', {scope: 'col', text: d('attention.column.open')})));
        const rows = a.rows.map(row => el('tr', {},
            // The name is a text cell (cut at the console's limit, whole in its title); the signals fill the row.
            el('td', {}, el('span', {title: row.user, text: row.user})),
            el('td', {class: 'zt-fill zt-cell-chips'}, row.signals.map(chip)),
            el('td', {class: 'zt-num zt-wide', text: row.lastAt ? ZT.shortTime(row.lastAt) : '—'}),
            el('td', {}, el('a', {class: 'zt-link', href: openOf(row), title: d('attention.view')},
                el('span', {class: 'zt-long', text: d('attention.view')}),
                el('span', {class: 'zt-short', text: d('attention.viewShort')})))));
        // A phone has no room for the chips beside the name: each user is one cell there, the chips under the name.
        const phone = el('div', {class: 'flex flex-col gap-2'}, a.rows.map(row => el('div', {class: 'zt-fact flex flex-col gap-2'},
            el('div', {class: 'flex items-start justify-between gap-3'}, el('span', {class: 'font-semibold',
                style: {overflowWrap: 'anywhere'}, text: row.user}), el('a', {class: 'zt-link flex-shrink-0', href: openOf(row),
                text: d('attention.view')})),
            el('div', {class: 'flex flex-wrap gap-1'}, row.signals.map(chip)),
            el('span', {class: 'zt-muted', text: d('attention.column.last') + ' ' + (row.lastAt ? ZT.shortTime(row.lastAt) : '—')}))));
        const table = form('signal-table', el('div', {},
            el('div', {class: 'modern-table zt-table-wrap max-sm:hidden'}, el('table', {class: 'zt-table'}, head,
                el('tbody', {}, rows))),
            el('div', {class: 'sm:hidden'}, phone)));
        // When a source had more users than were read, the count is at least the number shown.
        const card = ZT.card(d('attention.title'), d('attention.aside', ZT.count(a.rows.length),
            short(a.withSignals) + (a.capped ? '+' : '')), table);
        ZT.withTip(card, d('attention.tip'));
        return foot(card, ...links);
    }

    // ----- B: the recent admin changes: who changed what and when, down a timeline; the period's counts by kind -----

    const KIND_AREA = {POLICY: 'policy', USER: 'iam', ROLE: 'iam', PROMPT: 'prompt', MODE: 'system',
        OVERRIDE: 'security', AGENT: 'agents', GROUP: 'iam', PERMISSION: 'iam', HIERARCHY: 'iam', ASSIGNMENT: 'iam',
        PASSWORD: 'iam', MENU: 'system', SETTINGS: 'system', IP: 'security', SESSION: 'security',
        RESOURCE: 'policy', BLOCK: 'security', CONDITION: 'policy'};

    function changesCard() {
        const c = D.changes;
        const total = c.byKind.reduce((sum, kind) => sum + kind.count, 0);
        // A change no words name reads by its kind; a mode by the console's words for it.
        const what = change => change.action ? d('changes.action.' + change.action) : d('changes.kind.' + change.kind);
        const target = change => change.kind === 'MODE' && change.target ? t('zt.console.ui.mode.' + change.target)
            : change.target || '—';
        const body = c.recent.length ? [
            form('kind-chips', el('div', {class: 'flex flex-wrap gap-2'}, c.byKind.filter(kind => kind.count > 0)
                .map(kind => ZT.statusChip(null, d('changes.kindCount', d('changes.kind.' + kind.key), short(kind.count)))))),
            form('timeline', el('ol', {class: 'flex flex-col gap-4 min-w-0',
                style: {borderLeft: '2px solid ' + C.BORDER, marginLeft: '4px'}},
            c.recent.map(change => el('li', {class: 'relative min-w-0', style: {paddingLeft: '16px'}},
                // The dot on the line, in the colour of the area the change belongs to; its words say the area.
                el('span', {class: 'absolute rounded-full', 'aria-hidden': 'true', style: {left: '-6px', top: '6px',
                    width: '10px', height: '10px', background: AREAS[KIND_AREA[change.kind] || 'system'].color}}),
                el('div', {class: 'text-sm font-semibold', style: {overflowWrap: 'anywhere'},
                    text: d('changes.target', what(change), target(change))}),
                el('div', {class: 'zt-muted', style: {overflowWrap: 'anywhere'},
                    text: d('changes.by', change.actor, ZT.shortTime(change.at))})))))]
            : [form('empty-state', ZT.emptyNote(d('changes.none')))];
        const card = ZT.card(d('changes.title'), d('changes.aside', periodName, short(total)), ...body);
        ZT.withTip(card, d('changes.tip'));
        return foot(card, link(events(null), d('changes.link')));
    }

    // ----- C: the most refused access of signed-in users: the top resources and the top users as ranked bars -----

    function rankedBars(rows, of) {
        const box = el('div');
        const narrow = global.innerWidth <= 480;
        charts.push(() => ZT.chart(box, 'm', {type: 'bar', label: d('denials.label', of),
            data: {labels: rows.map(row => row.key), datasets: [{label: d('denials.count'), data: rows.map(row => row.count),
                backgroundColor: AREAS.security.color, borderRadius: 4, maxBarThickness: 20}]},
            options: {indexAxis: 'y'},
            axes: {
                x: {grid: {color: C.BORDER, tickLength: 0}, ticks: {maxTicksLimit: 4, callback: value => ZT.shortCount(value)}},
                y: {grid: {display: false}, beginAtZero: false, ticks: {autoSkip: false, callback(value) {
                    const label = this.getLabelForValue(value);
                    const room = narrow ? 10 : 18;
                    return label.length > room ? label.slice(0, room - 1) + '…' : label;
                }}, afterFit(scale) {
                    scale.width = narrow ? 88 : 136;
                }}}}, true));
        return box;
    }

    function denialsCard() {
        const n = D.denials;
        const part = (title, rows) => form('ranked-bars', el('div', {class: 'flex flex-col gap-3 min-w-0'},
            ZT.subhead(title), rows.length ? rankedBars(rows, title) : ZT.emptyNote(d('denials.none'))));
        const body = n.total ? [el('div', {class: 'zt-split'}, part(d('denials.resources'), n.resources),
            part(d('denials.users'), n.users))] : [form('empty-state', ZT.emptyNote(d('denials.none')))];
        const card = ZT.card(d('denials.title'), d('denials.aside', periodName, short(n.total)), ...body);
        ZT.withTip(card, d('denials.tip'));
        return foot(card, link(events('AUTHORIZATION_DENIED'), d('denials.link')));
    }

    // ----- the page -----

    function render(content, value) {
        D = value;
        zt = D.zeroTrust;
        mode = D.system.mode;
        off = mode === 'DISABLED' || mode === 'OBSERVE' || !mode;
        shadow = mode === 'SHADOW';
        periodKey = D.period && PERIODS.includes(D.period.key) ? D.period.key : currentPeriod();
        periodName = t('zt.console.ui.period.' + periodKey);
        band();
        const items = todoItems();
        ITEMS = items;
        charts.length = 0;
        content.replaceChildren(
            summary(items),
            keyCards(),
            grid(span(attentionCard(), 8), span(changesCard(), 4)),
            grid(span(denialsCard(), 12)),
            grid(span(queueCard(items), 8), span(agentsCard(), 4)),
            grid(span(securityCard(), 8), span(iamCard(), 4)),
            grid(span(policyCard(), 8), span(promptCard(), 4)),
            grid(span(zeroTrustCard(), 8), span(systemCard(), 4)));
        charts.forEach(draw => {
            const chart = draw();
            if (chart) {
                drawnCharts.push(chart);
            }
        });
    }

    async function draw() {
        const content = document.getElementById('zt-content');
        if (!content) {
            return;
        }
        drawnCharts.splice(0).forEach(chart => chart.destroy());
        try {
            render(content, await ZT.load(''));
        } catch (error) {
            ZT.failed(content, error);
        }
    }

    periodChips(draw);
    draw();
})(window);
