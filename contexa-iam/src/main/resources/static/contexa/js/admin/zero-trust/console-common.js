/*
 * Zero Trust console: what every screen shares (console plan 1.1 to 1.3, design 2 and 6.0). The API calls, the
 * numbers and their "no data" reasons, the band above the screen, the one Chart.js setting, and the visualisations
 * made from the data and the axis ranges, never from coordinates written by hand.
 */
(function (global) {
    'use strict';

    const SVG = 'http://www.w3.org/2000/svg';
    const css = getComputedStyle(document.documentElement);
    const token = name => css.getPropertyValue(name).trim();
    const COLORS = {
        ALLOW: token('--zt-allow'), CHALLENGE: token('--zt-challenge'), ESCALATE: token('--zt-escalate'),
        BLOCK: token('--zt-block'), NO_DECISION: token('--zt-muted'), GOOD: token('--zt-good'),
        WARN: token('--zt-warn'), BAD: token('--zt-bad'), MUTED: token('--zt-muted'), TRACK: token('--zt-track'),
        TEXT: token('--zt-text'), ACCENT: token('--zt-accent'), BORDER: token('--zt-border')
    };
    const SERIES = [COLORS.ACCENT, COLORS.ALLOW, COLORS.CHALLENGE, COLORS.ESCALATE, COLORS.BLOCK, COLORS.MUTED];

    function readMessages() {
        const node = document.getElementById('zt-messages');
        if (!node) {
            return {};
        }
        try {
            return JSON.parse(node.textContent || '{}');
        } catch (unreadable) {
            return {};
        }
    }

    const messages = readMessages();
    const locale = document.documentElement.lang || 'en';

    /** A message by its key, its {0}, {1}... filled; the key itself when the message is missing. */
    function t(key, ...args) {
        const text = messages[key];
        if (text == null) {
            return key;
        }
        return text.replace(/\{(\d+)\}/g, (match, index) => (args[index] == null ? '' : String(args[index])));
    }

    function el(tag, attributes, ...children) {
        const node = document.createElement(tag);
        Object.entries(attributes || {}).forEach(([name, value]) => {
            if (value == null || value === false) {
                return;
            }
            if (name === 'text') {
                node.textContent = value;
            } else if (name === 'style' && typeof value === 'object') {
                // A custom property is set with setProperty: assigning it as a field is ignored.
                Object.entries(value).forEach(([property, setting]) => {
                    if (setting == null) {
                        return;
                    }
                    if (property.startsWith('--')) {
                        node.style.setProperty(property, setting);
                    } else {
                        node.style[property] = setting;
                    }
                });
            } else {
                node.setAttribute(name, value === true ? '' : value);
            }
        });
        children.flat().forEach(child => {
            if (child != null) {
                node.append(child instanceof Node ? child : document.createTextNode(String(child)));
            }
        });
        return node;
    }

    function svg(tag, attributes) {
        const node = document.createElementNS(SVG, tag);
        Object.entries(attributes || {}).forEach(([name, value]) => {
            if (value != null) {
                node.setAttribute(name, value);
            }
        });
        return node;
    }

    // ----- numbers -----

    const integer = new Intl.NumberFormat(locale);
    const decimal = new Intl.NumberFormat(locale, {maximumFractionDigits: 1});

    function count(value) {
        return value == null ? '—' : integer.format(value);
    }

    const compact = new Intl.NumberFormat(locale, {notation: 'compact', maximumFractionDigits: 1});

    /** A count shortened for a narrow cell (1.3: shortened in place, the full value in the tooltip). */
    function shortCount(value) {
        return value == null ? '—' : Math.abs(value) < 10_000 ? integer.format(value) : compact.format(value);
    }

    function percent(ratio, digits = 1) {
        if (ratio == null) {
            return '—';
        }
        return new Intl.NumberFormat(locale, {style: 'percent', maximumFractionDigits: digits}).format(ratio);
    }

    function seconds(ms) {
        if (ms == null) {
            return '—';
        }
        return ms < 1000 ? t('zt.console.ui.unit.ms', integer.format(Math.round(ms)))
            : t('zt.console.ui.unit.seconds', decimal.format(ms / 1000));
    }

    function time(iso) {
        if (!iso) {
            return '—';
        }
        const date = new Date(iso);
        return Number.isNaN(date.getTime()) ? iso : new Intl.DateTimeFormat(locale, {
            month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
        }).format(date);
    }

    /** A time on 24 hours (11. 14. 19:12): the narrow form a phone's table shows. */
    function shortTime(iso) {
        if (!iso) {
            return '—';
        }
        const date = new Date(iso);
        return Number.isNaN(date.getTime()) ? iso : new Intl.DateTimeFormat(locale, {
            month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
        }).format(date);
    }

    function day(iso) {
        if (!iso) {
            return '—';
        }
        const date = new Date(iso.length === 10 ? iso + 'T00:00:00' : iso);
        return new Intl.DateTimeFormat(locale, {month: '2-digit', day: '2-digit'}).format(date);
    }

    /** A metric's shown value: by its unit, or "—" when it has none. */
    function metricText(metric) {
        if (!metric || metric.value == null) {
            return '—';
        }
        switch (metric.unit) {
            case 'RATIO':
                return percent(metric.value);
            case 'MILLISECONDS':
                return seconds(metric.value);
            case 'HOURS':
                return t('zt.console.ui.unit.hours', decimal.format(metric.value));
            case 'COUNT':
                return count(metric.value);
            case 'RELEASE_BUCKET':
                // the user's choice: the release median reads as the bucket it falls in (1~2시간 사이)
                return t('zt.console.ui.releaseBucket.' + Math.round(metric.value));
            default:
                return decimal.format(metric.value);
        }
    }

    /** Why a metric has no value, in words. */
    function reason(code) {
        return code ? t('zt.console.reason.' + code) : '';
    }

    /**
     * A metric as the console shows every number (design 2.2): its name, its value, its numerator and denominator,
     * its definition; without a value, "—" and the reason.
     */
    function metric(value, options = {}) {
        const node = el('div', {class: 'zt-metric', 'data-metric': value ? value.key : null});
        node.append(el('div', {class: 'zt-metric-label', text: value ? value.label : ''}));
        node.append(el('div', {class: 'zt-metric-value' + (options.small ? ' zt-small' : '') + (value && value.value == null ? ' zt-none' : ''),
            text: metricText(value)}));
        if (value && value.value != null && value.unit === 'RATIO' && value.denominator != null) {
            node.append(el('div', {class: 'zt-metric-ratio', text: count(value.numerator) + ' / ' + count(value.denominator)}));
        }
        if (value && value.value == null && value.noDataReason) {
            node.append(el('div', {class: 'zt-metric-definition', text: reason(value.noDataReason)}));
        } else if (value && value.description && !options.hideDefinition) {
            node.append(el('div', {class: 'zt-metric-definition', text: value.description}));
        }
        return node;
    }

    /** A ranged metric: the value with its 95% range, the range shown when the sample is small. */
    function ranged(range, options = {}) {
        const node = metric(range ? range.metric : null, options);
        if (range && range.metric && range.metric.value != null && range.lower95 != null) {
            node.append(el('div', {class: 'zt-metric-ratio',
                text: t('zt.console.ui.range95', percent(range.lower95, 0), percent(range.upper95, 0), count(range.sample))}));
        }
        return node;
    }

    // ----- the band above every screen (6.0) -----

    function query() {
        return new URLSearchParams(global.location.search);
    }

    function apiUrl(path, extra) {
        const params = query();
        Object.entries(extra || {}).forEach(([name, value]) => {
            if (value == null || value === '') {
                params.delete(name);
            } else {
                params.set(name, value);
            }
        });
        const root = document.getElementById('zt-console');
        const base = root ? root.dataset.apiBase : '/contexa/admin/api/zero-trust';
        const search = params.toString();
        return base + path + (search ? '?' + search : '');
    }

    async function load(path, extra) {
        const response = await fetch(apiUrl(path, extra), {headers: {Accept: 'application/json'}, credentials: 'same-origin'});
        if (!response.ok) {
            throw new Error(String(response.status));
        }
        return response.json();
    }

    async function post(path, body) {
        const root = document.getElementById('zt-console');
        const headers = {'Content-Type': 'application/json', Accept: 'application/json'};
        if (root && root.dataset.csrfToken) {
            headers[root.dataset.csrfHeader || 'X-CSRF-TOKEN'] = root.dataset.csrfToken;
        }
        const response = await fetch(root.dataset.apiBase + path, {
            method: 'POST', headers, credentials: 'same-origin', body: JSON.stringify(body)
        });
        const text = await response.text();
        return {ok: response.ok, status: response.status, body: text ? JSON.parse(text) : null};
    }

    /** The period buttons: the chosen period is kept in the address (design 6.0). */
    function periodButtons(container, onChange) {
        const current = query().get('period') || 'week';
        const pick = (chosen, change) => {
            const params = query();
            change(params);
            params.delete('cursor');
            global.history.replaceState(null, '', global.location.pathname + '?' + params.toString());
            container.querySelectorAll('button[data-period]').forEach(other => other.setAttribute('aria-pressed',
                String(other === chosen)));
            onChange();
        };
        ['day', 'week', 'month', 'quarter'].forEach(key => {
            const button = el('button', {type: 'button', 'data-period': key, 'aria-pressed': String(key === current),
                text: t('zt.console.ui.period.' + key)});
            button.addEventListener('click', () => {
                days.forEach(node => node.hidden = true);
                pick(button, params => {
                    params.set('period', key);
                    params.delete('from');
                    params.delete('to');
                });
            });
            container.append(button);
        });
        // Design 6.0 [직접]: the days an operator chooses, kept in the address (period=custom, from, to).
        const custom = current === 'custom';
        const today = new Date().toISOString().slice(0, 10);
        const from = el('input', {type: 'date', class: 'modern-input', max: today, required: true,
            'aria-label': t('zt.console.ui.period.from'), value: custom ? query().get('from') || '' : ''});
        const to = el('input', {type: 'date', class: 'modern-input', max: today,
            'aria-label': t('zt.console.ui.period.to'), value: custom ? query().get('to') || '' : ''});
        const apply = el('button', {type: 'button', text: t('zt.console.ui.period.apply')});
        const choose = el('button', {type: 'button', 'data-period': 'custom', 'aria-pressed': String(custom),
            text: t('zt.console.ui.period.custom')});
        const days = [from, to, apply];
        days.forEach(node => node.hidden = !custom);
        choose.addEventListener('click', () => {
            days.forEach(node => node.hidden = false);
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

    function header(band, value) {
        band.replaceChildren();
        if (!value) {
            return;
        }
        const mode = value.mode || '';
        band.append(el('span', {class: 'status-badge zt-mode', 'data-mode': mode},
            (mode === 'ENFORCE' ? '● ' : mode === 'SHADOW' ? '◐ ' : '○ ') + t('zt.console.ui.mode.' + (mode || 'NONE')),
            value.modeSince ? ' · ' + t('zt.console.ui.since', day(value.modeSince)) : ''));
        band.append(el('span', {text: t('zt.console.ui.band.decisions', count(value.decisions))}));
        band.append(el('span', {text: t('zt.console.ui.band.users', count(value.users))}));
        if (value.bundles && value.bundles.length) {
            band.append(el('span', {text: t('zt.console.ui.band.bundle', value.bundles[0].key)}));
        }
        if (value.models && value.models.length) {
            band.append(el('span', {text: t('zt.console.ui.band.model', value.models[0].key)}));
        }
        // How the decisions are counted is the band's tooltip, not a sentence on every screen.
        band.append(el('span', {class: 'zt-band-info', title: t('zt.console.ui.band.note'), tabindex: '0',
            role: 'note', 'aria-label': t('zt.console.ui.band.note')}, el('i', {class: 'fas fa-info-circle',
            'aria-hidden': 'true'})));
        if (mode === 'SHADOW') {
            band.append(el('span', {class: 'zt-band-note', text: t('zt.console.ui.band.shadow')}));
        }
        if (value.standalone) {
            band.append(el('span', {class: 'zt-warning', role: 'note', text: t('zt.console.ui.band.standalone')}));
        }
    }

    // ----- cards -----

    function card(title, aside, ...body) {
        const node = el('section', {class: 'dash-card zt-card'});
        const head = el('div', {class: 'zt-card-head'}, el('h2', {text: title}));
        if (aside) {
            head.append(el('span', {class: 'zt-aside', text: aside}));
        }
        node.append(head, el('div', {class: 'zt-card-body'}, ...body));
        return node;
    }

    /** No value: the policy center's empty state, "—" and the reason under its icon. */
    function empty(reasonCode) {
        return el('div', {class: 'pc-empty', role: 'note'}, el('i', {class: 'fas fa-inbox', 'aria-hidden': 'true'}),
            el('p', {text: '— ' + reason(reasonCode || 'NO_DECISIONS')}));
    }

    function chip(action, text) {
        return el('span', {class: 'status-badge zt-chip', 'data-action': action, text: text || t('zt.console.ui.action.' + action)});
    }

    function statusChip(status, text) {
        return el('span', {class: 'status-badge zt-chip', 'data-status': status, text: text || t('zt.console.ui.status.' + status)});
    }

    function rows(items, render) {
        const list = el('ul', {class: 'zt-rows'});
        items.forEach(item => list.append(el('li', {class: 'zt-row'}, ...render(item))));
        return list;
    }

    // ----- charts (1.3): one setting for every Chart.js chart -----

    const PADDING = {top: 8, right: 8, bottom: 24, left: 40};

    function chartDefaults() {
        if (!global.Chart || global.Chart.ztReady) {
            return;
        }
        const defaults = global.Chart.defaults;
        defaults.font.family = getComputedStyle(document.body).fontFamily;
        defaults.font.size = 12;
        defaults.color = COLORS.MUTED;
        defaults.borderColor = COLORS.BORDER;
        defaults.maintainAspectRatio = false;
        defaults.responsive = true;
        defaults.animation = false;
        defaults.plugins.legend.display = false;
        defaults.plugins.tooltip.backgroundColor = '#0f172a';
        defaults.plugins.tooltip.borderColor = COLORS.BORDER;
        defaults.plugins.tooltip.borderWidth = 1;
        defaults.layout.padding = {top: PADDING.top, right: PADDING.right, bottom: 0, left: 0};
        global.Chart.ztReady = true;
    }

    /**
     * The axes' fixed room: the x axis's labels take 24px, the y axis's 40px (1.3). A share drawn beside the counts
     * (options.ratio) reads on a scale of 0 to 100% that takes no room: its values are in the tooltip and the legend.
     */
    function axes(options = {}) {
        const scales = {
            x: Object.assign({
                grid: {display: false},
                ticks: {autoSkip: true, maxRotation: 0, callback(value) {
                    const label = this.getLabelForValue(value);
                    return typeof label === 'string' && label.length > 8 ? label.slice(0, 7) + '…' : label;
                }},
                afterFit(scale) {
                    scale.height = PADDING.bottom;
                }
            }, options.x || {}),
            y: Object.assign({
                beginAtZero: true,
                // No tick marks: the 40px axis keeps its whole width for the label.
                grid: {color: COLORS.BORDER, tickLength: 0},
                // The axis has 40px: its labels are shortened (12,480 reads 1.2만), the tooltip has the full value.
                ticks: {maxTicksLimit: 5, padding: 4, callback: options.yFormat || (value => shortCount(value))},
                afterFit(scale) {
                    scale.width = PADDING.left;
                }
            }, options.y || {})
        };
        if (options.ratio) {
            scales.ratio = {display: false, min: 0, max: 1};
        }
        return scales;
    }

    /** The tooltip of a chart with a share beside its counts: the share reads as a percent. */
    function ratioTooltip() {
        return {callbacks: {label(context) {
            const value = context.parsed && context.parsed.y;
            const shown = context.dataset.yAxisID === 'ratio' ? percent(value) : count(value);
            return (context.dataset.label ? context.dataset.label + ': ' : '') + shown;
        }}};
    }

    /** A legend above the chart's top left, colour and words together. */
    function legend(entries) {
        return el('div', {class: 'zt-legend'}, entries.map(entry => el('span',
            {style: {'--zt-legend-color': entry.color}, text: entry.label})));
    }

    /**
     * A Chart.js chart in a box of one of the three heights. An empty series is no chart: "—" and the reason take its
     * place.
     */
    function chart(box, size, config, hasData, reasonCode) {
        box.replaceChildren();
        box.className = 'zt-chart zt-chart-' + size;
        if (!hasData) {
            box.className = '';
            box.append(empty(reasonCode));
            return null;
        }
        chartDefaults();
        const canvas = el('canvas', {role: 'img', 'aria-label': config.label || ''});
        box.append(canvas);
        if (!global.Chart) {
            return null;
        }
        const ratio = config.axes && config.axes.ratio;
        config.options = Object.assign({scales: axes(config.axes)}, ratio ? {plugins: {tooltip: ratioTooltip()}} : {},
            config.options || {});
        delete config.axes;
        delete config.label;
        return new global.Chart(canvas, config);
    }

    // ----- custom visualisations, from data and axis ranges (1.3) -----

    /** A bar of a value between 0 and max with a mark at the bound (criteria, interval). */
    function bar(value, max, options = {}) {
        const track = el('div', {class: 'zt-bar', role: 'img', 'aria-label': options.label || ''});
        if (value != null && max > 0) {
            const share = Math.max(0, Math.min(1, value / max));
            track.append(el('div', {class: 'zt-bar-fill', style: {width: (share * 100) + '%',
                background: options.color || COLORS.ACCENT}}));
        }
        if (options.mark != null && max > 0) {
            const at = Math.max(0, Math.min(1, options.mark / max));
            track.append(el('div', {class: 'zt-bar-mark', style: {left: 'calc(' + (at * 100) + '% - 1px)'}}));
        }
        if (options.lower != null && options.upper != null && max > 0) {
            const lower = Math.max(0, Math.min(1, options.lower / max));
            const upper = Math.max(lower, Math.min(1, options.upper / max));
            // The range is drawn inside the track (an inset line), so the track's clipping keeps all of it.
            track.append(el('div', {class: 'zt-bar-fill', style: {left: (lower * 100) + '%',
                width: ((upper - lower) * 100) + '%', background: 'transparent',
                boxShadow: 'inset 0 0 0 2px ' + COLORS.TEXT}}));
        }
        return track;
    }

    /** A 100% stacked bar of the parts, each part's colour named in a legend beside it. */
    function stacked(parts, options = {}) {
        const total = parts.reduce((sum, part) => sum + (part.count || 0), 0);
        const node = el('div', {class: 'zt-stacked', role: 'img', 'aria-label': options.label || parts.map(part =>
            part.label + ' ' + percent(total ? part.count / total : null)).join(', ')});
        if (total > 0) {
            parts.forEach((part, index) => {
                if (part.count > 0) {
                    node.append(el('span', {title: part.label + ' ' + count(part.count), style: {
                        width: (part.count / total * 100) + '%', background: part.color || SERIES[index % SERIES.length]}}));
                }
            });
        }
        return node;
    }

    /** A donut of criteria: one arc per criterion, its colour by its status; computed from the count. */
    function gauge(items, centre, caption) {
        const size = 200;
        const radius = 80;
        const circumference = 2 * Math.PI * radius;
        const gap = items.length > 1 ? 6 : 0;
        const arc = items.length ? circumference / items.length - gap : circumference;
        const node = svg('svg', {viewBox: '0 0 ' + size + ' ' + size, width: '100%', height: '100%', role: 'img',
            'aria-label': caption + ' ' + centre});
        node.append(svg('circle', {cx: 100, cy: 100, r: radius, fill: 'none', stroke: COLORS.TRACK, 'stroke-width': 20}));
        items.forEach((item, index) => {
            node.append(svg('circle', {cx: 100, cy: 100, r: radius, fill: 'none', 'stroke-width': 20,
                stroke: item.status === 'MET' ? COLORS.GOOD : item.status === 'UNMET' ? COLORS.BAD : COLORS.WARN,
                'stroke-dasharray': arc + ' ' + circumference, 'stroke-dashoffset': -(index * (arc + gap)),
                transform: 'rotate(-90 100 100)'}));
        });
        const value = svg('text', {x: 100, y: 98, 'text-anchor': 'middle', fill: COLORS.TEXT, 'font-size': 32,
            'font-weight': 700});
        value.textContent = centre;
        const label = svg('text', {x: 100, y: 124, 'text-anchor': 'middle', fill: COLORS.MUTED, 'font-size': 13});
        label.textContent = caption;
        node.append(value, label);
        return node;
    }

    /**
     * A small trend line of a series, its points in the box from the series' own range; a missing day breaks the
     * line instead of drawing a 0.
     */
    function sparkline(values, options = {}) {
        const width = 120;
        const height = 32;
        const present = values.filter(value => value != null);
        const node = svg('svg', {viewBox: '0 0 ' + width + ' ' + height, width: '100%', height: height,
            role: 'img', 'aria-label': options.label || '', preserveAspectRatio: 'none'});
        if (present.length < 2) {
            return node;
        }
        const min = options.min != null ? options.min : Math.min(...present);
        const max = options.max != null ? options.max : Math.max(...present);
        const span = max - min || 1;
        const step = width / (values.length - 1);
        let path = '';
        values.forEach((value, index) => {
            if (value == null) {
                return;
            }
            const x = index * step;
            const y = 2 + (height - 4) * (1 - (value - min) / span);
            const move = path === '' || values[index - 1] == null;
            path += (move ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1) + ' ';
        });
        node.append(svg('path', {d: path.trim(), fill: 'none', stroke: options.color || COLORS.ACCENT,
            'stroke-width': 2, 'vector-effect': 'non-scaling-stroke'}));
        return node;
    }

    /** A funnel of steps, each bar's length its share of the first step. */
    function funnel(steps) {
        const first = steps.length ? steps[0].count : 0;
        const node = el('div', {class: 'zt-rows', role: 'img', 'aria-label': steps.map(step =>
            step.label + ' ' + (step.count == null ? '—' : count(step.count))).join(', ')});
        steps.forEach(step => {
            node.append(el('div', {class: 'zt-row'}, el('span', {text: step.label}),
                el('span', {text: step.count == null ? '—' : count(step.count)})));
            node.append(bar(step.count, first, {color: step.color || COLORS.ACCENT, label: step.label}));
        });
        return node;
    }

    /** A matrix of cells, each cell's tone its share of the largest (heat map). */
    /** cellHref (optional) opens what a cell counts (design 6.2: every number opens its decisions). */
    function heatmap(rowKeys, columnKeys, cells, rowLabel, columnLabel, columnShort, cellHref) {
        const max = cells.reduce((largest, cell) => Math.max(largest, cell.count), 0);
        const table = el('table', {class: 'zt-table', role: 'grid'});
        // A phone reads the short head (12시 for 12-16시) when one is given; the full words stay in the title.
        const head = el('tr', {}, el('th', {text: ''}), columnKeys.map(key => columnShort
            ? el('th', {class: 'zt-num', title: columnLabel(key)}, [el('span', {class: 'zt-long', text: columnLabel(key)}),
                el('span', {class: 'zt-short', text: columnShort(key)})])
            : el('th', {class: 'zt-num', text: columnLabel(key)})));
        table.append(el('thead', {}, head));
        const body = el('tbody');
        rowKeys.forEach(rowKey => {
            const line = el('tr', {}, el('th', {scope: 'row', text: rowLabel(rowKey)}));
            columnKeys.forEach(columnKey => {
                const cell = cells.find(found => found.row === rowKey && found.column === columnKey);
                const value = cell ? cell.count : 0;
                const tone = max ? value / max : 0;
                const href = value > 0 && cellHref ? cellHref(rowKey, columnKey) : null;
                line.append(el('td', {class: 'zt-num', title: rowLabel(rowKey) + ' · ' + columnLabel(columnKey)
                        + ' · ' + count(value),
                    style: {background: 'rgba(165, 180, 252, ' + (0.08 + tone * 0.6).toFixed(2) + ')'}},
                    href ? el('a', {class: 'zt-link', href, text: shortCount(value)}) : shortCount(value)));
            });
            body.append(line);
        });
        table.append(body);
        return el('div', {class: 'modern-table zt-table-wrap'}, table);
    }

    /** The time a decision took, stage after stage: each bar starts where the previous ended. */
    function waterfall(stages) {
        const total = stages.reduce((sum, stage) => sum + (stage.ms || 0), 0);
        const node = el('div', {class: 'zt-rows', role: 'img', 'aria-label': stages.map(stage =>
            stage.label + ' ' + seconds(stage.ms)).join(', ')});
        let start = 0;
        stages.forEach(stage => {
            const track = el('div', {class: 'zt-bar'});
            if (stage.ms != null && total > 0) {
                track.append(el('div', {class: 'zt-bar-fill', style: {left: (start / total * 100) + '%',
                    width: (stage.ms / total * 100) + '%', background: COLORS.ACCENT}}));
                start += stage.ms;
            }
            node.append(el('div', {class: 'zt-row'}, el('span', {text: stage.label}),
                el('span', {text: seconds(stage.ms)})), track);
        });
        return node;
    }

    function failed(container, error) {
        container.replaceChildren(el('div', {class: 'pc-empty', role: 'alert'},
            el('i', {class: 'fas fa-exclamation-triangle', 'aria-hidden': 'true'}),
            el('p', {text: '— ' + t('zt.console.ui.loadFailed', error && error.message ? error.message : '')})));
    }

    /** The terms of the console, the business word beside the engine's (design principle 6). */
    const GLOSSARY = ['decision', 'noDecision', 'coverage', 'reuse', 'stopped', 'timing', 'hypothesis', 'source',
        'engineChanged', 'modelLess', 'firstLayer', 'secondLayer', 'baseline', 'context', 'unknownFact', 'shadow',
        'enforce', 'review'];

    /** The screens whose numbers have a CSV (ZeroTrustConsoleController.screenCsv); the records have their own. */
    const CSV_SCREENS = ['overview', 'impact', 'trust', 'adoption', 'operations'];

    /** The glossary every screen opens from its toolbar. */
    function glossary() {
        const list = el('dl', {class: 'zt-glossary-list'});
        GLOSSARY.forEach(term => {
            list.append(el('dt', {text: t('zt.console.glossary.' + term + '.label')}),
                el('dd', {text: t('zt.console.glossary.' + term + '.help')}));
        });
        return el('details', {class: 'zt-glossary'}, el('summary', {class: 'modern-btn-secondary'},
            el('i', {class: 'fas fa-book', 'aria-hidden': 'true'}), t('zt.console.glossary.title')), list);
    }

    /** The parameters the tab bar's links keep, so another screen opens on the same period and tenant. */
    const TAB_KEPT = ['period', 'from', 'to', 'tenant'];

    function keepPeriodOnTabs(root) {
        const params = query();
        root.querySelectorAll('a[data-zt-tab]').forEach(link => {
            const target = new URL(link.getAttribute('href'), global.location.origin);
            TAB_KEPT.forEach(name => {
                if (params.get(name)) {
                    target.searchParams.set(name, params.get(name));
                } else {
                    target.searchParams.delete(name);
                }
            });
            link.setAttribute('href', target.pathname + target.search);
        });
    }

    /** Starts a screen: its band, its period buttons and its render, again on each change of the period. */
    function start(path, render) {
        const root = document.getElementById('zt-console');
        const band = document.getElementById('zt-band');
        const content = document.getElementById('zt-content');
        const period = document.getElementById('zt-period');
        const toolbar = root ? root.querySelector('.zt-toolbar') : null;
        // Console plan 5-2 ⑥: a screen of numbers gives them as a CSV of its period, as the AI monitor's tabs did.
        const screen = root ? root.dataset.screen : null;
        const csv = CSV_SCREENS.includes(screen) ? el('a', {class: 'modern-btn-secondary',
            title: t('zt.console.ui.csvTitle')}, el('i', {class: 'fas fa-download', 'aria-hidden': 'true'}),
            t('zt.console.ui.csv')) : null;
        if (toolbar && csv && !toolbar.querySelector('.zt-screen-csv')) {
            csv.classList.add('zt-screen-csv');
            toolbar.append(csv);
        }
        if (toolbar && !toolbar.querySelector('.zt-glossary')) {
            toolbar.append(glossary());
        }
        const draw = async () => {
            if (csv) {
                csv.setAttribute('href', apiUrl('/' + screen + '.csv'));
            }
            if (root) {
                keepPeriodOnTabs(root);
            }
            try {
                const value = await load(path);
                header(band, value.header);
                content.replaceChildren();
                render(content, value);
            } catch (error) {
                failed(content, error);
            }
        };
        if (period && path) {
            periodButtons(period, draw);
        }
        if (root) {
            draw();
        }
        return draw;
    }

    global.ZT = {
        t, el, svg, count, shortCount, percent, seconds, time, shortTime, day, metric, ranged, metricText, reason, load, post, apiUrl, query,
        header, card, empty, chip, statusChip, rows, chart, legend, bar, stacked, gauge, sparkline, funnel, heatmap,
        waterfall, failed, start, COLORS, SERIES
    };
})(window);
/*
 * Zero Trust console: what the overview, the threats and business impact and the trust screens add to window.ZT
 * (console plan 1.3). Load after console-common.js. The donut's arcs are computed from the counts, never written by
 * hand.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    if (!ZT) {
        return;
    }

    const CONSOLE = '/contexa/admin/zero-trust';
    /** The parameters of the page's address that a link into another screen keeps, so its numbers stay the same. */
    const KEPT = ['period', 'from', 'to', 'tenant'];

    /**
     * The address of a console screen ('' for the overview, '/decisions' for the decision list) with its filters; the
     * current page's period and tenant come along unless the filters name their own.
     */
    function consoleLink(path, params) {
        const search = new URLSearchParams();
        Object.entries(params || {}).forEach(([name, value]) => {
            if (value != null && value !== '') {
                search.set(name, String(value));
            }
        });
        const current = ZT.query();
        KEPT.forEach(name => {
            if (!search.has(name) && current.get(name)) {
                search.set(name, current.get(name));
            }
        });
        const text = search.toString();
        return CONSOLE + path + (text ? '?' + text : '');
    }

    /**
     * A link the server gave (an alert's), with the current page's period and tenant added when it names none and
     * points into the console.
     */
    function keepPeriod(link) {
        if (!link || link.indexOf(CONSOLE) !== 0) {
            return link;
        }
        const at = link.indexOf('?');
        const path = at < 0 ? link : link.slice(0, at);
        const search = new URLSearchParams(at < 0 ? '' : link.slice(at + 1));
        const current = ZT.query();
        KEPT.forEach(name => {
            if (!search.has(name) && current.get(name)) {
                search.set(name, current.get(name));
            }
        });
        const text = search.toString();
        return path + (text ? '?' + text : '');
    }

    /** The words of a code under a message prefix; the code itself when no message names it. */
    function keyLabel(prefix, key) {
        const full = prefix + key;
        const text = ZT.t(full);
        return text === full ? String(key) : text;
    }

    /** The words of a reason code the model cited (DEVIATION_DEVICE reads as the unusual device). */
    function reasonName(code) {
        return code ? keyLabel('zt.console.reasonCode.', code) : '—';
    }

    /** The words of a decision fact's name (Approval reads as the approval records). */
    function factName(name) {
        return name ? keyLabel('zt.console.fact.', name) : '—';
    }

    /**
     * The words of a failure or change cause: the screen's own words first, then the shared ones; a cause no message
     * names reads as "other cause" (the engine's set is open: a provider's category can be any word).
     */
    function causeName(code, screenPrefix) {
        if (!code) {
            return '—';
        }
        for (const prefix of [screenPrefix, 'zt.console.ui.operations.cause.', 'zt.console.ui.trust.cause.']) {
            if (prefix && ZT.t(prefix + code) !== prefix + code) {
                return ZT.t(prefix + code);
            }
        }
        return ZT.t('zt.console.ui.cause.other');
    }

    /** The "no data" block of the console with a sentence of the screen's own instead of a reason code's. */
    function emptyNote(text) {
        const node = ZT.empty();
        node.lastChild.textContent = text;
        return node;
    }

    /**
     * A donut of parts [{label, count, color}]: each arc's length is its count's share of the parts' sum. It draws no
     * text of its own; the numbers stand beside it in words (colour is never alone).
     */
    function donut(parts, options = {}) {
        const size = 200;
        const centre = size / 2;
        const radius = 80;
        const stroke = 24;
        const circumference = 2 * Math.PI * radius;
        const drawn = parts.filter(part => part.count > 0);
        const total = drawn.reduce((sum, part) => sum + part.count, 0);
        const gap = drawn.length > 1 ? 4 : 0;
        const node = ZT.svg('svg', {viewBox: '0 0 ' + size + ' ' + size, width: '100%', height: '100%', role: 'img',
            'aria-label': options.label || parts.map(part => part.label + ' ' + ZT.count(part.count)).join(', ')});
        node.append(ZT.svg('circle', {cx: centre, cy: centre, r: radius, fill: 'none', stroke: ZT.COLORS.TRACK,
            'stroke-width': stroke}));
        let start = 0;
        drawn.forEach((part, index) => {
            const length = total > 0 ? part.count / total * circumference : 0;
            const arc = Math.max(0, length - gap);
            const circle = ZT.svg('circle', {cx: centre, cy: centre, r: radius, fill: 'none', 'stroke-width': stroke,
                stroke: part.color || ZT.SERIES[index % ZT.SERIES.length],
                'stroke-dasharray': arc.toFixed(2) + ' ' + circumference.toFixed(2),
                'stroke-dashoffset': (-start).toFixed(2), transform: 'rotate(-90 ' + centre + ' ' + centre + ')'});
            const title = ZT.svg('title');
            title.textContent = part.label + ' ' + ZT.count(part.count);
            circle.append(title);
            node.append(circle);
            start += length;
        });
        return node;
    }

    Object.assign(ZT, {consoleLink, keepPeriod, keyLabel, reasonName, factName, causeName, emptyNote, donut});
})(window);

/*
 * Zero Trust console, screens B: what console-common.js lacks for the decision, adoption and operations screens: the
 * hypotheses board (console plan 1.3), its lengths computed from the data, and a compact number for chart axes.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    if (!ZT) {
        return;
    }

    /** The four steps of an assessment, weakest first (output contract v4). */
    const ASSESSMENTS = ['NO_EVIDENCE', 'UNLIKELY', 'POSSIBLE', 'MOST_LIKELY'];

    function idsOf(value) {
        if (Array.isArray(value)) {
            return value.filter(entry => entry != null && entry !== '').map(String);
        }
        return value == null || value === '' ? [] : [String(value)];
    }

    function stepOf(hypothesis) {
        return ASSESSMENTS.indexOf(String(hypothesis.assessment || '').toUpperCase());
    }

    /**
     * The explanations the model weighed (hypotheses board): one entry per explanation, most likely first. Its bar is
     * the step of its assessment on the four-step scale (no evidence is an empty bar, most likely a full one), its
     * words say the step, and the facts it cited for and against follow it.
     *
     * @param hypotheses [{id, assessment, for: [factId], against: [factId]}]
     * @param options    {name(id), assessment(code), cited(kind 'for'|'against', factId), href(factId) -> url|null, label}
     */
    function hypothesisBoard(hypotheses, options) {
        const steps = ASSESSMENTS.length - 1;
        const sorted = (hypotheses || []).slice().sort((one, other) => stepOf(other) - stepOf(one)
            || String(one.id).localeCompare(String(other.id)));
        const list = ZT.el('ul', {class: 'zt-rows', 'aria-label': options.label || null});
        sorted.forEach(hypothesis => {
            const id = String(hypothesis.id || '').toUpperCase();
            const step = stepOf(hypothesis);
            const name = options.name(id);
            const said = step < 0 ? '—' : options.assessment(ASSESSMENTS[step]);
            const facts = ZT.el('div', {class: 'zt-toolbar'});
            [['for', hypothesis.for], ['against', hypothesis.against]].forEach(([kind, cited]) => {
                idsOf(cited).forEach(fact => {
                    const text = options.cited(kind, fact);
                    const href = options.href ? options.href(fact) : null;
                    facts.append(href ? ZT.el('a', {class: 'zt-link', href, text})
                        : ZT.el('span', {class: 'zt-muted', text}));
                });
            });
            list.append(ZT.el('li', {class: 'zt-item'},
                ZT.el('div', {class: 'zt-row'}, ZT.el('span', {text: name, title: name}), ZT.el('span', {text: said})),
                ZT.bar(step < 0 ? null : step, steps, {
                    color: step === steps ? ZT.COLORS.TEXT : ZT.COLORS.ACCENT, label: name + ' ' + said}),
                facts.childNodes.length ? facts : null));
        });
        return list;
    }

    const compactFormat = new Intl.NumberFormat(document.documentElement.lang || 'en',
        {notation: 'compact', maximumFractionDigits: 1});

    /**
     * A count in compact form (12,480 as 12K, 5,200,000 as 520만), for an axis whose 40px of room (console plan 1.3)
     * cannot hold every digit; the tooltip keeps the full number.
     */
    function compact(value) {
        return value == null ? '—' : compactFormat.format(value);
    }

    ZT.hypothesisBoard = hypothesisBoard;
    ZT.compact = compact;
})(window);

/*
 * Zero Trust console: the admin dashboard's parts, shared by every screen so they read alike. The key cards (the
 * dashboard's gradient cards: a name, an icon, the number, one line under it and an optional daily trend), the rows of
 * a value (a dot or a badge, a name, a value, a link), the donut with its total in the centre and its rows, and a card
 * whose views switch with the tab bar of the policy center. A definition is a tooltip, never a sentence on the screen.
 */
(function (global) {
    'use strict';

    const ZT = global.ZT;
    if (!ZT) {
        return;
    }
    const el = ZT.el;
    const SPARK = 'rgba(255, 255, 255, 0.85)';

    /**
     * A key card. options: tone (indigo, purple, teal, green, amber, red), icon (a Font Awesome name), label, value
     * (its text), sub (the line under it), title (the definition, a tooltip), href, trend (daily values for the line).
     */
    function kpi(options) {
        const card = el(options.href ? 'a' : 'div', {class: 'zt-kpi', 'data-tone': options.tone || 'indigo',
            href: options.href || null, title: options.title || null},
            el('div', {class: 'zt-kpi-head'}, el('span', {class: 'zt-kpi-label'}, options.label || '',
                options.title ? [' ', info(options.title)] : null),
                el('i', {class: 'fas ' + (options.icon || 'fa-chart-line'), 'aria-hidden': 'true'})),
            el('div', {class: 'zt-kpi-value', text: options.value == null ? '—' : options.value}),
            el('div', {class: 'zt-kpi-sub', text: options.sub || ''}));
        const trend = options.trend || [];
        if (trend.filter(point => point != null).length >= 2) {
            card.append(el('div', {class: 'zt-kpi-spark'}, ZT.sparkline(trend,
                {label: options.trendLabel || options.label || '', color: SPARK})));
        }
        return card;
    }

    /** A key card of a console metric: its label, its value or "—", its definition or its no-data reason as tooltip. */
    function kpiMetric(metric, options) {
        const value = metric || {};
        const missing = value.value == null;
        return kpi(Object.assign({label: value.label, value: ZT.metricText(value),
            title: missing && value.noDataReason ? ZT.reason(value.noDataReason) : value.description,
            sub: missing ? ZT.reason(value.noDataReason || 'NO_DECISIONS') : options.sub}, options,
        missing ? {sub: ZT.reason(value.noDataReason || 'NO_DECISIONS')} : {}));
    }

    function kpiRow(...cards) {
        return el('div', {class: 'zt-kpi-row'}, ...cards.filter(Boolean));
    }

    /**
     * Rows of a value. Each row: label, value, and optionally color (a dot), chip (a badge node instead of the label),
     * href (the row opens it), title (a tooltip).
     */
    function valueRows(rows) {
        return el('div', {class: 'zt-result-rows'}, rows.map(row => el(row.href ? 'a' : 'div', {class: 'zt-result-row',
            href: row.href || null, title: row.title || null},
            row.chip ? row.chip : el('span', {class: 'zt-result-name'},
                row.color ? el('span', {class: 'zt-dot', style: {background: row.color}}) : null, row.label,
                row.title && row.title !== row.label ? [' ', info(row.title)] : null),
            el('span', {class: 'zt-result-value', text: row.value}))));
    }

    /** The mark of a definition (design 2, 5: every number says what it is): ⓘ, the definition its tooltip. */
    function info(text) {
        return el('span', {class: 'zt-band-info', title: text, tabindex: '0', role: 'note', 'aria-label': text},
            el('i', {class: 'fas fa-info-circle', 'aria-hidden': 'true'}));
    }

    /** A small heading inside a card, between groups of rows. */
    function subhead(text, title) {
        return el('div', {class: 'zt-subhead', text, title: title || null});
    }

    /** The donut with the total in its centre, and its parts as rows under it. */
    function donutBlock(parts, total, caption, rowOf) {
        const ring = el('div', {class: 'zt-donut'}, ZT.donut(parts, {label: caption}),
            el('div', {class: 'zt-donut-centre'}, el('div', {class: 'zt-donut-value', text: ZT.count(total)}),
                el('div', {class: 'zt-donut-caption', text: caption})));
        return el('div', {class: 'zt-result'}, ring, valueRows(parts.map(rowOf)));
    }

    /** A card whose views switch with a tab bar; the first view shows first. */
    function tabbedCard(title, aside, views) {
        const bar = el('div', {class: 'zt-tabs', role: 'tablist'});
        const holder = el('div', {class: 'zt-card-body'});
        const buttons = views.map((view, index) => {
            const button = el('button', {type: 'button', role: 'tab', 'aria-selected': String(index === 0),
                text: view.label});
            button.addEventListener('click', () => {
                buttons.forEach(other => other.setAttribute('aria-selected', String(other === button)));
                holder.replaceChildren(view.node);
            });
            bar.append(button);
            return button;
        });
        holder.append(views.length ? views[0].node : ZT.empty('NO_DECISIONS'));
        return ZT.card(title, aside, bar, holder);
    }

    /** A card's head aside with its definition as tooltip and an info mark. */
    function withTip(card, text) {
        if (!text) {
            return card;
        }
        const head = card.querySelector('.zt-card-head');
        if (head) {
            head.append(el('span', {class: 'zt-band-info', title: text, tabindex: '0', role: 'note', 'aria-label': text},
                el('i', {class: 'fas fa-info-circle', 'aria-hidden': 'true'})));
        }
        return card;
    }

    Object.assign(ZT, {kpi, kpiMetric, kpiRow, valueRows, subhead, donutBlock, tabbedCard, withTip, info});
})(window);
