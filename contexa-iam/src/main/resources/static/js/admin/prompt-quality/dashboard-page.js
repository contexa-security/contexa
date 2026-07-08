import { appPath, escapeHtml, ensureArray, rawText, text } from '../verification-ui-common.js';
import { getJson, publicError } from './prompt-quality-api.js';
import { setStatus, badge } from './prompt-quality-page.js';
import { ensureBundle, t } from './prompt-quality-i18n.js';

function promptQualityApiRoot(root = document.querySelector('[data-pqa-page="dashboard"]')) {
    return rawText(root?.dataset?.pqaApiRoot) || '/contexa/admin/api/prompt-quality';
}

function promptQualityApiPath(root, path) {
    const base = promptQualityApiRoot(root).replace(/\/+$/, '');
    const suffix = String(path || '').startsWith('/') ? String(path || '') : `/${path || ''}`;
    return `${base}${suffix}`;
}

function promptQualityRouteRoot(root = document.querySelector('[data-pqa-page="dashboard"]')) {
    return rawText(root?.dataset?.pqaRouteRoot) || '/contexa/admin/prompt-quality';
}

function promptQualityRoutePath(root, path) {
    const base = promptQualityRouteRoot(root).replace(/\/+$/, '');
    const suffix = String(path || '').startsWith('/') ? String(path || '') : `/${path || ''}`;
    return appPath(`${base}${suffix}`);
}

const charts = { stages: null, evidence: null, issue: null };
const TONE_COLORS = {
    ready: '#34d399',
    info: '#38bdf8',
    warn: '#fbbf24',
    danger: '#f87171',
    neutral: '#94a3b8'
};

document.addEventListener('DOMContentLoaded', async () => {
    const root = document.querySelector('[data-pqa-page="dashboard"]');
    if (!root) return;
    try { await ensureBundle(); }
    catch (error) {
        setStatus(root, 'error', t('enterprise.pqa.common.status.bundleError'), publicError(error));
        return;
    }
    installResourceStateSearch(root);
    await reload(root);
});

async function reload(root) {
    setStatus(root, 'loading', t('enterprise.pqa.common.status.loading'), t('enterprise.pqa.common.status.loadingDetail.page'));
    const loaded = await Promise.all([
        loadData('dashboard', promptQualityApiPath(root, '/dashboard/summary'), {}),
        loadData('resources', promptQualityApiPath(root, '/resources/summary'), { resources: [] }),
        loadData('runtimeEvidence', promptQualityApiPath(root, '/runtime-evidence/search?size=100'), [])
    ]);
    const byName = Object.fromEntries(loaded.map(item => [item.name, item.data]));
    const payload = {
        dash: byName.dashboard || {},
        resources: ensureArray(byName.resources?.resources),
        runtimeEvidence: ensureArray(byName.runtimeEvidence),
        bundles: [],
        recipes: [],
        apiErrors: loaded.filter(item => item.error)
    };

    renderHero(root, payload);
    renderPipeline(root, payload);
    renderChartStages(root, payload);
    renderChartEvidence(root, payload);
    if (payload.apiErrors.length) {
        setStatus(root, 'warning',
                t('enterprise.pqa.dashboard.status.partial.title'),
                t('enterprise.pqa.dashboard.status.partial.detail', String(payload.apiErrors.length)));
        return;
    }
    setStatus(root, 'success', t('enterprise.pqa.common.status.success'), t('enterprise.pqa.common.status.successDetail'));
}

async function loadData(name, endpoint, fallback) {
    try {
        return { name, data: await getJson(endpoint), error: null };
    }
    catch (error) {
        return { name, data: fallback, error: publicError(error) };
    }
}

function installResourceStateSearch(root) {
    const form = root.querySelector('[data-pqa-resource-state-search-form]');
    const result = root.querySelector('[data-pqa-resource-state-search-result]');
    if (!form || !result) return;
    form.addEventListener('submit', async event => {
        event.preventDefault();
        const resourceId = String(root.querySelector('[data-pqa-resource-state-search]')?.value || '').trim();
        const resourceUrl = String(root.querySelector('[data-pqa-resource-state-url]')?.value || '').trim();
        const httpMethod = String(root.querySelector('[data-pqa-resource-state-method]')?.value || '').trim();
        if (!resourceId) {
            result.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.dashboard.search.inputResourceId'))}</div>`;
            return;
        }
        const params = new URLSearchParams({ resourceId });
        if (resourceUrl) params.set('resourceUrl', resourceUrl);
        if (httpMethod) params.set('httpMethod', httpMethod);
        result.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.dashboard.search.queryingStatus'))}</div>`;
        try {
            renderResourceStateSearchResult(result, await getJson(`${promptQualityApiPath(root, '/resources/state-search')}?${params.toString()}`));
        }
        catch (error) {
            result.innerHTML = `<div class="empty-state pqa-search-error">${escapeHtml(publicError(error))}</div>`;
        }
    });
}

function renderResourceStateSearchResult(target, payload) {
    const resource = payload?.resource || {};
    const currentStage = payload?.currentStage || {};
    const currentExecution = payload?.currentExecutionStateDescriptor || {};
    const metrics = ensureArray(payload?.metrics);
    const stages = ensureArray(payload?.processStages);
    const routes = ensureArray(payload?.routes);
    target.innerHTML = `
        <div class="pqa-resource-state-result-head">
            <div>
                <strong>${escapeHtml(resource.resourceId || '')}</strong>
                <span class="muted">${escapeHtml(resource.httpMethod || '')} ${escapeHtml(resource.resourceUrl || '')}</span>
            </div>
            <div class="pqa-resource-state-current">
                ${badge(currentStage.label || currentStage.code || 'PROCESS')}
                ${badge(currentExecution.label || payload?.currentExecutionState || 'PENDING')}
            </div>
        </div>
        <div class="pqa-resource-state-metrics">
            ${metrics.map(metric => `
                <a class="pqa-resource-state-metric tone-${safeTone(metric.tone)}" href="${escapeHtml(metric.route || '#')}">
                    <span>${escapeHtml(metric.label || metric.code)}</span>
                    <strong>${escapeHtml(metric.value)}</strong>
                </a>`).join('')}
        </div>
        <ol class="pqa-resource-state-stage-list">
            ${stages.map((stage, index) => renderSearchStage(stage, routes[index])).join('')}
        </ol>
        <div class="pqa-resource-state-actions">
            <a class="pqa-link-button" href="${resourceDetailHref(resource)}">
                ${escapeHtml(t('enterprise.pqa.common.action.viewDetail'))}
            </a>
        </div>`;
}

function resourceDetailHref(resource) {
    const params = new URLSearchParams();
    setRouteParam(params, 'resourceUrl', resource.resourceUrl);
    setRouteParam(params, 'resourceId', resource.resourceId);
    setRouteParam(params, 'httpMethod', resource.httpMethod || 'GET');
    return promptQualityRoutePath(undefined, `/resources/detail?${params.toString()}`);
}

function setRouteParam(params, name, value) {
    const normalized = rawText(value);
    if (normalized) {
        params.set(name, normalized);
    }
}

function renderSearchStage(stage, route) {
    const process = stage?.processStage || {};
    const state = stage?.state || {};
    const execution = stage?.executionStateDescriptor || {};
    return `
        <li class="pqa-resource-state-stage tone-${safeTone(execution.tone || state.tone)}">
            <span class="pqa-resource-state-stage-index">${escapeHtml(process.order || '')}</span>
            <div>
                <strong>${escapeHtml(process.label || process.code || '')}</strong>
                <small>${escapeHtml(stage?.summary || state.label || '')}</small>
            </div>
            <div class="pqa-resource-state-stage-badges">
                ${badge(execution.label || stage?.executionState || '')}
                ${badge(state.label || state.code || '')}
            </div>
            <a class="pqa-inline-link" href="${escapeHtml(route?.route || stage?.route || '#')}">${escapeHtml(stage?.nextAction || route?.nextAction || t('enterprise.pqa.common.action.open'))}</a>
        </li>`;
}

function safeTone(value) {
    return String(value || 'neutral').toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
}

function destroyChart(key) {
    if (charts[key]) { charts[key].destroy(); charts[key] = null; }
}

function parseDate(raw) {
    if (!raw) return null;
    const d = new Date(String(raw).replace(' ', 'T'));
    return isNaN(d.getTime()) ? null : d;
}

function number(raw) {
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : 0;
}

function percent(part, total) {
    return total > 0 ? Math.round(part / total * 100) : 0;
}

function isRuntimeEvidenceReady(item) {
    return item && item.sealed === true && item.integrityValid === true;
}

function runtimeEvidenceWarningCount(items) {
    return ensureArray(items).filter(item => !isRuntimeEvidenceReady(item)).length;
}

function buildStages(p) {
    const d = p.dash;
    const totalResources = number(d.totalResourceCount) || p.resources.length;
    const evidenceCount = p.runtimeEvidence.length;
    const evidenceReady = p.runtimeEvidence.filter(isRuntimeEvidenceReady).length;
    const stages = [
        stage('resources', t('enterprise.pqa.dashboard.pipeline.stage.resources'), totalResources,
                promptQualityRoutePath(root, '/resources'), 'info', 'fa-solid fa-shield-halved'),
        stage('runtimeEvidence', t('enterprise.pqa.dashboard.pipeline.stage.runtimeEvidence'), evidenceCount,
                promptQualityRoutePath(root, '/runtime-evidence'), evidenceCount ? 'info' : 'neutral', 'fa-solid fa-cube'),
        stage('verify', t('enterprise.pqa.dashboard.pipeline.stage.verify'), evidenceReady,
                promptQualityRoutePath(root, '/verification'), evidenceReady ? 'info' : 'neutral', 'fa-solid fa-clipboard-check')
    ];
    const max = Math.max(1, ...stages.map(item => item.value));
    return stages.map(item => ({ ...item, score: Math.max(8, Math.round(item.value / max * 100)) }));
}

function stage(key, label, value, href, tone, icon, countLabel) {
    return { key, label, value, href, tone, icon, countLabel: countLabel || String(value) };
}

function renderHero(root, p) {
    const target = root.querySelector('[data-pqa-dash-hero]');
    if (!target) return;
    const d = p.dash;
    const totalResources = number(d.totalResourceCount) || p.resources.length;
    const enabled = number(d.zeroTrustEnabledCount);
    const pending = number(d.pendingCount);
    const evidenceWarnings = runtimeEvidenceWarningCount(p.runtimeEvidence);
    const evidenceReady = p.runtimeEvidence.filter(isRuntimeEvidenceReady).length;
    const rate = percent(enabled, totalResources);
    const risk = evidenceWarnings;
    const tone = risk > 0 ? 'danger' : (pending > 0 ? 'warn' : 'ready');
    const verdict = totalResources === 0
            ? t('enterprise.pqa.dashboard.hero.verdict.empty')
            : t('enterprise.pqa.dashboard.hero.verdict.summary',
                    String(enabled), String(totalResources), String(p.runtimeEvidence.length), String(risk));
    const kpis = [
        { label: t('enterprise.pqa.dashboard.hero.kpi.totalResources'), value: totalResources, tone: 'neutral', href: promptQualityRoutePath(root, '/resources'), icon: 'fa-solid fa-shield-halved' },
        { label: t('enterprise.pqa.dashboard.hero.kpi.runtimeEvidence'), value: p.runtimeEvidence.length, tone: 'info', href: promptQualityRoutePath(root, '/runtime-evidence'), icon: 'fa-solid fa-cube' },
        { label: t('enterprise.pqa.dashboard.hero.kpi.readyEvidence'), value: evidenceReady, tone: 'ready', href: promptQualityRoutePath(root, '/verification'), icon: 'fa-solid fa-clipboard-check' }
    ];
    const kpiHtml = kpis.map(k => `
        <a class="pqa-dash-hero-kpi pqa-dash-hero-kpi-${k.tone}" href="${k.href}">
            <span class="pqa-dash-kpi-icon"><i class="${k.icon}" aria-hidden="true"></i></span>
            <span class="pqa-dash-hero-kpi-value">${escapeHtml(k.value)}</span>
            <span class="pqa-dash-hero-kpi-label">${escapeHtml(k.label)}</span>
        </a>`).join('');
    target.innerHTML = `
        <div class="pqa-dash-hero pqa-dash-hero-${tone}">
            <div class="pqa-dash-hero-gauge">
                <svg viewBox="0 0 160 160" width="160" height="160" aria-hidden="true">
                    <circle cx="80" cy="80" r="68" stroke="rgba(148,163,184,0.25)" stroke-width="14" fill="none"/>
                    <circle cx="80" cy="80" r="68" stroke="currentColor" stroke-width="14" fill="none"
                            stroke-dasharray="${(rate / 100 * 2 * Math.PI * 68).toFixed(1)} ${(2 * Math.PI * 68).toFixed(1)}"
                            stroke-linecap="round" transform="rotate(-90 80 80)"/>
                </svg>
                <div class="pqa-dash-hero-gauge-value">${rate}<span>%</span></div>
                <div class="pqa-dash-hero-gauge-caption">${escapeHtml(t('enterprise.pqa.dashboard.hero.gauge.caption'))}</div>
            </div>
            <div class="pqa-dash-hero-body">
                <div class="pqa-dash-hero-tone">${escapeHtml(t(`enterprise.pqa.dashboard.hero.tone.${tone}`))}</div>
                <h2>${escapeHtml(verdict)}</h2>
                <p class="muted">${escapeHtml(t('enterprise.pqa.dashboard.hero.context',
                        String(pending), '0', '0', String(evidenceWarnings)))}</p>
                <div class="pqa-dash-hero-kpis">${kpiHtml}</div>
            </div>
        </div>`;
}

function renderPipeline(root, p) {
    const target = root.querySelector('[data-pqa-dash-pipeline]');
    if (!target) return;
    const stages = buildStages(p);
    target.innerHTML = stages.map((s, idx) => `
        <a class="pqa-dash-pipe-stage pqa-dash-pipe-${s.tone}" href="${s.href}" style="--pqa-stage-score:${s.score}%">
            <span class="pqa-dash-pipe-idx">${idx + 1}</span>
            <span class="pqa-dash-pipe-icon"><i class="${s.icon}" aria-hidden="true"></i></span>
            <span class="pqa-dash-pipe-count">${escapeHtml(s.countLabel)}</span>
            <span class="pqa-dash-pipe-label">${escapeHtml(s.label)}</span>
            <span class="pqa-dash-pipe-meter" aria-hidden="true"><span></span></span>
        </a>
        ${idx < stages.length - 1 ? '<span class="pqa-dash-pipe-arrow" aria-hidden="true">›</span>' : ''}`).join('');
}

function renderChartStages(root, p) {
    const canvas = root.querySelector('[data-pqa-dash-chart-stages]');
    if (!canvas || typeof window.Chart === 'undefined') return;
    destroyChart('stages');
    const stages = buildStages(p);
    charts.stages = new window.Chart(canvas, {
        type: 'bar',
        data: {
            labels: stages.map(item => item.label.split(/[\s·]+/)),
            datasets: [{
                label: t('enterprise.pqa.dashboard.chart.stages.dataset'),
                data: stages.map(item => item.value),
                backgroundColor: stages.map(item => TONE_COLORS[item.tone] || TONE_COLORS.neutral),
                borderRadius: 6
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    ticks: {
                        color: '#e2e8f0',
                        font: { size: 10, lineHeight: 1.2 },
                        maxRotation: 0,
                        autoSkip: false
                    },
                    grid: { display: false }
                },
                y: { ticks: { color: '#94a3b8', precision: 0 }, grid: { color: 'rgba(148,163,184,0.12)' } }
            }
        }
    });
}

function renderChartEvidence(root, p) {
    const canvas = root.querySelector('[data-pqa-dash-chart-evidence]');
    if (!canvas || typeof window.Chart === 'undefined') return;
    destroyChart('evidence');
    const buckets = lastBuckets(14);
    p.runtimeEvidence.forEach(item => {
        const d = parseDate(item.capturedAt);
        if (!d) return;
        const hit = buckets.find(x => x.key === dateKey(d));
        if (!hit) return;
        if (isRuntimeEvidenceReady(item)) hit.ready += 1;
        else hit.warning += 1;
    });
    charts.evidence = new window.Chart(canvas, {
        type: 'bar',
        data: {
            labels: buckets.map(x => x.label),
            datasets: [
                { label: t('enterprise.pqa.dashboard.chart.evidence.ready'), data: buckets.map(x => x.ready), backgroundColor: '#34d399', stack: 'e', borderRadius: 3 },
                { label: t('enterprise.pqa.dashboard.chart.evidence.warning'), data: buckets.map(x => x.warning), backgroundColor: '#f87171', stack: 'e', borderRadius: 3 }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: '#e2e8f0', usePointStyle: true } } },
            scales: {
                x: { stacked: true, ticks: { color: '#94a3b8' }, grid: { display: false } },
                y: { stacked: true, ticks: { color: '#94a3b8', precision: 0 }, grid: { color: 'rgba(148,163,184,0.12)' } }
            }
        }
    });
}

function renderChartIssue(root, p) {
    const canvas = root.querySelector('[data-pqa-dash-chart-issue]');
    if (!canvas || typeof window.Chart === 'undefined') return;
    destroyChart('issue');
    const issues = ensureArray(p.dash?.recurringIssues).slice(0, 5);
    const labels = issues.map(i => text(i.title || i.issueId || '—'));
    const data = issues.map(i => number(i.count || i.occurrences || 1));
    const empty = labels.length === 0;
    charts.issue = new window.Chart(canvas, {
        type: 'bar',
        data: {
            labels: empty ? [t('enterprise.pqa.dashboard.chart.issue.noData')] : labels,
            datasets: [{ data: empty ? [0] : data, backgroundColor: '#f87171', borderRadius: 4 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8', precision: 0 }, grid: { color: 'rgba(148,163,184,0.12)' } },
                y: { ticks: { color: '#e2e8f0' }, grid: { display: false } }
            }
        }
    });
}

function lastBuckets(days) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const buckets = [];
    for (let i = days - 1; i >= 0; i--) {
        const d = new Date(today);
        d.setDate(d.getDate() - i);
        buckets.push({ key: dateKey(d), label: `${d.getMonth() + 1}/${d.getDate()}`, ready: 0, warning: 0 });
    }
    return buckets;
}

function dateKey(d) {
    return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function renderRecurring(root, p) {
    const target = root.querySelector('[data-pqa-dash-recurring]');
    if (!target) return;
    const items = ensureArray(p.dash?.recurringIssues).slice(0, 5);
    if (!items.length) {
        target.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.dashboard.alert.recurring.empty'))}</div>`;
        return;
    }
    target.innerHTML = `<ul class="pqa-warning-list">${items.map(it => `
        <li class="pqa-warning-item">
            <div class="pqa-warning-head">
                ${badge(it.severity)}
                <strong>${escapeHtml(text(it.title))}</strong>
            </div>
            <div class="pqa-warning-body muted">${escapeHtml(text(it.nextAction || it.plainProblem || ''))}</div>
        </li>`).join('')}</ul>`;
}

function renderWarnings(root, p) {
    const target = root.querySelector('[data-pqa-dash-warnings]');
    if (!target) return;
    const items = [
        ...p.apiErrors.map(item => ({
            tone: 'blocked',
            label: t('enterprise.pqa.dashboard.signal.api'),
            body: t('enterprise.pqa.dashboard.signal.api.body', item.name)
        })),
        ...ensureArray(p.dash?.recentWarnings).map(item => ({
            tone: 'neutral',
            label: t('enterprise.pqa.dashboard.signal.recent'),
            body: text(item)
        }))
    ].filter(item => item.body).slice(0, 6);
    if (!items.length) {
        target.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.dashboard.alert.warnings.empty'))}</div>`;
        return;
    }
    target.innerHTML = `<ul class="pqa-warning-list">${items.map(item => `
        <li class="pqa-warning-item pqa-signal-${item.tone}">
            <div class="pqa-warning-head">${badge(item.label, { tone: item.tone === 'warn' ? 'pending' : item.tone })}</div>
            <div class="pqa-warning-body">${escapeHtml(item.body)}</div>
        </li>`).join('')}</ul>`;
}

function renderTools(root, p) {
    const target = root.querySelector('[data-pqa-dash-tiles]');
    if (!target) return;
    const readyBundles = p.bundles.filter(b => (b.readinessState || '').toUpperCase() === 'READY').length;
    const tools = [
        tool(
                t('enterprise.pqa.dashboard.tile.contextGeneration'),
                t('enterprise.pqa.dashboard.tools.context.note'),
                p.runtimeEvidence.length,
                t('enterprise.pqa.dashboard.tools.metric.runtimeEvidence'),
                p.bundles.length,
                t('enterprise.pqa.dashboard.tools.metric.bundle'),
                promptQualityRoutePath(root, '/runtime-evidence'),
                'fa-solid fa-flask-vial',
                'info'),
        tool(
                t('enterprise.pqa.dashboard.tile.evidenceBundles'),
                t('enterprise.pqa.dashboard.tools.evidence.note'),
                p.bundles.length,
                t('enterprise.pqa.dashboard.tools.metric.bundle'),
                readyBundles,
                t('enterprise.pqa.dashboard.tools.metric.ready'),
                promptQualityRoutePath(root, '/runtime-evidence'),
                'fa-solid fa-box-archive',
                readyBundles ? 'ready' : 'neutral'),
        tool(
                t('enterprise.pqa.dashboard.tile.recipes'),
                t('enterprise.pqa.dashboard.tools.recipes.note'),
                p.recipes.length,
                t('enterprise.pqa.dashboard.tools.metric.recipe'),
                p.runtimeEvidence.length,
                t('enterprise.pqa.dashboard.tools.metric.runtimeEvidence'),
                promptQualityRoutePath(root, '/verification'),
                'fa-solid fa-scroll',
                'ready'),
        tool(
                t('enterprise.pqa.dashboard.tile.assembly'),
                t('enterprise.pqa.dashboard.tools.assembly.note'),
                p.runtimeEvidence.length,
                t('enterprise.pqa.dashboard.tools.metric.promptSource'),
                p.apiErrors.length,
                t('enterprise.pqa.dashboard.tools.metric.alert'),
                promptQualityRoutePath(root, '/verification/prompt-comparison'),
                'fa-solid fa-diagram-project',
                p.apiErrors.length ? 'warn' : 'info'),
        tool(
                t('enterprise.pqa.dashboard.tile.policies'),
                t('enterprise.pqa.dashboard.tools.policies.note'),
                number(p.dash.blockedCount),
                t('enterprise.pqa.dashboard.tools.metric.blocked'),
                number(p.dash.reverifyRequiredCount),
                t('enterprise.pqa.dashboard.tools.metric.reverify'),
                promptQualityRoutePath(root, '/verification/metrics'),
                'fa-solid fa-sliders',
                number(p.dash.blockedCount) ? 'warn' : 'neutral')
    ];
    target.classList.add('pqa-dash-tool-grid');
    target.innerHTML = tools.map(item => `
        <a class="pqa-dash-tool-card pqa-dash-tool-${item.tone}" href="${item.href}">
            <div class="pqa-dash-tool-head">
                <span class="pqa-dash-tool-icon"><i class="${item.icon}" aria-hidden="true"></i></span>
                <span class="pqa-dash-tool-badge">${escapeHtml(t('enterprise.pqa.dashboard.tools.badge.support'))}</span>
            </div>
            <div class="pqa-dash-tool-title">${escapeHtml(item.label)}</div>
            <div class="pqa-dash-tool-metrics">
                <span><strong>${escapeHtml(item.primaryValue)}</strong><small>${escapeHtml(item.primaryLabel)}</small></span>
                <span><strong>${escapeHtml(item.secondaryValue)}</strong><small>${escapeHtml(item.secondaryLabel)}</small></span>
            </div>
            <div class="pqa-dash-tool-note">${escapeHtml(item.note)}</div>
            <div class="pqa-dash-tool-action">${escapeHtml(t('enterprise.pqa.dashboard.tools.action'))}</div>
        </a>`).join('');
}

function tool(label, note, primaryValue, primaryLabel, secondaryValue, secondaryLabel, href, icon, tone) {
    return { label, note, primaryValue, primaryLabel, secondaryValue, secondaryLabel, href, icon, tone };
}

function renderTodo(root, p) {
    const target = root.querySelector('[data-pqa-dash-todo]');
    if (!target) return;
    const d = p.dash;
    const items = [];
    const blocked = number(d.blockedCount);
    const reverify = number(d.reverifyRequiredCount);
    const issues = ensureArray(d.recurringIssues).length;
    const evidenceWarnings = runtimeEvidenceWarningCount(p.runtimeEvidence);
    if (p.apiErrors.length) items.push({ priority: 'high', title: t('enterprise.pqa.dashboard.todo.api.title', String(p.apiErrors.length)), body: t('enterprise.pqa.dashboard.todo.api.body'), href: promptQualityRoutePath(root, '/dashboard'), cta: t('enterprise.pqa.dashboard.todo.api.cta') });
    if (p.runtimeEvidence.length === 0) items.push({ priority: 'high', title: t('enterprise.pqa.dashboard.todo.noRuntimeEvidence.title'), body: t('enterprise.pqa.dashboard.todo.noRuntimeEvidence.body'), href: promptQualityRoutePath(root, '/runtime-evidence'), cta: t('enterprise.pqa.dashboard.todo.noRuntimeEvidence.cta') });
    if (evidenceWarnings > 0) items.push({ priority: 'high', title: t('enterprise.pqa.dashboard.todo.evidenceWarning.title', String(evidenceWarnings)), body: t('enterprise.pqa.dashboard.todo.evidenceWarning.body'), href: promptQualityRoutePath(root, '/runtime-evidence'), cta: t('enterprise.pqa.dashboard.todo.evidenceWarning.cta') });
    if (blocked > 0) items.push({ priority: 'high', title: t('enterprise.pqa.dashboard.todo.blocked.title', String(blocked)), body: t('enterprise.pqa.dashboard.todo.blocked.body'), href: promptQualityRoutePath(root, '/verification/metrics'), cta: t('enterprise.pqa.dashboard.todo.blocked.cta') });
    if (reverify > 0) items.push({ priority: 'medium', title: t('enterprise.pqa.dashboard.todo.reverify.title', String(reverify)), body: t('enterprise.pqa.dashboard.todo.reverify.body'), href: promptQualityRoutePath(root, '/verification/run'), cta: t('enterprise.pqa.dashboard.todo.reverify.cta') });
    if (issues > 0) items.push({ priority: 'medium', title: t('enterprise.pqa.dashboard.todo.issues.title', String(issues)), body: t('enterprise.pqa.dashboard.todo.issues.body'), href: promptQualityRoutePath(root, '/verification/metrics'), cta: t('enterprise.pqa.dashboard.todo.issues.cta') });
    if (!items.length) {
        target.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.dashboard.todo.empty'))}</div>`;
        return;
    }
    target.innerHTML = `<ol class="pqa-todo-list">${items.slice(0, 5).map((it, idx) => `
        <li class="pqa-todo-item pqa-todo-${it.priority}">
            <span class="pqa-todo-index">${idx + 1}</span>
            <div class="pqa-todo-body">
                <strong>${escapeHtml(it.title)}</strong>
                <p class="muted">${escapeHtml(it.body)}</p>
                <a class="pqa-link-button" href="${it.href}">${escapeHtml(it.cta)}</a>
            </div>
        </li>`).join('')}</ol>`;
}

function shortDate(raw) {
    const d = parseDate(raw);
    return d ? `${d.getMonth() + 1}/${d.getDate()}` : text(raw);
}
