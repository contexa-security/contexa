import { $, appPath, escapeHtml, ensureArray, rawText, text } from '../verification-ui-common.js';
import { badge, bootSummaryPage } from './prompt-quality-page.js';
import { t } from './prompt-quality-i18n.js';
import { focusHighlightedRow, targetRefMatches, targetRefToken } from './prompt-quality-target-ref.js';

const CRITICALITY_TONE = {
    CRITICAL: 'blocked',
    HIGH: 'blocked',
    SENSITIVE: 'reverify',
    MEDIUM: 'pending',
    NORMAL: 'ready',
    LOW: 'neutral'
};

const METHOD_COLORS = {
    GET: { bg: 'linear-gradient(135deg,#10b981,#059669)', text: '#042f1d' },
    POST: { bg: 'linear-gradient(135deg,#60a5fa,#2563eb)', text: '#0b1220' },
    PUT: { bg: 'linear-gradient(135deg,#fbbf24,#b45309)', text: '#422006' },
    PATCH: { bg: 'linear-gradient(135deg,#a78bfa,#7c3aed)', text: '#1e1b4b' },
    DELETE: { bg: 'linear-gradient(135deg,#f87171,#dc2626)', text: '#450a0a' },
    OPTIONS: { bg: 'linear-gradient(135deg,#94a3b8,#475569)', text: '#0f172a' }
};

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);
const API_BASE = appPath('/admin/api/enterprise/prompt-quality');
const PAGE_BASE = appPath('/admin/enterprise/prompt-quality');

const RESOURCE_PAGE_SIZE = 10;

let latestResources = [];
let latestStateCatalog = [];
let activeTargetRef = '';
let resourcePage = 0;

bootSummaryPage(`${API_BASE}/resources/summary`, (root, payload) => {
    latestResources = ensureArray(payload.resources);
    latestStateCatalog = ensureArray(payload.stateCatalog?.states);
    activeTargetRef = targetRefToken();
    renderSummary(root, latestResources);
    wireFilters(root);
    renderStream(root, latestResources);
    focusHighlightedRow(root);
});

function renderSummary(root, resources) {
    const summary = root.querySelector('[data-pqa-summary]');
    if (!summary) {
        return;
    }
    const evidenceObserved = resources.filter(runtimeEvidenceAvailable).length;
    const officialCompleted = resources.filter(officialInspectionAvailable).length;
    const officialBlocked = resources.filter(officialInspectionBlocked).length;
    const pills = [
        { label: t('enterprise.pqa.resource.summary.total'), value: resources.length, color: '#60a5fa', glow: 'rgba(96,165,250,0.55)' },
        { label: t('enterprise.pqa.resource.summary.evidenceObserved'), value: evidenceObserved, color: '#34d399', glow: 'rgba(52,211,153,0.55)' },
        { label: t('enterprise.pqa.resource.summary.officialCompleted'), value: officialCompleted, color: '#fbbf24', glow: 'rgba(251,191,36,0.55)' },
        { label: t('enterprise.pqa.resource.summary.officialBlocked'), value: officialBlocked, color: '#f87171', glow: 'rgba(248,113,113,0.55)' }
    ];
    summary.innerHTML = pills.map(pill => `
        <div style="display:flex;align-items:center;gap:1rem;padding:0.85rem 1.25rem;border-radius:999px;background:rgba(15,23,42,0.55);border:1px solid ${pill.color}55;box-shadow:0 10px 24px rgba(0,0,0,0.3), inset 0 0 0 1px ${pill.color}22;">
            <span style="flex-shrink:0;width:58px;height:58px;border-radius:50%;background:radial-gradient(circle,${pill.color}44 0%,rgba(2,6,23,0.6) 70%);display:grid;place-items:center;color:${pill.color};font-size:1.6rem;font-weight:900;border:2px solid ${pill.color}80;box-shadow:0 0 18px ${pill.glow};">${pill.value}</span>
            <span style="display:grid;gap:0.15rem;min-width:0;">
                <span style="color:${pill.color};font-size:0.72rem;font-weight:800;letter-spacing:0.14em;text-transform:uppercase;">${escapeHtml(pill.label)}</span>
                <span style="color:#e2e8f0;font-size:0.95rem;font-weight:600;">${escapeHtml(t('enterprise.pqa.resource.summary.unit'))}</span>
            </span>
        </div>
    `).join('');
}

function wireFilters(root) {
    const search = $(root, '[data-pqa-resource-search]');
    const state = $(root, '[data-pqa-resource-state]');
    populateStateFilter(state);
    const update = () => {
        resourcePage = 0;
        renderStream(root, filtered(root));
    };
    search?.addEventListener('input', update);
    state?.addEventListener('change', update);
}

function populateStateFilter(select) {
    if (!select || select.dataset.pqaCatalogHydrated === 'true') {
        return;
    }
    const allLabel = select.querySelector('option[value=""]')?.textContent
            || t('enterprise.pqa.resource.toolbar.state.all');
    const states = latestStateCatalog
            .filter(item => item.dimension === 'RESOURCE_OPERATIONAL' || item.dimension === 'RESOURCE_REQUEST_OBSERVATION')
            .sort((left, right) => Number(left.order || 0) - Number(right.order || 0));
    if (!states.length) {
        return;
    }
    select.innerHTML = `<option value="">${escapeHtml(allLabel)}</option>`
            + states.map(item => `<option value="${escapeHtml(item.dimension + ':' + item.code)}">${escapeHtml(item.label)}</option>`).join('');
    select.dataset.pqaCatalogHydrated = 'true';
}

function filtered(root) {
    const keyword = String($(root, '[data-pqa-resource-search]')?.value || '').trim().toLowerCase();
    const state = String($(root, '[data-pqa-resource-state]')?.value || '').trim().toUpperCase();
    return latestResources.filter(resource => {
        const url = String(resource.resourceUrl || '').toLowerCase();
        const id = String(resource.resourceId || '').toLowerCase();
        const method = String(resource.httpMethod || '').toLowerCase();
        const keywordMatch = !keyword || url.includes(keyword) || id.includes(keyword) || method.includes(keyword);
        const stateMatch = matchesSelectedState(resource, state);
        return keywordMatch && stateMatch;
    });
}

function matchesSelectedState(resource, selected) {
    if (!selected) {
        return true;
    }
    const [dimension, code] = selected.includes(':') ? selected.split(':', 2) : ['', selected];
    if (dimension === 'RESOURCE_OPERATIONAL') {
        return String(resource.operationalState || '').toUpperCase() === code;
    }
    if (dimension === 'RESOURCE_REQUEST_OBSERVATION') {
        return String(resource.runtimeRequestStateDescriptor?.code || '').toUpperCase() === code;
    }
    return String(resource.operationalState || '').toUpperCase() === code
            || String(resource.runtimeRequestStateDescriptor?.code || '').toUpperCase() === code;
}

function friendlyName(resource) {
    const url = text(resource.resourceUrl);
    if (!url) {
        return text(resource.resourceId) || t('enterprise.pqa.resource.card.unnamed');
    }
    const segments = url.split(/[/?#]/).filter(Boolean);
    const last = segments[segments.length - 1] || url;
    const decoded = last.replace(/^\{|\}$/g, '').replace(/[-_.]+/g, ' ').trim();
    if (!decoded) {
        return url;
    }
    return decoded.charAt(0).toUpperCase() + decoded.slice(1);
}

function renderStream(root, resources) {
    const stream = root.querySelector('[data-pqa-resource-stream]');
    const countBadge = root.querySelector('[data-pqa-resource-count]');
    const safeResources = ensureArray(resources);
    const total = safeResources.length;
    const totalPages = Math.max(1, Math.ceil(total / RESOURCE_PAGE_SIZE));
    resourcePage = Math.min(Math.max(0, resourcePage), totalPages - 1);
    const start = resourcePage * RESOURCE_PAGE_SIZE;
    const pageItems = safeResources.slice(start, start + RESOURCE_PAGE_SIZE);
    const end = start + pageItems.length;
    if (countBadge) {
        countBadge.textContent = total
                ? `${start + 1}-${end} / ${total}`
                : t('enterprise.pqa.resource.summary.filteredCount', 0);
    }
    if (!stream) {
        return;
    }
    if (!total) {
        stream.innerHTML = `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.resource.table.empty'))}</p></div>`;
        return;
    }
    stream.innerHTML = pageItems.map(renderTicket).join('') + resourcePaginationHtml(resourcePage, totalPages, total);
    wireResourceCards(stream);
    wireResourcePagination(stream, root, safeResources);
}

function resourcePaginationHtml(page, totalPages, total) {
    if (total <= RESOURCE_PAGE_SIZE) {
        return '';
    }
    return `
        <nav class="pqa-pagination" data-pqa-resource-pagination style="display:flex;align-items:center;justify-content:flex-end;gap:0.6rem;margin-top:0.2rem;">
            <button type="button" class="pqa-action-button" data-pqa-resource-page="prev" ${page <= 0 ? 'disabled' : ''}>${escapeHtml(t('enterprise.pqa.common.pagination.prev'))}</button>
            <span style="color:#cbd5e1;font-size:0.9rem;font-weight:700;">${escapeHtml(t('enterprise.pqa.common.pagination.page'))} ${page + 1} / ${totalPages}</span>
            <button type="button" class="pqa-action-button" data-pqa-resource-page="next" ${page >= totalPages - 1 ? 'disabled' : ''}>${escapeHtml(t('enterprise.pqa.common.pagination.next'))}</button>
        </nav>`;
}

function wireResourcePagination(stream, root, resources) {
    stream.querySelectorAll('[data-pqa-resource-page]').forEach(button => {
        button.addEventListener('click', () => {
            const action = button.dataset.pqaResourcePage;
            resourcePage += action === 'next' ? 1 : -1;
            renderStream(root, resources);
        });
    });
}

function renderTicket(resource) {
    const resourceId = text(resource.resourceId);
    const httpMethod = normalizeHttpMethod(resource.httpMethod) || 'GET';
    const resourceUrl = text(resource.resourceUrl);
    const detailHref = resourceDetailHref(resource);
    const operationalDescriptor = resource.operationalStateDescriptor
            || descriptor('RESOURCE_OPERATIONAL', resource.operationalState);
    const runtimeDescriptor = resource.runtimeRequestStateDescriptor
            || descriptor('RESOURCE_REQUEST_OBSERVATION', null);
    const evidenceAction = runtimeEvidenceActionHtml(resource, runtimeDescriptor);
    const officialBadge = officialInspectionBadgeHtml(resource);
    const criticalityCode = String(resource.criticality || '').toUpperCase();
    const criticalityTone = CRITICALITY_TONE[criticalityCode] || 'neutral';
    const criticalityLabel = criticalityCode
            ? t('enterprise.pqa.resource.criticality.' + criticalityCode.toLowerCase())
            : t('enterprise.pqa.resource.criticality.unknown');
    const method = METHOD_COLORS[httpMethod] || METHOD_COLORS.GET;
    const sigChangedTitle = escapeHtml(t('enterprise.pqa.resources.signatureChanged'));
    const sigKeptTitle = escapeHtml(t('enterprise.pqa.resources.signatureKept'));
    const signatureDot = resource.signatureChanged
            ? `<span aria-label="${sigChangedTitle}" style="width:10px;height:10px;border-radius:50%;background:#fbbf24;box-shadow:0 0 10px rgba(251,191,36,0.7);flex-shrink:0;"></span>`
            : `<span aria-label="${sigKeptTitle}" style="width:10px;height:10px;border-radius:50%;background:#34d399;box-shadow:0 0 8px rgba(52,211,153,0.5);flex-shrink:0;"></span>`;
    const highlightClass = targetRefMatches(resource, ['resourceId', 'resourceUrl', 'httpMethod'], activeTargetRef) ? 'pqa-row-highlight' : '';
    return `
        <article data-pqa-resource-card
           data-pqa-detail-href="${detailHref}"
           role="link"
           tabindex="0"
           class="${highlightClass}"
           style="position:relative;display:flex;align-items:center;gap:1rem;padding:0.75rem 1.5rem 0.75rem 0.75rem;border-radius:2.5rem 0.7rem 2.5rem 0.7rem;background:linear-gradient(135deg,rgba(30,41,59,0.72),rgba(15,23,42,0.82));border:1px solid rgba(71,85,105,0.5);box-shadow:0 10px 24px rgba(0,0,0,0.32);text-decoration:none;color:inherit;overflow:hidden;">
            <span style="flex-shrink:0;width:58px;height:58px;border-radius:50%;background:${method.bg};color:${method.text};display:grid;place-items:center;font-size:0.85rem;font-weight:900;letter-spacing:0.02em;box-shadow:0 8px 18px rgba(0,0,0,0.35);">${escapeHtml(httpMethod)}</span>
            <span style="display:flex;flex-direction:column;min-width:0;flex:1;gap:0.15rem;">
                <span style="display:flex;align-items:center;gap:0.55rem;min-width:0;">
                    <span style="color:#f8fafc;font-size:1.05rem;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:22ch;">${escapeHtml(friendlyName(resource))}</span>
                    <span style="color:#94a3b8;font-size:0.9rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:'SFMono-Regular','Menlo','Consolas',monospace;flex:1;min-width:0;">${escapeHtml(resourceUrl)}</span>
                </span>
                <span style="display:flex;align-items:center;gap:0.55rem;color:#64748b;font-size:0.82rem;font-family:'SFMono-Regular','Menlo',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(resourceId)}</span>
            </span>
            <span style="display:inline-flex;align-items:center;gap:0.4rem;padding:0.35rem 0.8rem;border-radius:999px;background:rgba(2,6,23,0.55);border:1px solid rgba(148,163,184,0.25);white-space:nowrap;flex-shrink:0;">
                <span style="color:#94a3b8;font-size:0.72rem;font-weight:800;letter-spacing:0.12em;text-transform:uppercase;">${escapeHtml(t('enterprise.pqa.resource.card.criticality'))}</span>
                ${badge(criticalityLabel, { tone: criticalityTone })}
            </span>
            <span style="display:flex;flex-direction:column;gap:0.25rem;flex-shrink:0;white-space:nowrap;">
                ${badge(operationalDescriptor?.label || resource.operationalStateLabel, { tone: badgeTone(operationalDescriptor) })}
                ${runtimeDescriptor?.label ? badge(runtimeDescriptor.label, { tone: badgeTone(runtimeDescriptor) }) : ''}
                ${officialBadge}
            </span>
            <span style="display:inline-flex;align-items:center;gap:0.45rem;padding:0.35rem 0.75rem;border-radius:999px;background:rgba(2,6,23,0.55);border:1px solid rgba(148,163,184,0.25);white-space:nowrap;flex-shrink:0;">
                ${signatureDot}
                <span style="color:#cbd5e1;font-size:0.82rem;font-weight:600;">${escapeHtml(resource.signatureChanged ? t('enterprise.pqa.resource.signature.changed') : t('enterprise.pqa.resource.signature.unchanged'))}</span>
            </span>
            <span style="display:inline-flex;align-items:center;gap:0.45rem;flex-shrink:0;white-space:nowrap;">
                ${evidenceAction}
                <a href="${detailHref}" style="padding:0.35rem 0.8rem;border-radius:0.4rem;background:rgba(148,163,184,0.08);border:1px solid rgba(148,163,184,0.25);color:#cbd5e1;display:inline-flex;align-items:center;justify-content:center;font-size:0.8rem;font-weight:700;text-decoration:none;" aria-label="${escapeHtml(t('enterprise.pqa.resource.table.action.detail'))}">${escapeHtml(t('enterprise.pqa.resource.table.action.detail'))}</a>
            </span>
        </article>
    `;
}

function runtimeEvidenceActionHtml(resource, runtimeDescriptor) {
    if (runtimeEvidenceAvailable(resource)) {
        const evidenceHref = runtimeEvidenceHref(resource);
        return `<a href="${evidenceHref}" style="padding:0.35rem 0.8rem;border-radius:0.4rem;background:rgba(52,211,153,0.14);border:1px solid rgba(52,211,153,0.35);color:#6ee7b7;display:inline-flex;align-items:center;justify-content:center;font-size:0.8rem;font-weight:700;cursor:pointer;text-decoration:none;" aria-label="${escapeHtml(t('enterprise.pqa.resource.table.action.verify'))}">${escapeHtml(t('enterprise.pqa.resource.table.action.verify'))}</a>`;
    }
    const label = runtimeDescriptor?.label || '-';
    return `<span aria-disabled="true" style="padding:0.35rem 0.8rem;border-radius:0.4rem;background:rgba(148,163,184,0.08);border:1px solid rgba(148,163,184,0.18);color:#94a3b8;display:inline-flex;align-items:center;justify-content:center;font-size:0.8rem;font-weight:700;text-decoration:none;cursor:not-allowed;">${escapeHtml(label)}</span>`;
}

function officialInspectionBadgeHtml(resource) {
    if (!officialInspectionAvailable(resource)) {
        return badge(t('enterprise.pqa.resource.official.none'), { tone: 'neutral' });
    }
    const blocked = officialInspectionBlocked(resource);
    const label = blocked
            ? t('enterprise.pqa.resource.official.blocked')
            : t('enterprise.pqa.resource.official.completed');
    const tone = blocked ? 'blocked' : 'ready';
    const passed = Number(resource.latestOfficialPassedMetricCount);
    const expected = Number(resource.latestOfficialExpectedMetricCount);
    const suffix = Number.isFinite(passed) && Number.isFinite(expected) && expected > 0
            ? ` ${passed}/${expected}`
            : '';
    return badge(`${label}${suffix}`, { tone });
}

function wireResourceCards(stream) {
    stream.querySelectorAll('[data-pqa-resource-card]').forEach(card => {
        const href = card.dataset.pqaDetailHref;
        if (!href) {
            return;
        }
        const navigate = event => {
            if (event?.target?.closest?.('a, button')) {
                return;
            }
            window.location.href = href;
        };
        card.addEventListener('click', navigate);
        card.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                navigate(event);
            }
        });
    });
}

function resourceDetailHref(resource) {
    return pageHref('/resources/detail', resourceIdentityParams(resource, { allowInternalResourceId: true }));
}

function runtimeEvidenceHref(resource) {
    return pageHref('/runtime-evidence', resourceEvidenceParams(resource));
}

function runtimeEvidenceAvailable(resource) {
    const params = resourceEvidenceParams(resource);
    return params.has('packageId') || params.has('resourceUrl');
}

function officialInspectionAvailable(resource) {
    return Boolean(rawText(resource.latestOfficialAggregateRunId));
}

function officialInspectionBlocked(resource) {
    const decision = String(resource.latestOfficialDecision || '').toUpperCase();
    return resource.latestOfficialBlocked === true
            || decision === 'BLOCKED'
            || decision === 'BLOCK'
            || decision === 'OFFICIAL_BLOCKED';
}

function pageHref(path, params) {
    const query = params.toString();
    return `${PAGE_BASE}${path}${query ? `?${query}` : ''}`;
}

function resourceIdentityParams(resource, options = {}) {
    const params = new URLSearchParams();
    setRouteParam(params, 'resourceUrl', resource.resourceUrl);
    setRouteParam(params, 'resourceId', searchableResourceId(resource.resourceId, options));
    const method = options.evidenceSearch ? normalizeHttpMethod(resource.httpMethod) : rawText(resource.httpMethod);
    setRouteParam(params, 'httpMethod', method);
    return params;
}

function resourceEvidenceParams(resource) {
    const params = new URLSearchParams();
    const packageId = rawText(resource.latestRuntimeEvidencePackageId || resource.runtimeEvidencePackageId || resource.packageId);
    if (packageId) {
        setRouteParam(params, 'packageId', packageId);
        setRouteParam(params, 'resourceUrl', searchableResourceUrl(resource.latestRuntimeEvidenceResourceUrl || resource.resourceUrl));
        setRouteParam(params, 'resourceId', searchableResourceId(resource.latestRuntimeEvidenceResourceId));
        setRouteParam(params, 'httpMethod', normalizeHttpMethod(resource.latestRuntimeEvidenceHttpMethod || resource.httpMethod));
        return params;
    }
    const resourceUrl = searchableResourceUrl(resource.resourceUrl);
    if (resourceUrl) {
        setRouteParam(params, 'resourceUrl', resourceUrl);
        setRouteParam(params, 'resourceId', searchableResourceId(resource.resourceId));
        setRouteParam(params, 'httpMethod', normalizeHttpMethod(resource.httpMethod));
    }
    return params;
}

function searchableResourceUrl(value) {
    const url = rawText(value);
    if (!url || isInternalResourceIdentifier(url)) {
        return '';
    }
    return url;
}

function normalizeHttpMethod(value) {
    const method = String(rawText(value) || '').toUpperCase();
    return HTTP_METHODS.has(method) ? method : '';
}

function searchableResourceId(value, options = {}) {
    const identifier = rawText(value);
    if (!identifier) {
        return '';
    }
    if (!options.allowInternalResourceId && isInternalResourceIdentifier(identifier)) {
        return '';
    }
    return identifier;
}

function isInternalResourceIdentifier(value) {
    const identifier = rawText(value);
    return !identifier.startsWith('/')
            && (identifier.includes('$$') || identifier.includes('#') || identifier.includes('SpringCGLIB'));
}

function setRouteParam(params, name, value) {
    const normalized = rawText(value);
    if (normalized) {
        params.set(name, normalized);
    }
}

function descriptor(dimension, code) {
    const normalized = String(code || '').toUpperCase();
    return latestStateCatalog.find(item => item.dimension === dimension && item.code === normalized);
}

function aggregate(descriptor) {
    return String(descriptor?.aggregateGroup || '').toUpperCase();
}

function badgeTone(descriptor) {
    const tone = String(descriptor?.tone || 'neutral').toLowerCase();
    if (tone === 'ready') {
        return 'ready';
    }
    if (tone === 'blocked') {
        return 'blocked';
    }
    if (tone === 'pending') {
        return 'pending';
    }
    if (tone === 'reverify') {
        return 'reverify';
    }
    return 'neutral';
}
