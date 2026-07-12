import { appPath, escapeHtml, ensureArray, rawText, text } from '../verification-ui-common.js';
import { bootDetailPage } from './prompt-quality-page.js';
import { t } from './prompt-quality-i18n.js';

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);
const API_BASE = appPath('/admin/api/enterprise/prompt-quality');
const PAGE_BASE = appPath('/admin/enterprise/prompt-quality');

const root = document.querySelector('[data-pqa-page="resource-detail"]');
const resourceId = root?.dataset.resourceId || '';
const httpMethod = root?.dataset.httpMethod || 'GET';
const resourceUrl = rawText(root?.dataset.resourceUrl)
        || rawText(new URLSearchParams(window.location.search || '').get('resourceUrl'))
        || '';
const routeScope = {
    resourceUrl,
    resourceId,
    httpMethod
};

const OPERATIONAL_CLASS = {
    ZERO_TRUST_ENABLED: 'success',
    CERTIFIED: 'success',
    PENDING_VERIFICATION: 'warning',
    SUSPENDED: 'warning',
    BLOCKED: 'error',
    EXPIRED: 'warning',
    RETIRED: 'neutral',
    DISCOVERED: 'info'
};

const CRITICALITY_CLASS = {
    CRITICAL: 'error',
    HIGH: 'error',
    SENSITIVE: 'warning',
    MEDIUM: 'warning',
    NORMAL: 'success',
    LOW: 'neutral'
};

bootDetailPage(`${API_BASE}/resources/detail?${resourceIdentityQuery({
    resourceUrl,
    resourceId,
    httpMethod
}, { allowTemplateResourceUrl: true })}`, (pageRoot, payload) => {
    const resource = payload.resource;
    const history = ensureArray(payload.history);
    renderStrip(pageRoot, resource);
    renderNextAction(pageRoot, resource);
    renderOwnership(pageRoot, resource);
    renderLineage(pageRoot, payload);
    renderHistory(pageRoot, history);
});

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

function badgeHtml(label, tone) {
    const cls = tone || 'neutral';
    return `<span class="badge ${cls}">${escapeHtml(label || '-')}</span>`;
}

const METHOD_TONE = { GET: 'success', POST: 'info', PUT: 'warning', PATCH: 'neutral', DELETE: 'error', OPTIONS: 'neutral' };

function metaRow(label, valueHtml, isLast) {
    return `
        <div class="pqa-resource-detail-meta-row${isLast ? ' is-last' : ''}">
            <div class="pqa-resource-detail-meta-label">
                ${escapeHtml(label)}
            </div>
            <div class="pqa-resource-detail-meta-value">
                ${valueHtml}
            </div>
        </div>
    `;
}

function monoValue(value) {
    return `<code class="pqa-resource-detail-meta-code">${escapeHtml(value || '-')}</code>`;
}

function badgeValueLarge(label, tone) {
    return `<span class="badge ${tone || 'neutral'} pqa-resource-detail-badge-large">${escapeHtml(label || '-')}</span>`;
}

function renderStrip(root, resource) {
    const target = root.querySelector('[data-pqa-resource-strip]');
    if (!target) {
        return;
    }
    const criticalityCode = String(resource.criticality || '').toUpperCase();
    const criticalityCls = CRITICALITY_CLASS[criticalityCode] || 'neutral';
    const criticalityLabel = criticalityCode
            ? t('enterprise.pqa.resource.criticality.' + criticalityCode.toLowerCase())
            : t('enterprise.pqa.resource.criticality.unknown');
    const operationalCls = OPERATIONAL_CLASS[String(resource.operationalState || '').toUpperCase()] || 'neutral';
    const verificationRequired = !!resource.verificationRequired;
    const verificationLabel = verificationRequired
            ? t('enterprise.pqa.resourceDetail.info.verificationRequired.required')
            : t('enterprise.pqa.resourceDetail.info.verificationRequired.optional');
    const verificationCls = verificationRequired ? 'error' : 'neutral';
    const syncLabel = resource.sync
            ? t('enterprise.pqa.resourceDetail.sync.linked')
            : t('enterprise.pqa.resourceDetail.sync.independent');
    const syncCls = resource.sync ? 'success' : 'neutral';
    const signatureLabel = resource.signatureChanged
            ? t('enterprise.pqa.resource.signature.changed')
            : t('enterprise.pqa.resource.signature.unchanged');
    const signatureCls = resource.signatureChanged ? 'warning' : 'success';

    const method = normalizeHttpMethod(resource.httpMethod) || 'GET';
    const methodTone = METHOD_TONE[method] || 'neutral';
    const url = text(resource.resourceUrl) || '-';
    const idValue = text(resource.resourceId) || '-';
    const source = `${text(resource.sourceClassName)}.${text(resource.sourceMethodName)}`;
    const metaHtml = `
        ${metaRow('URL', monoValue(url), false)}
        ${metaRow(t('enterprise.pqa.resourceDetail.meta.method'), badgeValueLarge(method, methodTone), false)}
        ${metaRow(t('enterprise.pqa.resourceDetail.meta.id'), monoValue(idValue), false)}
        ${metaRow(t('enterprise.pqa.resourceDetail.meta.source'), monoValue(source), true)}
    `;
    const statusBadges = [
        { label: t('enterprise.pqa.resourceDetail.info.criticality'), value: criticalityLabel, cls: criticalityCls },
        { label: t('enterprise.pqa.resourceDetail.info.operational'), value: resource.operationalStateLabel || '-', cls: operationalCls },
        { label: t('enterprise.pqa.resourceDetail.info.verificationRequired'), value: verificationLabel, cls: verificationCls },
        { label: t('enterprise.pqa.resourceDetail.info.sync'), value: syncLabel, cls: syncCls },
        { label: t('enterprise.pqa.resourceDetail.info.signature'), value: signatureLabel, cls: signatureCls }
    ];
    const badgeRowHtml = statusBadges.map(b => `
        <span class="pqa-resource-detail-chip">
            <span class="pqa-resource-detail-chip-label">${escapeHtml(b.label)}</span>
            <span class="badge ${b.cls} pqa-resource-detail-chip-value">${escapeHtml(b.value)}</span>
        </span>
    `).join('');
    target.innerHTML = `
        <div class="pqa-resource-detail-meta">${metaHtml}</div>
        <div class="pqa-resource-detail-chip-row">${badgeRowHtml}</div>
    `;
}

function renderNextAction(root, resource) {
    const target = root.querySelector('[data-pqa-next-action]');
    if (!target) {
        return;
    }
    const name = friendlyName(resource);
    const method = normalizeHttpMethod(resource.httpMethod) || 'GET';
    const url = text(resource.resourceUrl);
    const verifyAction = runtimeEvidenceDetailActionHtml(resource);
    target.innerHTML = `
        <dl class="detail-list">
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.dt.state'))}</dt>
                <dd>${escapeHtml(text(resource.plainStatus))}</dd>
            </div>
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.dt.nextAction'))}</dt>
                <dd>${escapeHtml(text(resource.nextAction))}</dd>
            </div>
        </dl>
        <div class="action-button-row pqa-resource-detail-actions">
            ${verifyAction}
        </div>
    `;
}

function runtimeEvidenceDetailActionHtml(resource) {
    if (runtimeEvidenceAvailable(resource)) {
        const verifyHref = runtimeEvidenceHref(resource);
        return `<a class="button primary pqa-resource-detail-button-primary" href="${verifyHref}" data-pqa-click-href="${escapeHtml(verifyHref)}">${escapeHtml(t('enterprise.pqa.resourceDetail.action.verify'))}</a>`;
    }
    const label = resource.runtimeRequestStateDescriptor?.label || '-';
    return `<span class="button pqa-resource-detail-button-primary is-disabled" aria-disabled="true" data-pqa-disabled-reason="${escapeHtml(label)}">${escapeHtml(label)}</span>`;
}

function renderOwnership(root, resource) {
    const target = root.querySelector('[data-pqa-ownership]');
    if (!target) {
        return;
    }
    const owner = text(resource.ownerField) || t('enterprise.pqa.resourceDetail.info.ownerField.unknown');
    const overlayParams = new URLSearchParams();
    setRouteParam(overlayParams, 'resourceUrl', resource.resourceUrl);
    setRouteParam(overlayParams, 'httpMethod', normalizeHttpMethod(resource.httpMethod));
    setRouteParam(overlayParams, 'tenantId', resource.tenantId);
    const overlayHref = `${PAGE_BASE}/resources/${encodeURIComponent(text(resource.resourceId))}/overlay/edit?${overlayParams.toString()}`;
    target.innerHTML = `
        <dl class="detail-list">
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.info.ownerField'))}</dt>
                <dd>${escapeHtml(owner)}</dd>
            </div>
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.section.ownership.subtitle'))}</dt>
                <dd class="muted">${escapeHtml(t('enterprise.pqa.resourceDetail.overlay.helper'))}</dd>
            </div>
        </dl>
        <div class="action-button-row pqa-resource-detail-actions">
            <a class="button primary pqa-resource-detail-button-primary" href="${overlayHref}" data-pqa-click-href="${escapeHtml(overlayHref)}">
                ${escapeHtml(t('enterprise.pqa.resourceDetail.info.overlayEditButton'))}
            </a>
        </div>
    `;
}

function renderHistory(root, items) {
    const target = root.querySelector('[data-pqa-resource-history]');
    if (!target) {
        return;
    }
    if (!items.length) {
        target.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.resourceDetail.history.empty'))}</div>`;
        return;
    }
    const rows = items.map(item => `
        <tr>
            <td>${escapeHtml(text(item.stateLabel))}</td>
            <td>${escapeHtml(text(item.plainResult))}</td>
            <td>${escapeHtml(text(item.nextAction))}</td>
        </tr>
    `).join('');
    target.innerHTML = `
        <div class="table-wrap">
            <table class="ops-table">
                <thead>
                    <tr>
                        <th>${escapeHtml(t('enterprise.pqa.resourceDetail.th.state'))}</th>
                        <th>${escapeHtml(t('enterprise.pqa.resourceDetail.th.result'))}</th>
                        <th>${escapeHtml(t('enterprise.pqa.resourceDetail.th.nextAction'))}</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

function renderLineage(root, payload) {
    const target = root.querySelector('[data-pqa-resource-lineage]');
    if (!target) {
        return;
    }
    const assuranceCase = payload.assuranceCase;
    const artifacts = ensureArray(payload.artifactReferences);
    const lineage = ensureArray(payload.lineage);
    const impacts = ensureArray(payload.impacts);
    if (!assuranceCase && !artifacts.length && !lineage.length && !impacts.length) {
        target.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.resourceDetail.empty.noVerification'))}</div>`;
        return;
    }
    const caseId = realIdentifier(assuranceCase?.caseId);
    const caseCell = caseId
            ? `<a class="pqa-inline-link" href="${scopedDetailHref(`${PAGE_BASE}/cases/${encodeURIComponent(caseId)}`, routeScope)}"><code class="pqa-hash">${escapeHtml(caseId)}</code></a>`
            : '-';
    const artifactHtml = artifacts.length
            ? `<div class="action-button-row pqa-resource-lineage-artifacts">
                    ${artifacts.map(renderArtifactReference).join('')}
               </div>`
            : `<div class="empty-state pqa-resource-lineage-empty">${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.empty.refs'))}</div>`;
    const stageRows = lineage.length
            ? `<div class="table-wrap pqa-resource-lineage-table">
                    <table class="ops-table">
                        <thead>
                            <tr><th>${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.th.step'))}</th><th>${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.th.summary'))}</th><th>${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.th.reference'))}</th></tr>
                        </thead>
                        <tbody>
                            ${lineage.slice(0, 6).map(item => `
                                <tr>
                                    <td>${escapeHtml(text(item.stageKey))}</td>
                                    <td>${escapeHtml(text(item.summary))}</td>
                                    <td>${escapeHtml(text(item.artifactRef))}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
               </div>`
            : `<div class="empty-state pqa-resource-lineage-empty">${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.empty.steps'))}</div>`;
    const impactRows = impacts.length
            ? `<div class="table-wrap pqa-resource-lineage-table">
                    <table class="ops-table">
                        <thead>
                            <tr><th>${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.th.impactCause'))}</th><th>${escapeHtml(t('enterprise.pqa.resourceDetail.th.state'))}</th><th>${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.th.summary'))}</th></tr>
                        </thead>
                        <tbody>
                            ${impacts.slice(0, 6).map(item => `
                                <tr>
                                    <td>${escapeHtml(text(item.sourceType))}</td>
                                    <td>${escapeHtml(text(item.impactState))}</td>
                                    <td>${escapeHtml(text(item.summary))}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
               </div>`
            : `<div class="empty-state pqa-resource-lineage-empty">${escapeHtml(t('enterprise.pqa.resourceDetail.lineage.empty.impacts'))}</div>`;
    target.innerHTML = `
        <dl class="detail-list">
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.dt.case'))}</dt>
                <dd>${caseCell}</dd>
            </div>
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.dt.currentStage'))}</dt>
                <dd>${escapeHtml(text(assuranceCase?.currentStage) || '-')}</dd>
            </div>
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.dt.reverifyState'))}</dt>
                <dd>${escapeHtml(text(assuranceCase?.dirtyState) || '-')}</dd>
            </div>
            <div>
                <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.dt.summary'))}</dt>
                <dd>${escapeHtml(text(assuranceCase?.summary) || '-')}</dd>
            </div>
        </dl>
        ${artifactHtml}
        ${stageRows}
        ${impactRows}
    `;
}

function renderArtifactReference(item) {
    const label = `${rawText(item.label) || rawText(item.referenceType) || t('enterprise.pqa.resourceDetail.label.referenceFallback')} · ${rawText(item.referenceId) || '-'}`;
    const route = validRoute(item.route);
    if (route) {
        return `<a class="button secondary pqa-resource-lineage-artifact-link" href="${escapeHtml(route)}">${escapeHtml(label)}</a>`;
    }
    return `<span class="badge neutral pqa-resource-lineage-artifact-badge">${escapeHtml(label)}</span>`;
}

function resourceIdentityQuery(resource, options = {}) {
    const params = new URLSearchParams();
    if (options.allowTemplateResourceUrl || (!options.evidenceSearch && !isTemplateResourceUrl(resource.resourceUrl))) {
        setRouteParam(params, 'resourceUrl', resource.resourceUrl);
    }
    if (options.evidenceSearch) {
        setRouteParam(params, 'resourceUrl', searchableResourceUrl(resource.resourceUrl));
    }
    setRouteParam(params, 'resourceId', searchableResourceId(resource.resourceId, options));
    const method = options.evidenceSearch ? normalizeHttpMethod(resource.httpMethod) : rawText(resource.httpMethod);
    setRouteParam(params, 'httpMethod', method);
    return params.toString();
}

function runtimeEvidenceParams(resource) {
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
        setRouteParam(params, 'resourceId', searchableResourceId(resource.resourceId, { evidenceSearch: true }));
        setRouteParam(params, 'httpMethod', normalizeHttpMethod(resource.httpMethod));
    }
    return params;
}

function runtimeEvidenceHref(resource) {
    const params = runtimeEvidenceParams(resource);
    const query = params.toString();
    return `${PAGE_BASE}/runtime-evidence${query ? `?${query}` : ''}`;
}

function runtimeEvidenceAvailable(resource) {
    const params = runtimeEvidenceParams(resource);
    return params.has('packageId') || params.has('resourceUrl');
}

function scopedTargetHref(baseRoute, resource) {
    const params = new URLSearchParams();
    if (!isTemplateResourceUrl(resource.resourceUrl)) {
        setRouteParam(params, 'resourceUrl', resource.resourceUrl);
    }
    setRouteParam(params, 'resourceId', searchableResourceId(resource.resourceId));
    setRouteParam(params, 'httpMethod', normalizeHttpMethod(resource.httpMethod));
    setRouteParam(params, 'targetRef', !isTemplateResourceUrl(resource.resourceUrl)
            ? rawText(resource.resourceUrl)
            : rawText(resource.resourceId));
    const query = params.toString();
    return `${baseRoute}${query ? `?${query}` : ''}`;
}

function scopedDetailHref(baseRoute, resource, options = {}) {
    const query = resourceIdentityQuery(resource, options);
    return `${baseRoute}${query ? `?${query}` : ''}`;
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
    if (options.evidenceSearch && !options.allowInternalResourceId && isInternalResourceIdentifier(identifier)) {
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

function renderProcessStages(root, stages) {
    const target = root.querySelector('[data-pqa-resource-process-stages]');
    if (!target) {
        return;
    }
    if (!stages.length) {
        target.innerHTML = `<div class="empty-state">${escapeHtml(t('enterprise.pqa.resourceDetail.process.empty'))}</div>`;
        return;
    }
    target.innerHTML = `
        <ol class="pqa-resource-process-timeline">
            ${stages.map((stage, index) => renderProcessStage(stage, index)).join('')}
        </ol>
    `;
}

function renderProcessStage(stage, index) {
    const process = stage.processStage || {};
    const state = stage.state || {};
    const execution = stage.executionStateDescriptor || {};
    const tone = safeTone(state.tone || process.tone);
    const executionTone = safeTone(execution.tone || 'neutral');
    const evidence = text(stage.evidenceRef);
    const action = `<span>${escapeHtml(text(stage.nextAction) || text(state.nextAction) || '-')}</span>`;
    return `
        <li class="pqa-resource-process-step ${stage.current ? 'is-current' : ''} tone-${tone}">
            <span class="pqa-resource-process-index">${index + 1}</span>
            <div class="pqa-resource-process-main">
                <strong>${escapeHtml(text(process.label) || text(process.code))}</strong>
                <div class="pqa-resource-process-badges">
                    ${badgeHtml(text(execution.label) || text(stage.executionState) || '-', stateToneToBadge(executionTone))}
                    ${badgeHtml(text(state.label) || '-', stateToneToBadge(tone))}
                    ${stage.current ? badgeHtml(t('enterprise.pqa.resourceDetail.process.current'), 'success') : ''}
                </div>
                <p>${escapeHtml(text(stage.summary) || text(state.nextAction) || '-')}</p>
                <dl>
                    <div>
                        <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.process.evidence'))}</dt>
                        <dd>${evidence ? `<code>${escapeHtml(evidence)}</code>` : '-'}</dd>
                    </div>
                    <div>
                        <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.process.next'))}</dt>
                        <dd>${action}</dd>
                    </div>
                    <div>
                        <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.process.startedAt'))}</dt>
                        <dd>${escapeHtml(formatProcessTime(stage.startedAt))}</dd>
                    </div>
                    <div>
                        <dt>${escapeHtml(t('enterprise.pqa.resourceDetail.process.endedAt'))}</dt>
                        <dd>${escapeHtml(formatProcessTime(stage.endedAt))}</dd>
                    </div>
                </dl>
            </div>
        </li>
    `;
}

function safeTone(value) {
    return String(value || 'neutral').toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
}

function stateToneToBadge(tone) {
    if (tone === 'ready') {
        return 'success';
    }
    if (tone === 'blocked') {
        return 'error';
    }
    if (tone === 'pending' || tone === 'reverify' || tone === 'warning') {
        return 'warning';
    }
    return 'neutral';
}

function formatProcessTime(value) {
    const raw = text(value);
    if (!raw) {
        return '-';
    }
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) {
        return raw;
    }
    return date.toLocaleString();
}

function validRoute(value) {
    const route = rawText(value);
    if (!route) {
        return null;
    }
    return sanitizeRoute(route);
}

function sanitizeRoute(route) {
    let url;
    try {
        url = new URL(route, window.location.origin);
    }
    catch {
        return route;
    }
    if (url.searchParams.get('resourceUrl')?.includes('{resourceId}')
            && !url.pathname.endsWith('/resources/detail')
            && !url.pathname.includes('/overlay/edit')) {
        url.searchParams.delete('resourceUrl');
    }
    return `${url.pathname}${url.search}${url.hash}`;
}

function isTemplateResourceUrl(value) {
    return String(rawText(value) || '').includes('{resourceId}');
}

function realIdentifier(value) {
    const normalized = rawText(value);
    if (!normalized || normalized === '-' || normalized === '\u2014') {
        return '';
    }
    return normalized;
}
