import { $, appPath, escapeHtml, ensureArray, rawText } from '../verification-ui-common.js';
import { getJson, publicError } from './prompt-quality-api.js';
import { badge, setStatus } from './prompt-quality-page.js';
import { ensureBundle, t } from './prompt-quality-i18n.js';
import { showActionTooltip } from './prompt-quality-ui.js';

const root = document.querySelector('[data-pqa-page="runtime-evidence"]');
function promptQualityApiRoot() {
    return rawText(root?.dataset?.pqaApiRoot) || '/contexa/admin/api/prompt-quality';
}

function promptQualityApiPath(path) {
    const base = promptQualityApiRoot().replace(/\/+$/, '');
    const suffix = String(path || '').startsWith('/') ? String(path || '') : `/${path || ''}`;
    return `${base}${suffix}`;
}

function promptQualityRouteRoot() {
    return rawText(root?.dataset?.pqaRouteRoot) || '/contexa/admin/prompt-quality';
}

function promptQualityRoutePath(path) {
    const base = promptQualityRouteRoot().replace(/\/+$/, '');
    const suffix = String(path || '').startsWith('/') ? String(path || '') : `/${path || ''}`;
    return appPath(`${base}${suffix}`);
}
const locationParams = new URLSearchParams(window.location.search || '');
const lockedResourceContext = scopedResourceContext(locationParams);

if (root) {
    initialize(root).catch(error => {
        setStatus(root, 'error', 'Failed to load localization resources.', publicError(error));
    });
}

async function initialize(pageRoot) {
    await ensureBundle();
    renderSummary(pageRoot, []);
    bindSearch(pageRoot);
    bindDetailModal(pageRoot);
    hydrateSearchFormFromLocation(pageRoot);
    keepSearchControlsEnabled(pageRoot);
    setStatus(pageRoot, 'loading', t('enterprise.pqa.runtimeEvidence.recent.loading.title'), t('enterprise.pqa.runtimeEvidence.recent.loading.detail'));
    searchEvidence(pageRoot);
}

function bindDetailModal(pageRoot) {
    const backdrop = pageRoot.querySelector('[data-pqa-runtime-modal]');
    if (!backdrop) {
        return;
    }
    backdrop.addEventListener('click', event => {
        if (event.target === backdrop) {
            closeDetailModal(pageRoot);
        }
    });
    pageRoot.querySelectorAll('[data-pqa-runtime-modal-close]').forEach(button => {
        button.addEventListener('click', () => closeDetailModal(pageRoot));
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && !backdrop.hasAttribute('hidden')) {
            closeDetailModal(pageRoot);
        }
    });
}

function openDetailModal(pageRoot) {
    const backdrop = pageRoot.querySelector('[data-pqa-runtime-modal]');
    if (!backdrop) {
        return;
    }
    backdrop.removeAttribute('hidden');
    document.body.style.overflow = 'hidden';
}

function closeDetailModal(pageRoot) {
    const backdrop = pageRoot.querySelector('[data-pqa-runtime-modal]');
    if (!backdrop) {
        return;
    }
    backdrop.setAttribute('hidden', '');
    document.body.style.overflow = '';
}

function hydrateSearchFormFromLocation(pageRoot) {
    const form = $(pageRoot, '[data-pqa-runtime-search-form]');
    if (!form) {
        return;
    }
    const params = new URLSearchParams(window.location.search || '');
    [
        'packageId', 'tenantId', 'userId', 'resourceUrl', 'resourceId', 'resourceTemplateId',
        'actualResourceId', 'httpMethod', 'aggregateRunId', 'officialRunId', 'reverifyRunId',
        'certificateId', 'caseId', 'from', 'to'
    ].forEach(name => {
        const value = rawText(params.get(name));
        if (!value) {
            return;
        }
        const field = form.elements.namedItem(name);
        if (field) {
            field.value = value;
        }
    });
}

function bindSearch(pageRoot) {
    const form = $(pageRoot, '[data-pqa-runtime-search-form]');
    keepSearchControlsEnabled(pageRoot);
    form?.addEventListener('submit', event => {
        event.preventDefault();
        keepSearchControlsEnabled(pageRoot);
        searchEvidence(pageRoot);
    });
    $(pageRoot, '[data-pqa-runtime-reset]')?.addEventListener('click', () => {
        form?.reset();
        applyLockedResourceContext(form);
        resetDetail(pageRoot);
        keepSearchControlsEnabled(pageRoot);
        searchEvidence(pageRoot);
    });
}

async function searchEvidence(pageRoot) {
    keepSearchControlsEnabled(pageRoot);
    const form = $(pageRoot, '[data-pqa-runtime-search-form]');
    const params = new URLSearchParams();
    new FormData(form).forEach((value, key) => {
        const normalized = String(value || '').trim();
        if (normalized) {
            params.set(key, normalized);
        }
    });
    applyLockedResourceContextToParams(params);
    const hasFilters = Array.from(params.keys()).length > 0;
    setStatus(pageRoot, 'loading', t('enterprise.pqa.runtimeEvidence.search.loading.title'), t('enterprise.pqa.runtimeEvidence.search.loading.detail'));
    try {
        const query = params.toString();
        const endpoint = query
                ? promptQualityApiPath(`/runtime-evidence/search?${query}`)
                : promptQualityApiPath('/runtime-evidence/search');
        const results = ensureArray(await getJson(endpoint));
        renderResults(pageRoot, results, hasFilters);
        renderSummary(pageRoot, results);
        if (results.length === 0) {
            setStatus(pageRoot,
                    'error',
                    t('enterprise.pqa.runtimeEvidence.empty.title'),
                    hasFilters
                            ? t('enterprise.pqa.runtimeEvidence.empty.filterDetail')
                            : t('enterprise.pqa.runtimeEvidence.empty.noFilterDetail'));
        }
        else {
            setStatus(pageRoot,
                    'success',
                    hasFilters ? t('enterprise.pqa.runtimeEvidence.searched.complete') : t('enterprise.pqa.runtimeEvidence.recent.complete'),
                    t('enterprise.pqa.runtimeEvidence.searched.countTpl', results.length));
        }
        const packageId = rawText(params.get('packageId'));
        const matched = packageId
                ? results.find(item => rawText(item.packageId) === packageId)
                : null;
        if (matched) {
            await loadDetail(pageRoot, matched);
        }
    }
    catch (error) {
        setStatus(pageRoot, 'error', t('enterprise.pqa.runtimeEvidence.search.failed'), publicError(error));
    }
}

function renderSummary(pageRoot, items) {
    const target = $(pageRoot, '[data-pqa-runtime-summary]');
    const total = ensureArray(items).length;
    const integrityOk = ensureArray(items).filter(item => item.integrityValid).length;
    const warning = total - integrityOk;
    if (!target) {
        return;
    }
    target.innerHTML = `
        <article class="pqa-summary-item">
            <span><i class="fa-solid fa-box-archive" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.summary.searched'))}</span>
            <strong>${escapeHtml(total)}</strong>
        </article>
        <article class="pqa-summary-item">
            <span><i class="fa-solid fa-circle-check" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.summary.integrityOk'))}</span>
            <strong>${escapeHtml(integrityOk)}</strong>
        </article>
        <article class="pqa-summary-item">
            <span><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.summary.confirmNeeded'))}</span>
            <strong>${escapeHtml(warning)}</strong>
        </article>
    `;
}

function renderResults(pageRoot, items, hasFilters = false) {
    const target = $(pageRoot, '[data-pqa-runtime-results]');
    const rows = ensureArray(items).map((item, index) => {
        const packageId = rawText(item.packageId);
        const actionUnavailable = t('enterprise.pqa.runtimeEvidence.action.packageIdRequired');
        const detailAction = packageId
                ? `<button type="button" class="pqa-action-button" data-pqa-runtime-package-id="${escapeHtml(packageId)}"><i class="fa-solid fa-circle-info" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.btn.detail'))}</button>`
                : `<button type="button" class="pqa-action-button is-disabled" aria-disabled="true" data-pqa-disabled-reason="${escapeHtml(actionUnavailable)}" aria-label="${escapeHtml(actionUnavailable)}"><i class="fa-solid fa-circle-info" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.btn.detail'))}</button>`;
        const inspectionAction = packageId
                ? `<a class="pqa-link-button" href="${officialInspectionUrl(item)}"><i class="fa-solid fa-arrow-right" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.btn.goToInspection'))}</a>`
                : `<a class="pqa-link-button is-disabled" href="#" aria-disabled="true" data-pqa-disabled-reason="${escapeHtml(actionUnavailable)}" aria-label="${escapeHtml(actionUnavailable)}"><i class="fa-solid fa-arrow-right" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.btn.goToInspection'))}</a>`;
        return `
        <tr data-pqa-runtime-result-row="${escapeHtml(packageId)}"
            data-pqa-click-href="${officialInspectionUrl(item)}"
            role="button"
            tabindex="0">
            <td>
                <div class="pqa-runtime-evidence-cell" style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <code class="pqa-hash" style="margin: 0; font-size: 13px; font-weight: 700;">${escapeHtml(displayValue(item.packageId))}</code>
                    <small style="color: var(--pqa-text-muted, #94a3b8); font-size: 12px; margin-top: 1px;">${escapeHtml(formatCapturedAt(item.capturedAt))}</small>
                </div>
            </td>
            <td>
                <span class="pqa-cell-primary">${escapeHtml(displayValue(item.userId))}</span>
                <span class="pqa-cell-meta">${escapeHtml(displayValue(item.tenantId))}</span>
            </td>
            <td>
                <span class="pqa-path-tag">${escapeHtml(formatRequestLabel(item))}</span>
                <small>${escapeHtml(displayValue(item.resourceId))}</small>
            </td>
            <td>
                <span class="pqa-badge-row">
                    ${stateBadge(item)}
                    ${badge(item.integrityValid ? t('enterprise.pqa.runtimeEvidence.badge.integrityOk') : t('enterprise.pqa.runtimeEvidence.badge.integrityError'), { tone: item.integrityValid ? 'ready' : 'blocked' })}
                    ${badge(item.sealed ? t('enterprise.pqa.runtimeEvidence.badge.sealed') : t('enterprise.pqa.runtimeEvidence.badge.unsealed'), { tone: item.sealed ? 'ready' : 'blocked' })}
                </span>
            </td>
            <td>
                <div class="pqa-runtime-decision-cell" style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span class="pqa-cell-primary" style="font-weight: 700; margin: 0;">${escapeHtml(displayValue(item.decisionAction))}</span>
                    <span class="pqa-cell-meta" style="color: var(--pqa-text-muted, #94a3b8); font-size: 12px; margin-top: 1px;">(${escapeHtml(t('enterprise.pqa.runtimeEvidence.confidencePrefix'))}${escapeHtml(displayValue(item.decisionConfidence))})</span>
                </div>
            </td>
            <td>
                <div class="pqa-runtime-row-actions" style="display: flex; align-items: center; gap: 0.45rem; flex-wrap: nowrap; white-space: nowrap;">
                    ${detailAction}
                    ${inspectionAction}
                </div>
            </td>
        </tr>
    `;
    });
    target.innerHTML = rows.length
            ? `<table class="pqa-table">
                    <thead><tr><th>${escapeHtml(t('enterprise.pqa.runtimeEvidence.col.evidence'))}</th><th>${escapeHtml(t('enterprise.pqa.runtimeEvidence.col.user'))}</th><th>${escapeHtml(t('enterprise.pqa.runtimeEvidence.col.request'))}</th><th>${escapeHtml(t('enterprise.pqa.runtimeEvidence.col.state'))}</th><th>${escapeHtml(t('enterprise.pqa.runtimeEvidence.col.decision'))}</th><th>${escapeHtml(t('enterprise.pqa.runtimeEvidence.col.action'))}</th></tr></thead>
                    <tbody>${rows.join('')}</tbody>
               </table>`
            : `<div class="pqa-empty"><p>${emptyEvidenceMessage(hasFilters)}</p></div>`;
    pageRoot.__runtimeEvidenceItems = ensureArray(items);
    target.querySelectorAll('[data-pqa-runtime-package-id]').forEach(button => {
        button.addEventListener('click', () => {
            const packageId = rawText(button.dataset.pqaRuntimePackageId);
            const item = ensureArray(items).find(candidate => rawText(candidate.packageId) === packageId);
            loadDetail(pageRoot, item || { packageId });
        });
    });
    target.querySelectorAll('[data-pqa-runtime-result-row]').forEach(row => {
        const packageId = rawText(row.dataset.pqaRuntimeResultRow);
        const item = ensureArray(items).find(candidate => rawText(candidate.packageId) === packageId);
        row.addEventListener('click', event => {
            if (event?.target?.closest?.('a, button')) {
                return;
            }
            if (packageId) {
                loadDetail(pageRoot, item || { packageId });
            }
        });
        row.addEventListener('keydown', event => {
            if ((event.key === 'Enter' || event.key === ' ') && packageId) {
                event.preventDefault();
                loadDetail(pageRoot, item || { packageId });
            }
        });
    });
    target.querySelectorAll('[data-pqa-disabled-reason]').forEach(control => {
        control.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
            const message = control.dataset.pqaDisabledReason
                    || t('enterprise.pqa.common.action.tooltip.blocked', control.textContent.trim());
            showActionTooltip(pageRoot, control, message, 'blocked');
            setStatus(pageRoot, 'error', t('enterprise.pqa.common.action.blocked.title'), message);
        });
    });
    keepSearchControlsEnabled(pageRoot);
}

function scopedResourceContext(params) {
    const context = {};
    [
        'resourceUrl', 'resourceId', 'resourceTemplateId', 'actualResourceId', 'httpMethod',
        'aggregateRunId', 'officialRunId', 'reverifyRunId', 'certificateId', 'caseId'
    ].forEach(name => {
        const value = rawText(params.get(name));
        if (value) {
            context[name] = value;
        }
    });
    return Object.keys(context).some(name => name !== 'httpMethod') ? context : {};
}

function hasLockedResourceContext() {
    return Object.keys(lockedResourceContext).length > 0;
}

function applyLockedResourceContext(form) {
    if (!form || !hasLockedResourceContext()) {
        return;
    }
    Object.entries(lockedResourceContext).forEach(([name, value]) => {
        const field = form.elements.namedItem(name);
        if (field) {
            field.value = value;
        }
    });
}

function applyLockedResourceContextToParams(params) {
    if (!hasLockedResourceContext()) {
        return;
    }
    Object.entries(lockedResourceContext).forEach(([name, value]) => {
        if (value) {
            params.set(name, value);
        }
    });
}

function keepSearchControlsEnabled(pageRoot) {
    const form = $(pageRoot, '[data-pqa-runtime-search-form]');
    if (!form) {
        return;
    }
    form.querySelectorAll('input, select, button').forEach(control => {
        control.disabled = false;
        control.removeAttribute('aria-disabled');
        control.classList.remove('is-disabled');
        control.removeAttribute('title');
    });
}

function emptyEvidenceMessage(hasFilters) {
    if (hasFilters) {
        return t('enterprise.pqa.runtimeEvidence.empty.filterMessage');
    }
    return t('enterprise.pqa.runtimeEvidence.empty.noFilterMessage');
}

function resetDetail(pageRoot) {
    const detail = $(pageRoot, '[data-pqa-runtime-detail]');
    if (detail) {
        detail.innerHTML = `<p>${escapeHtml(t('enterprise.pqa.runtimeEvidence.detail.emptyAlt'))}</p>`;
    }
}

function formatEvidenceName(item) {
    const path = resourceUrlOf(item);
    const method = rawText(item.httpMethod) || t('enterprise.pqa.runtimeEvidence.method.fallback');
    if (path) {
        return `${method} ${path}`;
    }
    const resourceId = rawText(item.resourceId);
    if (resourceId) {
        return resourceId;
    }
    return shortPackageId(item.packageId);
}

function formatRequestLabel(item) {
    const path = resourceUrlOf(item);
    const method = rawText(item.httpMethod);
    if (path && method) {
        return `${method} ${path}`;
    }
    return path || method || t('enterprise.pqa.runtimeEvidence.request.unknown');
}

function shortPackageId(packageId) {
    const raw = displayValue(packageId);
    return raw.length > 18 ? `${raw.slice(0, 10)}...${raw.slice(-6)}` : raw;
}

function resourceUrlOf(item) {
    return rawText(item?.resourceUrl)
            || rawText(item?.requestPath)
            || rawText(item?.path)
            || rawText(item?.uri);
}

function formatCapturedAt(value) {
    if (!value) {
        return t('enterprise.pqa.runtimeEvidence.savedTime.unknown');
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return displayValue(value);
    }
    return date.toLocaleString('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function officialInspectionUrl(source = {}) {
    const item = typeof source === 'string' ? { packageId: source } : (source || {});
    const params = new URLSearchParams();
    setRouteParam(params, 'packageId', item.packageId);
    setRouteParam(params, 'aggregateRunId', item.aggregateRunId || item.runId || lockedResourceContext.aggregateRunId);
    setRouteParam(params, 'officialRunId', item.officialRunId || lockedResourceContext.officialRunId);
    setRouteParam(params, 'reverifyRunId', item.reverifyRunId || lockedResourceContext.reverifyRunId);
    setRouteParam(params, 'certificateId', item.certificateId || lockedResourceContext.certificateId);
    setRouteParam(params, 'caseId', item.caseId || lockedResourceContext.caseId);
    setRouteParam(params, 'resourceUrl', resourceUrlOf(item) || lockedResourceContext.resourceUrl);
    setRouteParam(params, 'resourceId', item.resourceId || lockedResourceContext.resourceId);
    setRouteParam(params, 'resourceTemplateId', item.resourceTemplateId || item.protectableResourceId || lockedResourceContext.resourceTemplateId);
    setRouteParam(params, 'actualResourceId', item.actualResourceId || item.runtimeResourceId || lockedResourceContext.actualResourceId);
    setRouteParam(params, 'httpMethod', item.httpMethod || lockedResourceContext.httpMethod);
    const query = params.toString();
    return promptQualityRoutePath(`/verification/readiness${query ? `?${query}` : ''}`);
}

async function loadDetail(pageRoot, item) {
    if (!item?.packageId) {
        return;
    }
    setStatus(pageRoot, 'loading', t('enterprise.pqa.runtimeEvidence.detailLoading.title'), t('enterprise.pqa.runtimeEvidence.detailLoading.detail'));
    try {
        const detail = await getJson(promptQualityApiPath(`/runtime-evidence/${encodeURIComponent(item.packageId)}`));
        renderDetail(pageRoot, detail);
        openDetailModal(pageRoot);
        setStatus(pageRoot, 'success', t('enterprise.pqa.runtimeEvidence.detailSuccess.title'), t('enterprise.pqa.runtimeEvidence.detailSuccess.detail'));
    }
    catch (error) {
        setStatus(pageRoot, 'error', t('enterprise.pqa.runtimeEvidence.detailFailed.title'), publicError(error));
    }
}

function renderDetail(pageRoot, detail) {
    const target = $(pageRoot, '[data-pqa-runtime-detail]');
    const warnings = ensureArray(detail.qualityWarnings);
    target.innerHTML = `
        <div class="pqa-runtime-detail-card">
            <section class="pqa-runtime-purpose-card">
                <i class="fa-solid fa-route" aria-hidden="true"></i>
                <div>
                    <strong>${escapeHtml(t('enterprise.pqa.runtimeEvidence.purpose.title'))}</strong>
                    <p>${escapeHtml(t('enterprise.pqa.runtimeEvidence.purpose.detail'))}</p>
                </div>
            </section>
            <dl class="pqa-registration-meta">
                <div><dt>${escapeHtml(t('enterprise.pqa.runtimeEvidence.dt.evidenceId'))}</dt><dd><code>${escapeHtml(displayValue(detail.summary?.packageId))}</code></dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.runtimeEvidence.dt.request'))}</dt><dd>${escapeHtml(displayValue(detail.summary?.httpMethod))} ${escapeHtml(displayValue(resourceUrlOf(detail.summary)))}</dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.runtimeEvidence.dt.promptCapture'))}</dt><dd>${badge(detail.rawUserPromptCaptured && detail.llmUserPromptCaptured ? t('enterprise.pqa.runtimeEvidence.badge.normal') : t('enterprise.pqa.runtimeEvidence.badge.confirmNeeded'))}</dd></div>
            </dl>
            ${renderOfficialPreflight(detail.promptConsistency)}
            ${warnings.length ? `<h3>${escapeHtml(t('enterprise.pqa.runtimeEvidence.title.confirmNeeded'))}</h3><ul class="pqa-runtime-signal-list">${warnings.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}
            <details class="pqa-runtime-prompt-preview">
                <summary>
                    <span>${escapeHtml(t('enterprise.pqa.runtimeEvidence.title.userPromptPreview'))}</span>
                    <small>${escapeHtml(t('enterprise.pqa.runtimeEvidence.userPromptPreview.help'))}</small>
                </summary>
                <pre>${escapeHtml(displayValue(detail.userPromptPreview))}</pre>
            </details>
            <div class="pqa-action-row">
                <a class="pqa-link-button" href="${officialInspectionUrl(detail.summary)}">
                    <i class="fa-solid fa-arrow-right" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.runtimeEvidence.btn.evaluateInOfficial'))}
                </a>
            </div>
        </div>
    `;
}

function stateBadge(item) {
    const descriptor = item?.stateDescriptor;
    if (!descriptor?.label) {
        return '';
    }
    return badge(descriptor.label, { tone: stateTone(descriptor.tone) });
}

function stateTone(tone) {
    const normalized = rawText(tone)?.toLowerCase() || 'neutral';
    if (['ready', 'blocked', 'pending', 'reverify'].includes(normalized)) {
        return normalized;
    }
    return 'neutral';
}

function setRouteParam(params, name, value) {
    const normalized = rawText(value);
    if (normalized) {
        params.set(name, normalized);
    }
}

function renderOfficialPreflight(promptConsistency) {
    const result = promptConsistency || {};
    const checks = ensureArray(result.checks);
    const failed = checks.filter(check => !check.pass);
    const state = rawText(result.stateLabel) || rawText(result.state) || t('enterprise.pqa.runtimeEvidence.preflight.ready');
    const blocked = result.blocking || failed.length > 0;
    return `
        <section class="pqa-runtime-preflight-card ${blocked ? 'is-blocked' : 'is-ready'}">
            <div class="pqa-runtime-preflight-head">
                <div>
                    <h3>${escapeHtml(t('enterprise.pqa.runtimeEvidence.title.preflight'))}</h3>
                    <p>${escapeHtml(t('enterprise.pqa.runtimeEvidence.preflight.help'))}</p>
                </div>
                ${badge(state, { tone: blocked ? 'blocked' : 'ready' })}
            </div>
            <dl class="pqa-runtime-preflight-metrics">
                <div><dt>${escapeHtml(t('enterprise.pqa.runtimeEvidence.preflight.checks'))}</dt><dd>${checks.length}</dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.runtimeEvidence.preflight.blocking'))}</dt><dd>${failed.length}</dd></div>
            </dl>
            ${failed.length ? renderPreflightFailures(failed) : `<p class="pqa-runtime-section-note">${escapeHtml(t('enterprise.pqa.runtimeEvidence.preflight.readyDetail'))}</p>`}
        </section>
    `;
}

function renderPreflightFailures(failed) {
    return `
        <div class="pqa-runtime-preflight-failures">
            <strong>${escapeHtml(t('enterprise.pqa.runtimeEvidence.preflight.blockingTitle'))}</strong>
            <ul>
                ${failed.map(check => `<li><span>${escapeHtml(displayValue(check.label))}</span><em>${escapeHtml(displayValue(check.source))}</em></li>`).join('')}
            </ul>
        </div>
    `;
}

function displayValue(value) {
    return rawText(value) ?? t('enterprise.pqa.verification.value.notAvailable');
}

if (globalThis.__PQA_RENDER_CONTRACT_HOOKS__) {
    globalThis.__PQA_RENDER_CONTRACT_HOOKS__.runtimeEvidence = {
        renderResults,
        officialInspectionUrl
    };
}
