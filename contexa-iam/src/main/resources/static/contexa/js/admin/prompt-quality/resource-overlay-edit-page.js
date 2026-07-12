import { $, $$, escapeHtml, rawText, text } from '../verification-ui-common.js';
import { deleteJson, getJson, postJson, publicError } from './prompt-quality-api.js';
import { bootSummaryPage, setStatus } from './prompt-quality-page.js';
import { openConfirmModal } from './prompt-quality-ui.js';
import { t } from './prompt-quality-i18n.js';

const tristateFields = new Set(['overlayVerificationRequired', 'overlaySync']);
const checkboxFields = new Set(['acknowledgeSecurityRisk']);

bootSummaryPage(null, async (root) => {
    const resourceId = root.dataset.resourceId;
    const sourceResourceUrl = root.dataset.resourceUrl || '';
    const httpMethod = (root.dataset.httpMethod || 'GET').toUpperCase();
    const tenantId = root.dataset.tenantId || 'default';
    if (!resourceId) {
        setStatus(root, 'error',
                t('enterprise.pqa.resourceOverlayEdit.status.missingParam.title'),
                t('enterprise.pqa.resourceOverlayEdit.status.missingParam.detail'));
        return;
    }

    await Promise.all([
        loadResourceMeta(root, tenantId, resourceId, sourceResourceUrl, httpMethod),
        loadOverlay(root, tenantId, resourceId, sourceResourceUrl, httpMethod)
    ]);

    const form = $(root, '[data-pqa-overlay-form]');
    if (form) {
        form.addEventListener('submit', event => {
            event.preventDefault();
            confirmSave(root, tenantId, resourceId, sourceResourceUrl, httpMethod, form);
        });
    }

    const deleteButton = $(root, '[data-pqa-overlay-delete]');
    if (deleteButton) {
        deleteButton.addEventListener('click', () => confirmDelete(root, tenantId, resourceId, sourceResourceUrl, httpMethod));
    }

    const cancelLink = $(root, '[data-pqa-overlay-cancel]');
    if (cancelLink) {
        cancelLink.addEventListener('click', event => {
            event.preventDefault();
            navigateBack(resourceId, sourceResourceUrl, httpMethod);
        });
    }
});

const METHOD_TONE = { GET: 'success', POST: 'info', PUT: 'warning', PATCH: 'neutral', DELETE: 'error', OPTIONS: 'neutral' };
const CRITICALITY_TONE_MAP = { CRITICAL: 'error', HIGH: 'error', SENSITIVE: 'warning', MEDIUM: 'warning', NORMAL: 'success', LOW: 'neutral', DELEGATED: 'neutral', STANDARD: 'success' };
const OPERATIONAL_TONE_MAP = { ZERO_TRUST_ENABLED: 'success', CERTIFIED: 'success', PENDING_VERIFICATION: 'warning', SUSPENDED: 'warning', BLOCKED: 'error', EXPIRED: 'warning', RETIRED: 'neutral', DISCOVERED: 'info' };

function metaRow(label, valueHtml, isLast) {
    const borderBottom = isLast ? 'none' : '1px solid rgba(148,163,184,0.16)';
    return `
        <div style="display:flex;align-items:center;gap:1.5rem;padding:0.95rem 0.3rem;border-bottom:${borderBottom};">
            <div style="flex-shrink:0;min-width:170px;color:#94a3b8;font-size:0.76rem;font-weight:800;letter-spacing:0.15em;text-transform:uppercase;">
                ${escapeHtml(label)}
            </div>
            <div style="flex:1;min-width:0;color:#f8fafc;font-size:1.05rem;font-weight:600;line-height:1.55;word-break:break-all;">
                ${valueHtml}
            </div>
        </div>
    `;
}

function monoValue(value) {
    return `<code style="font-family:'SFMono-Regular','Menlo','Consolas',monospace;font-size:1rem;color:#f1f5f9;background:transparent;padding:0;border:none;">${escapeHtml(value || '-')}</code>`;
}

function badgeValue(label, tone) {
    return `<span class="badge ${tone || 'neutral'}" style="font-size:0.92rem;padding:0.35rem 0.85rem;">${escapeHtml(label || '-')}</span>`;
}

async function loadResourceMeta(root, tenantId, resourceId, sourceResourceUrl, httpMethod) {
    const meta = $(root, '[data-pqa-resource-meta]');
    if (!meta) {
        return;
    }
    try {
        const query = new URLSearchParams();
        setRouteParam(query, 'resourceUrl', sourceResourceUrl);
        setRouteParam(query, 'resourceId', resourceId);
        setRouteParam(query, 'httpMethod', httpMethod);
        const payload = await getJson(
                `/contexa/admin/api/prompt-quality/resources/detail?${query.toString()}`);
        const resource = payload && payload.resource ? payload.resource : {};
        const method = (text(resource.httpMethod) || 'GET').toUpperCase();
        const methodTone = METHOD_TONE[method] || 'neutral';
        const criticalityCode = String(resource.criticality || '').toUpperCase();
        const criticalityTone = CRITICALITY_TONE_MAP[criticalityCode] || 'neutral';
        const criticalityLabel = text(resource.criticality) || '-';
        const operationalCode = String(resource.operationalState || '').toUpperCase();
        const operationalTone = OPERATIONAL_TONE_MAP[operationalCode] || 'neutral';
        const operationalLabel = text(resource.operationalStateLabel || resource.operationalState) || '-';
        meta.innerHTML = `
            ${metaRow(t('enterprise.pqa.resourceOverlayEdit.meta.url'), monoValue(text(resource.resourceUrl)), false)}
            ${metaRow(t('enterprise.pqa.resourceOverlayEdit.meta.httpMethod'), badgeValue(method, methodTone), false)}
            ${metaRow(t('enterprise.pqa.resourceOverlayEdit.meta.resourceId'), monoValue(text(resource.resourceId)), false)}
            ${metaRow(t('enterprise.pqa.resourceOverlayEdit.meta.currentCriticality'), badgeValue(criticalityLabel, criticalityTone), false)}
            ${metaRow(t('enterprise.pqa.resourceOverlayEdit.meta.operationalState'), badgeValue(operationalLabel, operationalTone), true)}
        `;
    }
    catch (error) {
        setStatus(root, 'error', t('enterprise.pqa.resourceOverlayEdit.status.metaFailed'), publicError(error));
    }
}

async function loadOverlay(root, tenantId, resourceId, sourceResourceUrl, httpMethod) {
    try {
        const query = new URLSearchParams({ httpMethod, tenantId });
        setRouteParam(query, 'resourceUrl', sourceResourceUrl);
        const payload = await getJson(
                `/contexa/admin/api/prompt-quality/resources/${encodeURIComponent(resourceId)}/overlay`
                + `?${query.toString()}`);
        if (payload && payload.present && payload.overlay) {
            applyOverlayToForm(root, payload.overlay);
            setStatus(root, 'info',
                    t('enterprise.pqa.resourceOverlayEdit.status.activeOverlay.title'),
                    t('enterprise.pqa.resourceOverlayEdit.status.activeOverlay.detail'));
        }
        else {
            setStatus(root, 'info',
                    t('enterprise.pqa.resourceOverlayEdit.status.noOverlay.title'),
                    t('enterprise.pqa.resourceOverlayEdit.status.noOverlay.detail'));
        }
    }
    catch (error) {
        setStatus(root, 'error', t('enterprise.pqa.resourceOverlayEdit.status.loadFailed'), publicError(error));
    }
}

function applyOverlayToForm(root, overlay) {
    $$(root, '[data-pqa-field]').forEach(input => {
        const key = input.dataset.pqaField;
        const value = overlay[key];
        if (checkboxFields.has(key)) {
            input.checked = value === true || value === 'true';
            return;
        }
        if (value === null || value === undefined) {
            input.value = '';
            return;
        }
        if (tristateFields.has(key)) {
            input.value = value === true || value === 'true' ? 'true' : 'false';
        }
        else {
            input.value = String(value);
        }
    });
}

function collectForm(form) {
    const body = {};
    $$(form, '[data-pqa-field]').forEach(input => {
        const key = input.dataset.pqaField;
        if (checkboxFields.has(key)) {
            body[key] = Boolean(input.checked);
            return;
        }
        const raw = (input.value || '').trim();
        if (!raw) {
            body[key] = null;
            return;
        }
        if (tristateFields.has(key)) {
            body[key] = raw === 'true';
        }
        else {
            body[key] = raw;
        }
    });
    return body;
}

function confirmSave(root, tenantId, resourceId, sourceResourceUrl, httpMethod, form) {
    const body = collectForm(form);
    if (!body.overrideReason || String(body.overrideReason).trim().length < 10) {
        setStatus(root, 'error',
                t('enterprise.pqa.resourceOverlayEdit.status.reasonRequired.title'),
                t('enterprise.pqa.resourceOverlayEdit.status.reasonRequired.detail'));
        return;
    }
    if (!body.acknowledgeSecurityRisk) {
        setStatus(root, 'error',
                t('enterprise.pqa.resourceOverlayEdit.status.acknowledgeRequired.title'),
                t('enterprise.pqa.resourceOverlayEdit.status.acknowledgeRequired.detail'));
        return;
    }
    openConfirmModal(root, {
        title: t('enterprise.pqa.resourceOverlayEdit.confirm.save.title'),
        message: t('enterprise.pqa.resourceOverlayEdit.confirm.save.message'),
        confirmLabel: t('enterprise.pqa.resourceOverlayEdit.confirm.save.button'),
        onConfirm: () => saveOverlay(root, tenantId, resourceId, sourceResourceUrl, httpMethod, body)
    });
}

async function saveOverlay(root, tenantId, resourceId, sourceResourceUrl, httpMethod, body) {
    setStatus(root, 'loading',
            t('enterprise.pqa.resourceOverlayEdit.status.saving.title'),
            t('enterprise.pqa.resourceOverlayEdit.status.saving.detail'));
    try {
        await postJson(
                `/contexa/admin/api/prompt-quality/resources/${encodeURIComponent(resourceId)}/overlay`,
                { ...body, tenantId, sourceResourceUrl, httpMethod });
        setStatus(root, 'success',
                t('enterprise.pqa.resourceOverlayEdit.status.saved.title'),
                t('enterprise.pqa.resourceOverlayEdit.status.saved.detail'));
    }
    catch (error) {
        setStatus(root, 'error', t('enterprise.pqa.resourceOverlayEdit.status.saveFailed'), publicError(error));
    }
}

function confirmDelete(root, tenantId, resourceId, sourceResourceUrl, httpMethod) {
    openConfirmModal(root, {
        title: t('enterprise.pqa.resourceOverlayEdit.confirm.delete.title'),
        message: t('enterprise.pqa.resourceOverlayEdit.confirm.delete.message'),
        confirmLabel: t('enterprise.pqa.resourceOverlayEdit.confirm.delete.button'),
        requireReason: true,
        reasonLabel: t('enterprise.pqa.resourceOverlayEdit.confirm.delete.reasonLabel'),
        onConfirm: reason => deleteOverlay(root, tenantId, resourceId, sourceResourceUrl, httpMethod, reason)
    });
}

async function deleteOverlay(root, tenantId, resourceId, sourceResourceUrl, httpMethod, reason) {
    if (!reason) {
        setStatus(root, 'error',
                t('enterprise.pqa.resourceOverlayEdit.status.deleteReasonRequired.title'),
                t('enterprise.pqa.resourceOverlayEdit.status.deleteReasonRequired.detail'));
        return;
    }
    setStatus(root, 'loading', t('enterprise.pqa.resourceOverlayEdit.status.deleting.title'), '');
    try {
        const query = new URLSearchParams({ httpMethod, reason, tenantId });
        setRouteParam(query, 'resourceUrl', sourceResourceUrl);
        await deleteJson(
                `/contexa/admin/api/prompt-quality/resources/${encodeURIComponent(resourceId)}/overlay?${query.toString()}`);
        setStatus(root, 'success',
                t('enterprise.pqa.resourceOverlayEdit.status.deleted.title'),
                t('enterprise.pqa.resourceOverlayEdit.status.deleted.detail'));
    }
    catch (error) {
        setStatus(root, 'error', t('enterprise.pqa.resourceOverlayEdit.status.deleteFailed'), publicError(error));
    }
}

function navigateBack(resourceId, sourceResourceUrl, httpMethod) {
    const params = new URLSearchParams({ httpMethod });
    setRouteParam(params, 'resourceUrl', sourceResourceUrl);
    window.location.href =
            `/contexa/admin/prompt-quality/resources/detail?resourceId=${encodeURIComponent(resourceId)}&${params.toString()}`;
}

function setRouteParam(params, name, value) {
    const normalized = rawText(value);
    if (normalized) {
        params.set(name, normalized);
    }
}
