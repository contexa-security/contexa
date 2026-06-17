import { $, appPath, escapeHtml, ensureArray, rawText } from '../verification-ui-common.js';
import { getJson, postJson, publicError, publicErrorGuidance } from './prompt-quality-api.js';
import { badge, setStatus } from './prompt-quality-page.js';
import { renderStatusChart } from './prompt-quality-charts.js';
import { openConfirmModal, showActionTooltip, wireTabs } from './prompt-quality-ui.js';
import { ensureBundle, has, t } from './prompt-quality-i18n.js';

const root = document.querySelector('[data-pqa-page="verification"]');
const RUN_PROGRESS_HIDE_MS = 650;
const RUN_PROGRESS_POLL_MS = 1200;
const RUN_PROGRESS_ESTIMATE_MS = 700;
const OFFICIAL_EXECUTION_RUNNING_STATES = new Set([
    'LOCK_ACQUIRED',
    'EVIDENCE_LOADED',
    'CONSISTENCY_CHECKED',
    'METRICS_RUNNING',
    'METRIC_FAILED',
    'SNAPSHOT_WRITING',
    'RUNNING'
]);
const PROMPT_CONSISTENCY_LABEL_KEYS = {
    'LLM system/user prompt captured': 'enterprise.pqa.promptConsistency.label.llmPromptCaptured',
    'promptHash recalculates from LLM prompt': 'enterprise.pqa.promptConsistency.label.promptHashRecalculated',
    'systemPromptHash matches LLM system prompt': 'enterprise.pqa.promptConsistency.label.systemPromptHash',
    'userPromptHash matches LLM user prompt': 'enterprise.pqa.promptConsistency.label.userPromptHash',
    'raw prompt and LLM prompt difference is recorded': 'enterprise.pqa.promptConsistency.label.rawPromptTrace',
    'requestId is traceable in sealed evidence': 'enterprise.pqa.promptConsistency.label.requestIdTrace',
    'correlationId is traceable in sealed evidence': 'enterprise.pqa.promptConsistency.label.correlationIdTrace',
    'requestPath is reflected in user prompt': 'enterprise.pqa.promptConsistency.label.requestPathReflected',
    'resourceId is reflected in user prompt': 'enterprise.pqa.promptConsistency.label.resourceIdReflected',
    'httpMethod is reflected in user prompt': 'enterprise.pqa.promptConsistency.label.httpMethodReflected'
};
const PROMPT_CONSISTENCY_SOURCE_KEYS = {
    promptHash: 'enterprise.pqa.promptConsistency.source.promptHash',
    promptCapture: 'enterprise.pqa.promptConsistency.source.promptCapture',
    requestFacts: 'enterprise.pqa.promptConsistency.source.requestFacts',
    sealedEvidencePackage: 'enterprise.pqa.promptConsistency.source.sealedEvidencePackage',
    promptExecutionMetadata: 'enterprise.pqa.promptConsistency.source.promptExecutionMetadata'
};
const PROMPT_CONSISTENCY_VALUE_KEYS = {
    present: 'enterprise.pqa.promptConsistency.value.present',
    missing: 'enterprise.pqa.promptConsistency.value.missing',
    same: 'enterprise.pqa.promptConsistency.value.same',
    'raw prompt missing': 'enterprise.pqa.promptConsistency.value.rawPromptMissing',
    'LLM prompt missing': 'enterprise.pqa.promptConsistency.value.llmPromptMissing',
    'system=captured, user=captured': 'enterprise.pqa.promptConsistency.value.promptCaptured',
    'system=missing, user=missing': 'enterprise.pqa.promptConsistency.value.promptMissing'
};
const PROMPT_CONSISTENCY_EXPECTATION_KEYS = {
    'system and user prompts': 'enterprise.pqa.promptConsistency.expected.promptCapture',
    'same prompt or compression metadata': 'enterprise.pqa.promptConsistency.expected.rawTrace'
};

if (root) {
    initialize(root).catch(error => {
        setStatus(root, 'error', t('enterprise.pqa.common.status.error'), publicError(error));
    });
}

async function initialize(pageRoot) {
    await ensureBundle().catch(() => {});
    pageRoot.__selectedEvidence = null;
    pageRoot.__selectedPackageId = null;
    pageRoot.__officialLedgerAvailable = null;
    const stage = verificationStage(pageRoot);
    const initialPackageId = packageIdFromLocation();
    const initialRouteIdentity = routeIdentityFromLocation();
    const resolvedSource = { packageId: initialPackageId, ...initialRouteIdentity };
    const resolvedPackageId = rawText(resolvedSource.packageId);
    pageRoot.__selectedPackageId = resolvedPackageId;
    pageRoot.__selectedAggregateRunId = rawText(resolvedSource.aggregateRunId) || aggregateRunIdFromLocation();
    pageRoot.__routeIdentity = identityFromSource(resolvedSource, initialRouteIdentity);
    updateSubrouteLinks(pageRoot, resolvedSource);
    renderEmptyResult(pageRoot);
    renderPromptConsistencyStage(pageRoot, null);
    updateHandoffLinks(pageRoot, resolvedSource);
    bindSubrouteGate(pageRoot);
    bindRun(pageRoot);
    wireTabs(pageRoot);
    if (stage === 'readiness') {
        await initializeReadinessStage(pageRoot, resolvedPackageId);
        return;
    }
    if (stage === 'run') {
        await initializeRunStage(pageRoot, resolvedPackageId);
        return;
    }
    await initializeReadOnlyStage(pageRoot, stage, resolvedPackageId);
    return;
}

async function initializeReadinessStage(pageRoot, packageId) {
    if (!packageId) {
        renderReadinessNeedsEvidence(pageRoot);
        setStatus(pageRoot,
                'loading',
                t('enterprise.pqa.verification.readiness.needEvidence.title'),
                t('enterprise.pqa.verification.readiness.needEvidence.detail'));
        return;
    }
    setStatus(pageRoot,
            'loading',
            t('enterprise.pqa.verification.readiness.loading.title'),
            t('enterprise.pqa.verification.readiness.loading.detail'));
    try {
        const detail = await loadSelectedEvidenceDetail(pageRoot, packageId);
        const item = detail.summary || { packageId };
        updateSubrouteLinks(pageRoot, item);
        updateHandoffLinks(pageRoot, item);
        renderReadinessSelected(pageRoot, item);
        renderPromptConsistencyStage(pageRoot, detail.promptConsistency, item);
        renderReadinessActions(pageRoot, item, detail.promptConsistency);
        const consistencyAllowsInspection = promptConsistencyAllowsInspection(detail.promptConsistency);
        setStatus(pageRoot,
                consistencyAllowsInspection ? 'success' : 'error',
                consistencyAllowsInspection
                        ? readinessReadyTitle(detail.promptConsistency)
                        : t('enterprise.pqa.verification.readiness.blocked.title'),
                consistencyAllowsInspection
                        ? readinessReadyDetail(detail.promptConsistency)
                        : t('enterprise.pqa.verification.readiness.blocked.detail'));
    }
    catch (error) {
        renderReadinessNeedsEvidence(pageRoot, packageId);
        setStatus(pageRoot,
                'error',
                t('enterprise.pqa.verification.readiness.failed.title'),
                publicError(error));
    }
}

async function initializeRunStage(pageRoot, packageId) {
    if (!packageId) {
        renderRunNeedsEvidence(pageRoot);
        setStatus(pageRoot,
                'loading',
                t('enterprise.pqa.verification.run.needEvidence.title'),
                t('enterprise.pqa.verification.run.needEvidence.detail'));
        return;
    }
    setStatus(pageRoot,
            'loading',
            t('enterprise.pqa.verification.run.selection.loading.title'),
            t('enterprise.pqa.verification.run.selection.loading.detail'));
    try {
        const detail = await loadSelectedEvidenceDetail(pageRoot, packageId);
        const item = detail.summary || { packageId };
        renderSelected(pageRoot, item, detail.promptConsistency);
        updateSubrouteLinks(pageRoot, item);
        updateHandoffLinks(pageRoot, item);
        if (!promptConsistencyAllowsInspection(detail.promptConsistency)) {
            setRunButtonState(pageRoot);
            setStatus(pageRoot,
                    'error',
                    t('enterprise.pqa.verification.run.selection.blocked.title'),
                    t('enterprise.pqa.verification.run.selection.blocked.detail'));
            return;
        }
        const ledger = await renderOfficialLedger(pageRoot, packageId);
        if (ledger) {
            const restoredRun = runFromOfficialLedger(pageRoot, ledger);
            renderRun(pageRoot, restoredRun);
            setStatus(pageRoot,
                    restoredRun.certificateIssued ? 'success' : 'error',
                    t('enterprise.pqa.verification.run.restored.title'),
                    runResultOneLine(restoredRun));
            return;
        }
        const executionStatus = await loadExecutionStatus(packageId).catch(() => null);
        if (executionStatus?.completed) {
            const failure = executionCompletedWithoutLedgerContext(executionStatus, packageId);
            renderExecutionFailure(pageRoot, failure, item);
            setRunProgress(
                    pageRoot,
                    failure.progressPercent,
                    t('enterprise.pqa.verification.run.ledgerMissingAfterRun.title'),
                    failure.detail,
                    'failed',
                    progressLabel(failure.progressPercent));
            setRunButtonState(pageRoot);
            setStatus(pageRoot, 'error', t('enterprise.pqa.verification.run.ledgerMissingAfterRun.title'), failure.detail);
            return;
        }
        if (executionStatus?.failed) {
            const failure = executionFailureContext(executionStatus, null, packageId);
            renderExecutionFailure(pageRoot, failure, item);
            setRunProgress(
                    pageRoot,
                    failure.progressPercent,
                    t('enterprise.pqa.verification.run.progress.failed.title'),
                    failure.detail,
                    'failed',
                    progressLabel(failure.progressPercent));
            setRunButtonState(pageRoot);
            setStatus(pageRoot, 'error', t('enterprise.pqa.verification.run.failed'), failure.detail);
            return;
        }
        if (isRunningStatus(executionStatus)) {
            const computed = officialInspectionProgress(executionStatus);
            setRunProgress(
                    pageRoot,
                    computed.percent ?? 0,
                    t('enterprise.pqa.verification.run.progress.ledger.title'),
                    progressDetail(computed),
                    'running',
                    progressLabel(computed.percent ?? 0, computed));
            setStatus(pageRoot,
                    'loading',
                    t('enterprise.pqa.verification.run.progress.ledger.title'),
                    progressDetail(computed));
            return;
        }
        renderEmptyResult(pageRoot);
        setStatus(pageRoot,
                'success',
                runSelectionReadyTitle(detail.promptConsistency),
                runSelectionReadyDetail(detail.promptConsistency));
    }
    catch (error) {
        renderRunNeedsEvidence(pageRoot, packageId);
        setStatus(pageRoot,
                'error',
                t('enterprise.pqa.verification.run.selection.failed.title'),
                publicError(error));
    }
}

async function initializeReadOnlyStage(pageRoot, stage, packageId) {
    if (packageId) {
        const routeOnlyEvidence = withRouteIdentity(pageRoot, { packageId });
        pageRoot.__selectedEvidence = routeOnlyEvidence;
        pageRoot.__selectedPackageId = packageId;
        updateSubrouteLinks(pageRoot, routeOnlyEvidence);
    }
    if ((stage === 'comparison' || stage === 'metrics') && packageId) {
        setStatus(pageRoot,
                'loading',
                t('enterprise.pqa.verification.readonly.loading.title'),
                t('enterprise.pqa.verification.readonly.loading.detail'));
        const ledger = await renderOfficialLedger(pageRoot, packageId);
        if (!ledger) {
            setStatus(pageRoot,
                    'error',
                    t('enterprise.pqa.verification.readonly.ledgerMissing.title'),
                    t('enterprise.pqa.verification.readonly.ledgerMissing.detail'));
            return;
        }
        setStatus(pageRoot,
                'success',
                t('enterprise.pqa.verification.readonly.ready.title'),
                t('enterprise.pqa.verification.readonly.ready.detail'));
        return;
    }
    setStatus(pageRoot,
            'loading',
            t('enterprise.pqa.verification.readonly.needPackage.title'),
            t('enterprise.pqa.verification.readonly.needPackage.detail'));
}

function bindRun(pageRoot) {
    $(pageRoot, '[data-pqa-run-verification]')?.addEventListener('click', event => {
        const item = pageRoot.__selectedEvidence;
        if (!item?.packageId) {
            explainAction(pageRoot,
                    event.currentTarget,
                    t('enterprise.pqa.verification.run.noEvidence.title'),
                    t('enterprise.pqa.verification.run.noEvidence.detail'));
            return;
        }
        const gate = processGate(pageRoot);
        if (!gate.allowed) {
            setRunButtonState(pageRoot);
            explainAction(pageRoot, event.currentTarget, gate.title, gate.detail);
            return;
        }
        showActionTooltip(pageRoot,
                event.currentTarget,
                t('enterprise.pqa.verification.run.tooltip.ready'),
                'ready');
        openConfirmModal(pageRoot, {
            title: t('enterprise.pqa.verification.run.confirm.titleAlt'),
            message: t('enterprise.pqa.verification.run.confirm.messageAlt', formatEvidenceName(item)),
            confirmLabel: t('enterprise.pqa.verification.run.confirm.label'),
            onConfirm: () => runVerification(pageRoot, item)
        });
    });
}

function bindSubrouteGate(pageRoot) {
    if (pageRoot.dataset.pqaSubrouteGateBound === 'true') {
        return;
    }
    pageRoot.dataset.pqaSubrouteGateBound = 'true';
    pageRoot.addEventListener('click', event => {
        const link = event.target.closest('[data-pqa-verification-subroute][aria-disabled="true"]');
        if (!link) {
            return;
        }
        event.preventDefault();
        explainAction(
                pageRoot,
                link,
                link.dataset.pqaGateTitle || t('enterprise.pqa.verification.readonly.blocked.title'),
                link.dataset.pqaGateDetail || t('enterprise.pqa.verification.readonly.blocked.detail'));
    });
}

function explainAction(pageRoot, anchor, title, detail) {
    const message = [title, detail].filter(Boolean).join(' - ');
    if (anchor && message) {
        anchor.setAttribute('data-pqa-disabled-reason', message);
        anchor.setAttribute('aria-label', message);
    }
    showActionTooltip(pageRoot, anchor, message, 'blocked');
    setStatus(pageRoot, 'error', title, detail);
}

async function loadSelectedEvidenceDetail(pageRoot, packageId) {
    const detail = await getJson(`/contexa/admin/api/prompt-quality/runtime-evidence/${encodeURIComponent(packageId)}`);
    const item = withRouteIdentity(pageRoot, detail.summary || { packageId });
    detail.summary = item;
    pageRoot.__selectedEvidence = item;
    pageRoot.__selectedPackageId = rawText(item.packageId) || rawText(packageId);
    pageRoot.__routeIdentity = identityFromSource(item, pageRoot.__routeIdentity);
    pageRoot.__selectedEvidenceDetail = detail;
    pageRoot.__officialLedgerAvailable = null;
    return detail;
}

function renderSelected(pageRoot, item, consistency = pageRoot.__selectedEvidenceDetail?.promptConsistency) {
    const target = $(pageRoot, '[data-pqa-verification-selected]');
    setRunButtonState(pageRoot);
    if (!target) {
        return;
    }
    const gate = processGate(pageRoot);
    const evidenceHref = runtimeEvidenceHref(item);
    target.innerHTML = `
        <div class="pqa-verification-selected-card"
             data-pqa-click-href="${escapeHtml(evidenceHref)}"
             data-pqa-click-label="${escapeHtml(t('enterprise.pqa.verification.readiness.needEvidence.goEvidence'))}">
            <span class="pqa-selected-evidence-icon" aria-hidden="true">
                <i class="fa-solid fa-vault"></i>
            </span>
            <div class="pqa-selected-evidence-copy">
                <span>선택된 봉인 증거</span>
                <strong>${escapeHtml(formatEvidenceName(item))}</strong>
                <p><code>${escapeHtml(item.packageId)}</code></p>
                <small>${escapeHtml(gate.allowed
                        ? gate.detail
                        : gate.detail)}</small>
            </div>
            <div class="pqa-badge-row pqa-selected-evidence-badges">
                ${badge(item.sealed ? t('enterprise.pqa.verification.summary.sealed') : t('enterprise.pqa.runtimeEvidence.badge.unsealed'), { tone: item.sealed ? 'ready' : 'blocked' })}
                ${badge(item.integrityValid ? t('enterprise.pqa.runtimeEvidence.badge.integrityOk') : t('enterprise.pqa.runtimeEvidence.badge.integrityError'), { tone: item.integrityValid ? 'ready' : 'blocked' })}
                ${badge(rawText(item.promptHash) ? t('enterprise.pqa.verification.badge.promptHashYes') : t('enterprise.pqa.verification.badge.promptHashNo'), { tone: rawText(item.promptHash) ? 'ready' : 'blocked' })}
                ${badge(text(consistency?.stateLabel), { tone: promptConsistencyTone(consistency?.state) })}
            </div>
        </div>
    `;
}

function renderReadinessSelected(pageRoot, item) {
    const target = $(pageRoot, '[data-pqa-readiness-selected]');
    if (!target) {
        return;
    }
    const evidenceHref = runtimeEvidenceHref(item);
    target.innerHTML = `
        <div class="pqa-verification-selected-card"
             data-pqa-click-href="${escapeHtml(evidenceHref)}"
             data-pqa-click-label="${escapeHtml(t('enterprise.pqa.verification.readiness.needEvidence.goEvidence'))}">
            <span class="pqa-selected-evidence-icon" aria-hidden="true">
                <i class="fa-solid fa-vault"></i>
            </span>
            <div class="pqa-selected-evidence-copy">
                <span>선택된 봉인 증거</span>
                <strong>${escapeHtml(formatEvidenceName(item))}</strong>
                <p><code>${escapeHtml(item.packageId)}</code></p>
            </div>
            <div class="pqa-badge-row pqa-selected-evidence-badges">
                ${badge(item.sealed ? t('enterprise.pqa.verification.summary.sealed') : t('enterprise.pqa.runtimeEvidence.badge.unsealed'), { tone: item.sealed ? 'ready' : 'blocked' })}
                ${badge(item.integrityValid ? t('enterprise.pqa.runtimeEvidence.badge.integrityOk') : t('enterprise.pqa.runtimeEvidence.badge.integrityError'), { tone: item.integrityValid ? 'ready' : 'blocked' })}
                ${badge(rawText(item.promptHash) ? t('enterprise.pqa.verification.badge.promptHashYes') : t('enterprise.pqa.verification.badge.promptHashNo'), { tone: rawText(item.promptHash) ? 'ready' : 'blocked' })}
            </div>
        </div>
    `;
}

function renderReadinessNeedsEvidence(pageRoot, packageId = '') {
    const target = $(pageRoot, '[data-pqa-readiness-selected]');
    renderReadinessActions(pageRoot, null, null);
    renderPromptConsistencyStage(pageRoot, null);
    if (!target) {
        return;
    }
    const evidenceHref = packageId
            ? runtimeEvidenceHref(withRouteIdentity(pageRoot, { packageId }))
            : appPath('/contexa/admin/prompt-quality/runtime-evidence');
    target.innerHTML = `
        <div class="pqa-verification-selected-card pqa-verification-selected-empty"
             data-pqa-click-href="${escapeHtml(evidenceHref)}"
             data-pqa-click-label="${escapeHtml(t('enterprise.pqa.verification.readiness.needEvidence.goEvidence'))}">
            <div>
                <strong>${escapeHtml(t('enterprise.pqa.verification.readiness.needEvidence.selectedTitle'))}</strong>
                <p>${escapeHtml(packageId
                        ? t('enterprise.pqa.verification.readiness.needEvidence.invalidDetail', packageId)
                        : t('enterprise.pqa.verification.readiness.needEvidence.selectedDetail'))}</p>
            </div>
            <a class="pqa-link-button" href="${escapeHtml(evidenceHref)}">
                <i class="fa-solid fa-box-archive" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.verification.readiness.needEvidence.goEvidence'))}
            </a>
        </div>
    `;
}

function renderReadinessActions(pageRoot, item, consistency) {
    const target = $(pageRoot, '[data-pqa-readiness-actions]');
    if (!target) {
        return;
    }
    const packageId = rawText(item?.packageId);
    if (!packageId) {
        target.innerHTML = '';
        return;
    }
    const runHref = verificationStageHref('run', item);
    const evidenceHref = runtimeEvidenceHref(item);
    const allowed = promptConsistencyAllowsInspection(consistency);
    target.innerHTML = allowed
            ? `<a class="pqa-link-button" href="${escapeHtml(runHref)}"><i class="fa-solid fa-play" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.verification.readiness.action.run'))}</a>`
            : `<span class="pqa-section-pill">${escapeHtml(t('enterprise.pqa.verification.readiness.action.blocked'))}</span>
               <a class="pqa-action-button" href="${escapeHtml(evidenceHref)}"><i class="fa-solid fa-box-archive" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.verification.readiness.action.reselect'))}</a>`;
}

function promptConsistencyPass(consistency) {
    const state = upperText(consistency?.state);
    return state === 'PASS' && consistency?.blocking !== true;
}

function promptConsistencyAllowsInspection(consistency) {
    return Boolean(consistency) && consistency.blocking !== true;
}

function readinessReadyTitle(consistency) {
    return promptConsistencyPass(consistency)
            ? t('enterprise.pqa.verification.readiness.ready.title')
            : t('enterprise.pqa.verification.readiness.review.title');
}

function readinessReadyDetail(consistency) {
    return promptConsistencyPass(consistency)
            ? t('enterprise.pqa.verification.readiness.ready.detail')
            : t('enterprise.pqa.verification.readiness.review.detail');
}

function processGate(pageRoot) {
    const item = pageRoot.__selectedEvidence;
    const detail = pageRoot.__selectedEvidenceDetail;
    if (pageRoot.__verificationRunning === true) {
        return {
            allowed: false,
            state: 'RUNNING',
            title: t('enterprise.pqa.verification.run.inProgress.title'),
            detail: t('enterprise.pqa.verification.run.inProgress.detail')
        };
    }
    if (!item?.packageId) {
        return {
            allowed: false,
            state: 'NO_PACKAGE',
            title: t('enterprise.pqa.verification.run.noEvidence.title'),
            detail: t('enterprise.pqa.verification.run.noEvidence.detail')
        };
    }
    if (!detail) {
        return {
            allowed: false,
            state: 'NO_DETAIL',
            title: t('enterprise.pqa.verification.run.selection.loading.title'),
            detail: t('enterprise.pqa.verification.run.selection.loading.detail')
        };
    }
    if (!promptConsistencyAllowsInspection(detail.promptConsistency)) {
        return {
            allowed: false,
            state: 'PROMPT_CONSISTENCY_BLOCKED',
            title: t('enterprise.pqa.verification.run.blockedByReadiness.title'),
            detail: t('enterprise.pqa.verification.run.blockedByReadiness.detail')
        };
    }
    return {
        allowed: true,
        state: 'READY',
        title: runSelectionReadyTitle(detail.promptConsistency),
        detail: runSelectionReadyDetail(detail.promptConsistency)
    };
}

function runSelectionReadyTitle(consistency) {
    return promptConsistencyPass(consistency)
            ? t('enterprise.pqa.verification.run.selection.ready.title')
            : t('enterprise.pqa.verification.run.selection.review.title');
}

function runSelectionReadyDetail(consistency) {
    return promptConsistencyPass(consistency)
            ? t('enterprise.pqa.verification.run.selection.ready.detail')
            : t('enterprise.pqa.verification.run.selection.review.detail');
}

function setRunButtonState(pageRoot) {
    const button = $(pageRoot, '[data-pqa-run-verification]');
    if (!button) {
        return;
    }
    const gate = processGate(pageRoot);
    button.hidden = false;
    button.disabled = false;
    button.setAttribute('aria-disabled', String(!gate.allowed));
    button.classList.toggle('is-disabled', !gate.allowed);
    button.dataset.pqaGateState = gate.state;
    const label = button.querySelector('span');
    if (label) {
        label.textContent = t('enterprise.pqa.verification.run.execute');
    }
    const message = gate.allowed
            ? t('enterprise.pqa.verification.run.tooltip.ready')
            : `${gate.title} - ${gate.detail}`;
    if (gate.allowed) {
        button.setAttribute('data-pqa-action-message', message);
        button.removeAttribute('data-pqa-disabled-reason');
    }
    else {
        button.setAttribute('data-pqa-disabled-reason', message);
        button.removeAttribute('data-pqa-action-message');
    }
    button.setAttribute('aria-label', message);
}

function renderReadOnlyGateBlocked(pageRoot, stage) {
    const title = t('enterprise.pqa.verification.readonly.blocked.title');
    const detail = t('enterprise.pqa.verification.readonly.blocked.detail');
    const summary = $(pageRoot, '[data-pqa-official-ledger-summary]');
    if (summary) {
        summary.innerHTML = `
            <div class="pqa-empty error">
                <strong>${escapeHtml(title)}</strong>
                <p>${escapeHtml(detail)}</p>
            </div>
        `;
    }
    setHandoffLinksEnabled(pageRoot, false, title, detail);
}

function setHandoffLinksEnabled(pageRoot, enabled, title = '', detail = '') {
    return;
}

function renderRunNeedsEvidence(pageRoot, packageId = '') {
    const target = $(pageRoot, '[data-pqa-verification-selected]');
    const button = $(pageRoot, '[data-pqa-run-verification]');
    if (button) {
        button.hidden = false;
        button.disabled = false;
        button.setAttribute('aria-disabled', 'true');
        button.classList.add('is-disabled');
        const message = t('enterprise.pqa.verification.run.noEvidence.detail');
        button.setAttribute('data-pqa-disabled-reason', message);
        button.removeAttribute('data-pqa-action-message');
        button.setAttribute('aria-label', message);
    }
    if (!target) {
        return;
    }
    const readinessHref = verificationStageHref('readiness', withRouteIdentity(pageRoot, { packageId }));
    target.innerHTML = `
        <div class="pqa-verification-selected-card pqa-verification-selected-empty">
            <div>
                <strong>${escapeHtml(t('enterprise.pqa.verification.run.needEvidence.selectedTitle'))}</strong>
                <p>${escapeHtml(packageId
                        ? t('enterprise.pqa.verification.run.needEvidence.invalidDetail', packageId)
                        : t('enterprise.pqa.verification.run.needEvidence.selectedDetail'))}</p>
            </div>
            <a class="pqa-link-button" href="${escapeHtml(readinessHref)}">
                <i class="fa-solid fa-link" aria-hidden="true"></i>${escapeHtml(t('enterprise.pqa.verification.run.needEvidence.goReadiness'))}
            </a>
        </div>
    `;
}

async function runVerification(pageRoot, item) {
    if (pageRoot.__verificationRunning === true) {
        return;
    }
    pageRoot.__officialLedgerAvailable = null;
    const gate = processGate(pageRoot);
    if (!gate.allowed) {
        setRunButtonState(pageRoot);
        setStatus(pageRoot, 'error', gate.title, gate.detail);
        return;
    }
    pageRoot.__verificationRunning = true;
    const packageId = rawText(item?.packageId) || rawText(pageRoot.__selectedPackageId) || packageIdFromLocation();
    const progress = beginRunProgress(pageRoot, packageId);
    setStatus(pageRoot, 'loading', t('enterprise.pqa.verification.run.loading.title'), t('enterprise.pqa.verification.run.loading.detail'));
    try {
        updateRunProgress(pageRoot, progress,
                t('enterprise.pqa.verification.run.progress.prepare.title'),
                t('enterprise.pqa.verification.run.progress.prepare.detail'));
        const run = await postJson(`/contexa/admin/api/prompt-quality/verification/runtime-runs?packageId=${encodeURIComponent(packageId)}`, {
            packageId
        });
        pageRoot.__selectedAggregateRunId = rawText(run.aggregateRunId) || rawText(run.runId);
        updateRunProgress(pageRoot, progress,
                t('enterprise.pqa.verification.run.progress.ledger.title'),
                t('enterprise.pqa.verification.run.progress.ledger.detail'),
                null,
                run);
        if (isRunningExecution(run)) {
            renderRun(pageRoot, run);
            setStatus(pageRoot,
                    'loading',
                    t('enterprise.pqa.verification.run.progress.ledger.title'),
                    runResultOneLine(run));
            await waitForExecutionCompletion(pageRoot, progress, packageId);
        }
        renderRun(pageRoot, run);
        const ledger = await renderOfficialLedger(pageRoot, packageId);
        const displayRun = ledger ? runFromOfficialLedger(pageRoot, ledger, run) : withRouteIdentity(pageRoot, run);
        renderRun(pageRoot, displayRun);
        updateSubrouteLinks(pageRoot, displayRun);
        finishRunProgress(pageRoot, progress, true,
                t('enterprise.pqa.verification.run.progress.complete.title'),
                t('enterprise.pqa.verification.run.progress.complete.detail'),
                null,
                ledger || displayRun);
        if (!ledger) {
            setStatus(pageRoot,
                    'error',
                    t('enterprise.pqa.verification.run.ledgerMissingAfterRun.title'),
                    t('enterprise.pqa.verification.run.ledgerMissingAfterRun.detail'));
            return;
        }
        const officialPassed = officialVerificationPassedForDisplay(displayRun, ledger);
        setStatus(pageRoot,
                officialPassed ? 'success' : 'error',
                officialPassed ? t('enterprise.pqa.verification.run.passed') : t('enterprise.pqa.verification.run.blocked'),
                runResultOneLine(displayRun));
    }
    catch (error) {
        pageRoot.__officialLedgerAvailable = false;
        const executionStatus = packageId ? await loadExecutionStatus(packageId).catch(() => null) : null;
        const failure = executionFailureContext(executionStatus, error, packageId);
        renderExecutionFailure(pageRoot, failure, pageRoot.__selectedEvidence || item);
        updateSubrouteLinks(pageRoot, pageRoot.__selectedEvidence || item);
        updateHandoffLinks(pageRoot, pageRoot.__selectedEvidence || item);
        finishRunProgress(pageRoot, progress, false,
                t('enterprise.pqa.verification.run.progress.failed.title'),
                failure.detail,
                null,
                executionStatus || pageRoot.__officialLedgerDetail);
        const guidance = publicErrorGuidance(error);
        setStatus(pageRoot, 'error', t('enterprise.pqa.verification.run.failed'), guidance ? `${failure.detail} | ${guidance}` : failure.detail);
    }
    finally {
        pageRoot.__verificationRunning = false;
        setRunButtonState(pageRoot);
    }
}

function beginRunProgress(pageRoot, packageId) {
    const progress = {
        currentPercent: 0,
        pollTimer: null,
        estimateTimer: null,
        startedAt: Date.now(),
        packageId: rawText(packageId)
    };
    pageRoot.__verificationRunProgress = progress;
    const button = $(pageRoot, '[data-pqa-run-verification]');
    if (button) {
        button.disabled = false;
        button.setAttribute('aria-disabled', 'true');
        button.classList.add('is-disabled');
        const message = t('enterprise.pqa.verification.run.inProgress.detail');
        button.setAttribute('data-pqa-disabled-reason', message);
        button.removeAttribute('data-pqa-action-message');
        button.setAttribute('aria-label', message);
    }
    setRunProgress(pageRoot, 0,
            t('enterprise.pqa.verification.run.progress.start.title'),
            t('enterprise.pqa.verification.run.progress.start.detail'),
            'running',
            progressLabel(0));
    startRunProgressEstimate(pageRoot, progress);
    startRunProgressPolling(pageRoot, progress);
    return progress;
}

function updateRunProgress(pageRoot, progress, title, detail, label, source) {
    if (!progress) {
        return;
    }
    const computed = officialInspectionProgress(source);
    const percent = computed.percent ?? progress.currentPercent ?? 0;
    setRunProgress(pageRoot, percent, title, detail, 'running', label || progressLabel(percent, computed));
}

function finishRunProgress(pageRoot, progress, success, title, detail, label, source) {
    clearRunProgressTimers(progress);
    const computed = officialInspectionProgress(source);
    const percent = success
            ? computed.percent ?? 100
            : computed.percent ?? progress?.currentPercent ?? 0;
    setRunProgress(pageRoot, percent, title, detail, success ? 'complete' : 'failed', label || progressLabel(percent, computed));
    if (!success) {
        pageRoot.__verificationRunProgress = null;
        return;
    }
    window.setTimeout(() => {
        if (pageRoot.__verificationRunProgress === progress) {
            hideRunProgress(pageRoot);
            pageRoot.__verificationRunProgress = null;
        }
    }, RUN_PROGRESS_HIDE_MS);
}

function clearRunProgressTimers(progress) {
    if (progress?.pollTimer) {
        window.clearInterval(progress.pollTimer);
        progress.pollTimer = null;
    }
    if (progress?.estimateTimer) {
        window.clearInterval(progress.estimateTimer);
        progress.estimateTimer = null;
    }
}

function startRunProgressEstimate(pageRoot, progress) {
    if (!progress || typeof window === 'undefined') {
        return;
    }
    progress.estimateTimer = window.setInterval(() => {
        if (pageRoot.__verificationRunProgress !== progress) {
            clearRunProgressTimers(progress);
            return;
        }
        const current = Number(progress.currentPercent || progress.current || 0);
        const title = current > 0
                ? t('enterprise.pqa.verification.run.progress.ledger.title')
                : t('enterprise.pqa.verification.run.progress.prepare.title');
        const detail = current > 0
                ? t('enterprise.pqa.verification.run.progress.ledger.detail')
                : t('enterprise.pqa.verification.run.progress.prepare.detail');
        setRunProgress(pageRoot, current, title, detail, 'running', progressLabel(current));
    }, RUN_PROGRESS_ESTIMATE_MS);
}

function startRunProgressPolling(pageRoot, progress) {
    if (!progress?.packageId || typeof window === 'undefined') {
        return;
    }
    progress.pollTimer = window.setInterval(async () => {
        if (pageRoot.__verificationRunProgress !== progress) {
            window.clearInterval(progress.pollTimer);
            progress.pollTimer = null;
            return;
        }
        try {
            const status = await loadExecutionStatus(progress.packageId);
            if (status && rawText(status.state) !== 'NOT_STARTED') {
                const computedStatus = officialInspectionProgress(status);
                if (computedStatus.percent !== null && computedStatus.percent !== undefined) {
                    if (rawText(status.aggregateRunId)) {
                        pageRoot.__selectedAggregateRunId = rawText(status.aggregateRunId);
                    }
                    setRunProgress(
                            pageRoot,
                            computedStatus.percent,
                            t('enterprise.pqa.verification.run.progress.ledger.title'),
                            progressDetail(computedStatus),
                            status.failed ? 'failed' : 'running',
                            progressLabel(computedStatus.percent, computedStatus));
                    if (status.completed || status.failed) {
                        return;
                    }
                }
            }
            const detail = await loadOfficialLedgerDetail(progress.packageId);
            const computed = officialInspectionProgress(detail);
            if (computed.percent !== null && computed.percent !== undefined) {
                pageRoot.__officialLedgerDetail = detail;
                setRunProgress(
                        pageRoot,
                        computed.percent,
                        t('enterprise.pqa.verification.run.progress.ledger.title'),
                        progressDetail(computed),
                        'running',
                        progressLabel(computed.percent, computed));
            }
        }
        catch (error) {
            // The ledger may not exist until the first official metric row is committed.
        }
    }, RUN_PROGRESS_POLL_MS);
}

async function waitForExecutionCompletion(pageRoot, progress, packageId) {
    const maxAttempts = 100;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const status = await loadExecutionStatus(packageId);
        const computed = officialInspectionProgress(status);
        if (computed.percent !== null && computed.percent !== undefined) {
            if (rawText(status.aggregateRunId)) {
                pageRoot.__selectedAggregateRunId = rawText(status.aggregateRunId);
            }
            setRunProgress(
                    pageRoot,
                    computed.percent,
                    t('enterprise.pqa.verification.run.progress.ledger.title'),
                    progressDetail(computed),
                    status.failed ? 'failed' : 'running',
                    progressLabel(computed.percent, computed));
        }
        if (status.completed) {
            return status;
        }
        if (status.failed) {
            const error = new Error(status.failureReason || t('enterprise.pqa.verification.run.failed'));
            error.body = {
                message: status.failureReason || t('enterprise.pqa.verification.run.failed'),
                nextAction: status.retryInstruction || ''
            };
            throw error;
        }
        await delay(RUN_PROGRESS_POLL_MS);
    }
    throw new Error(t('enterprise.pqa.verification.run.ledgerMissingAfterRun.detail'));
}

async function loadExecutionStatus(packageId) {
    if (!packageId) {
        return null;
    }
    return getJson(`/contexa/admin/api/prompt-quality/verification/runtime-runs/package/${encodeURIComponent(packageId)}/execution-status`);
}

function isRunningExecution(run) {
    const state = upperText(run?.executionState || run?.state || run?.certificateState);
    return OFFICIAL_EXECUTION_RUNNING_STATES.has(state) && Number(run?.progressPercent || 0) < 100;
}

function isRunningStatus(status) {
    const state = upperText(status?.state);
    return OFFICIAL_EXECUTION_RUNNING_STATES.has(state) && status?.completed !== true && status?.failed !== true;
}

function executionCompletedWithoutLedgerContext(status, packageId) {
    const progressPercent = Math.max(0, Math.min(100, Number(status?.progressPercent ?? 100) || 100));
    const reason = t('enterprise.pqa.verification.run.completedWithoutLedger.reason');
    const retry = t('enterprise.pqa.verification.run.completedWithoutLedger.retry');
    return {
        evidenceId: rawText(status?.packageId) || rawText(packageId),
        aggregateRunId: rawText(status?.aggregateRunId),
        state: rawText(status?.state) || 'COMPLETED',
        stage: 'COMPLETED',
        stageLabel: executionStageLabel('COMPLETED'),
        reason,
        retry,
        progressPercent,
        recoverable: true,
        detail: [reason, retry].filter(Boolean).join(' / ')
    };
}

function executionFailureContext(status, error, packageId) {
    const details = error?.body?.details || {};
    const stage = rawText(status?.failureStage)
            || rawText(details.failureStage)
            || rawText(status?.state)
            || rawText(details.executionState);
    const state = rawText(status?.state) || rawText(details.executionState);
    const reason = rawText(status?.failureReason)
            || rawText(details.failureReason)
            || rawText(error?.body?.cause)
            || publicError(error)
            || t('enterprise.pqa.verification.run.failureCard.reasonFallback');
    const retry = rawText(status?.retryInstruction)
            || rawText(details.retryInstruction)
            || rawText(error?.body?.nextAction)
            || t('enterprise.pqa.verification.run.failureCard.retryFallback');
    const progressPercent = Math.max(0, Math.min(100, Number(
            status?.progressPercent ?? details.progressPercent ?? 0) || 0));
    const evidenceId = rawText(status?.packageId)
            || rawText(details.packageId)
            || rawText(packageId);
    const aggregateRunId = rawText(status?.aggregateRunId)
            || rawText(details.aggregateRunId);
    const stageLabel = executionStageLabel(stage);
    const detail = [
        stageLabel ? t('enterprise.pqa.verification.run.failureCard.detailStage', stageLabel) : '',
        reason,
        retry ? t('enterprise.pqa.verification.run.failureCard.detailRetry', retry) : ''
    ].filter(Boolean).join(' / ');
    return {
        evidenceId,
        aggregateRunId,
        state,
        stage,
        stageLabel,
        reason,
        retry,
        progressPercent,
        recoverable: status?.recoverable ?? details.recoverable,
        detail
    };
}

function executionFailureDetail(status, error) {
    return executionFailureContext(status, error).detail;
}

function executionStageLabel(stage) {
    const normalized = upperText(stage);
    if (!normalized) {
        return '';
    }
    if (normalized.includes('BEFORE EXECUTION STATUS LEDGER')) {
        return t('enterprise.pqa.verification.run.stage.preLedger');
    }
    const labels = {
        REQUESTED: t('enterprise.pqa.verification.run.stage.requested'),
        LOCK_ACQUIRED: t('enterprise.pqa.verification.run.stage.lockAcquired'),
        EVIDENCE_LOADED: t('enterprise.pqa.verification.run.stage.evidenceLoaded'),
        CONSISTENCY_CHECKED: t('enterprise.pqa.verification.run.stage.consistencyChecked'),
        METRICS_RUNNING: t('enterprise.pqa.verification.run.stage.metricsRunning'),
        METRIC_FAILED: t('enterprise.pqa.verification.run.stage.metricFailed'),
        SNAPSHOT_WRITING: t('enterprise.pqa.verification.run.stage.snapshotWriting'),
        COMPLETED: t('enterprise.pqa.verification.run.stage.completed'),
        FAILED_RECOVERABLE: t('enterprise.pqa.verification.run.stage.failedRecoverable'),
        FAILED_TERMINAL: t('enterprise.pqa.verification.run.stage.failedTerminal'),
        FAILED: t('enterprise.pqa.verification.run.stage.failed')
    };
    return labels[normalized] || rawText(stage);
}

function delay(ms) {
    return new Promise(resolve => window.setTimeout(resolve, ms));
}

function setRunProgress(pageRoot, percent, title, detail, tone, label) {
    const panel = $(pageRoot, '[data-pqa-verification-progress]');
    if (!panel) {
        return;
    }
    const clamped = Math.max(0, Math.min(100, Number(percent) || 0));
    const fill = $(panel, '[data-pqa-verification-progress-fill]');
    const value = $(panel, '[data-pqa-verification-progress-percent]');
    const titleTarget = $(panel, '[data-pqa-verification-progress-title]');
    const detailTarget = $(panel, '[data-pqa-verification-progress-message]');
    panel.hidden = false;
    panel.dataset.state = tone || 'running';
    panel.dataset.mode = 'determinate';
    panel.setAttribute('aria-busy', tone === 'running' ? 'true' : 'false');
    panel.setAttribute('aria-valuenow', String(clamped));
    if (fill) {
        fill.style.width = `${clamped}%`;
    }
    if (value) {
        value.textContent = label || progressLabel(clamped);
    }
    if (title && titleTarget) {
        titleTarget.textContent = title;
    }
    if (detail && detailTarget) {
        detailTarget.textContent = detail;
    }
    const activeProgress = pageRoot.__verificationRunProgress;
    if (activeProgress) {
        activeProgress.current = clamped;
        activeProgress.currentPercent = clamped;
    }
}

function officialInspectionProgress(source) {
    if (!source) {
        return { percent: null, completed: 0, total: 0 };
    }
    const explicitPercent = Number(source.progressPercent ?? source.progress);
    if (Number.isFinite(explicitPercent) && explicitPercent >= 0) {
        return {
            percent: Math.max(0, Math.min(100, Math.round(explicitPercent))),
            completed: Math.round(explicitPercent),
            total: 100,
            unit: 'percent'
        };
    }
    const rows = ensureArray(source.runs).length
            ? ensureArray(source.runs)
            : ensureArray(source.metrics);
    const total = firstPositiveNumber(
            source.totalRunCount,
            source.totalMetricCount,
            source.ledgerConsistency?.expectedMetricCount,
            rows.length);
    const completed = Math.min(
            firstPositiveNumber(
                    Number(source.passedRunCount || 0) + Number(source.failedRunCount || 0),
                    Number(source.passedMetricCount || 0) + Number(source.failedMetricCount || 0),
                    rows.length),
            total);
    if (total > 0) {
        return {
            percent: Math.max(0, Math.min(100, Math.round((completed / total) * 100))),
            completed,
            total,
            unit: 'metric'
        };
    }
    return officialProcessStageProgress(source.processSteps);
}

function officialProcessStageProgress(processSteps) {
    const officialSteps = ['PROTECTABLE_RESOURCES', 'RUNTIME_EVIDENCE', 'OFFICIAL_VERIFICATION'];
    const byCode = ensureArray(processSteps).reduce((acc, step) => {
        const code = upperText(step?.stepCode);
        if (code) {
            acc.set(code, step);
        }
        return acc;
    }, new Map());
    if (!byCode.size) {
        return { percent: null, completed: 0, total: 0 };
    }
    const total = officialSteps.length;
    const completed = officialSteps
            .filter(code => upperText(byCode.get(code)?.executionState) === 'COMPLETED')
            .length;
    const running = officialSteps
            .some(code => upperText(byCode.get(code)?.executionState) === 'RUNNING');
    const effective = Math.min(total, completed + (running ? 0.5 : 0));
    return {
        percent: Math.max(0, Math.min(100, Math.round((effective / total) * 100))),
        completed,
        total,
        unit: 'stage'
    };
}

function firstPositiveNumber(...values) {
    for (const value of values) {
        const number = Number(value);
        if (Number.isFinite(number) && number > 0) {
            return number;
        }
    }
    return 0;
}

function firstText(...values) {
    return values.map(rawText).find(Boolean) || '';
}

function progressLabel(percent, computed = {}) {
    const safePercent = Math.max(0, Math.min(100, Number(percent) || 0));
    if (computed.total > 0 && computed.unit === 'metric') {
        return t('enterprise.pqa.verification.run.progress.percentWithMetrics', safePercent, computed.completed, computed.total);
    }
    if (computed.total > 0 && computed.unit === 'stage') {
        return t('enterprise.pqa.verification.run.progress.percentWithStages', safePercent, computed.completed, computed.total);
    }
    return t('enterprise.pqa.verification.run.progress.percentOnly', safePercent);
}

function progressDetail(computed = {}) {
    if (computed.total > 0 && computed.unit === 'metric') {
        return t('enterprise.pqa.verification.run.progress.metricDetail', computed.completed, computed.total);
    }
    if (computed.total > 0 && computed.unit === 'stage') {
        return t('enterprise.pqa.verification.run.progress.stageDetail', computed.completed, computed.total);
    }
    return t('enterprise.pqa.verification.run.progress.ledger.detail');
}

function hideRunProgress(pageRoot) {
    const panel = $(pageRoot, '[data-pqa-verification-progress]');
    if (!panel) {
        return;
    }
    panel.hidden = true;
    panel.removeAttribute('aria-busy');
    panel.removeAttribute('aria-valuenow');
    panel.removeAttribute('data-mode');
}

function renderRun(pageRoot, run) {
    const scopedRun = withRouteIdentity(pageRoot, run || {});
    const runTotals = metricCheckTotals(ensureArray(scopedRun.metrics), scopedRun);
    const totalMetricCount = Number(scopedRun.totalMetricCount || 0);
    const blockedMetricCount = Number(runTotals.blockedMetrics || 0);
    const gateMetricCount = Number(runTotals.gateMetrics || 0);
    const gateConditionCount = Number(runTotals.gateConditions || 0);
    const inputReviewCount = Number(runTotals.inputReviewMetrics || 0);
    const notApplicableMetricCount = Number(runTotals.notApplicableMetrics || 0);
    const rawPassedMetricCount = Number(scopedRun.passedMetricCount || 0);
    const derivedPassedMetricCount = Math.max(
            totalMetricCount - blockedMetricCount - gateMetricCount - inputReviewCount - notApplicableMetricCount,
            0);
    const passedMetricCount = totalMetricCount > 0
            ? Math.min(rawPassedMetricCount || derivedPassedMetricCount, derivedPassedMetricCount)
            : rawPassedMetricCount;
    renderRunSummary(pageRoot, scopedRun);
    updateHandoffLinks(pageRoot, scopedRun);
    renderStatusChart(
            pageRoot.querySelector('[data-pqa-verification-chart]'),
            [
                { label: t('enterprise.pqa.verification.summary.passed'), count: passedMetricCount, tone: 'ready' },
                { label: t('enterprise.pqa.verification.summary.blocked'), count: blockedMetricCount, tone: 'blocked' },
                { label: '추가 확인', count: gateConditionCount, tone: 'warning' },
                { label: '사전 입력 문제', count: inputReviewCount, tone: 'neutral' },
                { label: '검사 대상 아님', count: notApplicableMetricCount, tone: 'neutral' }
            ],
            { title: t('enterprise.pqa.verification.chart.title'), subtitle: t('enterprise.pqa.verification.chart.subtitle') });
}

function renderRunSummary(pageRoot, run) {
    const target = $(pageRoot, '[data-pqa-run-summary]');
    if (!target) {
        return;
    }
    const metrics = ensureArray(run.metrics);
    const totals = metricCheckTotals(metrics, run);
    const total = Number(run.totalMetricCount || metrics.length || 12);
    const actualProblems = Number(totals.actualProblems || visibleActualPromptProblems(run.actualPromptProblems).length || 0);
    const blockedMetrics = Number(totals.blockedMetrics || 0);
    const gateMetrics = Number(totals.gateMetrics || 0);
    const gateConditions = Number(totals.gateConditions || 0);
    const inputReviewMetrics = Number(totals.inputReviewMetrics || 0);
    const notApplicableMetrics = Number(totals.notApplicableMetrics || 0);
    const passed = Math.max(total - blockedMetrics - gateMetrics - inputReviewMetrics - notApplicableMetrics, 0);
    const officialPassed = officialVerificationPassedForDisplay(run, {
        totalMetricCount: total,
        passedMetricCount: passed,
        failedMetricCount: blockedMetrics,
        actualProblems
    });
    const resultTone = officialPassed || run.certificateIssued
            ? 'ready'
            : actualProblems > 0 || blockedMetrics > 0
                    ? 'blocked'
                    : inputReviewMetrics > 0 || gateMetrics > 0
                            ? 'warning'
                            : 'ready';
    const resultTitle = firstCleanText(
            run?.officialStateLabel,
            officialDecisionLabel(run?.officialFinalDecision || run?.finalDecision || run?.state),
            run?.stateLabel,
            run?.certificateStateLabel,
            run?.certificateState,
            run?.state,
            run?.certificateSummary,
            run?.plainSummary,
            ...ensureArray(run?.nextActions));
    const requestLabel = `${text(run.httpMethod)} ${text(resourceUrlOf(run))}`;
    const promptHash = rawText(run.promptHash);
    const contextHash = rawText(run.contextHash);
    target.innerHTML = `
        <section class="pqa-run-summary-shell ${escapeHtml(resultTone)}">
            <article class="pqa-run-hero-card ${escapeHtml(resultTone)}">
                <div class="pqa-run-hero-main">
                    <div class="pqa-run-hero-copy">
                        <span class="pqa-run-kicker">Official Prompt Assurance</span>
                        <strong>${escapeHtml(resultTitle)}</strong>
                        <p>${escapeHtml(runResultOneLine(run))}</p>
                    </div>
                </div>
                <div class="pqa-run-score-card">
                    <span>지표 통과</span>
                    <strong>${escapeHtml(`${passed} / ${total}`)}</strong>
                    <small>${escapeHtml(runResultOneLine(run))}</small>
                </div>
            </article>
            <section class="pqa-run-result-panel" aria-label="검사 결과">
                <div class="pqa-run-panel-title">
                    <span>핵심 요약</span>
                    <strong>현재 처리 상태</strong>
                </div>
                <div class="pqa-run-kpi-grid">
                    ${runKpiCard('', '통과 지표', `${passed} / ${total}`, '전체 지표 중 통과', passed === total ? 'ready' : 'neutral')}
                    ${runKpiCard('', '프롬프트 문제', `${actualProblems}개`, actualProblems ? '후속 조치 필요' : '없음', actualProblems ? 'blocked' : 'ready')}
                    ${runKpiCard('', '사전 입력 문제', inputReviewMetrics ? `${inputReviewMetrics}개 지표` : '없음', inputReviewMetrics ? '먼저 처리' : '없음', inputReviewMetrics ? 'warning' : 'ready')}
                    ${runKpiCard('', '추가 확인', gateConditions ? `${gateConditions}개` : '없음', gateMetrics ? '확인 필요' : '없음', gateMetrics ? 'warning' : 'ready')}
                    ${runKpiCard('', '검사 대상 아님', notApplicableMetrics ? `${notApplicableMetrics}개` : '없음', notApplicableMetrics ? '이번 요청 제외' : '없음', notApplicableMetrics ? 'neutral' : 'ready')}
                </div>
            </section>
            <section class="pqa-run-info-panel" aria-label="실행 정보">
                <div class="pqa-run-panel-title">
                    <span>실행 정보</span>
                    <strong>선택 증거</strong>
                </div>
                <dl class="pqa-run-info-list">
                    ${runInfoItem('요청 증거 번호', `<code>${escapeHtml(text(run.packageId))}</code>`)}
                    ${runInfoItem('요청 식별자', `<code>${escapeHtml(runDisplayRequestId(run))}</code>`)}
                    ${runInfoItem('요청', `<span>${escapeHtml(requestLabel)}</span>`)}
                    ${runInfoItem('프롬프트 해시', `<code class="pqa-hash">${escapeHtml(promptHash ? shortHash(promptHash) : text(run.promptHash))}</code>`)}
                    ${runInfoItem('컨텍스트 해시', `<code class="pqa-hash">${escapeHtml(contextHash ? shortHash(contextHash) : text(run.contextHash))}</code>`)}
                    ${runInfoItem('품질 건', caseLink(run))}
                    ${runInfoItem('검사 상태', badge(resultTitle || '-', { tone: resultTone }))}
                </dl>
            </section>
            ${renderGuidance(run, { actualProblems, blockedMetrics, gateMetrics, gateConditions, inputReviewMetrics, gateMetricCodes: gateMetricCodesFromRuns(metrics, run), resultTone })}
        </section>
    `;
}

function renderResolutionActions(actions = []) {
    const visibleActions = ensureArray(actions)
            .filter(action => rawText(action?.href) && rawText(action?.label));
    if (!visibleActions.length) {
        return '';
    }
    return `
        <div class="pqa-resolution-actions">
            ${visibleActions.map(action => `
                <a class="pqa-resolution-action${action.primary ? ' primary' : ''}" href="${escapeHtml(action.href)}">
                    ${escapeHtml(action.label)}
                </a>
            `).join('')}
        </div>
    `;
}
function runIntegrityLabel(run = {}) {
    if (run.integrityValid === true) {
        return t('enterprise.pqa.runtimeEvidence.badge.integrityOk');
    }
    if (run.integrityValid === false) {
        return t('enterprise.pqa.runtimeEvidence.badge.integrityError');
    }
    return '상세 확인';
}

function runIntegrityTone(run = {}) {
    if (run.integrityValid === true) {
        return 'ready';
    }
    if (run.integrityValid === false) {
        return 'blocked';
    }
    return 'neutral';
}

function runPromptConsistencyChipTone(run = {}) {
    const consistency = run.promptConsistency || run.sealedEvidence?.promptConsistency;
    if (rawText(consistency?.stateLabel) || rawText(consistency?.state)) {
        return promptConsistencyTone(consistency.state);
    }
    const comparisons = ensureArray(run.promptComparisons);
    if (comparisons.length) {
        return comparisonProblemCounts(comparisons, run).total ? 'warning' : 'ready';
    }
    return 'neutral';
}

function runEvidenceChip(icon, label, value, tone = 'neutral', htmlValue = false) {
    const safeTone = rawText(tone) || 'neutral';
    return `
        <article class="pqa-run-evidence-chip ${escapeHtml(safeTone)}">
            <span class="pqa-run-badge-icon"><i class="fa-solid ${escapeHtml(icon)}" aria-hidden="true"></i></span>
            <span class="pqa-run-badge-label">${escapeHtml(label)}</span>
            <strong>${htmlValue ? value : escapeHtml(text(value))}</strong>
        </article>
    `;
}

function runKpiCard(icon, label, value, detail, tone = 'neutral') {
    const marker = rawText(icon)
            ? `<span class="pqa-run-badge-icon"><i class="fa-solid ${escapeHtml(icon)}" aria-hidden="true"></i></span>`
            : '';
    return `
        <article class="pqa-run-kpi-card ${escapeHtml(tone)}">
            ${marker}
            <span class="pqa-run-badge-label">${escapeHtml(label)}</span>
            <strong>${escapeHtml(String(value))}</strong>
            <small>${escapeHtml(detail)}</small>
        </article>
    `;
}

function runInfoItem(label, valueHtml) {
    return `
        <div>
            <dt>${escapeHtml(label)}</dt>
            <dd>${valueHtml}</dd>
        </div>
    `;
}

function runInfoCard(icon, label, valueHtml) {
    return `
        <article class="pqa-run-info-card">
            <i class="fa-solid ${escapeHtml(icon)}" aria-hidden="true"></i>
            <div>
                <span>${escapeHtml(label)}</span>
                <strong>${valueHtml}</strong>
            </div>
        </article>
    `;
}

function renderExecutionFailure(pageRoot, failure, source) {
    const target = $(pageRoot, '[data-pqa-run-summary]');
    clearChart(pageRoot);
    if (!target) {
        return;
    }
    const evidenceId = rawText(failure?.evidenceId) || rawText(source?.packageId) || t('enterprise.pqa.verification.value.notAvailable');
    const stateLabel = failure?.recoverable === false
            ? t('enterprise.pqa.verification.run.failureCard.stateTerminal')
            : t('enterprise.pqa.verification.run.failureCard.stateRecoverable');
    target.innerHTML = `
        <div class="pqa-conclusion pqa-runtime-summary-card pqa-execution-failure-card">
            <strong>${escapeHtml(t('enterprise.pqa.verification.run.failureCard.title'))}</strong>
            <p>${escapeHtml(failure?.reason || t('enterprise.pqa.verification.run.failureCard.reasonFallback'))}</p>
            <dl class="pqa-registration-meta">
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.dt.requestEvidenceId'))}</dt><dd><code>${escapeHtml(evidenceId)}</code></dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.run.failureCard.stage'))}</dt><dd>${escapeHtml(failure?.stageLabel || text(failure?.stage))}</dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.run.failureCard.state'))}</dt><dd>${badge(stateLabel, { tone: 'blocked' })}</dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.run.failureCard.progress'))}</dt><dd>${escapeHtml(progressLabel(failure?.progressPercent || 0))}</dd></div>
                ${failure?.aggregateRunId
                        ? `<div><dt>${escapeHtml(t('enterprise.pqa.verification.run.failureCard.aggregateRunId'))}</dt><dd><code>${escapeHtml(failure.aggregateRunId)}</code></dd></div>`
                        : ''}
            </dl>
            <div class="pqa-guidance-list">
                <article>
                    <strong>${escapeHtml(t('enterprise.pqa.verification.run.failureCard.reason'))}</strong>
                    <p>${escapeHtml(failure?.reason || t('enterprise.pqa.verification.run.failureCard.reasonFallback'))}</p>
                </article>
                <article>
                    <strong>${escapeHtml(t('enterprise.pqa.verification.run.failureCard.retry'))}</strong>
                    <p>${escapeHtml(failure?.retry || t('enterprise.pqa.verification.run.failureCard.retryFallback'))}</p>
                </article>
            </div>
        </div>
    `;
}

function renderPromptConsistencyStage(pageRoot, result, source) {
    const target = $(pageRoot, '[data-pqa-prompt-consistency-content]');
    if (!target) {
        return;
    }
    if (!result) {
        target.classList.add('pqa-runtime-detail-empty');
        target.innerHTML = `<p>${escapeHtml(t('enterprise.pqa.promptConsistency.empty'))}</p>`;
        return;
    }
    target.classList.remove('pqa-runtime-detail-empty');
    target.innerHTML = `
        ${renderPromptConsistency(result)}
    `;
}

function renderPromptConsistency(result) {
    if (!result) {
        return '';
    }
    const checks = ensureArray(result.checks);
    const failed = checks.filter(check => !check.pass);
    const passed = checks.filter(check => check.pass);
    const blocking = Boolean(result.blocking);
    const decisionTitle = promptConsistencyDecisionTitle(result, failed.length);
    const decisionDetail = promptConsistencyDecisionDetail(result, failed.length);
    
    const passedIcon = `<svg style="width:14px;height:14px;color:#10b981;flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>`;
    const failedIcon = `<svg style="width:14px;height:14px;color:#fbbf24;flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
    const nextIcon = `<svg style="width:14px;height:14px;color:#60a5fa;flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M13 5l7 7-7 7M5 5l7 7-7 7"></path></svg>`;
    
    return `
        <section class="pqa-prompt-consistency" data-pqa-prompt-consistency>
            <div class="pqa-prompt-consistency-head">
                <strong>${escapeHtml(decisionTitle)}</strong>
                ${badge(text(result.stateLabel), { tone: promptConsistencyTone(result.state) })}
            </div>
            <p class="pqa-prompt-consistency-summary">${escapeHtml(decisionDetail)}</p>
            <div class="pqa-prompt-consistency-grid">
                <div>
                    <span style="display:flex;align-items:center;gap:0.35rem;">${passedIcon}확인 완료</span>
                    <strong>${escapeHtml(String(passed.length))}</strong>
                </div>
                <div>
                    <span style="display:flex;align-items:center;gap:0.35rem;">${failedIcon}차단</span>
                    <strong>${escapeHtml(String(failed.length))}</strong>
                </div>
                <div>
                    <span style="display:flex;align-items:center;gap:0.35rem;">${nextIcon}다음 단계</span>
                    <strong>${escapeHtml(blocking ? '해결 필요' : '검사 실행')}</strong>
                </div>
            </div>
            ${failed.length ? `
                <div class="pqa-prompt-consistency-section">
                    <h4 style="display:flex;align-items:center;gap:0.5rem;">
                        <svg style="width:16px;height:16px;color:#fbbf24;flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                        공식검사 전 해결 항목 <span>${escapeHtml(String(failed.length))}</span>
                    </h4>
                    ${renderPromptConsistencyGroups(failed, false)}
                </div>
            ` : ''}
            <details class="pqa-prompt-consistency-section pqa-prompt-consistency-passed">
                <summary style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;">
                    <svg style="width:16px;height:16px;color:#10b981;flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <strong>확인 완료 항목</strong>
                    <span>${escapeHtml(String(passed.length))}</span>
                    <em>필요할 때만 펼쳐 봅니다.</em>
                </summary>
                ${renderPromptConsistencyGroups(passed, true)}
            </details>
        </section>
    `;
}

function renderPromptConsistencyGroups(checks, passed) {
    if (!checks.length) {
        return `<p class="pqa-prompt-consistency-empty">${escapeHtml(t('enterprise.pqa.promptConsistency.section.empty'))}</p>`;
    }
    const groups = checks.reduce((acc, check) => {
        const source = text(check.source) || t('enterprise.pqa.promptConsistency.source.unknown');
        if (!acc.has(source)) {
            acc.set(source, []);
        }
        acc.get(source).push(check);
        return acc;
    }, new Map());
    return Array.from(groups.entries())
            .map(([source, group]) => `
                <article class="pqa-prompt-consistency-source ${passed ? 'is-pass' : 'is-fail'}">
                    <header>
                        <span>${escapeHtml(t('enterprise.pqa.promptConsistency.source.label'))}</span>
                        <strong>${escapeHtml(promptConsistencySourceLabel(source))}</strong>
                        <em>${escapeHtml(t('enterprise.pqa.promptConsistency.source.itemCount', group.length))}</em>
                    </header>
                    <ul class="pqa-prompt-consistency-list">
                        ${group.map(renderPromptConsistencyCheck).join('')}
                    </ul>
                </article>
            `)
            .join('');
}

function renderPromptConsistencyCheck(check) {
    const pass = Boolean(check.pass);
    return `
        <li class="${pass ? 'is-pass' : 'is-fail'}">
            <div class="pqa-prompt-consistency-check-head">
                <strong>${escapeHtml(promptConsistencyCheckLabel(check))}</strong>
                ${badge(pass ? t('enterprise.pqa.promptConsistency.check.pass') : t('enterprise.pqa.promptConsistency.check.fail'), { tone: pass ? 'ready' : 'blocked' })}
            </div>
            <p>${escapeHtml(promptConsistencyOperatorSummary(check))}</p>
            ${pass ? '' : `
                <dl class="pqa-prompt-consistency-action">
                    <div><dt>${escapeHtml(t('enterprise.pqa.promptConsistency.detail.impact'))}</dt><dd>${escapeHtml(promptConsistencyOperatorImpact(check))}</dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.promptConsistency.detail.action'))}</dt><dd>${escapeHtml(promptConsistencyOperatorAction(check))}</dd></div>
                </dl>
            `}
            <details class="pqa-prompt-consistency-technical">
                <summary>${escapeHtml(t('enterprise.pqa.promptConsistency.detail.technical'))}</summary>
                <dl>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.metricCheck.expected'))}</dt><dd>${escapeHtml(promptConsistencyExpected(check.expectedValue))}</dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.metricCheck.actual'))}</dt><dd>${escapeHtml(promptConsistencyActual(check.actualValue))}</dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.detailLine.evidenceLocation'))}</dt><dd><code>${escapeHtml(text(check.source))}</code></dd></div>
                </dl>
            </details>
        </li>
    `;
}

function promptConsistencyDecisionTitle(result, failedCount) {
    if (result?.blocking) {
        return t('enterprise.pqa.promptConsistency.decision.blocked.title');
    }
    if (failedCount > 0) {
        return t('enterprise.pqa.promptConsistency.decision.review.title');
    }
    return t('enterprise.pqa.promptConsistency.decision.pass.title');
}

function promptConsistencyDecisionDetail(result, failedCount) {
    if (result?.blocking) {
        return t('enterprise.pqa.promptConsistency.decision.blocked.detail');
    }
    if (failedCount > 0) {
        return t('enterprise.pqa.promptConsistency.decision.review.detail');
    }
    return t('enterprise.pqa.promptConsistency.decision.pass.detail');
}

function promptConsistencyCheckLabel(check) {
    const rawLabel = text(check?.label);
    const mapped = PROMPT_CONSISTENCY_LABEL_KEYS[rawLabel];
    if (mapped && has(mapped)) {
        return t(mapped);
    }
    const existsMatch = rawLabel.match(/^(.+) exists in sealed evidence$/);
    if (existsMatch && has('enterprise.pqa.promptConsistency.label.existsInSealedEvidence')) {
        return t('enterprise.pqa.promptConsistency.label.existsInSealedEvidence', existsMatch[1]);
    }
    const reflectedMatch = rawLabel.match(/^(.+) is reflected in user prompt$/);
    if (reflectedMatch && has('enterprise.pqa.promptConsistency.label.reflectedInUserPrompt')) {
        return t('enterprise.pqa.promptConsistency.label.reflectedInUserPrompt', reflectedMatch[1]);
    }
    return rawLabel;
}

function promptConsistencySourceLabel(source) {
    const rawSource = text(source);
    const base = rawSource.split('.')[0] || rawSource;
    const key = PROMPT_CONSISTENCY_SOURCE_KEYS[base];
    return key && has(key) ? t(key) : rawSource;
}

function promptConsistencyValue(value) {
    const rawValue = text(value);
    const key = PROMPT_CONSISTENCY_VALUE_KEYS[rawValue];
    return key && has(key) ? t(key) : rawValue;
}

function promptConsistencyExpected(value) {
    const rawValue = text(value);
    const key = PROMPT_CONSISTENCY_EXPECTATION_KEYS[rawValue];
    if (key && has(key)) {
        return t(key);
    }
    if (/^[a-zA-Z][a-zA-Z0-9_]* value$/.test(rawValue)) {
        return t('enterprise.pqa.promptConsistency.expected.namedValue', rawValue.replace(/ value$/, ''));
    }
    return promptConsistencyValue(rawValue);
}

function promptConsistencyActual(value) {
    const rawValue = text(value);
    if (rawValue.startsWith('declared=') && rawValue.includes('recalculated=')) {
        const hashes = rawValue.match(/sha256:[a-f0-9]+/gi) || [];
        return hashes.length >= 2 && hashes[0] === hashes[1]
                ? t('enterprise.pqa.promptConsistency.actual.hashMatched', shortHash(hashes[0]))
                : t('enterprise.pqa.promptConsistency.actual.hashMismatched');
    }
    if (rawValue === 'different, compressionApplied=true') {
        return t('enterprise.pqa.promptConsistency.actual.compressedTrace');
    }
    if (rawValue === 'different, compressionApplied=false') {
        return t('enterprise.pqa.promptConsistency.actual.untrackedDifference');
    }
    if (rawValue.startsWith('sha256:')) {
        return shortHash(rawValue);
    }
    return promptConsistencyValue(rawValue);
}

function promptConsistencyOperatorSummary(check) {
    const label = text(check?.label);
    const source = promptConsistencySourceBase(check?.source);
    const actual = text(check?.actualValue);
    const pass = Boolean(check?.pass);
    if (label === 'raw prompt and LLM prompt difference is recorded') {
        return actual === 'different, compressionApplied=true'
                ? t('enterprise.pqa.promptConsistency.summary.rawCompressedPass')
                : pass ? t('enterprise.pqa.promptConsistency.summary.rawTracePass')
                        : t('enterprise.pqa.promptConsistency.summary.rawTraceFail');
    }
    if (label.includes('Hash')) {
        return pass
                ? t('enterprise.pqa.promptConsistency.summary.hashPass')
                : t('enterprise.pqa.promptConsistency.summary.hashFail');
    }
    if (label.endsWith('is traceable in sealed evidence')) {
        return pass
                ? t('enterprise.pqa.promptConsistency.summary.tracePass')
                : t('enterprise.pqa.promptConsistency.summary.traceFail');
    }
    if (label.endsWith('is reflected in user prompt')) {
        return pass
                ? t('enterprise.pqa.promptConsistency.summary.factReflectedPass')
                : t('enterprise.pqa.promptConsistency.summary.factReflectedFail');
    }
    if (label.endsWith('exists in sealed evidence')) {
        return pass
                ? t('enterprise.pqa.promptConsistency.summary.factExistsPass')
                : t('enterprise.pqa.promptConsistency.summary.factExistsFail');
    }
    if (source === 'promptCapture') {
        return pass
                ? t('enterprise.pqa.promptConsistency.summary.capturePass')
                : t('enterprise.pqa.promptConsistency.summary.captureFail');
    }
    return pass
            ? t('enterprise.pqa.promptConsistency.summary.defaultPass')
            : t('enterprise.pqa.promptConsistency.summary.defaultFail');
}

function promptConsistencyOperatorImpact(check) {
    const label = text(check?.label);
    const source = promptConsistencySourceBase(check?.source);
    if (label.includes('Hash') || source === 'promptHash') {
        return t('enterprise.pqa.promptConsistency.impact.hash');
    }
    if (label.endsWith('is reflected in user prompt') || label.endsWith('exists in sealed evidence')) {
        return t('enterprise.pqa.promptConsistency.impact.fact');
    }
    return t('enterprise.pqa.promptConsistency.impact.default');
}

function promptConsistencyOperatorAction(check) {
    const label = text(check?.label);
    const source = promptConsistencySourceBase(check?.source);
    if (label.includes('Hash') || source === 'promptHash') {
        return t('enterprise.pqa.promptConsistency.action.hash');
    }
    if (label.endsWith('is reflected in user prompt') || label.endsWith('exists in sealed evidence')) {
        return t('enterprise.pqa.promptConsistency.action.fact');
    }
    return t('enterprise.pqa.promptConsistency.action.default');
}

function promptConsistencySourceBase(source) {
    const rawSource = text(source);
    return rawSource.split('.')[0] || rawSource;
}

function shortHash(value) {
    const rawValue = text(value);
    return rawValue.length > 22 ? `${rawValue.slice(0, 16)}...${rawValue.slice(-8)}` : rawValue;
}

function certificateLink(run) {
    if (!run.certificateId) {
        return t('enterprise.pqa.verification.value.none');
    }
    return `<code>${escapeHtml(run.certificateId)}</code>`;
}

function caseLink(run) {
    if (!run.caseId) {
        return t('enterprise.pqa.verification.value.none');
    }
    return `<code>${escapeHtml(run.caseId)}</code>`;
}

function resourceCheckHref(source = {}) {
    return scopedStageUrl('/contexa/admin/prompt-quality/resources/detail', source, ['resourceUrl', 'resourceId', 'httpMethod'])
            || scopedStageUrl('/contexa/admin/prompt-quality/resources', source)
            || verificationStageHref('metrics', source);
}

function runDisplayRequestId(run = {}) {
    return rawText(run.requestId)
            || rawText(run.correlationId)
            || rawText(run.sealedEvidence?.summary?.correlationId)
            || comparisonValueFor(run.promptComparisons, 'requestId')
            || comparisonValueFor(run.promptComparisons, 'correlationId')
            || rawText(run.packageId)
            || t('enterprise.pqa.verification.value.notAvailable');
}

function comparisonValueFor(comparisons, fieldKey) {
    const normalized = lowerText(fieldKey);
    const item = ensureArray(comparisons).find(candidate => lowerText(candidate?.fieldKey) === normalized);
    if (!item) {
        return '';
    }
    return firstText(item.sealedEvidenceValue, item.officialFactValue, item.promptValue);
}

function promptConsistencyBadge(run = {}) {
    const consistency = run.promptConsistency || run.sealedEvidence?.promptConsistency;
    if (rawText(consistency?.stateLabel) || rawText(consistency?.state)) {
        return badge(rawText(consistency.stateLabel) || rawText(consistency.state), {
            tone: promptConsistencyTone(consistency.state)
        });
    }
    const comparisons = ensureArray(run.promptComparisons);
    if (comparisons.length) {
        const problemCount = comparisonProblemCounts(comparisons, run).total;
        return badge(problemCount ? '검토 필요' : '통과', { tone: problemCount ? 'warning' : 'ready' });
    }
    return badge('비교 탭에서 확인', { tone: 'neutral' });
}

function runResultOneLine(run = {}) {
    const summary = firstCleanText(
            run?.certificateSummary,
            run?.plainSummary,
            run?.blockReasonSummary,
            ...ensureArray(run?.nextActions));
    return summary ? truncateForOperator(summary, 180) : '';
}

function renderGuidance(run, summary = {}) {
    const actionText = firstCleanText(...ensureArray(run?.nextActions));
    if (!actionText) {
        return '';
    }
    const href = rawText(run?.nextActionHref);
    const actionLink = rawText(href)
            ? `<a class="pqa-link-button" href="${escapeHtml(href)}">
                    <span>${escapeHtml(actionText)}</span>
            </a>`
            : '';
    return `
        <section class="pqa-run-next-card warning">
            <div>
                <span>다음 단계</span>
                <strong>${escapeHtml(actionText)}</strong>
            </div>
            ${actionLink}
        </section>
    `;
}
function reverifyLink(run) {
    const params = new URLSearchParams();
    const identity = identityFromSource(run, routeIdentityFromLocation());
    const packageId = rawText(run?.packageId);
    const runId = rawText(run?.aggregateRunId) || rawText(run?.runId);
    if (packageId) {
        params.set('failedPackageId', packageId);
    }
    if (runId) {
        params.set('runId', runId);
        params.set('aggregateRunId', runId);
    }
    setParam(params, 'officialRunId', rawText(run?.officialRunId));
    setParam(params, 'reverifyRunId', rawText(run?.reverifyRunId));
    setParam(params, 'certificateId', rawText(run?.certificateId));
    setParam(params, 'caseId', rawText(run?.caseId));
    setParam(params, 'resourceUrl', identity.resourceUrl);
    setParam(params, 'resourceId', identity.resourceId);
    setParam(params, 'resourceTemplateId', identity.resourceTemplateId);
    setParam(params, 'actualResourceId', identity.actualResourceId);
    setParam(params, 'httpMethod', identity.httpMethod);
    const query = params.toString();
    return appPath(`/contexa/admin/prompt-quality/verification/run${query ? `?${query}` : ''}`);
}

function issueListLink(run) {
    return issueLinkForPath('/contexa/admin/prompt-quality/verification/metrics', run);
}

function issueLinkForPath(path, run) {
    const params = new URLSearchParams();
    const packageId = rawText(run?.packageId);
    const runId = rawText(run?.aggregateRunId) || rawText(run?.runId);
    if (packageId) {
        params.set('packageId', packageId);
    }
    if (runId) {
        params.set('aggregateRunId', runId);
    }
    const query = params.toString();
    return appPath(`${path}${query ? `?${query}` : ''}`);
}

function updateHandoffLinks(pageRoot, source) {
    // OSS official inspection stops at result diagnosis. Enterprise handoff links
    // are intentionally not rendered from the migrated core UI.
}

function remediationGroupIdOf(group) {
    return rawText(group?.groupId) || rawText(group?.remediationGroupId);
}

function setParam(params, name, value) {
    const normalized = rawText(value);
    if (normalized) {
        params.set(name, normalized);
    }
}

function isStoredVerificationResultRoute(route) {
    return route === 'comparison' || route === 'metrics';
}

function runtimeEvidenceHref(source = {}) {
    const identity = identityFromSource(source, routeIdentityFromLocation());
    const params = new URLSearchParams();
    setParam(params, 'packageId', source.packageId);
    setParam(params, 'aggregateRunId', rawText(source.aggregateRunId) || rawText(source.runId));
    setParam(params, 'officialRunId', source.officialRunId);
    setParam(params, 'reverifyRunId', source.reverifyRunId);
    setParam(params, 'certificateId', source.certificateId);
    setParam(params, 'caseId', source.caseId);
    setParam(params, 'resourceUrl', identity.resourceUrl);
    setParam(params, 'resourceId', identity.resourceId);
    setParam(params, 'resourceTemplateId', identity.resourceTemplateId);
    setParam(params, 'actualResourceId', identity.actualResourceId);
    setParam(params, 'httpMethod', identity.httpMethod);
    const query = params.toString();
    return appPath(`/contexa/admin/prompt-quality/runtime-evidence${query ? `?${query}` : ''}`);
}

function verificationStageHref(route, source = {}) {
    const packageId = rawText(source?.packageId)
            || (typeof source === 'string' ? rawText(source) : null);
    const identity = identityFromSource(source, routeIdentityFromLocation());
    const paths = {
        readiness: '/contexa/admin/prompt-quality/verification/readiness',
        run: '/contexa/admin/prompt-quality/verification/run',
        comparison: '/contexa/admin/prompt-quality/verification/prompt-comparison',
        metrics: '/contexa/admin/prompt-quality/verification/metrics'
    };
    const params = new URLSearchParams();
    setParam(params, 'packageId', packageId);
    setParam(params, 'aggregateRunId', rawText(source?.aggregateRunId) || rawText(source?.runId) || aggregateRunIdFromLocation());
    if (isStoredVerificationResultRoute(route)) {
        const query = params.toString();
        return appPath(`${paths[route] || paths.run}${query ? `?${query}` : ''}`);
    }
    setParam(params, 'officialRunId', rawText(source?.officialRunId));
    setParam(params, 'reverifyRunId', rawText(source?.reverifyRunId));
    setParam(params, 'certificateId', rawText(source?.certificateId));
    setParam(params, 'caseId', rawText(source?.caseId));
    setParam(params, 'resourceUrl', identity.resourceUrl);
    setParam(params, 'resourceId', identity.resourceId);
    setParam(params, 'resourceTemplateId', identity.resourceTemplateId);
    setParam(params, 'actualResourceId', identity.actualResourceId);
    setParam(params, 'httpMethod', identity.httpMethod);
    const query = params.toString();
    return appPath(`${paths[route] || paths.run}${query ? `?${query}` : ''}`);
}

function distinctText(values) {
    const seen = new Set();
    ensureArray(values)
            .map(rawText)
            .filter(Boolean)
            .forEach(value => seen.add(value));
    return Array.from(seen);
}

function issueDetailLink(source = {}) {
    const issues = ensureArray(source?.issues);
    const failures = ensureArray(source?.failureCauses);
    const issue = issues.find(item => rawText(item?.issueId)) || {};
    const failure = failures.find(item => rawText(item?.issueId)) || {};
    const issueId = rawText(issue.issueId) || rawText(failure.issueId);
    if (!issueId) {
        return issueListLink(source);
    }
    const url = new URL(issueListLink(source), window.location.origin);
    const params = new URLSearchParams(url.search || '');
    const problemId = rawText(issue.problemId) || rawText(failure.problemId) || rawText(source?.problemId) || distinctText(source?.problemIds || [])[0];
    if (problemId) {
        params.set('problemId', problemId);
    }
    const query = params.toString();
    return appPath(`/contexa/admin/prompt-quality/verification/metrics${query ? `?${query}` : ''}`);
}

async function renderOfficialLedger(pageRoot, packageId) {
    const panel = $(pageRoot, '[data-pqa-official-ledger]');
    if (!packageId) {
        return null;
    }
    if (panel) {
        panel.hidden = false;
    }
    const summary = $(pageRoot, '[data-pqa-official-ledger-summary]');
    const attempts = $(pageRoot, '[data-pqa-official-ledger-attempts]');
    const process = $(pageRoot, '[data-pqa-official-ledger-process]');
    const audit = $(pageRoot, '[data-pqa-official-ledger-audit]');
    const prompt = $(pageRoot, '[data-pqa-official-ledger-prompt]');
    const failures = $(pageRoot, '[data-pqa-official-ledger-failures]');
    const remediation = $(pageRoot, '[data-pqa-official-ledger-remediation]');
    const runs = $(pageRoot, '[data-pqa-official-ledger-runs]');
    const raw = $(pageRoot, '[data-pqa-official-ledger-raw]');
    if (summary) {
        summary.innerHTML = `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.ledger.loading'))}</p></div>`;
    }
    try {
        const detail = await loadOfficialLedgerDetail(packageId);
        pageRoot.__officialLedgerDetail = detail;
        const hasLedgerRuns = officialLedgerHasRuns(detail);
        pageRoot.__officialLedgerAvailable = hasLedgerRuns;
        pageRoot.__selectedAggregateRunId = rawText(detail.aggregateRunId) || aggregateRunIdFromLocation();
        renderOfficialLedgerSummary(summary, detail);
        renderOfficialAttempts(attempts, detail, pageRoot);
        renderOfficialProcess(process, detail);
        renderOfficialAudit(audit, detail);
        if (prompt) {
            renderOfficialPromptComparison(prompt, await officialPromptComparisonDetail(packageId, detail));
        }
        renderOfficialFailures(failures, detail);
        renderOfficialRemediationGroups(remediation, detail);
        renderOfficialRuns(runs, detail);
        renderOfficialRaw(raw, detail);
        updateSubrouteLinks(pageRoot, {
            ...pageRoot.__selectedEvidence,
            packageId,
            aggregateRunId: detail.aggregateRunId
        });
        updateHandoffLinks(pageRoot, {
            ...pageRoot.__selectedEvidence,
            packageId,
            aggregateRunId: detail.aggregateRunId
        });
        setRunButtonState(pageRoot);
        return hasLedgerRuns ? detail : null;
    }
    catch (error) {
        pageRoot.__officialLedgerAvailable = false;
        const errorHtml = `<div class="pqa-empty pqa-empty-error"><p>${escapeHtml(t('enterprise.pqa.verification.ledger.failed'))}: ${escapeHtml(publicError(error))}</p></div>`;
        if (summary) {
            summary.innerHTML = errorHtml;
        }
        [prompt, runs, process, audit, failures, remediation, raw].filter(Boolean).forEach(target => {
            target.innerHTML = errorHtml;
        });
        const runSummary = $(pageRoot, '[data-pqa-run-summary]');
        if (runSummary && !rawText(runSummary.textContent)) {
            runSummary.innerHTML = errorHtml;
        }
        updateSubrouteLinks(pageRoot, pageRoot.__selectedEvidence || { packageId });
        updateHandoffLinks(pageRoot, { packageId });
        setRunButtonState(pageRoot);
        return null;
    }
}

async function loadOfficialLedgerDetail(packageId) {
    const params = new URLSearchParams();
    const aggregateRunId = rawText(root?.__selectedAggregateRunId) || aggregateRunIdFromLocation();
    if (aggregateRunId) {
        params.set('aggregateRunId', aggregateRunId);
    }
    const query = params.toString();
    return getJson(`/contexa/admin/api/prompt-quality/verification/runtime-runs/package/${encodeURIComponent(packageId)}${query ? `?${query}` : ''}`);
}

async function loadOfficialTechnicalLedger(packageId) {
    const params = new URLSearchParams();
    const aggregateRunId = rawText(root?.__selectedAggregateRunId) || aggregateRunIdFromLocation();
    if (aggregateRunId) {
        params.set('aggregateRunId', aggregateRunId);
    }
    const query = params.toString();
    return getJson(`/contexa/admin/api/prompt-quality/verification/runtime-runs/package/${encodeURIComponent(packageId)}/technical-ledger${query ? `?${query}` : ''}`);
}

async function loadOfficialPromptComparison(packageId) {
    const params = new URLSearchParams();
    const aggregateRunId = rawText(root?.__selectedAggregateRunId) || aggregateRunIdFromLocation();
    if (aggregateRunId) {
        params.set('aggregateRunId', aggregateRunId);
    }
    const query = params.toString();
    return getJson(`/contexa/admin/api/prompt-quality/verification/packages/${encodeURIComponent(packageId)}/prompt-comparison${query ? `?${query}` : ''}`);
}

async function loadOfficialActualPromptProblems(packageId) {
    const params = new URLSearchParams();
    const aggregateRunId = rawText(root?.__selectedAggregateRunId) || aggregateRunIdFromLocation();
    if (aggregateRunId) {
        params.set('aggregateRunId', aggregateRunId);
    }
    const query = params.toString();
    return getJson(`/contexa/admin/api/prompt-quality/verification/packages/${encodeURIComponent(packageId)}/actual-prompt-problems${query ? `?${query}` : ''}`);
}

async function officialPromptComparisonDetail(packageId, detail) {
    const promptComparisons = ensureArray(detail?.promptComparisons);
    const actualPromptProblems = ensureArray(detail?.actualPromptProblems);
    if (promptComparisons.length && actualPromptProblems.length) {
        return {
            ...detail,
            promptComparisons,
            actualPromptProblems
        };
    }
    try {
        const [loadedComparisons, loadedActualProblems] = await Promise.all([
            promptComparisons.length ? Promise.resolve(promptComparisons) : loadOfficialPromptComparison(packageId),
            actualPromptProblems.length ? Promise.resolve(actualPromptProblems) : loadOfficialActualPromptProblems(packageId)
        ]);
        return {
            ...detail,
            promptComparisons: ensureArray(loadedComparisons),
            actualPromptProblems: ensureArray(loadedActualProblems)
        };
    }
    catch (error) {
        return {
            ...detail,
            promptComparisons,
            actualPromptProblems,
            promptComparisonError: publicError(error)
        };
    }
}

async function loadOfficialAuditPayloads(packageId) {
    const params = new URLSearchParams();
    const aggregateRunId = rawText(root?.__selectedAggregateRunId) || aggregateRunIdFromLocation();
    if (aggregateRunId) {
        params.set('aggregateRunId', aggregateRunId);
    }
    const query = params.toString();
    return getJson(`/contexa/admin/api/prompt-quality/verification/runtime-runs/package/${encodeURIComponent(packageId)}/audit-payloads${query ? `?${query}` : ''}`);
}

function officialLedgerHasRuns(detail) {
    return Number(detail?.totalRunCount || detail?.actualMetricCount || 0) > 0
            || ensureArray(detail?.runs).length > 0
            || ensureArray(detail?.metrics).length > 0;
}

function runFromOfficialLedger(pageRoot, detail, fallbackRun = {}) {
    const summary = detail?.sealedEvidence?.summary || {};
    const runs = ensureArray(detail?.runs).length
            ? ensureArray(detail.runs)
            : ensureArray(detail?.metrics);
    const actualPromptProblems = ensureArray(detail?.actualPromptProblems).length
            ? ensureArray(detail.actualPromptProblems)
            : ensureArray(fallbackRun.actualPromptProblems);
    const promptProblemFindings = actualPromptProblemFindingTexts(actualPromptProblems);
    const promptProblemNextActions = actualPromptProblemActionTexts(actualPromptProblems);
    const firstRun = runs[0] || {};
    const totalCount = Number(detail?.totalRunCount ?? runs.length ?? fallbackRun.totalMetricCount ?? 0);
    const rawPassedCount = Number(detail?.passedRunCount ?? runs.filter(run => passState(run.state)).length ?? fallbackRun.passedMetricCount ?? 0);
    const promptTotals = metricCheckTotals(runs, detail);
    const failedCount = Number(promptTotals.blockedMetrics || 0);
    const gateCount = Number(promptTotals.gateMetrics || 0);
    const gateConditionCount = Number(promptTotals.gateConditions || 0);
    const passedCount = totalCount > 0
            ? (rawPassedCount || Math.max(totalCount - failedCount - gateCount, 0))
            : rawPassedCount;
    const finalDecision = firstCleanText(detail?.officialFinalDecision, detail?.finalDecision, fallbackRun.officialFinalDecision, fallbackRun.finalDecision);
    const officialPassed = officialVerificationPassedForDisplay(detail, {
        totalMetricCount: totalCount,
        passedMetricCount: passedCount,
        failedMetricCount: failedCount,
        actualProblems: promptTotals.actualProblems,
        blockedMetrics: promptTotals.blockedMetrics
    });
    const officialStateLabel = firstCleanText(
            detail?.officialStateLabel,
            officialDecisionLabel(finalDecision),
            officialPassed ? '공식검사 통과' : '');
    const serverNextActions = ensureArray(detail?.nextActions).map(rawText).filter(Boolean);
    const certificateSummary = firstCleanText(
            officialPassed ? '12개 공식검사 기준을 충족했습니다.' : '',
            detail?.certificateSummary,
            fallbackRun.certificateSummary,
            fallbackRun.plainSummary,
            ...serverNextActions,
            ...promptProblemNextActions,
            ...promptProblemFindings);
    return withRouteIdentity(pageRoot, {
        ...fallbackRun,
        runId: rawText(detail?.aggregateRunId) || rawText(fallbackRun.runId),
        aggregateRunId: rawText(detail?.aggregateRunId) || rawText(fallbackRun.aggregateRunId) || rawText(fallbackRun.runId),
        packageId: rawText(detail?.packageId) || rawText(summary.packageId) || rawText(fallbackRun.packageId),
        caseId: rawText(detail?.caseId) || rawText(fallbackRun.caseId),
        certificateId: rawText(detail?.certificateId) || rawText(fallbackRun.certificateId),
        certificateState: rawText(detail?.certificateState) || rawText(fallbackRun.certificateState),
        certificateStateLabel: rawText(detail?.certificateStateLabel) || rawText(fallbackRun.certificateStateLabel),
        certificateIssued: Boolean(detail?.certificateIssued || fallbackRun.certificateIssued),
        finalDecision,
        officialFinalDecision: finalDecision,
        officialStateLabel,
        officialVerificationPassed: officialPassed,
        state: finalDecision || rawText(fallbackRun.state),
        stateLabel: officialStateLabel || rawText(fallbackRun.stateLabel),
        sealed: detail?.sealed ?? summary.sealed ?? fallbackRun.sealed,
        integrityValid: detail?.integrityValid ?? summary.integrityValid ?? fallbackRun.integrityValid,
        certificateSummary,
        plainSummary: certificateSummary,
        totalMetricCount: totalCount,
        passedMetricCount: passedCount,
        failedMetricCount: failedCount,
        tenantId: rawText(summary.tenantId) || rawText(fallbackRun.tenantId),
        userId: rawText(summary.userId) || rawText(fallbackRun.userId),
        requestId: rawText(firstRun.requestId) || rawText(fallbackRun.requestId) || rawText(summary.correlationId),
        requestPath: rawText(summary.requestPath) || rawText(detail?.actualRequestPath) || rawText(fallbackRun.requestPath),
        resourceUrl: rawText(summary.resourceUrl) || rawText(summary.requestPath) || rawText(detail?.actualRequestPath) || rawText(detail?.resourceUrlTemplate) || rawText(fallbackRun.resourceUrl),
        resourceId: rawText(summary.resourceId) || rawText(detail?.actualResourceId) || rawText(detail?.resourceTemplateId) || rawText(fallbackRun.resourceId),
        httpMethod: rawText(summary.httpMethod) || rawText(detail?.httpMethod) || rawText(fallbackRun.httpMethod),
        promptHash: rawText(summary.promptHash) || rawText(detail?.promptHash) || rawText(fallbackRun.promptHash),
        contextHash: rawText(detail?.contextHash) || rawText(fallbackRun.contextHash),
        metrics: runs.length ? runs : ensureArray(fallbackRun.metrics),
        issues: ensureArray(fallbackRun.issues),
        blockingFindings: promptProblemFindings,
        nextActions: [...serverNextActions, ...promptProblemNextActions].filter(Boolean),
        failureCauses: ensureArray(detail?.failureCauses).length
                ? ensureArray(detail.failureCauses)
                : ensureArray(fallbackRun.failureCauses),
        remediationGroups: ensureArray(detail?.remediationGroups).length
                ? ensureArray(detail.remediationGroups)
                : ensureArray(fallbackRun.remediationGroups),
        summaryCounts: detail?.summaryCounts || fallbackRun.summaryCounts || null,
        promptComparisons: ensureArray(detail?.promptComparisons).length
                ? ensureArray(detail.promptComparisons)
                : ensureArray(fallbackRun.promptComparisons),
        actualPromptProblems: actualPromptProblems,
        promptConsistency: detail?.sealedEvidence?.promptConsistency || fallbackRun.promptConsistency
    });
}

function actualPromptProblemFindingTexts(problems) {
    return visibleActualPromptProblems(problems)
            .map(problem => {
                const title = firstCleanText(problem?.promptLabel, problem?.fieldKey);
                const reason = firstCleanText(problem?.whyItMatters, problem?.actualState, problem?.problemType);
                return [title, reason].filter(Boolean).join('. ');
            })
            .filter(Boolean);
}

function actualPromptProblemActionTexts(problems) {
    return visibleActualPromptProblems(problems)
            .map(problem => firstCleanText(problem?.fixAction, problem?.reverifyCriterionDetail))
            .filter(Boolean);
}

function renderOfficialLedgerSummary(target, detail) {
    if (!target) {
        return;
    }
    const runs = ensureArray(detail?.runs);
    const metrics = ensureArray(detail?.metrics);
    const totalCount = Number(detail?.totalRunCount ?? detail?.actualMetricCount ?? metrics.length ?? runs.length ?? 0);
    const passedCount = Number(detail?.passedRunCount ?? detail?.passedMetricCount ?? runs.filter(run => passState(run.state)).length ?? metrics.filter(run => passState(run.state)).length ?? 0);
    const failedCount = Number(detail?.failedRunCount ?? detail?.failedMetricCount ?? Math.max(totalCount - passedCount, 0));
    const certificateIssued = Boolean(detail?.certificateIssued);
    const promptTotals = metricCheckTotals(runs, detail);
    const verdict = officialVerdict(detail, totalCount, passedCount, failedCount, promptTotals);
    const failures = sortFailuresProblemFirst(ensureArray(detail?.failureCauses));
    const actionGroups = dedupeRemediationGroups(ensureArray(detail?.remediationGroups))
            .filter(Boolean)
            .sort((left, right) => Number(right.findingCount || 0) - Number(left.findingCount || 0));
    const passedRuns = sortMetricRunsProblemFirst(runs).filter(run => passState(run.state));
    target.innerHTML = `
        <section class="pqa-official-result-dashboard">
            <article class="pqa-official-verdict-card ${escapeHtml(verdict.tone)}">
                <div>
                    <span class="pqa-official-kicker">최종 판정</span>
                    <strong>${escapeHtml(verdict.title)}</strong>
                    <p>${escapeHtml(verdict.detail)}</p>
                </div>
                ${badge(verdict.badge, { tone: verdict.tone })}
            </article>
            <div class="pqa-official-decision-grid">
                ${comparisonKpi('프롬프트 문제', promptTotals.actualProblems, promptTotals.actualProblems ? 'blocked' : 'ready')}
                ${comparisonKpi('영향 지표', promptTotals.blockedMetrics, promptTotals.blockedMetrics ? 'blocked' : 'ready')}
                ${comparisonKpi('추가 확인', promptTotals.gateConditions ? `${promptTotals.gateConditions}개` : '없음', promptTotals.gateConditions ? 'warning' : 'ready')}
                ${comparisonKpi('판정 기준', criteriaProgressText(promptTotals), promptTotals.gateMetrics ? 'warning' : 'ready')}
            </div>
            ${renderOfficialNextStepOverview(detail, runs, promptTotals, failures, actionGroups, passedRuns)}
            <details class="pqa-official-summary-evidence">
                <summary>검사 ID</summary>
                <dl class="pqa-registration-meta">
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.dt.requestEvidenceId'))}</dt><dd><code>${escapeHtml(detail.packageId)}</code></dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.ledger.aggregateRun'))}</dt><dd><code>${escapeHtml(text(detail.aggregateRunId))}</code></dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.ledger.integrity'))}</dt><dd>${badge(detail.integrityValid ? t('enterprise.pqa.runtimeEvidence.badge.integrityOk') : t('enterprise.pqa.runtimeEvidence.badge.integrityError'), { tone: detail.integrityValid ? 'ready' : 'blocked' })}</dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.ledger.runCount'))}</dt><dd>${escapeHtml(passedCount)} / ${escapeHtml(totalCount)}</dd></div>
                </dl>
                ${renderLedgerConsistency(detail.ledgerConsistency)}
            </details>
        </section>
    `;
}

function officialVerdict(detail, totalCount, passedCount, failedCount, promptTotals = {}) {
    const gateMetrics = Number(promptTotals.gateMetrics || 0);
    const inputReviewMetrics = Number(promptTotals.inputReviewMetrics || 0);
    const officialPassed = officialVerificationPassedForDisplay(detail, {
        totalMetricCount: totalCount,
        passedMetricCount: passedCount,
        failedMetricCount: failedCount,
        actualProblems: promptTotals.actualProblems,
        blockedMetrics: promptTotals.blockedMetrics
    });
    const title = firstCleanText(
            detail?.officialStateLabel,
            officialDecisionLabel(detail?.officialFinalDecision || detail?.finalDecision),
            detail?.stateLabel,
            detail?.certificateStateLabel,
            detail?.certificateState,
            detail?.certificateSummary,
            detail?.finalDecision,
            ...ensureArray(detail?.nextActions));
    const detailText = firstCleanText(
            detail?.certificateSummary,
            ...ensureArray(detail?.nextActions),
            ...ensureArray(detail?.blockingFindings));
    if (officialPassed || detail?.certificateIssued || (totalCount > 0 && passedCount === totalCount && !gateMetrics && !inputReviewMetrics && !failedCount)) {
        return {
            tone: 'ready',
            badge: title || '-',
            title: title || '-',
            detail: detailText
        };
    }
    if (inputReviewMetrics > 0 || gateMetrics > 0 || failedCount > 0) {
        return {
            tone: failedCount > 0 ? 'blocked' : 'warning',
            badge: title || '-',
            title: title || '-',
            detail: detailText
        };
    }
    return {
        tone: 'warning',
        badge: title || '-',
        title: title || '-',
        detail: detailText
    };
}

function renderOfficialNextStepOverview(detail, runs, totals, failures, groups, passedRuns) {
    const nextActionText = firstCleanText(...ensureArray(detail?.nextActions));
    if (!nextActionText && !Number(totals?.actualProblems || 0)) {
        return renderSuccessfulMetricSummary(passedRuns);
    }
    const actualProblems = actualPromptProblemsForTotals(runs, detail);
    const firstProblem = actualProblems[0] || {};
    const detailText = nextActionText
            || firstCleanText(firstProblem?.fixAction, firstProblem?.reverifyCriterionDetail, firstProblem?.whyItMatters);
    if (!detailText) {
        return '';
    }
    const href = rawText(detail?.nextActionHref);
    const actionLink = href
            ? `<a class="pqa-resolution-action primary" href="${escapeHtml(href)}">${escapeHtml(detailText)}</a>`
            : '';
    return `
        <section class="pqa-official-summary-section pqa-official-next-work">
            <div class="pqa-official-ops-head">
                <strong>다음에 할 일</strong>
                <span>${escapeHtml(detailText)}</span>
            </div>
            <div class="pqa-official-next-work-grid">
                <article>
                    <span class="pqa-official-kicker">DB 처리 경로</span>
                    <strong>${escapeHtml(detailText)}</strong>
                    ${actionLink}
                </article>
            </div>
        </section>
    `;
}

function renderNextWorkOverview(failures, groups, passedRuns) {
    const firstGroup = groups[0];
    const owner = rawText(firstGroup?.remediationOwner) || rawText(failures[0]?.remediationOwner) || '해결 담당 확인 필요';
    const title = rawText(firstGroup?.operatorTitle) || rawText(failures[0]?.checkLabel) || '보강 작업 필요';
    const issueCount = failures.length;
    const groupCount = groups.length;
    if (!failures.length && !groups.length) {
        return renderSuccessfulMetricSummary(passedRuns);
    }
    return `
        <section class="pqa-official-summary-section pqa-official-next-work">
            <div class="pqa-official-ops-head">
                <strong>다음에 할 일</strong>
                <span>공식 품질 검사는 여기서 확정하고, 보강 작업은 후속 공정에서 처리합니다.</span>
            </div>
            <div class="pqa-official-next-work-grid">
                <article>
                    <span class="pqa-official-kicker">우선 대상</span>
                    <strong>${escapeHtml(owner)}</strong>
                    <p>${escapeHtml(`${issueCount}개 문제 항목이 ${groupCount || 1}개 해결 담당 묶음으로 정리되었습니다.`)}</p>
                </article>
                <article>
                    <span class="pqa-official-kicker">후속 조치에서 확인</span>
                    <strong>${escapeHtml(title)}</strong>
                    <p>해결 담당, 필요한 보강값, 재검증 기준을 후속 공정에서 항목별로 확인하십시오.</p>
                </article>
                <article>
                    <span class="pqa-official-kicker">현재 화면 역할</span>
                    <strong>검사 결과 확정</strong>
                    <p>이 화면은 실행 결과와 차단 여부만 확정합니다. 실제 보강과 재검증은 다음 공정에서 진행합니다.</p>
                </article>
            </div>
        </section>
    `;
}

function renderTopBlockingCauses(failures) {
    if (!failures.length) {
        return `
            <section class="pqa-official-summary-section">
                <div class="pqa-official-ops-head">
                    <strong>차단 원인 TOP</strong>
                    <span>현재 공식검사에서 고객 조치가 필요한 차단 원인은 없습니다.</span>
                </div>
                <p class="pqa-prompt-consistency-ok">차단 원인 없음</p>
            </section>
        `;
    }
    return `
        <section class="pqa-official-summary-section">
            <div class="pqa-official-ops-head">
                <strong>차단 원인 TOP ${Math.min(3, failures.length)}</strong>
                <span>먼저 후속 조치가 필요한 항목, 원인, 담당 공정입니다.</span>
            </div>
            <div class="pqa-official-top-failures">
                ${failures.slice(0, 3).map(renderTopBlockingCause).join('')}
            </div>
        </section>
    `;
}

function renderTopBlockingCause(item) {
    const problem = rawText(item.problemStatement) || rawText(item.checkLabel) || '공식검사 차단 원인';
    const cause = rawText(item.rootCause) || '저장된 진단 원인을 확인해야 합니다.';
    const target = rawText(item.affectedTarget) || rawText(item.remediationOwner) || rawText(item.metricName) || '해결 담당 확인 필요';
    const impact = rawText(item.impact) || '이 문제가 해결되지 않으면 LLM 입력 품질을 신뢰하기 어렵습니다.';
    return `
        <article class="pqa-official-top-failure">
            <header>
                <strong>${escapeHtml(problem)}</strong>
                ${badge(rawText(item.metricName) || rawText(item.metricCode) || '공식 지표', { tone: 'blocked' })}
            </header>
            <dl>
                <div><dt>문제</dt><dd>${escapeHtml(problem)}</dd></div>
                <div><dt>원인</dt><dd>${escapeHtml(cause)}</dd></div>
                <div><dt>담당 공정</dt><dd>${escapeHtml(target)}</dd></div>
                <div><dt>영향</dt><dd>${escapeHtml(impact)}</dd></div>
                <div><dt>후속 조치</dt><dd>${escapeHtml(operatorFullText(item.remediationHint))}</dd></div>
                <div><dt>재검증</dt><dd>${escapeHtml(operatorFullText(item.reverifyCriterion))}</dd></div>
            </dl>
            <details class="pqa-official-technical-evidence">
                <summary>검사 기준과 실제 결과</summary>
                <dl>
                    <div><dt>기대 결과</dt><dd>${escapeHtml(text(item.expectedValue))}</dd></div>
                    <div><dt>실제 결과</dt><dd>${escapeHtml(text(item.actualValue))}</dd></div>
                    <div><dt>근거 위치</dt><dd><code>${escapeHtml(text(item.source))}</code></dd></div>
                    <div><dt>지표 코드</dt><dd><code>${escapeHtml(text(item.metricCode))}</code></dd></div>
                </dl>
            </details>
        </article>
    `;
}

function renderSummaryActionGroups(groups) {
    if (!groups.length) {
        return '';
    }
    return `
        <section class="pqa-official-summary-section">
            <div class="pqa-official-ops-head">
                <strong>담당별 보강 작업</strong>
                <span>같은 담당에 속한 항목을 함께 확인할 수 있도록 정리했습니다.</span>
            </div>
            <div class="pqa-official-summary-actions">
                ${groups.slice(0, 4).map(group => `
                    <article>
                        <strong>${escapeHtml(rawText(group.operatorTitle) || '보강 작업 필요')}</strong>
                        <p>${escapeHtml(operatorFullText(group.nextAction))}</p>
                        <dl>
                            <div><dt>해결 담당</dt><dd>${escapeHtml(text(group.remediationOwner))}</dd></div>
                            <div><dt>문제 수</dt><dd>${Number(group.findingCount || 0)}건</dd></div>
                            <div><dt>재검증</dt><dd>${escapeHtml(operatorFullText(group.reverifyCriterion))}</dd></div>
                        </dl>
                    </article>
                `).join('')}
            </div>
        </section>
    `;
}

function renderSuccessfulMetricSummary(passedRuns) {
    if (!passedRuns.length) {
        return '';
    }
    return `
        <details class="pqa-official-summary-section pqa-official-success-summary">
            <summary>
                <strong>성공 지표 요약</strong>
                <span>${passedRuns.length}개 지표 통과</span>
            </summary>
            <ul>
                ${passedRuns.map(run => `<li><strong>${escapeHtml(rawText(run.metricName) || officialMetricLabel(run.metricCode))}</strong><span>통과 ${escapeHtml(String(run.passedChecks))} · 전체 ${escapeHtml(String(run.totalChecks))}</span></li>`).join('')}
            </ul>
        </details>
    `;
}

function renderLedgerConsistency(consistency) {
    if (!consistency) {
        return '';
    }
    const warnings = ensureArray(consistency.warnings);
    const sourceNeedsDetail = Number(consistency.missingSourceCheckCount || 0) + Number(consistency.abstractSourceCheckCount || 0);
    return `
        <section class="pqa-ledger-consistency">
            <div class="pqa-ledger-consistency-head">
                <strong>${escapeHtml(t('enterprise.pqa.verification.ledgerConsistency.title'))}</strong>
                ${badge(consistency.readyForIssueResolution ? t('enterprise.pqa.verification.ledgerConsistency.ready') : t('enterprise.pqa.verification.ledgerConsistency.review'), { tone: consistency.readyForIssueResolution ? 'ready' : 'warning' })}
            </div>
            <div class="pqa-official-compare-summary">
                ${comparisonKpi(t('enterprise.pqa.verification.ledgerConsistency.expectedMetricCount'), consistency.expectedMetricCount, consistency.metricCountMatched ? 'ready' : 'blocked')}
                ${comparisonKpi(t('enterprise.pqa.verification.ledgerConsistency.actualRunCount'), consistency.actualRunCount, consistency.metricCountMatched ? 'ready' : 'blocked')}
                ${comparisonKpi(t('enterprise.pqa.verification.ledgerConsistency.declaredCheckCount'), consistency.declaredCheckCount, consistency.checkCountMatched ? 'ready' : 'blocked')}
                ${comparisonKpi(t('enterprise.pqa.verification.ledgerConsistency.totalCheckCount'), consistency.storedCheckRowCount ?? consistency.totalCheckCount, consistency.checkCountMatched ? 'ready' : 'blocked')}
                ${comparisonKpi(t('enterprise.pqa.verification.ledgerConsistency.sourceNeedsDetail'), sourceNeedsDetail, sourceNeedsDetail ? 'warning' : 'ready')}
                ${comparisonKpi(t('enterprise.pqa.verification.ledgerConsistency.factBackedRunCount'), consistency.factBackedRunCount, consistency.factBackedRunCount === consistency.actualRunCount ? 'ready' : 'warning')}
                ${comparisonKpi(t('enterprise.pqa.verification.ledgerConsistency.rawArtifactRunCount'), consistency.rawArtifactRunCount, consistency.rawArtifactRunCount === consistency.actualRunCount ? 'ready' : 'warning')}
            </div>
            ${warnings.length
                ? `<ul class="pqa-ledger-warning-list">${warnings.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`
                : `<p class="pqa-prompt-consistency-ok">${escapeHtml(t('enterprise.pqa.verification.ledgerConsistency.noWarnings'))}</p>`}
        </section>
    `;
}

function renderOfficialAttempts(target, detail, pageRoot) {
    if (!target) {
        return;
    }
    const attempts = ensureArray(detail?.attempts);
    if (!attempts.length) {
        target.innerHTML = '';
        return;
    }
    const identity = identityFromSource(detail?.sealedEvidence?.summary || {}, routeIdentityFromLocation());
    const rows = attempts.map(attempt => {
        const params = new URLSearchParams();
        setParam(params, 'packageId', attempt.packageId || detail.packageId);
        setParam(params, 'aggregateRunId', attempt.aggregateRunId);
        setParam(params, 'resourceUrl', identity.resourceUrl);
        setParam(params, 'resourceId', identity.resourceId);
        setParam(params, 'httpMethod', identity.httpMethod);
        const href = appPath(`/contexa/admin/prompt-quality/verification/run?${params.toString()}`);
        return `
            <tr class="${attempt.latest ? 'is-selected' : ''}">
                <td>${escapeHtml(attempt.attemptNo)}</td>
                <td><code>${escapeHtml(text(attempt.aggregateRunId))}</code></td>
                <td>${badge(text(attempt.stateLabel), { tone: passState(attempt.state) ? 'ready' : 'blocked' })}</td>
                <td>${escapeHtml(attempt.passedRunCount)} / ${escapeHtml(attempt.totalRunCount)}</td>
                <td>${escapeHtml(text(attempt.startedAt))}</td>
                <td>${escapeHtml(text(attempt.completedAt))}</td>
                <td>${attempt.latest
                        ? badge(t('enterprise.pqa.verification.attempt.latest'), { tone: 'ready' })
                        : `<a class="pqa-link-button compact" href="${escapeHtml(href)}" data-pqa-action-message="${escapeHtml(t('enterprise.pqa.verification.attempt.open'))}">${escapeHtml(t('enterprise.pqa.verification.attempt.open'))}</a>`}
                </td>
            </tr>
        `;
    });
    target.innerHTML = `
        <details class="pqa-official-ops-panel pqa-official-support-details">
            <summary>
                <strong>${escapeHtml(t('enterprise.pqa.verification.attempt.title'))}</strong>
                <span>${escapeHtml(t('enterprise.pqa.verification.attempt.description'))}</span>
            </summary>
            <div class="pqa-table-wrap">
                <table class="pqa-table pqa-official-attempt-table">
                    <thead>
                        <tr>
                            <th>${escapeHtml(t('enterprise.pqa.verification.attempt.no'))}</th>
                            <th>${escapeHtml(t('enterprise.pqa.verification.ledger.aggregateRun'))}</th>
                            <th>${escapeHtml(t('enterprise.pqa.verification.col.state'))}</th>
                            <th>${escapeHtml(t('enterprise.pqa.verification.col.checks'))}</th>
                            <th>${escapeHtml(t('enterprise.pqa.verification.attempt.startedAt'))}</th>
                            <th>${escapeHtml(t('enterprise.pqa.verification.attempt.completedAt'))}</th>
                            <th>${escapeHtml(t('enterprise.pqa.verification.col.detail'))}</th>
                        </tr>
                    </thead>
                    <tbody>${rows.join('')}</tbody>
                </table>
            </div>
        </details>
    `;
    target.querySelectorAll('a[data-pqa-action-message]').forEach(link => {
        link.addEventListener('click', () => {
            pageRoot.__selectedAggregateRunId = rawText(new URL(link.href, window.location.origin).searchParams.get('aggregateRunId'));
        });
    });
}

function renderOfficialProcess(target, detail) {
    if (!target) {
        return;
    }
    const steps = ensureArray(detail?.processSteps);
    const history = ensureArray(detail?.processHistory);
    if (!steps.length && !history.length) {
        target.innerHTML = '';
        return;
    }
    target.innerHTML = `
        <details class="pqa-official-ops-panel pqa-official-support-details">
            <summary>
                <strong>${escapeHtml(t('enterprise.pqa.verification.process.title'))}</strong>
                <span>${escapeHtml(processCompactLabel(steps))}</span>
            </summary>
            ${steps.length ? renderProcessStepStrip(steps, detail) : ''}
            ${history.length ? renderProcessHistory(history) : ''}
        </details>
    `;
}

function renderProcessStepStrip(steps, detail) {
    return `
        <div class="pqa-process-step-strip">
            ${steps.map(step => {
                return `
                <article class="${escapeHtml(processStepClass(step))}">
                    <strong>${escapeHtml(processStepLabel(step.stepCode))}</strong>
                    ${badge(processExecutionLabel(step.executionState), { tone: processTone(step.executionState) })}
                    <span>${escapeHtml(text(step.summary) || text(step.nextAction) || text(step.evidenceRef))}</span>
                </article>
            `;
            }).join('')}
        </div>
    `;
}

function processCompactLabel(steps) {
    const total = ensureArray(steps).length;
    const completed = ensureArray(steps).filter(step => upperText(step.executionState) === 'COMPLETED').length;
    const failed = ensureArray(steps).filter(step => ['FAILED', 'CANCELLED'].includes(upperText(step.executionState))).length;
    if (!total) {
        return t('enterprise.pqa.verification.process.description');
    }
    if (failed > 0) {
        return `${failed}개 단계 확인 필요 / 총 ${total}개`;
    }
    return `${completed} / ${total}개 단계 완료`;
}

function scopedStageUrl(path, source = {}, required = []) {
    const params = new URLSearchParams();
    const identity = identityFromSource(source, routeIdentityFromLocation());
    const values = {
        packageId: rawText(source.packageId),
        aggregateRunId: rawText(source.aggregateRunId) || rawText(source.runId),
        officialRunId: rawText(source.officialRunId),
        reverifyRunId: rawText(source.reverifyRunId),
        certificateId: rawText(source.certificateId),
        caseId: rawText(source.caseId),
        resourceUrl: identity.resourceUrl,
        resourceId: identity.resourceId,
        resourceTemplateId: identity.resourceTemplateId,
        actualResourceId: identity.actualResourceId,
        httpMethod: identity.httpMethod
    };
    if (required.some(name => !rawText(values[name]))) {
        return '';
    }
    setParam(params, 'packageId', values.packageId);
    setParam(params, 'aggregateRunId', values.aggregateRunId);
    setParam(params, 'officialRunId', values.officialRunId);
    setParam(params, 'reverifyRunId', values.reverifyRunId);
    setParam(params, 'certificateId', values.certificateId);
    setParam(params, 'caseId', values.caseId);
    setParam(params, 'resourceUrl', values.resourceUrl);
    setParam(params, 'resourceId', values.resourceId);
    setParam(params, 'resourceTemplateId', values.resourceTemplateId);
    setParam(params, 'actualResourceId', values.actualResourceId);
    setParam(params, 'httpMethod', values.httpMethod);
    const query = params.toString();
    return appPath(`${path}${query ? `?${query}` : ''}`);
}

function renderProcessHistory(history) {
    const visible = history.slice(-8).reverse();
    return `
        <details class="pqa-official-process-history">
            <summary>${escapeHtml(t('enterprise.pqa.verification.process.history'))}</summary>
            <ol>
                ${visible.map(item => `
                    <li>
                        <strong>${escapeHtml(processStepLabel(item.stepCode || item.processCode))}</strong>
                        <span>${escapeHtml(text(item.fromState) || '-')} -> ${escapeHtml(text(item.toState))}</span>
                        <small>${escapeHtml(text(item.reason))}</small>
                        <time>${escapeHtml(text(item.changedAt))}</time>
                    </li>
                `).join('')}
            </ol>
        </details>
    `;
}

function renderOfficialAudit(target, detail) {
    if (!target) {
        return;
    }
    const snapshots = ensureArray(detail?.auditSnapshots);
    const events = ensureArray(detail?.processEvents).filter(event => rawText(event.type));
    if (!snapshots.length && !events.length) {
        const packageId = rawText(detail?.packageId) || packageIdFromLocation();
        target.innerHTML = `
            <section class="pqa-official-ops-panel">
                <div class="pqa-official-ops-head">
                    <strong>${escapeHtml(t('enterprise.pqa.verification.audit.title'))}</strong>
                    <span>${escapeHtml(t('enterprise.pqa.verification.audit.lazy'))}</span>
                </div>
                <button type="button" class="pqa-action-button" data-pqa-load-audit-payloads>
                    ${escapeHtml(t('enterprise.pqa.verification.audit.load'))}
                </button>
                <div data-pqa-audit-payload-body></div>
            </section>
        `;
        target.querySelector('[data-pqa-load-audit-payloads]')?.addEventListener('click', async event => {
            const button = event.currentTarget;
            const body = target.querySelector('[data-pqa-audit-payload-body]');
            button.setAttribute('aria-disabled', 'true');
            if (body) {
                body.innerHTML = `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.ledger.loading'))}</p></div>`;
            }
            try {
                const payloads = await loadOfficialAuditPayloads(packageId);
                if (body) {
                    body.innerHTML = ensureArray(payloads).length
                            ? ensureArray(payloads).map(renderAuditSnapshot).join('')
                            : `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.audit.empty'))}</p></div>`;
                }
                button.hidden = true;
            }
            catch (error) {
                if (body) {
                    body.innerHTML = `<div class="pqa-empty pqa-empty-error"><p>${escapeHtml(publicError(error))}</p></div>`;
                }
                button.setAttribute('aria-disabled', 'false');
            }
        });
        return;
    }
    target.innerHTML = `
        <section class="pqa-official-ops-panel">
            <div class="pqa-official-ops-head">
                <strong>${escapeHtml(t('enterprise.pqa.verification.audit.title'))}</strong>
                <span>${escapeHtml(t('enterprise.pqa.verification.audit.description'))}</span>
            </div>
            ${snapshots.map(renderAuditSnapshot).join('')}
            ${renderAuditEvents(events)}
        </section>
    `;
}

function renderAuditSnapshot(snapshot) {
    return `
        <article class="pqa-official-audit-snapshot">
            <div>
                <strong><code>${escapeHtml(text(snapshot.snapshotId))}</code></strong>
                ${badge(snapshot.persisted ? t('enterprise.pqa.verification.audit.persisted') : t('enterprise.pqa.verification.audit.derived'), { tone: snapshot.persisted ? 'ready' : 'warning' })}
            </div>
            <dl class="pqa-registration-meta">
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.dt.requestEvidenceId'))}</dt><dd><code>${escapeHtml(text(snapshot.packageId))}</code></dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.ledger.aggregateRun'))}</dt><dd><code>${escapeHtml(text(snapshot.aggregateRunId))}</code></dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.col.state'))}</dt><dd>${escapeHtml(text(snapshot.stateLabel))}</dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.audit.failedMetricCount'))}</dt><dd>${escapeHtml(snapshot.failedMetricCount)} / ${escapeHtml(snapshot.totalMetricCount)}</dd></div>
                <div><dt>${escapeHtml(t('enterprise.pqa.verification.dt.promptHash'))}</dt><dd><code>${escapeHtml(text(snapshot.promptHash))}</code></dd></div>
            </dl>
            <details class="pqa-official-run-fact">
                <summary>${escapeHtml(t('enterprise.pqa.verification.audit.payload'))}</summary>
                <pre>${escapeHtml(text(snapshot.payloadJson) || '{}')}</pre>
            </details>
        </article>
    `;
}

function renderAuditEvents(events) {
    if (!events.length) {
        return '';
    }
    return `
        <details class="pqa-official-process-history">
            <summary>${escapeHtml(t('enterprise.pqa.verification.audit.events'))}</summary>
            <ol>
                ${events.slice(-10).reverse().map(event => `
                    <li>
                        <strong>${escapeHtml(text(event.type))}</strong>
                        <span>${escapeHtml(processStepLabel(event.stepCode))}</span>
                        <time>${escapeHtml(text(event.occurredAt))}</time>
                        <small>${escapeHtml(text(event.payloadJson))}</small>
                    </li>
                `).join('')}
            </ol>
        </details>
    `;
}

function processStepClass(step) {
    return `pqa-process-step-card ${processTone(step?.executionState)}`;
}

function processTone(state) {
    const normalized = upperText(state);
    if (normalized === 'COMPLETED') {
        return 'ready';
    }
    if (normalized === 'FAILED' || normalized === 'CANCELLED') {
        return 'blocked';
    }
    if (normalized === 'RUNNING') {
        return 'warning';
    }
    return 'neutral';
}

function processExecutionLabel(state) {
    const normalized = upperText(state);
    const key = `enterprise.pqa.verification.process.state.${normalized.toLowerCase()}`;
    return has(key) ? t(key) : text(state);
}

function processStepLabel(stepCode) {
    const normalized = rawText(stepCode);
    const key = `enterprise.pqa.verification.process.step.${normalized.toLowerCase()}`;
    return has(key) ? t(key) : normalized || t('enterprise.pqa.verification.value.none');
}

function renderOfficialPromptComparison(target, detail) {
    if (!target) {
        return;
    }
    const actualProblems = visibleActualPromptProblems(detail?.actualPromptProblems);
    const items = visiblePromptComparisonItems(detail.promptComparisons);
    if (!items.length && !actualProblems.length) {
        const packageId = rawText(detail?.packageId) || packageIdFromLocation();
        target.innerHTML = `
            <div class="pqa-empty">
                <p>${escapeHtml(detail?.promptComparisonError || t('enterprise.pqa.verification.ledger.prompt.empty'))}</p>
                ${packageId ? `<button type="button" class="pqa-action-button" data-pqa-load-prompt-comparison>${escapeHtml(t('enterprise.pqa.verification.comparison.load'))}</button>` : ''}
            </div>`;
        target.querySelector('[data-pqa-load-prompt-comparison]')?.addEventListener('click', async event => {
            const button = event.currentTarget;
            button.setAttribute('aria-disabled', 'true');
            try {
                const [comparisons, problems] = await Promise.all([
                    loadOfficialPromptComparison(packageId),
                    loadOfficialActualPromptProblems(packageId)
                ]);
                renderOfficialPromptComparison(target, {
                    ...detail,
                    promptComparisons: ensureArray(comparisons),
                    actualPromptProblems: ensureArray(problems),
                    promptComparisonError: ''
                });
            }
            catch (error) {
                target.innerHTML = `<div class="pqa-empty pqa-empty-error"><p>${escapeHtml(publicError(error))}</p></div>`;
            }
        });
        return;
    }
    const showAll = target.dataset.pqaCompareShowAll === 'true';
    const sorted = sortComparisons(items);
    const comparisonProblems = sorted.filter(isProblemComparison);
    const problems = actualProblems.length ? actualProblems : comparisonProblems;
    const ledgerItems = sorted;
    const showDiagnosticLedger = !actualProblems.length && ledgerItems.length;
    const promptSourceAvailable = hasPromptSource(detail);
    if (!promptSourceAvailable) {
        target.innerHTML = `
            ${renderComparisonSummary(items, { ...detail, actualPromptProblems: actualProblems })}
            <section class="pqa-official-compare-source-missing">
                <strong>프롬프트 원문 확인이 먼저 필요합니다.</strong>
                <p>봉인 증거에는 비교할 값이 있지만 최종 시스템/사용자 프롬프트 원문이 상세 응답에 없습니다. 이 상태에서는 각 값을 “프롬프트 누락”으로 확정하지 않고, 프롬프트 캡처 또는 상세 조회 경로를 먼저 확인해야 합니다.</p>
            </section>
            ${actualProblems.length ? renderActualPromptProblemPriorityList(actualProblems, detail) : ''}
            ${renderPromptSourceViewer(detail, ledgerItems.length ? ledgerItems : items)}
        `;
        renderPromptSourceBody(target, detail, defaultPromptSearchQuery(items));
        return;
    }
    target.innerHTML = `
        ${renderComparisonSummary(items, { ...detail, actualPromptProblems: actualProblems })}
        ${showDiagnosticLedger ? `
        <div class="pqa-official-compare-toolbar">
            <strong>진단 원장</strong>
            <span>문제 카드가 없을 때만 확인합니다.</span>
                <button type="button" class="pqa-action-button" data-pqa-comparison-toggle>
                    ${escapeHtml(showAll ? '진단 접기' : '진단 원장 보기')}
                </button>
        </div>` : ''}
        ${problems.length
            ? (actualProblems.length ? renderActualPromptProblemPriorityList(actualProblems, detail) : renderComparisonPriorityList(problems))
            : `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.comparison.noProblems'))}</p></div>`}
        ${actualProblems.length ? '' : renderPromptLocationMap(problems)}
        ${showDiagnosticLedger ? renderComparisonMatrixDetails(ledgerItems, showAll) : ''}
        ${renderPromptSourceViewer(detail, ledgerItems.length ? ledgerItems : items)}
    `;
    target.querySelector('[data-pqa-comparison-toggle]')?.addEventListener('click', () => {
        target.dataset.pqaCompareShowAll = showAll ? 'false' : 'true';
        renderOfficialPromptComparison(target, detail);
    });
    target.querySelector('[data-pqa-prompt-search]')?.addEventListener('input', event => {
        renderPromptSourceBody(target, detail, event.target.value);
    });
    target.querySelectorAll('[data-pqa-comparison-search]').forEach(button => {
        button.addEventListener('click', () => {
            const query = rawText(button.dataset.pqaComparisonSearch) || '';
            const input = target.querySelector('[data-pqa-prompt-search]');
            if (input) {
                input.value = query;
            }
            const source = target.querySelector('.pqa-official-prompt-source');
            if (source) {
                source.open = true;
            }
            renderPromptSourceBody(target, detail, query);
        });
    });
    renderPromptSourceBody(target, detail, defaultPromptSearchQuery(items));
}

function renderComparisonPriorityList(items) {
    return `
        <section class="pqa-official-compare-priority" aria-label="${escapeHtml(t('enterprise.pqa.verification.comparison.priority.aria'))}">
            <div class="pqa-official-compare-priority-head">
                <strong>${escapeHtml(t('enterprise.pqa.verification.comparison.priority.title'))}</strong>
                <span>${escapeHtml(t('enterprise.pqa.verification.comparison.priority.description'))}</span>
            </div>
            <ul class="pqa-official-compare-list">
                ${items.map(renderComparisonItem).join('')}
            </ul>
        </section>
    `;
}

function renderActualPromptProblemPriorityList(items, detail = {}) {
    return `
        <section class="pqa-official-compare-priority" aria-label="actual prompt problem ledger">
            <div class="pqa-official-compare-priority-head">
                <strong>실제 프롬프트 문제</strong>
                <span>DB에 저장된 문제, 구체 근거, 해결 기준만 표시합니다.</span>
            </div>
            <ul class="pqa-assurance-problem-list">
                ${items.map(item => renderActualPromptProblemItem(item, detail)).join('')}
            </ul>
        </section>
    `;
}

function renderActualPromptProblemItem(item, detail = {}) {
    const token = rawText(item?.promptLabel) || rawText(item?.fieldKey) || rawText(item?.sourceFieldPath);
    return renderAssuranceProblemCard(item, {
        tag: 'li',
        extraClass: actualProblemStateClass(item),
        searchToken: token,
        showSourceButton: true
    });
}

function actualPromptProblemView(item) {
    return {
        title: contractProblemText(item, 'promptLabel'),
        metricLine: actualProblemMetricLabels(item) ? `영향 지표 ${actualProblemMetricLabels(item)}` : '영향 지표 없음',
        problem: contractProblemText(item, 'promptValue'),
        impact: contractProblemText(item, 'whyItMatters'),
        fix: contractProblemText(item, 'fixAction'),
        reverify: contractProblemText(item, 'reverifyCriterionDetail'),
        owner: contractProblemText(item, 'remediationOwner'),
        location: firstCleanText(item?.sourceFieldPath, item?.sealedEvidencePath)
    };
}

function renderAssuranceProblemCard(item, options = {}) {
    const tag = options.tag === 'li' ? 'li' : 'article';
    const view = actualPromptProblemView(item);
    const searchToken = rawText(options.searchToken);
    const sourceButton = options.showSourceButton && searchToken
            ? `<button type="button"
                       class="pqa-source-button"
                       data-pqa-comparison-search="${escapeHtml(searchToken)}">
                    <span>원문 찾기</span>
               </button>`
            : '';
    const metricLine = actualProblemMetricLabels(item) || '';
    const metricChip = metricLine
            ? `<span class="pqa-assurance-metric-chip">${escapeHtml(metricLine)}</span>`
            : '';
    const stateBadge = options.showStateBadge === false
            ? ''
            : badge(actualProblemDisplayStateLabel(item), { tone: actualProblemTone(item) });
    const evidenceList = actualProblemEvidenceFacts(item);
    return `
        <${tag} class="pqa-assurance-issue-card ${escapeHtml(options.extraClass || '')}">
            <div class="pqa-assurance-issue-head">
                <div class="pqa-assurance-issue-tags">
                    ${metricChip}
                    ${stateBadge}
                </div>
                ${sourceButton}
            </div>
            <div class="pqa-assurance-issue-main">
                <div class="pqa-assurance-issue-title">
                    <strong>${escapeHtml(view.title)}</strong>
                    ${view.problem ? `<p>${escapeHtml(view.problem)}</p>` : ''}
                </div>
                <div class="pqa-assurance-resolution-grid">
                    ${renderAssuranceEvidenceBlock('구체 근거', evidenceList)}
                    ${renderAssuranceContextBlock('확인한 프롬프트 항목', actualProblemContextItems(item))}
                    ${renderAssuranceFocusBlock('왜 중요한가', view.impact)}
                    ${renderAssuranceFocusBlock('해결 방안', view.fix)}
                    ${renderAssuranceFocusBlock('완료 기준', view.reverify)}
                </div>
            </div>
        </${tag}>
    `;
}

function renderAssuranceFocusBlock(title, value) {
    if (!rawText(value)) {
        return '';
    }
    return `
        <section class="pqa-assurance-focus-block">
            <span>${escapeHtml(title)}</span>
            <p>${escapeHtml(value)}</p>
        </section>
    `;
}

function renderAssuranceEvidenceBlock(title, values = []) {
    const facts = ensureArray(values).map(rawText).filter(Boolean);
    if (!facts.length) {
        return '';
    }
    return `
        <section class="pqa-assurance-focus-block pqa-assurance-evidence-block">
            <span>${escapeHtml(title)}</span>
            <ul>
                ${facts.map(value => `<li>${escapeHtml(value)}</li>`).join('')}
            </ul>
        </section>
    `;
}

function renderAssuranceContextBlock(title, values = []) {
    const items = ensureArray(values).map(rawText).filter(Boolean);
    if (!items.length) {
        return '';
    }
    return `
        <section class="pqa-assurance-focus-block pqa-assurance-context-block">
            <span>${escapeHtml(title)}</span>
            <p>${items.map(escapeHtml).join(', ')}</p>
        </section>
    `;
}

function actualProblemContextItems(item) {
    return customerVisibleItemList(
            item?.contextItems,
            item?.customerVisibleContextItems,
            item?.promptItems,
            item?.customerVisiblePromptItems);
}

function actualProblemEvidenceFacts(item) {
    const runtimeFacts = customerVisibleItemList(
            item?.runtimeFacts,
            item?.customerVisibleRuntimeFacts);
    if (runtimeFacts.length) {
        return runtimeFacts;
    }
    const evidenceText = contractProblemText(item, 'actualState');
    return evidenceText ? [evidenceText] : [];
}

function contractProblemText(item, fieldName) {
    const textValue = rawText(item?.[fieldName]);
    if (!textValue || textValue === 'undefined' || textValue === 'null') {
        return '';
    }
    return textValue.replace(/\s+/g, ' ');
}

function firstCleanText(...values) {
    for (const value of values) {
        const textValue = rawText(value);
        if (!textValue || textValue === 'undefined' || textValue === 'null') {
            continue;
        }
        return textValue.replace(/\s+/g, ' ');
    }
    return '';
}

function renderComparisonItem(item) {
    const metrics = metricLabels(item);
    const linked = comparisonLinkSummary(item);
    const token = comparisonSearchToken(item);
    return `
        <li class="pqa-official-compare-item ${escapeHtml(comparisonStateClass(item))}">
            <div>
                <strong>${escapeHtml(text(item.fieldLabel))}</strong>
                <small>${escapeHtml(metrics)}</small>
                ${linked ? `<small>${escapeHtml(linked)}</small>` : ''}
                <small>${escapeHtml(t('enterprise.pqa.verification.ledger.value.location'))}: ${escapeHtml(text(item.promptLocation))} · ${escapeHtml(t('enterprise.pqa.verification.ledger.value.source'))}: ${escapeHtml(text(item.evidenceSource))}</small>
                <p>${escapeHtml(text(item.meaning))}</p>
            </div>
            <div class="pqa-official-compare-item-actions">
                ${badge(comparisonDisplayStateLabel(item), { tone: comparisonToneForItem(item) })}
                <button type="button"
                        class="pqa-action-button compact"
                        data-pqa-comparison-search="${escapeHtml(token)}">
                    ${escapeHtml(t('enterprise.pqa.verification.comparison.focusSource'))}
                </button>
            </div>
        </li>
    `;
}

function renderComparisonMatrix(items) {
    return `
        <div class="pqa-official-compare-matrix" data-pqa-comparison-matrix>
            <table>
                <thead>
                    <tr>
                        <th>${escapeHtml(t('enterprise.pqa.verification.comparison.matrix.item'))}</th>
                        <th>${escapeHtml(t('enterprise.pqa.verification.ledger.value.sealed'))}</th>
                        <th>${escapeHtml(t('enterprise.pqa.verification.ledger.value.prompt'))}</th>
                        <th>${escapeHtml(t('enterprise.pqa.verification.ledger.value.official'))}</th>
                        <th>${escapeHtml(t('enterprise.pqa.verification.col.state'))}</th>
                    </tr>
                </thead>
                <tbody>
                    ${items.map(renderComparisonMatrixRow).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function renderComparisonMatrixDetails(items, open = false) {
    const list = ensureArray(items);
    if (!list.length) {
        return '';
    }
    return `
        <details class="pqa-official-compare-ledger-details" ${open ? 'open' : ''}>
            <summary>진단 원장 ${escapeHtml(list.length)}개 보기</summary>
            <p>문제 카드가 없을 때만 원장 기준으로 확인합니다. 실제 후속 조치에는 사용하지 않습니다.</p>
            ${renderComparisonMatrix(list)}
        </details>
    `;
}

function renderComparisonMatrixRow(item) {
    return `
        <tr class="${escapeHtml(comparisonStateClass(item))}" data-pqa-comparison-row>
            <td>
                <strong>${escapeHtml(text(item.fieldLabel))}</strong>
                <span class="pqa-official-compare-field-key">${escapeHtml(text(item.fieldKey))}</span>
                <span class="pqa-official-compare-metrics">${escapeHtml(metricLabels(item))}</span>
                <span class="pqa-official-compare-metrics">${escapeHtml(comparisonLinkSummary(item))}</span>
                <span class="pqa-official-compare-metrics">${escapeHtml(t('enterprise.pqa.verification.ledger.value.source'))}: ${escapeHtml(text(item.evidenceSource))}</span>
            </td>
            <td>${comparisonCell(item.sealedEvidenceValue, item, 'sealed')}</td>
            <td>${comparisonCell(item.promptValue, item, 'prompt')}</td>
            <td>${comparisonCell(item.officialFactValue, item, 'official')}</td>
            <td class="pqa-official-compare-state">
                ${badge(comparisonDisplayStateLabel(item), { tone: comparisonToneForItem(item) })}
                <small>${escapeHtml(t('enterprise.pqa.verification.ledger.value.owner'))}: ${escapeHtml(text(item.recommendedOwner))}</small>
            </td>
        </tr>
    `;
}

function comparisonCell(value, item, role) {
    const missing = comparisonRoleMissing(item, role);
    const normalized = text(value);
    return `
        <span class="pqa-official-compare-value ${missing ? 'missing' : ''}">
            ${escapeHtml(normalized)}
        </span>
    `;
}

function comparisonRoleMissing(item, role) {
    const state = rawText(item?.state)?.toUpperCase() || '';
    if (state === 'NOT_APPLICABLE') {
        return true;
    }
    return (role === 'prompt' && state === 'PROMPT_MISSING')
            || (role === 'official' && state === 'FACT_MISSING');
}

function metricLabels(item) {
    return ensureArray(item.metricCodes).map(text).filter(Boolean).join(', ')
            || t('enterprise.pqa.verification.value.none');
}

function comparisonLinkSummary(item) {
    const findings = distinctText(ensureArray(item.findingIds));
    const checks = distinctText(ensureArray(item.checkCodes));
    const groups = distinctText(ensureArray(item.remediationGroupIds));
    const parts = [];
    if (findings.length) {
        parts.push(`공식 문제 ${findings.length}개`);
    }
    if (checks.length) {
        parts.push(`검사 체크 ${checks.length}개`);
    }
    if (groups.length) {
        parts.push(`조치 묶음 ${groups.length}개`);
    }
    return parts.join(' · ');
}

function comparisonSearchToken(item) {
    const state = rawText(item?.state)?.toUpperCase() || '';
    if (state === 'PROMPT_MISSING') {
        return rawText(item?.fieldKey)
                || rawText(item?.sealedEvidenceValue)
                || rawText(item?.fieldLabel)
                || '';
    }
    if (state === 'FACT_MISSING') {
        return rawText(item?.sealedEvidenceValue)
                || rawText(item?.fieldKey)
                || rawText(item?.fieldLabel)
                || '';
    }
    return rawText(item?.promptValue)
            || rawText(item?.sealedEvidenceValue)
            || rawText(item?.fieldKey)
            || rawText(item?.fieldLabel)
            || '';
}

function renderComparisonSummary(items, detail = {}) {
    const promptSourceAvailable = hasPromptSource(detail);
    const counts = comparisonProblemCounts(items, detail);
    return `
        <section class="pqa-official-compare-summary" aria-label="증거와 프롬프트 비교 요약">
            <p class="pqa-official-compare-note">${escapeHtml(promptSourceAvailable
                    ? 'LLM 사용자 프롬프트 기준 문제 원장입니다.'
                    : '최종 프롬프트 원문이 없어 먼저 프롬프트 캡처를 확인해야 합니다.')}</p>
            ${comparisonKpi('프롬프트 문제', counts.total, counts.total ? 'blocked' : 'ready')}
            ${counts.missing ? comparisonKpi(t('enterprise.pqa.verification.comparison.missing'), counts.missing, 'blocked') : ''}
        </section>
    `;
}

function visiblePromptComparisonItems(items) {
    return dedupePromptComparisons(ensureArray(items).filter(item => {
        const fieldKey = lowerText(item?.fieldKey);
        const state = upperText(item?.state);
        return fieldKey !== 'modelprofile' && state !== 'NOT_APPLICABLE';
    }));
}

function visibleActualPromptProblems(items) {
    const merged = new Map();
    ensureArray(items).filter(Boolean).forEach(item => {
        const key = rawText(item?.problemId);
        if (!key || merged.has(key)) {
            return;
        }
        merged.set(key, item);
    });
    return Array.from(merged.values()).filter(item => {
        const severity = upperText(item?.severity);
        const problemType = upperText(item?.problemType);
        if (problemType === 'INPUT_NOT_READY' || problemType === 'NOT_EVALUATED_INPUT_NOT_READY') {
            return false;
        }
        return severity === 'BLOCKING' || severity === 'HIGH' || !severity;
    });
}

function actualPromptProblemCounts(items) {
    const counts = { total: 0, match: 0, missing: 0, mismatch: 0 };
    visibleActualPromptProblems(items).forEach(item => {
        const type = upperText(item?.problemType);
        if (type.includes('MISSING')) {
            counts.missing += 1;
        } else {
            counts.mismatch += 1;
        }
    });
    counts.total = counts.missing + counts.mismatch;
    return counts;
}

function actualProblemsForMetric(items, metricCode) {
    const normalizedMetricCode = upperText(metricCode);
    if (!normalizedMetricCode) {
        return [];
    }
    return visibleActualPromptProblems(items).filter(item => {
        return ensureArray(item?.metricCodes)
                .map(upperText)
                .includes(normalizedMetricCode);
    });
}

function actualPromptProblemsFromRuns(runs) {
    const merged = new Map();
    ensureArray(runs).forEach(run => {
        visibleActualPromptProblems(run?.actualPromptProblems).forEach(problem => {
            const key = rawText(problem?.problemId);
            if (key && !merged.has(key)) {
                merged.set(key, problem);
            }
        });
    });
    return Array.from(merged.values());
}

function actualPromptProblemsForTotals(runs, detail = {}) {
    const fromDetail = visibleActualPromptProblems(detail?.actualPromptProblems);
    if (fromDetail.length) {
        return fromDetail;
    }
    return actualPromptProblemsFromRuns(runs);
}

function actualProblemMetricLabels(item) {
    return ensureArray(item?.metricCodes).map(text).filter(Boolean).join(', ')
            || text(item?.metricCode)
            || t('enterprise.pqa.verification.value.none');
}

function actualProblemStateClass(item) {
    return actualProblemTone(item);
}

function actualProblemTone(item) {
    const severity = upperText(item?.severity);
    return severity === 'BLOCKING' || severity === 'HIGH' ? 'blocked' : 'warning';
}

function actualProblemDisplayStateLabel(item) {
    const type = upperText(item?.problemType);
    if (type.includes('MISSING')) {
        return '누락';
    }
    if (type.includes('MISMATCH')) {
        return '불일치';
    }
    return '개선 필요';
}

function dedupePromptComparisons(items) {
    const merged = new Map();
    ensureArray(items).filter(Boolean).forEach(item => {
        const key = comparisonLedgerKey(item);
        if (!merged.has(key)) {
            merged.set(key, { ...item });
            return;
        }
        const current = merged.get(key);
        current.metricCodes = distinctText([...(current.metricCodes || []), ...(item.metricCodes || [])]);
        current.checkCodes = distinctText([...(current.checkCodes || []), ...(item.checkCodes || [])]);
        current.findingIds = distinctText([...(current.findingIds || []), ...(item.findingIds || [])]);
        current.issueIds = distinctText([...(current.issueIds || []), ...(item.issueIds || [])]);
        current.remediationGroupIds = distinctText([...(current.remediationGroupIds || []), ...(item.remediationGroupIds || [])]);
        current.meaning = firstText(current.meaning, item.meaning);
        current.sealedEvidenceValue = firstText(current.sealedEvidenceValue, item.sealedEvidenceValue);
        current.promptValue = firstText(current.promptValue, item.promptValue);
        current.officialFactValue = firstText(current.officialFactValue, item.officialFactValue);
    });
    return Array.from(merged.values());
}

function comparisonLedgerKey(item) {
    const problemId = canonicalComparisonProblemId(item);
    if (problemId) {
        return `problem:${problemId}`;
    }
    const state = upperText(item?.state) || 'UNKNOWN';
    const fieldKey = rawText(item?.fieldKey) || rawText(item?.fieldLabel) || 'unknown-field';
    return `${isProblemComparison(item) ? 'problem' : 'reference'}:${fieldKey}:${state}`;
}

function canonicalComparisonProblemId(item) {
    const problemId = distinctText(item?.problemIds || [])
            .find(value => value);
    if (problemId) {
        return problemId;
    }
    return distinctText(item?.checkCodes || [])
            .find(value => /^app-/i.test(value) || /^actual-prompt-/i.test(value))
            || '';
}

function officialBlockingComparisons(items) {
    return visiblePromptComparisonItems(items).filter(isProblemComparison);
}

function promptComparisonsForMetric(items, metricCode) {
    const normalizedMetricCode = upperText(metricCode);
    if (!normalizedMetricCode) {
        return [];
    }
    return visiblePromptComparisonItems(items).filter(item => {
        return ensureArray(item?.metricCodes)
                .map(upperText)
                .includes(normalizedMetricCode);
    });
}

function primaryMetricCodeForComparison(item) {
    const metricCodes = ensureArray(item?.metricCodes)
            .map(upperText)
            .filter(Boolean);
    return metricCodes.length ? metricCodes[0] : '';
}

function comparisonMetricCodeForRun(item, runMetricCode) {
    const normalizedRunMetric = upperText(runMetricCode);
    const metricCodes = ensureArray(item?.metricCodes)
            .map(upperText)
            .filter(Boolean);
    if (normalizedRunMetric && metricCodes.includes(normalizedRunMetric)) {
        return normalizedRunMetric;
    }
    return metricCodes.length ? metricCodes[0] : normalizedRunMetric;
}

function comparisonProblemCounts(items, detail = {}) {
    const actualProblems = visibleActualPromptProblems(detail?.actualPromptProblems);
    if (actualProblems.length) {
        const counts = actualPromptProblemCounts(actualProblems);
        const comparisonCounts = comparisonLedgerCounts(items);
        counts.match = comparisonCounts.match;
        return counts;
    }
    return comparisonLedgerCounts(items);
}

function comparisonLedgerCounts(items) {
    const counts = { total: 0, match: 0, missing: 0, mismatch: 0 };
    const comparisonItems = visiblePromptComparisonItems(items);
    comparisonItems.forEach(item => {
        const state = upperText(item.state);
        if (state === 'MATCH') {
            counts.match += 1;
        } else if (state === 'PROMPT_MISSING' || state === 'FACT_MISSING') {
            counts.missing += 1;
        } else if (isProblemComparison(item)) {
            counts.mismatch += 1;
        }
    });
    counts.total = counts.missing + counts.mismatch;
    return counts;
}

function officialFailureCauses(detail = {}) {
    const seen = new Set();
    return ensureArray(detail?.failureCauses).filter(item => {
        const key = officialFailureKey(item, seen.size);
        if (!key || seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}

function officialFailureKey(item, index = 0) {
    const findingId = rawText(item?.findingId);
    if (findingId) {
        return `finding:${findingId}`;
    }
    const issueId = rawText(item?.issueId);
    if (issueId) {
        return `issue:${issueId}`;
    }
    const metric = rawText(item?.metricCode) || 'metric';
    const check = rawText(item?.checkCode) || rawText(item?.checkLabel);
    return check ? `check:${metric}:${check}` : `failure:${metric}:${index}`;
}

function hasPromptSource(detail = {}) {
    const evidence = detail.sealedEvidence || {};
    return Boolean(rawText(evidence.systemPromptText)
            || rawText(evidence.systemPromptPreview)
            || rawText(evidence.userPromptText)
            || rawText(evidence.userPromptPreview));
}

function comparisonKpi(label, value, tone) {
    return `
        <article class="pqa-official-compare-kpi ${escapeHtml(tone)}">
            <span>${escapeHtml(label)}</span>
            <strong>${escapeHtml(String(value))}</strong>
        </article>
    `;
}

function sortComparisons(items) {
    return [...items].sort((left, right) => comparisonWeight(left) - comparisonWeight(right));
}

function comparisonWeight(item) {
    const state = upperText(item.state);
    if (isProblemComparison(item)) {
        return state === 'PROMPT_MISSING' || state === 'FACT_MISSING' ? 1 : 0;
    }
    if (state === 'VALUE_MISMATCH') {
        return 0;
    }
    if (state === 'PROMPT_MISSING' || state === 'FACT_MISSING') {
        return 1;
    }
    if (state === 'NOT_APPLICABLE') {
        return 3;
    }
    if (state === 'MATCH') {
        return 4;
    }
    return 2;
}

function isProblemComparison(item) {
    const state = upperText(item.state);
    if (state === 'NOT_APPLICABLE') {
        return false;
    }
    return state !== 'MATCH'
            || Boolean(canonicalComparisonProblemId(item))
            || distinctText(item?.findingIds || []).length > 0;
}

function renderPromptLocationMap(items) {
    const sorted = sortComparisons(items).filter(item => rawText(item.promptLocation));
    const groups = promptLocationGroups().map(group => ({
        ...group,
        items: sorted.filter(item => promptLocationGroup(item.promptLocation) === group.key)
    }));
    return `
        <section class="pqa-official-prompt-locations">
            <h4>${escapeHtml(t('enterprise.pqa.verification.comparison.locationTitle'))}</h4>
            <div class="pqa-official-prompt-location-grid">
                ${groups.map(renderPromptLocationGroup).join('')}
            </div>
        </section>
    `;
}

function renderPromptLocationGroup(group) {
    const problemCount = group.items.filter(isProblemComparison).length;
    const samples = problemCount
            ? group.items.filter(isProblemComparison)
            : group.items;
    return `
        <article class="pqa-official-prompt-location-card ${problemCount ? 'has-problem' : ''}">
            <strong>${escapeHtml(group.label)}</strong>
            <span>${escapeHtml(t('enterprise.pqa.verification.comparison.location.count', group.items.length, problemCount))}</span>
            <div class="pqa-badge-row">
                ${samples.length
                    ? samples.map(item => badge(text(item.fieldLabel), { tone: comparisonToneForItem(item) })).join('')
                    : badge(t('enterprise.pqa.verification.comparison.location.empty'), { tone: 'neutral' })}
            </div>
        </article>
    `;
}

function promptLocationGroups() {
    return [
        { key: 'system', label: t('enterprise.pqa.verification.comparison.location.system') },
        { key: 'user', label: t('enterprise.pqa.verification.comparison.location.user') },
        { key: 'metadata', label: t('enterprise.pqa.verification.comparison.location.metadata') },
        { key: 'baseline', label: t('enterprise.pqa.verification.comparison.location.baseline') },
        { key: 'rag', label: t('enterprise.pqa.verification.comparison.location.rag') }
    ];
}

function promptLocationGroup(location) {
    const normalized = text(location).toLowerCase();
    if (normalized.includes('system')) {
        return 'system';
    }
    if (normalized.includes('metadata') || normalized.includes('execution')) {
        return 'metadata';
    }
    if (normalized.includes('baseline')) {
        return 'baseline';
    }
    if (normalized.includes('rag') || normalized.includes('retrieval')) {
        return 'rag';
    }
    return 'user';
}

function renderPromptSourceViewer(detail, items) {
    const defaultQuery = defaultPromptSearchQuery(items);
    return `
        <details class="pqa-official-prompt-source">
            <summary>
                <span>${escapeHtml(t('enterprise.pqa.verification.comparison.raw.title'))}</span>
                <small>${escapeHtml(t('enterprise.pqa.verification.comparison.raw.description'))}</small>
            </summary>
            <label>
                <span>${escapeHtml(t('enterprise.pqa.verification.comparison.raw.search'))}</span>
                <input type="search" data-pqa-prompt-search value="${escapeHtml(defaultQuery)}">
            </label>
            ${renderPromptSourceTokens(items)}
            <div class="pqa-official-prompt-source-body" data-pqa-prompt-source-body></div>
        </details>
    `;
}

function renderPromptSourceTokens(items) {
    const tokens = sortComparisons(ensureArray(items))
            .filter(isProblemComparison)
            .map(item => ({
                label: text(item.fieldLabel),
                token: comparisonSearchToken(item),
                state: item.state
            }))
            .filter(item => rawText(item.token))
            .filter((item, index, array) => array.findIndex(candidate => candidate.label === item.label && candidate.token === item.token) === index);
    if (!tokens.length) {
        return '';
    }
    return `
        <div class="pqa-prompt-source-token-row">
            <strong>${escapeHtml(t('enterprise.pqa.verification.comparison.raw.problemTokens'))}</strong>
            ${tokens.map(item => `
                <button type="button"
                        class="pqa-section-pill"
                        data-pqa-comparison-search="${escapeHtml(item.token)}">
                    ${escapeHtml(item.label)}
                </button>
            `).join('')}
        </div>
    `;
}

function defaultPromptSearchQuery(items) {
    const problem = sortComparisons(ensureArray(items)).find(isProblemComparison);
    if (!problem) {
        return '';
    }
    return comparisonSearchToken(problem);
}

function renderPromptSourceBody(target, detail, query) {
    const body = target.querySelector('[data-pqa-prompt-source-body]');
    if (!body) {
        return;
    }
    const evidence = detail.sealedEvidence || {};
    body.innerHTML = `
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.system'), rawText(evidence.systemPromptText) || rawText(evidence.systemPromptPreview), query, 'wide', 'system')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.user'), rawText(evidence.userPromptText) || rawText(evidence.userPromptPreview), query, 'wide', 'user')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.request'), jsonText(evidence.requestFacts), query, '', 'request')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.auth'), jsonText(evidence.authState), query, '', 'auth')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.metadata'), jsonText(evidence.promptMetadata), query, '', 'metadata')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.baseline'), evidence.baselineSnapshotCaptured ? jsonText(evidence.baselineSnapshot) : t('enterprise.pqa.verification.comparison.raw.notCaptured'), query, '', 'baseline')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.rag'), evidence.ragResultsCaptured ? jsonText(evidence.ragResults) : t('enterprise.pqa.verification.comparison.raw.notCaptured'), query, '', 'rag')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.decision'), jsonText(evidence.decision), query, '', 'decision')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.missingKnowledge'), listText(evidence.missingKnowledgeSignals), query, '', 'missingKnowledge')}
        ${promptBlock(t('enterprise.pqa.verification.comparison.raw.qualityWarnings'), listText(evidence.qualityWarnings), query, '', 'qualityWarnings')}
    `;
}

function updateSubrouteLinks(pageRoot, source) {
    const identitySource = withRouteIdentity(pageRoot, source || {});
    const packageId = rawText(source?.packageId)
            || rawText(pageRoot.__selectedPackageId)
            || packageIdFromLocation();
    if (packageId) {
        pageRoot.__selectedPackageId = packageId;
    }
    pageRoot.querySelectorAll('[data-pqa-verification-subroute]').forEach(link => {
        const route = rawText(link.dataset.pqaVerificationSubroute);
        link.href = verificationStageHref(route, {
            ...identitySource,
            packageId,
            aggregateRunId: rawText(source?.aggregateRunId) || rawText(pageRoot.__selectedAggregateRunId) || aggregateRunIdFromLocation(),
            runId: rawText(source?.runId),
            officialRunId: rawText(source?.officialRunId),
            reverifyRunId: rawText(source?.reverifyRunId),
            certificateId: rawText(source?.certificateId),
            caseId: rawText(source?.caseId)
        });
        applySubrouteContract(pageRoot, link, route, packageId);
    });
}

function applySubrouteContract(pageRoot, link, route, packageId) {
    const contract = subrouteContract(pageRoot, route, packageId);
    if (contract.allowed) {
        link.removeAttribute('aria-disabled');
        link.classList.remove('is-disabled');
        const message = subrouteReadyTooltip(route);
        link.setAttribute('data-pqa-action-message', message);
        link.removeAttribute('data-pqa-disabled-reason');
        link.setAttribute('aria-label', message);
        delete link.dataset.pqaGateTitle;
        delete link.dataset.pqaGateDetail;
        return;
    }
    link.setAttribute('aria-disabled', 'true');
    link.classList.add('is-disabled');
    const message = `${contract.title} - ${contract.detail}`;
    link.setAttribute('data-pqa-disabled-reason', message);
    link.removeAttribute('data-pqa-action-message');
    link.setAttribute('aria-label', message);
    link.dataset.pqaGateTitle = contract.title;
    link.dataset.pqaGateDetail = contract.detail;
}

function subrouteReadyTooltip(route) {
    const keys = {
        readiness: 'enterprise.pqa.verification.subnav.tooltip.readiness',
        run: 'enterprise.pqa.verification.subnav.tooltip.run',
        comparison: 'enterprise.pqa.verification.subnav.tooltip.comparison',
        metrics: 'enterprise.pqa.verification.subnav.tooltip.metrics'
    };
    return t(keys[route] || 'enterprise.pqa.verification.subnav.tooltip.default');
}

function subrouteContract(pageRoot, route, packageId) {
    if (route === 'readiness') {
        return { allowed: true };
    }
    if (!packageId) {
        return {
            allowed: false,
            title: t('enterprise.pqa.verification.run.needEvidence.title'),
            detail: t('enterprise.pqa.verification.subnav.disabled.needEvidence')
        };
    }
    const hasLoadedEvidence = Boolean(pageRoot.__selectedEvidence?.packageId);
    if (!hasLoadedEvidence) {
        return {
            allowed: false,
            title: t('enterprise.pqa.verification.run.selection.loading.title'),
            detail: t('enterprise.pqa.verification.subnav.disabled.loading')
        };
    }
    if (requiresOfficialLedger(route) && pageRoot.__officialLedgerAvailable !== true) {
        return {
            allowed: false,
            title: t('enterprise.pqa.verification.readonly.ledgerMissing.title'),
            detail: t('enterprise.pqa.verification.readonly.ledgerMissing.detail')
        };
    }
    if (route === 'run') {
        const gate = processGate(pageRoot);
        if (!gate.allowed) {
            return {
                allowed: false,
                title: gate.title,
                detail: t('enterprise.pqa.verification.subnav.disabled.readiness')
            };
        }
    }
    return { allowed: true };
}

function requiresOfficialLedger(route) {
    return route === 'comparison' || route === 'metrics';
}

function packageIdFromLocation() {
    return rawText(new URLSearchParams(window.location.search || '').get('packageId'));
}

function aggregateRunIdFromLocation() {
    return rawText(new URLSearchParams(window.location.search || '').get('aggregateRunId'));
}

function routeIdentityFromLocation() {
    const params = new URLSearchParams(window.location.search || '');
    return {
        resourceUrl: rawText(params.get('resourceUrl')),
        resourceId: rawText(params.get('resourceId')),
        resourceTemplateId: rawText(params.get('resourceTemplateId')),
        actualResourceId: rawText(params.get('actualResourceId')),
        httpMethod: rawText(params.get('httpMethod')),
        officialRunId: rawText(params.get('officialRunId')),
        reverifyRunId: rawText(params.get('reverifyRunId')),
        certificateId: rawText(params.get('certificateId')),
        caseId: rawText(params.get('caseId'))
    };
}

function identityFromSource(source = {}, fallback = {}) {
    const resourceId = rawText(source?.resourceId) || rawText(fallback?.resourceId);
    const resourceUrl = resourceUrlOf(source) || rawText(fallback?.resourceUrl);
    const resourceTemplateId = rawText(source?.resourceTemplateId)
            || rawText(source?.protectableResourceId)
            || rawText(fallback?.resourceTemplateId)
            || (resourceId && resourceId.includes('{') ? resourceId : '');
    const actualResourceId = firstActualResourceId(
            source?.actualResourceId,
            source?.runtimeResourceId,
            fallback?.actualResourceId,
            actualResourceIdFromPath(resourceUrl),
            actualResourceIdFromPath(rawText(source?.requestPath) || rawText(fallback?.requestPath)),
            source?.resourceId,
            fallback?.resourceId)
            || (resourceId && !resourceId.includes('{') ? resourceId : '');
    return {
        resourceUrl,
        resourceId,
        resourceTemplateId,
        actualResourceId,
        httpMethod: rawText(source?.httpMethod) || rawText(fallback?.httpMethod),
        officialRunId: rawText(source?.officialRunId) || rawText(fallback?.officialRunId),
        reverifyRunId: rawText(source?.reverifyRunId) || rawText(fallback?.reverifyRunId),
        certificateId: rawText(source?.certificateId) || rawText(fallback?.certificateId),
        caseId: rawText(source?.caseId) || rawText(fallback?.caseId)
    };
}

function firstActualResourceId(...values) {
    return values.map(rawText)
            .find(value => value && !isTemplateToken(value) && !value.includes('/')) || '';
}

function actualResourceIdFromPath(value) {
    const path = rawText(value);
    if (!path || isTemplateToken(path)) {
        return '';
    }
    const cleanPath = path.split('?')[0].replace(/\/+$/, '');
    const segment = cleanPath.substring(cleanPath.lastIndexOf('/') + 1);
    return segment && !isTemplateToken(segment) ? segment : '';
}

function isTemplateToken(value) {
    return /\{[^}]+}/.test(rawText(value));
}

function withRouteIdentity(pageRoot, source = {}) {
    const routeIdentity = pageRoot?.__routeIdentity || routeIdentityFromLocation();
    const identity = identityFromSource(source, routeIdentity);
    return {
        ...source,
        resourceUrl: rawText(source?.resourceUrl) || identity.resourceUrl,
        resourceId: rawText(source?.resourceId) || identity.resourceId,
        resourceTemplateId: rawText(source?.resourceTemplateId) || identity.resourceTemplateId,
        actualResourceId: rawText(source?.actualResourceId) || identity.actualResourceId,
        httpMethod: rawText(source?.httpMethod) || identity.httpMethod,
        officialRunId: rawText(source?.officialRunId) || identity.officialRunId,
        reverifyRunId: rawText(source?.reverifyRunId) || identity.reverifyRunId,
        certificateId: rawText(source?.certificateId) || identity.certificateId,
        caseId: rawText(source?.caseId) || identity.caseId
    };
}

function verificationStage(pageRoot) {
    return rawText(pageRoot?.dataset?.pqaVerificationStage) || 'run';
}

function promptBlock(title, value, query, layout = '', section = '') {
    return `
        <article class="${layout === 'wide' ? 'pqa-source-wide' : ''}" data-pqa-prompt-source-section="${escapeHtml(section)}">
            <h5>${escapeHtml(title)}</h5>
            <pre>${highlightPrompt(value || t('enterprise.pqa.verification.comparison.raw.empty'), query)}</pre>
        </article>
    `;
}

function jsonText(value) {
    if (!value || (typeof value === 'object' && Object.keys(value).length === 0)) {
        return t('enterprise.pqa.verification.comparison.raw.jsonEmpty');
    }
    return JSON.stringify(value, null, 2);
}

function listText(value) {
    const items = ensureArray(value).map(text).filter(Boolean);
    return items.length ? items.join('\n') : t('enterprise.pqa.verification.comparison.raw.empty');
}

function highlightPrompt(value, query) {
    const escaped = escapeHtml(value);
    const term = rawText(query);
    if (!term) {
        return escaped;
    }
    const escapedTerm = escapeRegExp(escapeHtml(term));
    return escaped.replace(new RegExp(escapedTerm, 'gi'), match => `<mark>${match}</mark>`);
}

function escapeRegExp(value) {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function officialRunBlockingItems(detail) {
    return ensureArray(detail?.runs).flatMap(run => {
        if (!run || String(run.state || '').toUpperCase() === 'SUCCESS') {
            return [];
        }
        const failedChecks = ensureArray(run.checks).filter(check => check && !check.pass);
        if (!failedChecks.length) {
            return [{
                metricCode: run.metricCode,
                metricName: run.metricName,
                expectedValue: run.metricQualityQuestion || run.metricPurpose || run.metricName,
                actualValue: run.primaryFailureReason || run.stateLabel || run.state,
                reverifyCriterion: run.reverifyCriterion || run.nextAction || '',
                remediationOwner: run.remediationOwner || run.metricName,
                source: run.state || '',
                severity: 'BLOCKING'
            }];
        }
        return failedChecks.map(check => ({
            ...check,
            metricCode: run.metricCode,
            metricName: run.metricName,
            remediationOwner: check.remediationOwner || run.remediationOwner || run.metricName,
            source: check.source || run.state || '',
            severity: check.severity || 'BLOCKING'
        }));
    });
}

function renderOfficialFailures(target, detail) {
    if (!target) {
        return;
    }
    const storedFailures = sortFailuresProblemFirst(ensureArray(detail.failureCauses));
    const items = storedFailures.length ? storedFailures : sortFailuresProblemFirst(officialRunBlockingItems(detail));
    target.innerHTML = items.length
            ? `<section class="pqa-official-priority-block">
                    <div class="pqa-official-ops-head">
                        <strong>해결해야 할 문제</strong>
                        <span>공식 검사에서 멈춘 항목과 필요한 후속 조치를 확인합니다.</span>
                    </div>
                    ${renderPqaProcessRail()}
                    <ul class="pqa-official-failure-list">${items.slice(0, 8).map(item => renderFailureItem(item, detail)).join('')}</ul>
                    ${items.length > 8 ? `<p class="pqa-cell-meta">나머지 ${items.length - 8}개 항목은 '지표 상세'에서 확인하십시오.</p>` : ''}
                    ${renderOfficialNextActions(detail)}
               </section>`
            : `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.ledger.failure.empty'))}</p></div>`;
}

function renderPqaProcessRail() {
    const steps = [
        ['1', '공식 검사', '차단 원인 식별'],
        ['2', '후속 조치', '컨텍스트와 프롬프트 근거 보강'],
        ['3', '확장 관리', '보강 결과 적용 범위 확인'],
        ['4', '재검증', '같은 증거 흐름으로 통과 확인']
    ];
    return `
        <ol class="pqa-official-process-rail" aria-label="공식 품질 검사 이후 후속 조치 흐름">
            ${steps.map(([number, label, description]) => `
                <li>
                    <span class="pqa-rail-icon" aria-hidden="true">${escapeHtml(number)}</span>
                    <strong>${escapeHtml(label)}</strong>
                    <small>${escapeHtml(description)}</small>
                </li>
            `).join('')}
        </ol>
    `;
}

function renderFailureItem(item, detail) {
    const title = conciseProblemTitle(item);
    const cause = conciseCause(item);
    const action = conciseAction(item);
    const owner = rawText(item.remediationOwner) || rawText(item.affectedTarget) || rawText(item.metricName) || '담당 확인 필요';
    const actual = operatorFullText(item.actualValue);
    const reverify = operatorFullText(item.reverifyCriterion);
    const expected = operatorFullText(item.expectedValue);
    const reasonKind = remediationKind(item);
    return `
        <li class="pqa-official-failure-item">
            <div class="pqa-finding-card-head">
                <span class="pqa-problem-icon" aria-hidden="true">!</span>
                <div>
                    <strong>${escapeHtml(title)}</strong>
                    <p>${escapeHtml(reasonKind)}</p>
                </div>
                ${badge(t('enterprise.pqa.verification.metricCheck.blocked'), { tone: 'blocked' })}
            </div>
            <div class="pqa-finding-decision-grid">
                <section class="pqa-finding-panel problem">
                    <span class="pqa-official-kicker">문제 원인</span>
                    <p>${escapeHtml(cause)}</p>
                </section>
                <section class="pqa-finding-panel action">
                    <span class="pqa-official-kicker">후속 공정에서 할 일</span>
                    <p>${escapeHtml(action)}</p>
                </section>
                <section class="pqa-finding-panel verify">
                    <span class="pqa-official-kicker">완료 판단 기준</span>
                    <p>${escapeHtml(reverify)}</p>
                </section>
            </div>
            <dl class="pqa-finding-meta-grid">
                <div>
                    <dt>해결 담당</dt>
                    <dd>${escapeHtml(owner)}</dd>
                </div>
                <div>
                    <dt>현재 상태</dt>
                    <dd>${escapeHtml(actual)}</dd>
                </div>
                <div>
                    <dt>다음 공정</dt>
                    <dd>후속 조치 후 같은 요청 흐름으로 재검증</dd>
                </div>
            </dl>
            <details class="pqa-official-technical-evidence">
                <summary>판정 기준과 근거</summary>
                <dl>
                    <div><dt>지표</dt><dd><code>${escapeHtml(text(item.metricCode))}</code></dd></div>
                    <div><dt>근거 위치</dt><dd><code>${escapeHtml(text(item.source))}</code></dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.metricCheck.expected'))}</dt><dd>${escapeHtml(expected)}</dd></div>
                    <div><dt>${escapeHtml(t('enterprise.pqa.verification.metricCheck.actual'))}</dt><dd>${escapeHtml(actual)}</dd></div>
                </dl>
            </details>
        </li>
    `;
}

function renderOfficialNextActions(detail) {
    return '';
}

function renderOfficialRemediationGroups(target, detail) {
    if (!target) {
        return;
    }
    target.innerHTML = '';
}

function failureHandoffLink(item, detail) {
    return issueListLink(failureScopedSource(item, detail));
}

function failureScopedSource(item, detail) {
    const source = { ...(detail || {}), failureCauses: [item], remediationGroups: scopedRemediationGroupsForFailure(item, detail) };
    const issues = ensureArray(detail?.issues);
    const problemId = rawText(item?.problemId);
    const issueId = rawText(item?.issueId);
    const metricCode = rawText(item?.metricCode);
    const findingId = rawText(item?.findingId);
    const checkCode = rawText(item?.checkCode);
    const matched = issues.filter(issue =>
            (problemId && rawText(issue.problemId) === problemId)
            || (issueId && rawText(issue.issueId) === issueId)
            || (findingId && rawText(issue.findingId) === findingId)
            || (checkCode && rawText(issue.failedCheck || issue.checkCode) === checkCode)
            || (metricCode && rawText(issue.relatedMetricCode || issue.metricCode) === metricCode));
    if (problemId) {
        source.problemId = problemId;
    }
    if (matched.length) {
        source.issues = matched;
    } else {
        source.issues = [];
    }
    return source;
}

function scopedRemediationGroupsForFailure(item, detail) {
    const groups = ensureArray(detail?.remediationGroups);
    if (!groups.length) {
        return [];
    }
    const directGroupId = rawText(item?.remediationGroupId);
    if (directGroupId) {
        return groups.filter(group => remediationGroupIdOf(group) === directGroupId);
    }
    const metricCode = upperText(item?.metricCode);
    const checkCode = upperText(item?.checkCode);
    const byCheck = groups.filter(group => checkCode && splitListValue(group?.affectedCheckCodes)
            .map(upperText)
            .includes(checkCode));
    if (byCheck.length) {
        return byCheck;
    }
    return groups.filter(group => metricCode && splitListValue(group?.affectedMetricCodes)
            .map(upperText)
            .includes(metricCode));
}

function splitListValue(value) {
    if (Array.isArray(value)) {
        return distinctText(value);
    }
    const textValue = rawText(value);
    if (!textValue) {
        return [];
    }
    return textValue
            .split(',')
            .map(item => {
                const itemText = rawText(item);
                return itemText.trim();
            })
            .filter(Boolean);
}

function remediationKind(item) {
    const metric = upperText(item?.metricCode);
    const owner = rawText(item?.remediationOwner) || rawText(item?.affectedTarget);
    if (metric === 'PFR' || /프롬프트/.test(owner)) {
        return '프롬프트 구성 보강이 필요한 항목입니다.';
    }
    if (/기준선|행동|검색|컨텍스트|권한/.test(owner)) {
        return '후속 공정에서 운영 근거를 보강할 항목입니다.';
    }
    return '후속 공정에서 담당 영역과 보강 방식을 확정할 항목입니다.';
}

function dedupeRemediationGroups(groups) {
    const merged = new Map();
    ensureArray(groups).filter(Boolean).forEach(group => {
        const key = [
            rawText(group.remediationOwner),
            rawText(group.operatorTitle),
            rawText(group.rootCauseKey)
        ].join('|');
        if (!merged.has(key)) {
            merged.set(key, { ...group });
            return;
        }
        const current = merged.get(key);
        current.findingCount = Math.max(Number(current.findingCount || 0), Number(group.findingCount || 0));
        current.affectedMetricCodes = distinctText([
            ...ensureArray(current.affectedMetricCodes),
            ...ensureArray(group.affectedMetricCodes)
        ]);
        current.affectedCheckCodes = distinctText([
            ...ensureArray(current.affectedCheckCodes),
            ...ensureArray(group.affectedCheckCodes)
        ]);
    });
    return Array.from(merged.values());
}

function officialMetricLabel(code) {
    return text(code);
}

function sortFailuresProblemFirst(items) {
    return [...items].sort((left, right) =>
            text(left.metricCode).localeCompare(text(right.metricCode))
            || text(left.checkLabel).localeCompare(text(right.checkLabel)));
}

function sortMetricRunsProblemFirst(items) {
    return [...items].sort((left, right) => {
        const leftProblems = metricPromptIssueCount(left, {
            promptComparisons: left?.comparisons || [],
            actualPromptProblems: left?.actualPromptProblems || []
        });
        const rightProblems = metricPromptIssueCount(right, {
            promptComparisons: right?.comparisons || [],
            actualPromptProblems: right?.actualPromptProblems || []
        });
        const leftGateOnly = !leftProblems && !passState(left.state) ? 1 : 0;
        const rightGateOnly = !rightProblems && !passState(right.state) ? 1 : 0;
        return rightProblems - leftProblems
                || leftGateOnly - rightGateOnly
                || text(left.metricCode).localeCompare(text(right.metricCode));
    });
}

function sortChecksProblemFirst(items) {
    return [...items].sort((left, right) => {
        const leftPassed = left.pass ? 1 : 0;
        const rightPassed = right.pass ? 1 : 0;
        return leftPassed - rightPassed
                || text(left.checkCode).localeCompare(text(right.checkCode));
    });
}

function renderOfficialRuns(target, detail) {
    if (!target) {
        return;
    }
    const sourceRuns = ensureArray(detail.runs).length
            ? ensureArray(detail.runs)
            : ensureArray(detail.metrics);
    const officialFailures = officialFailureCauses(detail);
    const cards = sortMetricRunsProblemFirst(sourceRuns).map(run => {
        const officialRunId = rawText(run.officialRunId) || '';
        const disabledReason = t('enterprise.pqa.verification.metricDetail.missingRunId');
        const checkCounts = metricCheckCounts(run, officialFailures, detail);
        const rowFailures = metricOfficialFailures(run, officialFailures);
        const promptProblemItems = metricFailureItems({
            ...run,
            actualPromptProblems: ensureArray(detail?.actualPromptProblems).length
                    ? detail.actualPromptProblems
                    : run?.actualPromptProblems,
            comparisons: [
                ...ensureArray(detail?.promptComparisons),
                ...ensureArray(run?.comparisons)
            ]
        });
        const displayedFailures = promptProblemItems.length
                ? promptProblemItems
                : rowFailures.length ? rowFailures : ensureArray(run.failureCauses);
        const gateSummary = metricGateSummaryText(run, checkCounts);
        const failureText = truncateForOperator(metricRunSummaryText(run, checkCounts, displayedFailures, gateSummary), 120);
        return `
        <article class="pqa-metric-run-card ${escapeHtml(metricDisplayStateTone(run, checkCounts))}">
            <header>
                <div>
                    <code>${escapeHtml(text(run.metricCode))}</code>
                    <strong>${escapeHtml(text(run.metricName))}</strong>
                    <span>${escapeHtml(metricGroupLabel(run.groupName || run.metricGroup))}</span>
                </div>
                ${badge(metricDisplayStateLabel(run, checkCounts), { tone: metricDisplayStateTone(run, checkCounts) })}
            </header>
            ${renderMetricCheckSummary(checkCounts)}
            <p class="pqa-metric-run-cause">${escapeHtml(failureText)}</p>
            <footer>
                <span>판정 ${escapeHtml(metricScoreDisplay(run, checkCounts))}</span>
                <button type="button"
                        class="pqa-action-button compact ${officialRunId ? '' : 'is-disabled'}"
                        data-pqa-official-run-id="${escapeHtml(officialRunId)}"
                        aria-disabled="${officialRunId ? 'false' : 'true'}"
                        ${officialRunId
                                ? `data-pqa-action-message="${escapeHtml(t('enterprise.pqa.common.action.tooltip.ready', t('enterprise.pqa.verification.btn.detail')))}"`
                                : `data-pqa-disabled-reason="${escapeHtml(disabledReason)}"`}>
                    ${escapeHtml(t('enterprise.pqa.verification.btn.detail'))}
                </button>
            </footer>
        </article>
    `;
    });
    target.innerHTML = cards.length
            ? `${renderMetricCheckTotals(sourceRuns, detail)}
               <div class="pqa-metric-run-grid">${cards.join('')}</div>`
            : `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.ledger.runs.empty'))}</p></div>`;
    target.querySelectorAll('[data-pqa-official-run-id]').forEach(button => {
        button.addEventListener('click', () => showOfficialRunDetail(
                target,
                button.dataset.pqaOfficialRunId,
                button));
    });
}

function renderMetricCheckTotals(runs, detail = {}) {
    const totals = metricCheckTotals(runs, detail);
    return `
        <section class="pqa-metric-check-total-summary" aria-label="12개 프롬프트 품질 지표 집계">
            <article class="${totals.actualProblems ? 'is-blocked' : 'is-ready'}">
                <span>프롬프트 문제</span>
                <strong>${escapeHtml(String(totals.actualProblems))}</strong>
                <small>해결 필요한 프롬프트 문제</small>
            </article>
            <article class="${totals.blockedMetrics ? 'is-blocked' : 'is-ready'}">
                <span>영향 지표</span>
                <strong>${escapeHtml(String(totals.blockedMetrics))}</strong>
                <small>문제로 막힌 지표</small>
            </article>
            <article class="is-ready">
                <span>판정 기준</span>
                <strong>${escapeHtml(criteriaProgressText(totals))}</strong>
                <small>${escapeHtml(criteriaIssueSplitText(totals))}</small>
            </article>
            <article class="${totals.gateMetrics ? 'is-pending' : 'is-ready'}">
                <span>추가 확인</span>
                <strong>${escapeHtml(totals.gateConditions ? `${totals.gateConditions}개` : '없음')}</strong>
                <small>${escapeHtml(totals.gateMetrics ? `${totals.gateMetrics}개 지표 확인 필요` : '추가 확인 없음')}</small>
            </article>
        </section>
    `;
}
function metricCheckTotals(runs, detail = {}) {
    const safeRuns = ensureArray(runs);
    const serverTotals = metricSummaryCountsFromPayload(detail);
    if (serverTotals) {
        serverTotals.notApplicableMetrics = countNotApplicableMetrics(safeRuns);
        return serverTotals;
    }
    const actualProblems = actualPromptProblemsForTotals(safeRuns, detail);
    const blockedMetricCodes = new Set();
    if (actualProblems.length) {
        actualProblems.forEach(problem => {
            ensureArray(problem?.metricCodes)
                    .map(upperText)
                    .filter(Boolean)
                    .forEach(code => blockedMetricCodes.add(code));
        });
    }
    return safeRuns.reduce((acc, run) => {
        const counts = metricCheckCounts(run, [], detail);
        acc.technicalTotal += counts.technicalTotal;
        acc.technicalPassed += counts.technicalPassed;
        if (counts.gateFailed > 0) {
            acc.gateConditions += counts.gateFailed;
        }
        if (counts.inputFailed > 0) {
            acc.inputReviewMetrics += 1;
            acc.inputReadinessChecks += counts.inputFailed;
        }
        if (counts.notApplicable) {
            acc.notApplicableMetrics += 1;
        }
        acc.criteriaFailed += counts.criteriaFailed;
        if (counts.gateFailed > 0) {
            acc.gateMetrics += 1;
        }
        acc.otherFailed += counts.otherFailed;
        return acc;
    }, {
        actualProblems: actualProblems.length,
        blockedMetrics: blockedMetricCodes.size,
        technicalTotal: 0,
        technicalPassed: 0,
        technicalFailed: 0,
        gateConditions: 0,
        inputReviewMetrics: 0,
        inputReadinessChecks: 0,
        notApplicableMetrics: 0,
        criteriaFailed: 0,
        gateMetrics: 0,
        otherFailed: 0
    });
}

function countNotApplicableMetrics(runs) {
    return ensureArray(runs).filter(run => metricNotApplicable(run)).length;
}

function metricSummaryCountsFromPayload(detail = {}) {
    const raw = detail?.summaryCounts || detail?.metricSummaryCounts || detail?.officialSummaryCounts;
    if (!raw || typeof raw !== 'object') {
        return null;
    }
    const keys = [
        'actualProblems',
        'blockedMetrics',
        'technicalTotal',
        'technicalPassed',
        'technicalFailed',
        'gateConditions',
        'inputReviewMetrics',
        'inputReadinessChecks',
        'notApplicableMetrics',
        'criteriaFailed',
        'gateMetrics',
        'otherFailed'
    ];
    const hasAnyCount = keys.some(key => raw[key] !== null && raw[key] !== undefined && raw[key] !== '');
    if (!hasAnyCount) {
        return null;
    }
    return keys.reduce((acc, key) => {
        const value = Number(raw[key] || 0);
        acc[key] = Number.isFinite(value) ? value : 0;
        return acc;
    }, {});
}

function gateMetricCodesFromRuns(runs, detail = {}) {
    return distinctText(ensureArray(runs)
            .filter(run => metricGateReview(run, detail))
            .map(run => upperText(run?.metricCode))
            .filter(Boolean));
}

function gateMetricLocationText(metricCodes = []) {
    const codes = distinctText(metricCodes).filter(Boolean);
    return codes.length
            ? `12개 지표 상세 > ${codes.join(', ')}`
            : '12개 지표 상세에서 확인';
}

function metricCheckCounts(run, officialFailures = [], detail = {}) {
    const actualProblemCount = metricPromptIssueCount(run, detail);
    if (metricNotApplicable(run) && !actualProblemCount) {
        return {
            passed: 0,
            failed: 0,
            total: 0,
            actualProblemCount: 0,
            promptCriteriaFailed: 0,
            inputFailed: 0,
            gateFailed: 0,
            otherFailed: 0,
            technicalPassed: 0,
            technicalFailed: 0,
            technicalTotal: 0,
            criteriaFailed: 0,
            gateReview: false,
            inputReview: false,
            notApplicable: true
        };
    }
    const technical = metricTechnicalCheckCounts(run, detail);
    const split = metricFailedCheckSplit(run, technical.failed);
    const gateReview = split.gate > 0 || (!split.input && metricGateReview(run, detail));
    const inputReview = split.input > 0 || metricInputReadinessReview(run);
    return {
        passed: technical.passed,
        failed: actualProblemCount,
        total: technical.total,
        actualProblemCount,
        promptCriteriaFailed: split.customer,
        inputFailed: split.input,
        gateFailed: split.gate,
        otherFailed: split.other,
        technicalPassed: technical.passed,
        technicalFailed: split.gate + split.other,
        technicalTotal: technical.total,
        criteriaFailed: technical.failed,
        gateReview,
        inputReview
    };
}

function metricFailedCheckSplit(run, fallbackFailedCount = 0) {
    const split = { customer: 0, input: 0, gate: 0, other: 0 };
    const failedChecks = metricEvaluatedChecks(run).filter(check => check && !check.pass);
    failedChecks.forEach(check => {
        const evidence = metricPurposeEvidenceForCheck(run, check);
        const scopes = evidence.map(item => upperText(item?.readinessScope));
        if (evidence.some(item => Boolean(item?.customerVisible)
                && upperText(item?.readinessScope) === 'CUSTOMER_PROMPT_QUALITY')) {
            split.customer += 1;
        } else if (scopes.includes('INPUT_READINESS')) {
            split.input += 1;
        } else if (scopes.includes('INTERNAL_EXECUTION_GATE')) {
            split.gate += 1;
        } else {
            split.other += 1;
        }
    });
    const counted = split.customer + split.input + split.gate + split.other;
    const fallback = Math.max(Number(fallbackFailedCount || 0) - counted, 0);
    if (fallback > 0) {
        split.other += fallback;
    }
    return split;
}

function metricTechnicalCheckCounts(run, detail = {}) {
    if (metricNotApplicable(run)) {
        return { passed: 0, failed: 0, total: 0 };
    }
    const checks = metricEvaluatedChecks(run);
    const totalFromSnapshot = firstNumber(
            run?.totalChecks,
            run?.totalCheckCount,
            run?.total_checks,
            run?.total_check_count);
    const passedFromSnapshot = firstNumber(
            run?.passedChecks,
            run?.passedCheckCount,
            run?.passed_checks,
            run?.passed_check_count);
    const failedFromSnapshot = firstNumber(
            run?.failedCheckCount,
            run?.failedChecks,
            run?.failed_check_count,
            run?.failed_checks);
    const hasSnapshotCounts = totalFromSnapshot !== null || passedFromSnapshot !== null || failedFromSnapshot !== null;
    if (hasSnapshotCounts) {
        const total = Number(totalFromSnapshot || 0);
        const passed = Number(passedFromSnapshot || 0);
        const failed = Number(failedFromSnapshot ?? Math.max(total - passed, 0));
        return { passed, failed, total };
    }
    const passed = checks.filter(check => check && check.pass).length;
    const total = checks.length;
    return {
        passed,
        failed: Math.max(total - passed, 0),
        total
    };
}

function firstNumber(...values) {
    for (const value of values) {
        if (value === null || value === undefined || value === '') {
            continue;
        }
        const number = Number(value);
        if (Number.isFinite(number)) {
            return number;
        }
    }
    return null;
}

function metricGateReview(run, detail = {}) {
    if (!run || metricPromptIssueCount(run, detail) > 0) {
        return false;
    }
    return ensureArray(run?.checks).some(check => !check?.pass
            && metricPurposeEvidenceForCheck(run, check)
                    .some(item => upperText(item?.readinessScope) === 'INTERNAL_EXECUTION_GATE'));
}

function metricEvaluatedChecks(run) {
    return ensureArray(run?.checks).filter(check => check
            && !isNotApplicableMetricCheck(run, check)
            && upperText(check?.readinessScope) !== 'INTERNAL_REFERENCE');
}

function isNotApplicableMetricCheck(runOrCheck, maybeCheck = null) {
    const run = maybeCheck ? runOrCheck : null;
    const check = maybeCheck || runOrCheck;
    if (upperText(check?.purposeResult) === 'NOT_APPLICABLE'
            || upperText(check?.inputReadinessState) === 'NOT_APPLICABLE'
            || upperText(check?.applicabilityState) === 'NOT_APPLICABLE') {
        return true;
    }
    if (!run) {
        return false;
    }
    const evidence = metricPurposeEvidenceForCheck(run, check);
    return evidence.length > 0 && evidence.every(item => {
        const result = upperText(item?.purposeResult);
        const input = upperText(item?.inputReadinessState);
        const applicability = upperText(item?.applicabilityState);
        return result === 'NOT_APPLICABLE'
                || input === 'NOT_APPLICABLE'
                || applicability === 'NOT_APPLICABLE';
    });
}

function metricInputReadinessReview(run) {
    return ensureArray(run?.checks).some(check => !check?.pass
            && metricPurposeEvidenceForCheck(run, check)
                    .some(item => upperText(item?.readinessScope) === 'INPUT_READINESS'));
}

function metricPromptIssueCount(run, detail = {}) {
    const detailActualProblems = ensureArray(detail?.actualPromptProblems);
    if (detailActualProblems.length) {
        return actualProblemsForMetric(detailActualProblems, run?.metricCode).length;
    }
    const runActualProblems = ensureArray(run?.actualPromptProblems);
    if (runActualProblems.length) {
        return actualProblemsForMetric(runActualProblems, run?.metricCode).length;
    }
    return 0;
}

function metricOfficialFailures(run, officialFailures = []) {
    const metricCode = upperText(run?.metricCode);
    if (!metricCode) {
        return [];
    }
    return ensureArray(officialFailures).filter(item => upperText(item?.metricCode) === metricCode);
}

function renderMetricCheckSummary(countsOrPassed, failed, total) {
    const counts = typeof countsOrPassed === 'object' && countsOrPassed !== null
            ? countsOrPassed
            : {
                actualProblemCount: Number(failed || 0),
                technicalPassed: Number(countsOrPassed || 0),
                technicalFailed: 0,
                technicalTotal: Number(total || 0)
            };
    return `
        <div class="pqa-metric-check-summary">
            <span class="${counts.actualProblemCount ? 'is-blocked' : 'is-ready'}">문제 ${escapeHtml(String(counts.actualProblemCount || 0))}개</span>
            <span>${escapeHtml(criteriaProgressText(counts))}</span>
            ${counts.inputFailed ? `<span class="is-pending">사전 입력 문제 ${escapeHtml(String(counts.inputFailed))}개</span>` : ''}
            ${counts.gateFailed ? `<span class="is-pending">추가 확인 ${escapeHtml(String(counts.gateFailed))}개</span>` : ''}
            ${counts.otherFailed ? `<span class="is-pending">확인 필요 ${escapeHtml(String(counts.otherFailed))}개</span>` : ''}
        </div>
    `;
}

function criteriaProgressText(counts = {}) {
    if (counts.notApplicable) {
        return '적용 기준 없음';
    }
    const total = Number(counts.technicalTotal || 0);
    const passed = Number(counts.technicalPassed || 0);
    if (!total) {
        return '판정 기준 없음';
    }
    return `${total}개 중 ${passed}개 충족`;
}

function criteriaIssueSplitText(counts = {}) {
    const promptProblems = Number(counts.actualProblems ?? counts.actualProblemCount ?? counts.failed ?? 0);
    const certificateChecks = Number(counts.gateFailed ?? counts.technicalFailed ?? 0);
    const gateChecks = Number(counts.gateConditions ?? 0);
    const inputChecks = Number(counts.inputFailed ?? counts.inputReadinessChecks ?? 0);
    const otherChecks = Number(counts.otherFailed ?? 0);
    const parts = [];
    if (promptProblems > 0) {
        parts.push(`프롬프트 문제 ${promptProblems}개`);
    }
    if (gateChecks > 0 || certificateChecks > 0) {
        parts.push(`추가 확인 ${gateChecks || certificateChecks}개`);
    }
    if (inputChecks > 0) {
        parts.push(`사전 입력 문제 ${inputChecks}개`);
    }
    if (otherChecks > 0) {
        parts.push(`확인 필요 ${otherChecks}개`);
    }
    return parts.length ? parts.join(' · ') : '모두 충족';
}

function metricScoreDisplay(run, counts = {}) {
    if (metricNotApplicable(run)) {
        return '대상 아님';
    }
    if (counts.actualProblemCount > 0) {
        return '차단';
    }
    if (counts.inputFailed > 0 || counts.inputReview || metricInputReadinessReview(run)) {
        return '사전 입력 문제';
    }
    if (counts.gateFailed > 0 || counts.gateReview || metricGateReview(run, { actualPromptProblems: run?.actualPromptProblems || [] })) {
        return '추가 확인';
    }
    if (counts.otherFailed > 0) {
        return '확인 필요';
    }
    return Number(run?.score || 0).toFixed(1);
}

function metricDisplayStateLabel(run, counts = {}) {
    if (metricNotApplicable(run)) {
        return '검사 대상 아님';
    }
    if (counts.actualProblemCount > 0) {
        return '차단';
    }
    if (counts.inputFailed > 0 || metricInputReadinessReview(run)) {
        return '사전 입력 문제';
    }
    if (counts.gateFailed > 0 || metricGateReview(run, { actualPromptProblems: run?.actualPromptProblems || [] })) {
        return '추가 확인';
    }
    if (counts.otherFailed > 0 || (!passState(run?.state) && rawText(run?.state))) {
        return '확인 필요';
    }
    return '통과';
}

function metricGateSummaryText(run, counts = {}) {
    const summary = counts && Object.prototype.hasOwnProperty.call(counts, 'gateFailed')
            ? counts
            : metricCheckCounts(run, [], { actualPromptProblems: run?.actualPromptProblems || [] });
    if (!Number(summary.gateFailed || 0)) {
        return '';
    }
    const code = upperText(run?.metricCode);
    const failedCount = Number(summary.gateFailed || 0);
    if (code === 'MTR') {
        return failedCount ? `실행 이력 연결 ${failedCount}개를 확인해야 합니다.` : '실행 이력 연결 확인이 필요합니다.';
    }
    if (code === 'PRE') {
        return failedCount ? `보호 리소스 ${failedCount}개를 확인해야 합니다.` : '보호 리소스 확인이 필요합니다.';
    }
    return failedCount ? `추가 확인 ${failedCount}개를 처리해야 합니다.` : '추가 확인이 필요합니다.';
}
function metricDisplayStateTone(run, counts = {}) {
    if (metricNotApplicable(run)) {
        return 'neutral';
    }
    if (counts.actualProblemCount > 0) {
        return 'blocked';
    }
    if (counts.technicalFailed > 0 || counts.inputReview || metricInputReadinessReview(run)) {
        return 'pending';
    }
    return passState(run?.state) ? 'ready' : 'pending';
}

function metricNotApplicable(run) {
    return upperText(run?.state) === 'NOT_APPLICABLE'
            || (ensureArray(run?.checks).some(check => isNotApplicableMetricCheck(run, check))
                    && metricEvaluatedChecks(run).length === 0);
}

async function showOfficialRunDetail(tableRoot, runId, trigger) {
    const officialRunId = rawText(runId);
    if (!officialRunId) {
        const message = trigger?.dataset?.pqaDisabledReason || t('enterprise.pqa.verification.metricDetail.missingRunId');
        showActionTooltip(root, trigger, message, 'blocked');
        setStatus(root, 'error', t('enterprise.pqa.common.action.blocked.title'), message);
        return;
    }
    const ledger = tableRoot?.closest?.('[data-pqa-official-ledger]') || document;
    const panel = ledger.querySelector('[data-pqa-official-run-detail]');
    if (panel) {
        panel.hidden = true;
        panel.innerHTML = '';
    }
    const modal = ensureOfficialRunDetailModal();
    setOfficialRunDetailModalBody(
            modal,
            `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.metricDetail.loading'))}</p></div>`);
    openOfficialRunDetailModal(modal);
    try {
        const run = await loadMetricDetail(officialRunId);
        setOfficialRunDetailModalBody(modal, renderOfficialRunDetail(run || {}));
    }
    catch (error) {
        setOfficialRunDetailModalBody(
                modal,
                `<div class="pqa-empty pqa-empty-error"><p>${escapeHtml(t('enterprise.pqa.verification.metricDetail.failed'))}: ${escapeHtml(publicError(error))}</p></div>`);
    }
}

function ensureOfficialRunDetailModal() {
    let modal = document.querySelector('[data-pqa-official-run-modal]');
    if (modal) {
        return modal;
    }
    modal = document.createElement('section');
    modal.className = 'pqa-modal-backdrop pqa-official-run-modal-backdrop';
    modal.setAttribute('data-pqa-official-run-modal', '');
    modal.setAttribute('data-pqa-page', 'verification');
    modal.hidden = true;
    modal.innerHTML = `
        <div class="pqa-modal pqa-official-run-modal" role="dialog" aria-modal="true" aria-labelledby="pqa-official-run-modal-title">
            <div class="pqa-official-run-modal-head">
                <div>
                    <span class="pqa-section-pill">지표 상세</span>
                    <h2 id="pqa-official-run-modal-title">지표 목적 판정</h2>
                    <p>이 지표가 무엇을 보증했고, 무엇을 해결해야 하는지만 표시합니다.</p>
                </div>
                <button type="button" class="pqa-secondary-button" data-pqa-official-run-modal-close>${escapeHtml(t('enterprise.pqa.verification.metricDetail.close'))}</button>
            </div>
            <div class="pqa-official-run-modal-body" data-pqa-official-run-modal-body></div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.addEventListener('click', event => {
        if (event.target.matches('[data-pqa-official-run-modal], [data-pqa-official-run-modal-close]')) {
            closeOfficialRunDetailModal();
        }
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && !modal.hidden) {
            closeOfficialRunDetailModal();
        }
    });
    return modal;
}

function setOfficialRunDetailModalBody(modal, html) {
    const body = modal?.querySelector?.('[data-pqa-official-run-modal-body]');
    if (body) {
        body.innerHTML = html;
    }
}

function openOfficialRunDetailModal(modal) {
    if (!modal) {
        return;
    }
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    modal.querySelector('[data-pqa-official-run-modal-close]')?.focus();
}

function closeOfficialRunDetailModal() {
    const modal = document.querySelector('[data-pqa-official-run-modal]');
    if (modal) {
        modal.hidden = true;
        document.body.style.overflow = '';
    }
}

async function loadMetricDetail(runId) {
    return getJson(`/contexa/admin/api/prompt-quality/verification/runs/${encodeURIComponent(runId)}/metric-detail`);
}

function renderOfficialRunDetail(run) {
    const counts = metricCheckCounts(run, [], {
        promptComparisons: run?.comparisons || [],
        actualPromptProblems: run?.actualPromptProblems || []
    });
    const notApplicable = metricNotApplicable(run);
    const blocked = counts.actualProblemCount > 0;
    const review = counts.technicalFailed > 0 || counts.inputReview;
    const shellState = blocked ? 'blocked' : (review ? 'pending' : 'ready');
    return `
        <article class="pqa-official-run-detail-card pqa-metric-modal-shell ${shellState}">
            ${renderMetricModalHero(run, counts)}
            ${counts.actualProblemCount > 0 || notApplicable ? '' : renderMetricResolutionPath(run, counts)}
            ${renderMetricDetailSummary(run, counts)}
            ${notApplicable ? '' : renderMetricFailureCards(run)}
            ${renderMetricCheckTable(run)}
            ${notApplicable ? '' : renderMetricLedgerFacts(run)}
        </article>
    `;
}

function renderMetricModalHero(run, counts) {
    const actualBlocked = counts.actualProblemCount > 0;
    const internalBlocked = !actualBlocked && counts.technicalFailed > 0;
    const inputBlocked = !actualBlocked && !internalBlocked && counts.inputReview;
    const notApplicable = metricNotApplicable(run);
    const stateLabel = metricDisplayStateLabel(run, counts);
    const title = notApplicable
            ? firstCleanText(run?.operatorTitle, run?.metricName)
            : actualBlocked
            ? '프롬프트 개선 필요'
            : internalBlocked
                    ? '추가 확인 필요'
                    : inputBlocked
                            ? '사전 입력 문제'
                            : 'LLM 투입 가능';
    const detail = notApplicable
            ? firstCleanText(run?.operatorSummary, run?.nextAction, run?.reverifyCriterion)
            : actualBlocked
            ? '아래 문제를 해결한 뒤 다시 검사하십시오.'
            : internalBlocked
            ? '프롬프트 문제는 없습니다. 리소스와 검사 기록 조건을 확인하십시오.'
                    : inputBlocked
                            ? '프롬프트 문제로 판정하지 않습니다. 최신 봉인 증거를 선택한 뒤 다시 검사하십시오.'
                            : '이 지표의 판정 기준을 충족했습니다.';
    const purpose = metricPurposeDisplay(run);
    return `
        <section class="pqa-metric-modal-hero">
            <div class="pqa-metric-modal-hero-copy">
                <span>${escapeHtml(text(run.metricCode))} · ${escapeHtml(metricGroupLabel(run.groupName || run.metricGroup))}</span>
                <h3>${escapeHtml(title)}</h3>
                <p>${escapeHtml(detail)}</p>
                ${purpose ? `<div class="pqa-metric-purpose-line"><span>지표 목적</span><strong>${escapeHtml(purpose)}</strong></div>` : ''}
            </div>
            <div class="pqa-metric-modal-verdict">
                ${badge(stateLabel, { tone: metricDisplayStateTone(run, counts) })}
            </div>
        </section>
    `;
}

function renderMetricResolutionPath(run, counts) {
    const lane = {
        tone: metricDisplayStateTone(run, counts),
        label: firstCleanText(run?.stateLabel, run?.state),
        title: firstCleanText(run?.operatorTitle, run?.metricName, run?.metricCode),
        detail: firstCleanText(run?.nextAction, run?.operatorSummary, run?.reverifyCriterion),
        actions: []
    };
    if (!lane.label && !lane.title && !lane.detail) {
        return '';
    }
    return `
        <section class="pqa-metric-resolution-path ${escapeHtml(lane.tone)}">
            <div class="pqa-metric-resolution-copy">
                <span>${escapeHtml(lane.label)}</span>
                <strong>${escapeHtml(lane.title)}</strong>
                <p>${escapeHtml(lane.detail)}</p>
                ${renderResolutionActions(lane.actions)}
            </div>
        </section>
    `;
}

function renderMetricDetailSummary(run, counts) {
    const summary = counts || metricCheckCounts(run, [], {
        promptComparisons: run?.comparisons || [],
        actualPromptProblems: run?.actualPromptProblems || []
    });
    if (metricNotApplicable(run)) {
        const reason = firstCleanText(run?.operatorSummary, run?.primaryFailureReason, run?.nextAction, run?.reverifyCriterion);
        return `
            <section class="pqa-metric-modal-kpis" aria-label="지표 상세 요약">
                <article class="ready">
                    <span>프롬프트 문제</span>
                    <strong>0개</strong>
                    <small>없음</small>
                </article>
                <article class="neutral">
                    <span>적용 상태</span>
                    <strong>검사 대상 아님</strong>
                    <small>조치 없음</small>
                </article>
            </section>
            ${reason ? `
                <section class="pqa-official-run-subsection pqa-metric-not-applicable-reason">
                    <div class="pqa-metric-section-title">
                        <div>
                            <h4>적용 제외 사유</h4>
                            <p>${escapeHtml(reason)}</p>
                        </div>
                    </div>
                </section>
            ` : ''}
        `;
    }
    const cards = [
        {
            tone: summary.actualProblemCount ? 'blocked' : 'ready',
            label: '프롬프트 문제',
            value: `${summary.actualProblemCount || 0}개`,
            hint: summary.actualProblemCount ? '개선 필요' : '없음'
        },
        {
            tone: 'neutral',
            label: '판정 기준',
            value: metricModalCriteriaText(summary),
            hint: metricModalCriteriaHint(summary)
        }
    ];
    if ((summary.inputFailed || 0) > 0) {
        cards.push({
            tone: 'pending',
            label: '사전 입력 문제',
            value: `${summary.inputFailed || 0}개`,
            hint: '입력 해결'
        });
    }
    if ((summary.gateFailed || 0) > 0) {
        cards.push({
            tone: 'pending',
            label: '추가 확인',
            value: `${summary.gateFailed || 0}개`,
            hint: '추가 확인'
        });
    }
    if ((summary.otherFailed || 0) > 0) {
        cards.push({
            tone: 'pending',
            label: '확인 필요',
            value: `${summary.otherFailed || 0}개`,
            hint: '원장 확인'
        });
    }
    return `
        <section class="pqa-metric-modal-kpis" aria-label="지표 상세 요약">
            ${cards.map(card => `
                <article class="${escapeHtml(card.tone)}">
                    <span>${escapeHtml(card.label)}</span>
                    <strong>${escapeHtml(card.value)}</strong>
                    <small>${escapeHtml(card.hint)}</small>
                </article>
            `).join('')}
        </section>
    `;
}

function metricModalCriteriaText(summary) {
    const total = Number(summary?.technicalTotal ?? summary?.totalChecks ?? 0);
    const passed = Number(summary?.technicalPassed ?? summary?.passedChecks ?? 0);
    return total ? `${passed}개 / ${total}개` : '판정 기준 없음';
}

function metricModalCriteriaHint(summary) {
    const total = Number(summary?.technicalTotal ?? summary?.totalChecks ?? 0);
    const passed = Number(summary?.technicalPassed ?? summary?.passedChecks ?? 0);
    const failed = Math.max(0, total - passed);
    if (!failed) {
        return '모두 충족';
    }
    return criteriaIssueSplitText(summary);
}

function metricPurposeDisplay(run) {
    return firstCleanText(run?.metricQualityQuestion, run?.metricPurpose);
}

function renderMetricFailureCards(run) {
    const groups = groupMetricFailureCauses(run);
    if (!groups.length) {
        const counts = metricCheckCounts(run, [], {
            promptComparisons: run?.comparisons || [],
            actualPromptProblems: run?.actualPromptProblems || []
        });
        const message = counts.inputReview
                ? '프롬프트 문제는 없습니다. 최신 봉인 증거를 선택한 뒤 다시 검사하십시오.'
                : counts.technicalFailed > 0
                        ? '프롬프트 문제는 없습니다. 아래 추가 확인 항목을 처리하십시오.'
                        : '이 지표에 연결된 프롬프트 문제가 없습니다.';
        return `<section class="pqa-official-run-subsection"><div class="pqa-empty"><p>${escapeHtml(message)}</p></div></section>`;
    }
    return `
        <section class="pqa-official-run-subsection pqa-metric-problem-section">
            <div class="pqa-metric-section-title">
                <div>
                    <h4>해결할 항목</h4>
                    <p>아래 항목의 확인된 근거와 해결 작업을 처리하십시오.</p>
                </div>
                <span>${escapeHtml(`${groups.length}개`)}</span>
            </div>
            <div class="pqa-metric-problem-grid pqa-assurance-problem-list">
                ${groups.map(group => renderMetricFailureCard(run, group)).join('')}
            </div>
        </section>
    `;
}

function renderMetricFailureCard(run, group) {
    const primary = group.items[0] || {};
    return renderAssuranceProblemCard(primary, {
        tag: 'article',
        extraClass: 'pqa-metric-problem-card',
        showStateBadge: false
    });
}

function renderMetricCheckTable(run) {
    if (metricNotApplicable(run)) {
        return '';
    }
    const checks = sortChecksProblemFirst(metricEvaluatedChecks(run));
    if (!checks.length) {
        return '';
    }
    const passed = checks.filter(check => check.pass).length;
    const failedChecks = checks.filter(check => !check.pass);
    const purposeFailedChecks = failedChecks.filter(check => metricCheckCustomerVisible(run, check));
    const reviewChecks = failedChecks.filter(check => !metricCheckCustomerVisible(run, check));
    const passedChecks = checks.filter(check => check.pass);
    const counts = metricCheckCounts(run, [], {
        promptComparisons: run?.comparisons || [],
        actualPromptProblems: run?.actualPromptProblems || []
    });
    const promptProblemMode = counts.actualProblemCount > 0;
    if (promptProblemMode) {
        return `
            <section class="pqa-official-run-subsection pqa-metric-ledger-section">
                <div class="pqa-metric-section-title">
                    <div>
                        <h4>판정 기준</h4>
                        <p>미충족 기준은 위 해결 항목에 합쳐서 표시했습니다.</p>
                    </div>
                    <span>${escapeHtml(`${checks.length}개 중 ${passed}개 충족`)}</span>
                </div>
                ${passedChecks.length
                        ? `<details class="pqa-metric-raw-ledger-shell pqa-metric-passed-criteria">
                                <summary>
                                    <span>충족한 기준 ${escapeHtml(String(passedChecks.length))}개</span>
                                    <small>필요할 때만 확인</small>
                                </summary>
                                ${renderMetricCriteriaList(passedChecks, true, run)}
                           </details>`
                        : ''}
                ${reviewChecks.length
                        ? `<section class="pqa-metric-review-panel pqa-metric-raw-ledger-shell pqa-metric-review-criteria">
                                <div class="pqa-metric-review-head">
                                    <strong>${escapeHtml(metricReviewSectionLabel(run, reviewChecks))} ${escapeHtml(String(reviewChecks.length))}개</strong>
                                    <span>${escapeHtml(metricReviewActionText(run, reviewChecks))}</span>
                                </div>
                                ${renderMetricCriteriaList(reviewChecks, false, run)}
                           </section>`
                        : ''}
            </section>
        `;
    }
    return `
        <section class="pqa-official-run-subsection pqa-metric-ledger-section">
            <div class="pqa-metric-section-title">
                <div>
                    <h4>판정 기준</h4>
                    <p>각 기준의 결과와 DB에 저장된 근거입니다.</p>
                </div>
                <span>${escapeHtml(`${checks.length}개 중 ${passed}개 충족`)}</span>
            </div>
            ${purposeFailedChecks.length
                    ? renderMetricCriteriaList(purposeFailedChecks, false, run)
                    : `<div class="pqa-metric-criteria-empty">${badge(reviewChecks.length ? '프롬프트 문제 없음' : '모두 충족', { tone: 'ready' })}<span>${escapeHtml(reviewChecks.length ? 'LLM 사용자 프롬프트 개선 대상은 없습니다.' : '이 지표의 판정 기준을 모두 충족했습니다.')}</span></div>`}
            ${reviewChecks.length
                    ? `<section class="pqa-metric-review-panel pqa-metric-raw-ledger-shell pqa-metric-review-criteria">
                            <div class="pqa-metric-review-head">
                                <strong>${escapeHtml(metricReviewSectionLabel(run, reviewChecks))} ${escapeHtml(String(reviewChecks.length))}개</strong>
                                <span>${escapeHtml(metricReviewActionText(run, reviewChecks))}</span>
                            </div>
                            ${renderMetricCriteriaList(reviewChecks, false, run)}
                       </section>`
                    : ''}
            ${passedChecks.length
                    ? `<details class="pqa-metric-raw-ledger-shell pqa-metric-passed-criteria">
                            <summary>
                                <span>충족한 기준 ${escapeHtml(String(passedChecks.length))}개</span>
                                <small>필요할 때만 확인</small>
                            </summary>
                            ${renderMetricCriteriaList(passedChecks, true, run)}
                       </details>`
                    : ''}
        </section>
    `;
}

function renderMetricCriteriaList(checks, passedOnly = false, run = null) {
    return `
        <div class="pqa-metric-criteria-list ${passedOnly ? 'passed' : 'failed'}">
            ${ensureArray(checks).map(check => {
                const evidence = metricPurposeEvidenceForCheck(run, check);
                const label = metricCriteriaCardLabel(run, check);
                const cardClass = check.pass ? 'is-ready' : label.tone === 'warning' ? 'is-review' : 'is-blocked';
                const primary = customerVisiblePurposeEvidence(evidence)
                        || metricCriteriaFallbackEvidence(check, evidence, passedOnly);
                if (!primary) {
                    return '';
                }
                const title = rawText(primary.signalKey);
                const resultText = rawText(primary.evidenceValue);
                const runtimeFacts = customerVisibleItemList(primary.runtimeFacts);
                const contextItems = customerVisibleItemList(primary.contextItems);
                return `
                    <article class="pqa-metric-criteria-card ${cardClass}">
                        <header class="pqa-metric-criteria-card-head">
                            <div class="pqa-metric-criteria-title">
                                <span class="pqa-metric-criteria-kicker">${escapeHtml(label.kicker)}</span>
                                <strong>${escapeHtml(title)}</strong>
                            </div>
                            ${badge(label.badge, { tone: label.tone })}
                        </header>
                        <div class="pqa-metric-criteria-body">
                            ${resultText ? `<section class="pqa-metric-criteria-cell">
                                <span>검사 의미</span>
                                <p>${escapeHtml(resultText)}</p>
                            </section>` : ''}
                        </div>
                        ${runtimeFacts.length ? `<div class="pqa-metric-criteria-summary pqa-metric-criteria-summary-block">
                            <section><span>실제 확인값</span>${renderMetricEvidenceItems(runtimeFacts, 'fact')}</section>
                        </div>` : ''}
                        ${contextItems.length ? `<div class="pqa-metric-criteria-summary pqa-metric-criteria-summary-block">
                            <section><span>검사한 프롬프트 항목</span>${renderMetricEvidenceItems(contextItems, 'context')}</section>
                        </div>` : ''}
                    </article>
                `;
            }).join('')}
        </div>
    `;
}

function metricCriteriaFallbackEvidence(check, evidence = [], passedOnly = false) {
    if (!passedOnly && !check?.pass) {
        return null;
    }
    const signalKey = firstCleanText(
            check?.checkLabel,
            check?.label,
            metricPassedFriendlyTitle(check),
            check?.checkCode,
            '판정 기준');
    const evidenceValue = firstCleanText(
            metricCriteriaResultSummary(check),
            check?.operatorReason,
            check?.actualValue,
            check?.expectedValue,
            check?.decisionUtility,
            '검사 기준을 통과했습니다.');
    const runtimeFacts = customerVisibleItemList(
            check?.runtimeFacts,
            check?.facts,
            check?.evidenceFacts);
    const contextItems = distinctText([
        ...customerVisibleItemsFromEvidence(evidence),
        ...customerVisibleItemList(
                check?.contextItems,
                check?.customerVisibleContextItems,
                check?.promptItems,
                check?.customerVisiblePromptItems)
    ]);
    return {
        signalKey,
        evidenceValue,
        runtimeFacts,
        contextItems
    };
}

function renderMetricEvidenceItems(items = [], type = 'fact') {
    const values = customerVisibleItemList(items);
    if (!values.length) {
        return '';
    }
    const className = type === 'context'
            ? 'pqa-metric-evidence-items is-context'
            : 'pqa-metric-evidence-items is-fact';
    return `
        <ul class="${className}">
            ${values.map(value => `<li>${escapeHtml(value)}</li>`).join('')}
        </ul>
    `;
}

function renderMetricPassedCriteriaList(checks, run = null) {
    return renderMetricCriteriaList(checks, true, run);
}

function customerVisiblePurposeEvidence(evidence = []) {
    return ensureArray(evidence).find(row =>
            Boolean(row?.customerVisible)
            && rawText(row?.signalKey)
            && (rawText(row?.evidenceValue)
                    || customerVisibleItemList(row?.runtimeFacts).length
                    || customerVisibleItemList(
                            row?.contextItems,
                            row?.customerVisibleContextItems,
                            row?.promptItems,
                            row?.customerVisiblePromptItems).length));
}

function customerVisibleItemList(...values) {
    for (const value of values) {
        if (Array.isArray(value)) {
            return value.map(rawText).filter(Boolean);
        }
    }
    return [];
}

function customerVisibleItemsFromEvidence(evidence = []) {
    const items = [];
    ensureArray(evidence).forEach(row => {
        items.push(...customerVisibleItemList(
                row?.contextItems,
                row?.customerVisibleContextItems,
                row?.promptItems,
                row?.customerVisiblePromptItems));
    });
    return distinctText(items);
}

function metricPassedFriendlyTitle(check) {
    const title = metricIssueTitle(check)
            .replace(/\s*확인 완료$/g, '')
            .replace(/\s*보강 필요$/g, '')
            .replace(/\s*체크$/g, '')
            .trim();
    return title || '판정 기준 확인';
}

function metricConsistencyOutcome(evidence = []) {
    for (const item of ensureArray(evidence)) {
        const candidates = [
            firstCleanText(item?.signalKey),
            firstCleanText(item?.evidenceValue)
        ].filter(Boolean);
        for (const value of candidates) {
            const match = value.match(/(?:consistencyOutcome|stageNoteRelation)=([^,;\s]+)/i);
            if (match && match[1]) {
                return match[1].trim().toUpperCase();
            }
        }
    }
    return '';
}

function metricCriteriaResultSummary(check) {
    let value = firstCleanText(check?.actualValue, check?.operatorReason);
    if (!value) {
        return '';
    }
    value = value.split(/\sEvidence:\s/i)[0].trim();
    value = value.replace(/^확인 결과:\s*/, '').trim();
    value = value.replace(/^[^.]+기준을 충족했습니다\.\s*/, '').trim();
    value = value.replace(/^확인값은\s*/, '').trim();
    value = value.replace(/입니다\.?$/, '').trim();
    value = value.replace(/^final userPrompt에는\s*/, 'final userPrompt에 ');
    value = value.replace(/^system prompt가\s*/, 'system prompt가 ');
    return value;
}

function metricCriteriaCardLabel(run, check) {
    if (check?.pass) {
        return { kicker: '확인 기준', badge: '충족', tone: 'ready' };
    }
    const evidence = metricPurposeEvidenceForCheck(run, check);
    if (evidence.some(item => upperText(item?.readinessScope) === 'INPUT_READINESS')) {
        return { kicker: '사전 입력 항목', badge: '입력 준비', tone: 'warning' };
    }
    if (evidence.some(item => upperText(item?.readinessScope) === 'INTERNAL_EXECUTION_GATE')) {
        return { kicker: '추가 확인 항목', badge: '확인 필요', tone: 'warning' };
    }
    if (evidence.some(item => Boolean(item?.customerVisible)
            && upperText(item?.readinessScope) === 'CUSTOMER_PROMPT_QUALITY')) {
        return { kicker: '프롬프트 개선 기준', badge: '개선 필요', tone: 'blocked' };
    }
    return { kicker: '확인 항목', badge: '확인 필요', tone: 'warning' };
}

function metricPurposeEvidenceForCheck(run, check) {
    const metricCode = upperText(run?.metricCode);
    const checkCode = upperText(check?.checkCode);
    return ensureArray(run?.purposeEvidence)
            .filter(item => (!metricCode || upperText(item?.metricCode) === metricCode)
                    && (!checkCode || metricCheckCodesMatch(metricCode, checkCode, upperText(item?.checkCode))));
}

function metricCheckCodesMatch(metricCode, runCheckCode, evidenceCheckCode) {
    const runCode = upperText(runCheckCode);
    const evidenceCode = upperText(evidenceCheckCode);
    if (!runCode || !evidenceCode) {
        return false;
    }
    if (runCode === evidenceCode) {
        return true;
    }
    const metric = upperText(metricCode);
    if (!metric) {
        return false;
    }
    return stripMetricPrefix(metric, runCode) === stripMetricPrefix(metric, evidenceCode);
}

function stripMetricPrefix(metricCode, checkCode) {
    const metric = upperText(metricCode);
    const code = upperText(checkCode);
    const prefix = `${metric}_`;
    return code.startsWith(prefix) ? code.slice(prefix.length) : code;
}

function metricCheckCustomerVisible(run, check) {
    const evidence = metricPurposeEvidenceForCheck(run, check);
    if (evidence.length) {
        return evidence.some(item => Boolean(item?.customerVisible)
                && upperText(item?.readinessScope) === 'CUSTOMER_PROMPT_QUALITY');
    }
    return false;
}

function metricReviewSectionLabel(run, checks = []) {
    const evidence = checks.flatMap(check => metricPurposeEvidenceForCheck(run, check));
    if (evidence.some(item => upperText(item?.readinessScope) === 'INPUT_READINESS')) {
        return '사전 입력 문제';
    }
    if (evidence.some(item => upperText(item?.readinessScope) === 'INTERNAL_EXECUTION_GATE')) {
        return '추가 확인';
    }
    return '추가 확인';
}

function metricReviewActionText(run, checks = []) {
    const evidence = checks.flatMap(check => metricPurposeEvidenceForCheck(run, check));
    if (evidence.some(item => upperText(item?.readinessScope) === 'INPUT_READINESS')) {
        return '사전 입력값을 보강한 뒤 다시 검사하십시오.';
    }
    if (evidence.some(item => upperText(item?.readinessScope) === 'INTERNAL_EXECUTION_GATE')) {
        return '추가 확인에서 필요한 항목을 처리하십시오.';
    }
    return '아래 항목을 확인한 뒤 다시 검사하십시오.';
}

function metricPurposeEvidenceSummary(evidence) {
    const first = ensureArray(evidence).find(item => rawText(item?.interpretation));
    if (first) {
        return firstCleanText(first.interpretation);
    }
    return '';
}

function renderMetricLedgerFacts(run) {
    return `
        <section class="pqa-official-run-subsection pqa-metric-raw-ledger-section">
            <details class="pqa-metric-raw-ledger-shell">
                <summary>
                    <span>저장 기록</span>
                    <small>필요할 때만 원문 값을 확인합니다</small>
                </summary>
                <div class="pqa-official-run-fact-grid">
                    ${renderFactBlock(t('enterprise.pqa.verification.metricDetail.ledger.requestFacts'), run.requestFacts)}
                    ${renderFactBlock(t('enterprise.pqa.verification.metricDetail.ledger.promptFacts'), run.promptFacts)}
                    ${renderFactBlock(t('enterprise.pqa.verification.metricDetail.ledger.analysisFacts'), run.analysisFacts)}
                    ${renderEventsBlock(run.events)}
                    ${renderFactBlock(t('enterprise.pqa.verification.metricDetail.ledger.rawArtifact'), run.rawEvidence)}
                </div>
            </details>
        </section>
    `;
}

function renderFactBlock(title, value) {
    return `
        <details class="pqa-official-run-fact">
            <summary>${escapeHtml(title)}</summary>
            <pre>${escapeHtml(JSON.stringify(value || {}, null, 2))}</pre>
        </details>
    `;
}

function renderEventsBlock(events) {
    const items = ensureArray(events);
    return `
        <details class="pqa-official-run-fact">
            <summary>${escapeHtml(t('enterprise.pqa.verification.metricDetail.ledger.eventTimeline'))}</summary>
            <ol class="pqa-official-run-events">
                ${items.length ? items.map(event => `<li><strong>${escapeHtml(text(event.type))}</strong><span>${escapeHtml(text(event.layer))}</span><span>${escapeHtml(text(event.status))}</span><code>${escapeHtml(text(event.requestPath))}</code></li>`).join('') : `<li>${escapeHtml(t('enterprise.pqa.verification.metricDetail.ledger.events.empty'))}</li>`}
            </ol>
        </details>
    `;
}

function metricFailedChecks(run) {
    return metricEvaluatedChecks(run).filter(check => !check.pass);
}

function groupMetricFailureCauses(run) {
    const items = metricFailureItems(run);
    const groups = new Map();
    items.forEach(item => {
        const title = actualPromptProblemView(item).title;
        const owner = friendlyRemediationOwner(item.remediationOwner || item.affectedTarget || relatedComparison(run, item)?.recommendedOwner || item.source);
        const key = `${owner}|${title || rawText(item?.problemId)}`;
        if (!groups.has(key)) {
            groups.set(key, {
                title,
                owner,
                items: [],
                itemKeys: new Set(),
                sources: [],
                promptLocations: []
            });
        }
        const group = groups.get(key);
        const problemId = rawText(item?.problemId);
        const itemKey = problemId || [
            rawText(item?.checkCode),
            rawText(item?.source),
            rawText(item?.expectedValue),
            rawText(item?.actualValue)
        ].join('|');
        if (!group.itemKeys.has(itemKey)) {
            group.items.push(item);
            group.itemKeys.add(itemKey);
        }
        const source = compactEvidenceLocation(item.source);
        if (source && !group.sources.includes(source)) {
            group.sources.push(source);
        }
        const promptLocation = friendlyPromptLocation(item.promptLocation || relatedComparison(run, item)?.promptLocation);
        if (promptLocation && promptLocation !== '확인 불가' && !group.promptLocations.includes(promptLocation)) {
            group.promptLocations.push(promptLocation);
        }
    });
    return Array.from(groups.values()).sort((left, right) => right.items.length - left.items.length || left.title.localeCompare(right.title));
}

function metricFailureItems(run) {
    if (Array.isArray(run?.actualPromptProblems)) {
        const actualProblems = actualProblemsForMetric(run.actualPromptProblems, run?.metricCode);
        if (actualProblems.length) {
            return actualProblems.map(problem => actualProblemAsMetricFailureItem(run, problem));
        }
    }
    return [];
}

function actualProblemAsMetricFailureItem(run, problem) {
    return {
        problemId: rawText(problem?.problemId),
        fieldKey: rawText(problem?.fieldKey),
        problemType: rawText(problem?.problemType),
        promptLabel: rawText(problem?.promptLabel),
        promptSection: rawText(problem?.promptSection),
        sealedEvidencePath: rawText(problem?.sealedEvidencePath),
        sourceFieldPath: rawText(problem?.sourceFieldPath),
        metricCodes: ensureArray(problem?.metricCodes),
        metricCode: actualProblemMetricCodeForRun(problem, run?.metricCode),
        metricName: run?.metricName,
        checkCode: rawText(problem?.problemId),
        checkLabel: rawText(problem?.promptLabel),
        expectedValue: problem?.expectedState,
        actualValue: problem?.actualState,
        source: problem?.sealedEvidencePath || problem?.sourceFieldPath,
        promptLocation: problem?.promptSection,
        remediationOwner: problem?.remediationOwner,
        qualityQuestion: problem?.qualityQuestion,
        whyItMatters: problem?.whyItMatters,
        fixAction: problem?.fixAction,
        reverifyCriterionDetail: problem?.reverifyCriterionDetail,
        runtimeFacts: ensureArray(problem?.runtimeFacts),
        contextItems: ensureArray(problem?.contextItems),
        rootCause: problem?.whyItMatters,
        remediationHint: problem?.fixAction,
        reverifyCriterion: problem?.reverifyCriterionDetail
    };
}
function actualProblemMetricCodeForRun(problem, runMetricCode) {
    const normalizedRunMetric = upperText(runMetricCode);
    const metricCodes = ensureArray(problem?.metricCodes)
            .map(upperText)
            .filter(Boolean);
    if (normalizedRunMetric && metricCodes.includes(normalizedRunMetric)) {
        return normalizedRunMetric;
    }
    return metricCodes.length ? metricCodes[0] : normalizedRunMetric;
}

function comparisonAsMetricFailureItem(run, comparison) {
    const problemId = canonicalComparisonProblemId(comparison);
    return {
        problemId,
        metricCode: comparisonMetricCodeForRun(comparison, run?.metricCode),
        metricName: run?.metricName,
        checkCode: problemId || distinctText(comparison?.checkCodes || [])[0] || comparison?.fieldKey,
        checkLabel: comparison?.fieldLabel,
        expectedValue: comparisonExpectedDisplay(comparison),
        actualValue: comparisonActualDisplay(comparison),
        source: comparison?.evidenceSource,
        promptLocation: comparison?.promptLocation,
        remediationOwner: comparison?.recommendedOwner,
        rootCause: comparison?.meaning,
        remediationHint: comparison?.meaning,
        reverifyCriterion: `${text(comparison?.fieldLabel)} 항목이 같은 증거에서 기준을 통과해야 합니다.`
    };
}

function comparisonExpectedDisplay(comparison) {
    const state = upperText(comparison?.state);
    if (state === 'PROMPT_MISSING') {
        return '봉인 증거의 값이 최종 사용자 프롬프트에도 같은 의미로 있어야 합니다.';
    }
    if (state === 'FACT_MISSING') {
        return '최종 사용자 프롬프트의 값이 봉인 증거에도 같은 값으로 저장되어야 합니다.';
    }
    if (state === 'VALUE_MISMATCH') {
        return '최종 사용자 프롬프트와 봉인 증거가 같은 값을 가져야 합니다.';
    }
    return 'LLM이 해당 지표의 판단 목적을 수행할 수 있어야 합니다.';
}

function comparisonActualDisplay(comparison) {
    const state = upperText(comparison?.state);
    if (state === 'PROMPT_MISSING') {
        return '최종 사용자 프롬프트에서 확인되지 않음';
    }
    if (state === 'FACT_MISSING') {
        return '봉인 증거에서 확인되지 않음';
    }
    if (state === 'VALUE_MISMATCH') {
        return `프롬프트=${text(comparison?.promptValue)}, 봉인 증거=${text(comparison?.sealedEvidenceValue)}`;
    }
    return text(comparison?.meaning) || text(comparison?.stateLabel);
}

function metricIssueTitle(item) {
    return firstCleanText(
            item?.problemTitle,
            item?.promptLabel,
            item?.checkLabel,
            item?.label,
            item?.checkCode,
            '판정 기준');
}

function metricReferenceIssueTitle(item) {
    return metricIssueTitle(item);
}

function friendlyActualPromptIssueTitle(item) {
    return contractProblemText(item, 'promptLabel');
}

function metricIndividualCheckTitle(item) {
    return metricIssueTitle(item);
}

function metricExpectedDisplay(item) {
    return firstCleanText(
            item?.decisionUtility,
            item?.qualityQuestion,
            item?.expectedMessage,
            item?.expectedValue);
}

function metricRunSummaryText(run, counts = {}, displayedFailures = [], gateSummary = '') {
    const problemText = ensureArray(displayedFailures)
            .map(metricIssueTitle)
            .filter(Boolean)
            .slice(0, 2)
            .join(', ');
    if (problemText) {
        return problemText;
    }
    return gateSummary
            || rawText(run?.primaryFailureReason)
            || rawText(run?.operatorSummary)
            || t('enterprise.pqa.verification.value.none');
}

function simplifyExpectedValue(value) {
    return firstCleanText(value);
}

function simplifyActualValue(value) {
    return firstCleanText(value);
}

function humanizeMetricValue(value) {
    return firstCleanText(value);
}
function compactEvidenceLocation(source) {
    const value = rawText(source);
    if (!value) {
        return '근거 위치 확인 필요';
    }
    if (value.includes('baselineSnapshot.noveltySignals')) {
        return '봉인 증거 > 기준선 변화 신호';
    }
    if (value.includes('baselineSnapshot')) {
        return '봉인 증거 > 학습 기준선';
    }
    if (value.includes('canonicalContext')) {
        return '봉인 증거 > 표준 컨텍스트';
    }
    if (value.includes('requestFacts')) {
        return '봉인 증거 > 요청 사실';
    }
    if (value.includes('authState')) {
        return '봉인 증거 > 인증·권한';
    }
    if (value.includes('ragResults') || value.includes('retrieval')) {
        return '봉인 증거 > 학습 검색';
    }
    if (value.includes('decision')) {
        return '봉인 증거 > 판정 결과';
    }
    if (value.includes('promptExecutionMetadata')) {
        return '봉인 증거 > 프롬프트 실행 메타데이터';
    }
    if (value.includes('userPrompt')) {
        return '최종 프롬프트 > 사용자 프롬프트';
    }
    if (value.includes('systemPrompt')) {
        return '최종 프롬프트 > 시스템 프롬프트';
    }
    if (value.includes('sealedEvidence')) {
        return '봉인 증거';
    }
    return value;
}

function detailedEvidenceLocation(source) {
    const value = rawText(source);
    if (!value) {
        return '근거 위치 확인 필요';
    }
    const leaf = evidenceFieldLabel(value);
    const compact = compactEvidenceLocation(value);
    return leaf ? `${compact} > ${leaf}` : compact;
}

function evidenceFieldLabel(source) {
    const value = rawText(source);
    if (!value) {
        return '';
    }
    const last = value.split(/[.|]/u).filter(Boolean).pop() || '';
    const direct = {
        observationDays: '관찰 일수',
        eventCount: '관찰 이벤트 수',
        fallbackRatio: '대체 기준선 비율',
        coverage: '검색 문서 권한 범위',
        observedScope: '관찰 범위',
        personalComparableScope: '직접 비교 가능 이력',
        time: '접근 시간 변화 신호',
        network: '네트워크 변화 신호',
        browser: '브라우저 변화 신호',
        device: '장치 변화 신호',
        requestCombination: '요청 조합 변화 신호',
        state: '상태값'
    };
    if (direct[last]) {
        return direct[last];
    }
    if (value.includes('noveltySignals.time.state')) {
        return '접근 시간 변화 상태값';
    }
    if (value.includes('noveltySignals.network.state')) {
        return '네트워크 변화 상태값';
    }
    if (value.includes('noveltySignals.browser.state')) {
        return '브라우저 변화 상태값';
    }
    if (value.includes('noveltySignals.device.state')) {
        return '장치 변화 상태값';
    }
    if (value.includes('noveltySignals.requestCombination.state')) {
        return '요청 조합 변화 상태값';
    }
    return '';
}

function expectedFieldLabel(expectedValue) {
    const value = rawText(expectedValue);
    if (value.includes('observationDays')) {
        return '관찰 일수';
    }
    if (value.includes('eventCount')) {
        return '관찰 이벤트 수';
    }
    if (value.includes('fallbackRatio')) {
        return '대체 기준선 비율';
    }
    if (value.includes('coverage')) {
        return '검색 문서 권한 범위';
    }
    return '';
}

function checkCodeFieldLabel(checkCode) {
    const value = upperText(checkCode);
    if (value.includes('OBSERVATION_DAYS')) {
        return '관찰 일수';
    }
    if (value.includes('EVENT_COUNT')) {
        return '관찰 이벤트 수';
    }
    if (value.includes('FALLBACK_RATIO')) {
        return '대체 기준선 비율';
    }
    if (value.includes('COVERAGE')) {
        return '검색 문서 권한 범위';
    }
    return '';
}

function friendlyPromptLocation(location) {
    const value = rawText(location);
    if (!value) {
        return '확인 불가';
    }
    if (value.includes('userPrompt.baseline')) {
        return '사용자 프롬프트 > 기준선 설명';
    }
    if (value.includes('userPrompt.requestContext')) {
        return '사용자 프롬프트 > 요청 컨텍스트';
    }
    if (value.includes('systemPrompt')) {
        return '시스템 프롬프트';
    }
    if (value.includes('userPrompt')) {
        return '사용자 프롬프트';
    }
    return value;
}

function friendlyRemediationOwner(owner) {
    const value = rawText(owner);
    const upper = upperText(value);
    if (!value) {
        return '담당 공정 확인 필요';
    }
    if (upper.includes('BASELINE') || value.includes('기준선') || value.includes('학습')) {
        return '학습 기준선 정보';
    }
    if (upper.includes('PROMPT') || value.includes('프롬프트')) {
        return '프롬프트 생성 설정';
    }
    if (upper.includes('RAG') || upper.includes('RETRIEVAL') || value.includes('검색')) {
        return 'RAG 권한 필터';
    }
    if (upper.includes('AUTH') || value.includes('인증') || value.includes('권한')) {
        return '인증 및 권한 정보';
    }
    if (upper.includes('BEHAVIOR') || value.includes('행동')) {
        return '행동 정보';
    }
    if (upper.includes('GOVERNANCE')) {
        return '확장 관리';
    }
    return value;
}

function metricGroupLabel(groupName) {
    const value = rawText(groupName);
    if (!value) {
        return '지표 영역';
    }
    const upper = upperText(value);
    if (upper.includes('BEHAVIOR')) {
        return '행동 흐름';
    }
    if (upper.includes('CONTEXT')) {
        return '구현 정합성';
    }
    if (upper.includes('GOVERNANCE')) {
        return '확장 관리';
    }
    if (upper.includes('EVIDENCE')) {
        return '증거 무결성';
    }
    return value;
}
function compactPlainText(value) {
    return (rawText(value) || '').replace(/\s+/g, ' ').trim();
}

function relatedComparison(run, failure) {
    const haystack = `${text(failure?.checkLabel)} ${text(failure?.source)}`.toLowerCase();
    const metric = upperText(failure?.metricCode);
    return ensureArray(run.comparisons).find(item => haystack.includes(text(item.fieldKey).toLowerCase()))
            || ensureArray(run.comparisons).find(item => ensureArray(item.metricCodes).map(upperText).includes(metric))
            || {};
}

function runFailureCauses(run) {
    return ensureArray(run?.failureCauses);
}

function metricActionSentence(primary, comparison) {
    return rootCauseType(primary, comparison);
}

function rootCauseType(primary, comparison) {
    const state = upperText(comparison?.state);
    const source = rawText(primary?.source) || '';
    if (!source) {
        return t('enterprise.pqa.verification.metricDetail.rootCause.evidenceMissing');
    }
    if (state === 'PROMPT_MISSING') {
        return t('enterprise.pqa.verification.metricDetail.rootCause.promptAssemblyMissing');
    }
    if (state === 'VALUE_MISMATCH') {
        return t('enterprise.pqa.verification.metricDetail.rootCause.promptValueMismatch');
    }
    if (state === 'FACT_MISSING') {
        return t('enterprise.pqa.verification.metricDetail.rootCause.coreFactMissing');
    }
    if (sourceNeedsEvidenceUpgrade(source)) {
        return t('enterprise.pqa.verification.metricDetail.rootCause.sourceNeedsDetail');
    }
    return t('enterprise.pqa.verification.metricDetail.rootCause.policyOrThreshold');
}

function renderSourceUpgradeBadge(source) {
    return sourceNeedsEvidenceUpgrade(source)
            ? badge(t('enterprise.pqa.verification.metricDetail.source.needsDetail'), { tone: 'warning' })
            : '';
}

function sourceNeedsEvidenceUpgrade(source) {
    const normalized = text(source).toLowerCase();
    return normalized === 'coreevidencereplay'
            || normalized === 'evidencereplay'
            || normalized === 'missing_source'
            || normalized.includes('coreevidencereplay');
}

function renderOfficialRaw(target, detail) {
    if (!target) {
        return;
    }
    const packageId = rawText(detail?.packageId) || packageIdFromLocation();
    target.innerHTML = `
        <details data-pqa-technical-ledger>
            <summary>${escapeHtml(t('enterprise.pqa.verification.ledger.raw.title'))}</summary>
            <div class="pqa-official-lazy-ledger">
                <p>${escapeHtml(t('enterprise.pqa.verification.ledger.raw.lazy'))}</p>
                <button type="button" class="pqa-action-button" data-pqa-load-technical-ledger>
                    ${escapeHtml(t('enterprise.pqa.verification.ledger.raw.load'))}
                </button>
                <div data-pqa-technical-ledger-body></div>
            </div>
        </details>
    `;
    target.querySelector('[data-pqa-load-technical-ledger]')?.addEventListener('click', async event => {
        const button = event.currentTarget;
        const body = target.querySelector('[data-pqa-technical-ledger-body]');
        button.setAttribute('aria-disabled', 'true');
        if (body) {
            body.innerHTML = `<div class="pqa-empty"><p>${escapeHtml(t('enterprise.pqa.verification.ledger.loading'))}</p></div>`;
        }
        try {
            const technical = await loadOfficialTechnicalLedger(packageId);
            const rawRuns = ensureArray(technical?.runs).map(run => ({
                metricCode: run.metricCode,
                officialRunId: run.officialRunId,
                requestFacts: run.requestFacts,
                promptFacts: run.promptFacts,
                analysisFacts: run.analysisFacts,
                rawEvidence: run.rawEvidence
            }));
            if (body) {
                body.innerHTML = `<pre>${escapeHtml(JSON.stringify(rawRuns, null, 2))}</pre>`;
            }
            button.hidden = true;
        }
        catch (error) {
            if (body) {
                body.innerHTML = `<div class="pqa-empty pqa-empty-error"><p>${escapeHtml(publicError(error))}</p></div>`;
            }
            button.setAttribute('aria-disabled', 'false');
        }
    });
}

function comparisonTone(state) {
    const normalized = upperText(state);
    if (normalized === 'MATCH') {
        return 'ready';
    }
    if (normalized === 'PROMPT_MISSING'
            || normalized === 'FACT_MISSING'
            || normalized === 'VALUE_MISMATCH') {
        return 'blocked';
    }
    if (normalized === 'NOT_APPLICABLE') {
        return 'neutral';
    }
    return 'neutral';
}

function comparisonToneForItem(item) {
    if (isProblemComparison(item)) {
        return 'blocked';
    }
    return comparisonTone(item?.state);
}

function comparisonDisplayStateLabel(item) {
    if (isProblemComparison(item)) {
        return upperText(item?.state) === 'MATCH'
                ? '개선 필요'
                : (text(item?.stateLabel) || '개선 필요');
    }
    return text(item?.stateLabel);
}

function comparisonStateClass(item) {
    const prefix = isProblemComparison(item) ? 'state-problem' : `state-${(rawText(item?.state) || 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
    return prefix;
}

function promptConsistencyTone(state) {
    const normalized = upperText(state);
    if (normalized === 'PASS') {
        return 'ready';
    }
    if (normalized === 'BLOCKED') {
        return 'blocked';
    }
    return 'warning';
}

function passState(state) {
    const normalized = upperText(state);
    return ['SUCCESS', 'PASS', 'PASSED', 'VERIFIED', 'COMPLETED'].includes(normalized)
            || normalized.includes('THRESHOLD PASSED');
}

function officialVerificationPassedForDisplay(source = {}, counts = {}) {
    if (source?.officialVerificationPassed === true) {
        return true;
    }
    const decision = upperText(source?.officialFinalDecision || source?.finalDecision || source?.state);
    if (['CERTIFIABLE', 'CERTIFICATE_ISSUED', 'ISSUABLE', 'ISSUED'].includes(decision)) {
        return true;
    }
    const total = Number(source?.totalMetricCount ?? source?.totalRunCount ?? counts?.totalMetricCount ?? counts?.totalRunCount ?? 0);
    const passed = Number(source?.passedMetricCount ?? source?.passedRunCount ?? counts?.passedMetricCount ?? counts?.passedRunCount ?? 0);
    const failed = Number(source?.failedMetricCount ?? source?.failedRunCount ?? counts?.failedMetricCount ?? counts?.failedRunCount ?? 0);
    const actualProblems = Number(counts?.actualProblems ?? source?.summaryCounts?.actualProblems ?? 0);
    const blockedMetrics = Number(counts?.blockedMetrics ?? source?.summaryCounts?.blockedMetrics ?? 0);
    return total >= 12
            && passed >= total
            && failed === 0
            && actualProblems === 0
            && blockedMetrics === 0;
}

function officialDecisionLabel(decision) {
    switch (upperText(decision)) {
        case 'CERTIFIABLE':
        case 'CERTIFICATE_ISSUED':
        case 'ISSUABLE':
        case 'ISSUED':
            return '공식검사 통과';
        case 'BLOCKED':
            return '공식검사 차단';
        case 'REVIEW_REQUIRED':
            return '검토 필요';
        default:
            return '';
    }
}

function displayValue(value) {
    return rawText(value) ?? t('enterprise.pqa.verification.value.notAvailable');
}

function text(value) {
    return displayValue(value);
}

function upperText(value) {
    return (rawText(value) || '').toUpperCase();
}

function lowerText(value) {
    return (rawText(value) || '').toLowerCase();
}

function truncateForOperator(value, maxLength = 160) {
    const valueText = rawText(value) || '';
    if (!valueText) {
        return t('enterprise.pqa.verification.value.notAvailable');
    }
    return normalizeOperatorDisplayText(valueText);
}

function operatorFullText(value, fallback = '') {
    const valueText = rawText(value) || rawText(fallback) || '';
    if (!valueText) {
        return t('enterprise.pqa.verification.value.notAvailable');
    }
    return normalizeOperatorDisplayText(valueText)
            .replace(/^원인:\s*/g, '')
            .replace(/^기대 결과:\s*/g, '')
            .replace(/^실제 결과:\s*/g, '')
            .replace(/^확인 결과:\s*/g, '')
            .trim();
}

function normalizeOperatorDisplayText(value) {
    return rawText(value)
            .replace(/\s+/g, ' ')
            .replace(/^문제:\s*/g, '')
            .replace(/^조치:\s*/g, '')
            .replace(/^재검증 기준:\s*/g, '')
            .replace(/수정 대상/g, '해결 담당')
            .replace(/책임 대상/g, '해결 담당')
            .replace(/조치 그룹/g, '해결 담당 묶음')
            .replace(/수정하십시오/g, '보강하십시오')
            .replace(/수정해야/g, '보강해야')
            .replace(/소스코드/g, '프롬프트 품질 공정')
            .replace(/코드 수정/g, '프롬프트 품질 보강')
            .trim();
}

function segmentAfterLabel(value, label) {
    const source = rawText(value) || '';
    if (!source) {
        return '';
    }
    const pattern = new RegExp(`${label}:\\s*([^.]*(?:\\.[^가-힣A-Za-z0-9]*(?!문제:|원인:|근거 위치:|대상:|결과:|조치:|재검증 기준:)[^.]*)*)`);
    const match = source.match(pattern);
    return match?.[1]?.trim() || '';
}

function conciseProblemTitle(item) {
    const value = rawText(item?.problemStatement) || rawText(item?.checkLabel) || rawText(item?.metricName);
    return operatorFullText(value || '공식검사 차단 항목');
}

function conciseCause(item) {
    return operatorFullText(
            segmentAfterLabel(item?.rootCause, '원인')
            || rawText(item?.rootCause)
            || rawText(item?.operatorReason)
            || '저장된 진단 원인을 확인해야 합니다.');
}

function conciseAction(item) {
    return operatorFullText(
            rawText(item?.remediationHint)
            || rawText(item?.nextAction)
            || '후속 공정에서 담당 영역의 증거 생산 또는 프롬프트 조립 근거를 보강하십시오.');
}

function renderEmptyResult(pageRoot) {
    const summary = $(pageRoot, '[data-pqa-run-summary]');
    if (summary) {
        summary.innerHTML = '';
    }
    clearChart(pageRoot);
}

function clearChart(pageRoot) {
    const canvas = pageRoot.querySelector('[data-pqa-verification-chart]');
    if (canvas?.__pqaChart) {
        canvas.__pqaChart.destroy();
        canvas.__pqaChart = null;
    }
}

function formatEvidenceName(item) {
    const path = rawText(resourceUrlOf(item));
    const method = rawText(item.httpMethod) || t('enterprise.pqa.verification.method.fallback');
    if (path) {
        return `${method} ${path}`;
    }
    return shortPackageId(item.packageId);
}

function formatRequestLabel(item) {
    const path = rawText(resourceUrlOf(item));
    const method = rawText(item.httpMethod);
    if (path && method) {
        return `${method} ${path}`;
    }
    return path || method || t('enterprise.pqa.verification.request.unknown');
}

function shortPackageId(packageId) {
    const raw = text(packageId);
    return raw.length > 18 ? `${raw.slice(0, 10)}...${raw.slice(-6)}` : raw;
}

function resourceUrlOf(item) {
    return rawText(item?.resourceUrl) || rawText(item?.requestPath);
}

function formatCapturedAt(value) {
    if (!value) {
        return t('enterprise.pqa.verification.savedTime.unknown');
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return text(value);
    }
    return date.toLocaleString('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

if (globalThis.__PQA_RENDER_CONTRACT_HOOKS__) {
    globalThis.__PQA_RENDER_CONTRACT_HOOKS__.verification = {
        runtimeEvidenceHref,
        verificationStageHref,
        scopedStageUrl,
        renderTopBlockingCause,
        renderTopBlockingCauses,
        renderProcessStepStrip,
        updateSubrouteLinks,
        issueListLink,
        reverifyLink,
        failureHandoffLink,
        failureScopedSource,
        updateHandoffLinks,
        visiblePromptComparisonItems,
        visibleActualPromptProblems,
        comparisonProblemCounts,
        metricCheckTotals,
        actualProblemsForMetric,
        promptComparisonsForMetric,
        comparisonMetricCodeForRun
    };
}



