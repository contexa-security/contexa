import {buildChip, call, el, fillTable, formatTime, gateChip, list, number, pageRoot, query, read, reasonItem,
    scopeText, setStatus, settings, stateChip, t, yesNo}
    from './prompt-release-common.js';

const params = new URLSearchParams(window.location.search);
const bundle = {
    registryScope: params.get('registryScope') || settings.defaultScope,
    promptKey: params.get('promptKey') || '',
    promptVersion: params.get('promptVersion') || ''
};
const status = document.querySelector('[data-pr-status]');
const gate = document.querySelector('[data-pr-gate]');
const rationale = document.querySelector('[data-pr-rationale]');
const outcome = document.querySelector('[data-pr-outcome]');
const rollbackForm = document.querySelector('[data-pr-rollback]');
const rollbackNote = document.querySelector('[data-pr-rollback-note]');

function fact(name, value) {
    const node = document.querySelector(`[data-pr-fact="${name}"]`);
    if (!node) {
        return;
    }
    if (value instanceof Node) {
        node.replaceChildren(value);
    } else {
        node.textContent = value === null || value === undefined || value === '' ? '-' : String(value);
    }
}

function evidenceValue(name, value) {
    const node = document.querySelector(`[data-pr-evidence="${name}"]`);
    if (node) {
        node.textContent = value === null || value === undefined || value === '' ? '-' : String(value);
    }
}

/** What the gate refused or the rollback recorded, in the reader's words. */
function showOutcome(title, reasons, kind) {
    outcome.hidden = false;
    document.querySelector('[data-pr-outcome-title]').textContent = title;
    document.querySelector('[data-pr-outcome-reasons]').replaceChildren(...reasons.map((reason) => reasonItem(reason,
        kind)));
}

function hideOutcome() {
    outcome.hidden = true;
    document.querySelector('[data-pr-outcome-reasons]').replaceChildren();
}

/** W6-8: a transition through the release gate; a refusal (422) shows the receipt's blockers. */
async function transition(targetState, button) {
    button.disabled = true;
    hideOutcome();
    try {
        const answer = await call('/transition', {method: 'POST', body: {
            registryScope: bundle.registryScope, promptKey: bundle.promptKey, promptVersion: bundle.promptVersion,
            targetReleaseStatus: settings.releaseStatuses?.[targetState], rationale: rationale.value || null
        }});
        if (answer.ok) {
            await load();
            setStatus(status, t('promptRelease.gate.applied', targetState), 'done');
        } else if (answer.status === 422 && answer.body) {
            showOutcome(t('promptRelease.gate.refused', targetState), answer.body.blockers || [], 'blocker');
            await load();
            setStatus(status, t('promptRelease.gate.refused', targetState), 'error');
        } else {
            setStatus(status, t('promptRelease.common.error'), 'error');
        }
    } catch (error) {
        setStatus(status, t('promptRelease.common.error'), 'error');
    } finally {
        button.disabled = false;
    }
}

function renderGate(assessment) {
    gate.replaceChildren();
    const targets = (assessment?.targets || []).filter((target) => (settings.actions || []).includes(
        target.targetState));
    if (!assessment) {
        gate.append(el('p', {class: 'pi-note', text: t('promptRelease.gate.unavailable')}));
        return;
    }
    if (!targets.length) {
        gate.append(el('p', {class: 'pi-note', text: t('promptRelease.gate.none')}));
        return;
    }
    targets.forEach((target) => {
        const button = el('button', {type: 'button', class: 'pi-button pi-button-primary',
            'data-pr-transition': target.targetState, text: t('promptRelease.action.transition', target.targetState)});
        button.addEventListener('click', () => transition(target.targetState, button));
        gate.append(el('article', {class: 'pr-target', 'data-pr-target': target.targetState,
            'data-pr-ready': String(Boolean(target.ready))}, [
            el('div', {class: 'pr-target-head'}, [gateChip(target), button]),
            target.blockers?.length
                ? el('ul', {class: 'pr-reasons'}, target.blockers.map((blocker) => reasonItem(blocker, 'blocker')))
                : null
        ]));
    });
}

function renderEvidence(evidence) {
    const value = evidence || {};
    evidenceValue('changeRecorded', evidence ? yesNo(value.changeRecorded) : null);
    evidenceValue('evaluationReference', value.evaluationReference);
    evidenceValue('evaluationState', [value.evaluationState, value.empiricalEvidenceState].filter(Boolean).join(' / '));
    evidenceValue('evaluationForThisBundle', evidence ? yesNo(value.evaluationForThisBundle) : null);
    evidenceValue('evaluationRunReference', [value.evaluationRunReference, value.evaluationBundleHash]
        .filter(Boolean).join(' / '));
    evidenceValue('tevvGateState', value.tevvGateState);
    evidenceValue('qualityGateState', value.qualityGateState);
    evidenceValue('promptInjectionState', value.promptInjectionState);
    evidenceValue('latencyGateState', value.latencyGateState);
    evidenceValue('costGateState', value.costGateState);
    evidenceValue('scenarios', evidence ? `${number(value.coveredScenarioCount)} / ${number(value.requiredScenarioCount)}`
        : null);
    evidenceValue('approval', [value.approvalState, value.approvedBy].filter(Boolean).join(' / '));
    evidenceValue('rollback', [value.rollbackTargetPromptVersion, value.rollbackReadinessState].filter(Boolean)
        .join(' / '));
    evidenceValue('providerCompatibilityDeclared', evidence ? yesNo(value.providerCompatibilityDeclared) : null);
    evidenceValue('budgetProfileKeys', evidence ? list(value.budgetProfileKeys) : null);
    evidenceValue('policies', evidence ? [yesNo(value.tokenCountingPolicyDeclared), yesNo(value.cachePolicyGoverned),
        yesNo(value.compactionPolicyGoverned)].join(' / ') : null);
}

/** W6-10: an emergency stop waits for another operator's approval. */
async function approve(executionKey, button) {
    button.disabled = true;
    hideOutcome();
    try {
        const answer = await call(`/rollback/${encodeURIComponent(executionKey)}/approve`, {method: 'POST'});
        if (answer.ok) {
            await load();
            setStatus(status, t('promptRelease.rollback.approved'), 'done');
        } else if (answer.status === 422 && answer.body) {
            showOutcome(t('promptRelease.rollback.refused'), answer.body.refusals || [], 'refusal');
            setStatus(status, t('promptRelease.rollback.refused'), 'error');
        } else {
            setStatus(status, t('promptRelease.common.error'), 'error');
        }
    } catch (error) {
        setStatus(status, t('promptRelease.common.error'), 'error');
    } finally {
        button.disabled = false;
    }
}

function executionRow(execution) {
    let action = null;
    if (execution.status === settings.awaitingApproval) {
        action = el('button', {type: 'button', class: 'pi-button', 'data-pr-approve': execution.executionKey,
            text: t('promptRelease.action.approve')});
        action.addEventListener('click', () => approve(execution.executionKey, action));
    }
    return el('tr', {}, [
        el('td', {text: formatTime(execution.executedAt)}),
        el('td', {class: 'pi-code', text: execution.fromVersion}),
        el('td', {class: 'pi-code', text: execution.toVersion}),
        el('td', {text: execution.actor || '-'}),
        el('td', {text: execution.reason || '-'}),
        el('td', {text: yesNo(execution.emergency)}),
        el('td', {text: t(`promptRelease.execution.${execution.status}`)}),
        el('td', {text: execution.approvedBy || '-'}),
        el('td', {}, action)
    ]);
}

function renderRollback(detail) {
    const targets = detail.manifest?.rollbackTargets || [];
    const select = rollbackForm.elements.toVersion;
    select.replaceChildren(...targets.map((target) => el('option', {value: target, text: target})));
    rollbackForm.elements.reason.required = true;
    rollbackForm.querySelector('[data-pr-rollback-run]').disabled = !targets.length;
    rollbackNote.textContent = targets.length ? '' : t('promptRelease.rollback.noTargets');
    fillTable(document.querySelector('[data-pr-executions]'), (detail.rollbacks || []).map(executionRow), 9);
}

async function load() {
    try {
        const detail = await read('/gate' + query(bundle));
        const row = detail.bundle;
        fact('bundle', row.bundleVersion);
        fact('hash', row.bundleHash);
        fact('state', stateChip(row.state, row.unknownStatus));
        fact('scope', scopeText(row));
        fact('build', buildChip(row));
        fact('parent', detail.manifest?.parentVersion);
        fact('frozenOn', detail.manifest?.frozenOn);
        fact('vocabulary', detail.manifest?.vocabularyVersion);
        fact('rollbackTargets', detail.manifest ? list(detail.manifest.rollbackTargets) : null);
        fact('modelProfiles', detail.manifest ? list(detail.manifest.declaredModelProfiles) : null);
        fact('problemIds', detail.manifest ? list(detail.manifest.problemIds) : null);
        fact('changeSummary', detail.manifest?.changeSummary);
        renderGate(detail.gate);
        renderEvidence(detail.gate?.evidence);
        renderRollback(detail);
        document.querySelector('[data-pr-compare]').href = `${pageRoot}/compare${query({
            registryScope: bundle.registryScope, promptKey: bundle.promptKey, candidate: bundle.promptVersion})}`;
        setStatus(status, '');
    } catch (error) {
        setStatus(status, t(error.status === 404 ? 'promptRelease.common.notFound' : 'promptRelease.common.error'),
            'error');
    }
}

/** W6-10: the rollback to a declared target; a refusal (422) shows the recorded refusals. */
rollbackForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const reason = rollbackForm.elements.reason.value.trim();
    if (!reason) {
        setStatus(status, t('promptRelease.rollback.reasonRequired'), 'error');
        return;
    }
    const button = rollbackForm.querySelector('[data-pr-rollback-run]');
    button.disabled = true;
    hideOutcome();
    try {
        const answer = await call('/rollback', {method: 'POST', body: {
            registryScope: bundle.registryScope, promptKey: bundle.promptKey, fromVersion: bundle.promptVersion,
            toVersion: rollbackForm.elements.toVersion.value, reason, emergency: rollbackForm.elements.emergency.checked
        }});
        if (answer.ok && answer.body) {
            await load();
            setStatus(status, t(answer.body.status === settings.awaitingApproval ? 'promptRelease.rollback.awaiting'
                : 'promptRelease.rollback.executed', answer.body.executionKey), 'done');
        } else if (answer.status === 422 && answer.body) {
            showOutcome(t('promptRelease.rollback.refused'), answer.body.refusals || [], 'refusal');
            await load();
            setStatus(status, t('promptRelease.rollback.refused'), 'error');
        } else {
            setStatus(status, t('promptRelease.common.error'), 'error');
        }
    } catch (error) {
        setStatus(status, t('promptRelease.common.error'), 'error');
    } finally {
        button.disabled = !rollbackForm.elements.toVersion.options.length;
    }
});

setStatus(status, t('promptRelease.common.loading'));
load();
