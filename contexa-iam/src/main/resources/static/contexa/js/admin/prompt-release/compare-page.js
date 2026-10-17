import {dayEnd, dayStart, detailHref, el, fillTable, formatTime, list, localDate, number, query, read, setStatus,
    settings, shortHash, t, yesNo}
    from './prompt-release-common.js';

const form = document.querySelector('[data-pr-compare-form]');
const status = document.querySelector('[data-pr-status]');
const inspectionRoot = document.querySelector('[data-pr-page]')?.dataset.inspectionRoot
    || '/contexa/admin/prompt-inspection';

function currentState() {
    const params = new URLSearchParams(window.location.search);
    const today = new Date();
    const first = new Date(today);
    first.setDate(today.getDate() - (Number(settings.periodDays) || 1) + 1);
    return {
        registryScope: params.get('registryScope') || settings.defaultScope,
        promptKey: params.get('promptKey') || '',
        base: params.get('base') || '',
        candidate: params.get('candidate') || '',
        from: params.get('from') || localDate(first),
        to: params.get('to') || localDate(today)
    };
}

/**
 * The bundle compared with when none is given: the scope's active bundle of the prompt, else the previous bundle the
 * candidate's manifest names. This only fills the form; the comparison takes both bundles as it is asked.
 */
async function defaults(state) {
    const rows = await read('/bundles' + query({registryScope: state.registryScope}));
    const ofPrompt = rows.filter((row) => !state.promptKey || row.promptKey === state.promptKey);
    const promptKey = state.promptKey || ofPrompt[0]?.promptKey || '';
    const active = ofPrompt.find((row) => row.promptKey === promptKey && row.state === settings.activeState);
    const candidate = state.candidate || active?.bundleVersion || ofPrompt[0]?.bundleVersion || '';
    let base = state.base;
    if (!base && active && active.bundleVersion !== candidate) {
        base = active.bundleVersion;
    }
    return {...state, promptKey, candidate, base};
}

function options(select, versions, chosen) {
    select.replaceChildren(...versions.map((version) => el('option', {value: version, text: version,
        selected: version === chosen})));
}

function sideCell(side) {
    return side ? `${side.state} ${shortHash(side.hash)}` : '-';
}

function elementRow(element) {
    return el('tr', {class: element.changed ? 'pr-changed' : null, 'data-pr-element': element.id}, [
        el('th', {scope: 'row', text: t(`promptRelease.element.${element.id}`)}),
        el('td', {class: 'pi-code', title: element.base?.hash || '', text: sideCell(element.base)}),
        el('td', {class: 'pi-code', title: element.candidate?.hash || '', text: sideCell(element.candidate)}),
        el('td', {}, el('span', {class: `pi-chip pi-chip-${element.changed ? 'unverifiable' : 'neutral'}`,
            text: t(element.changed ? 'promptRelease.compare.changed' : 'promptRelease.compare.same')})),
        el('td', {title: element.base?.detail || '', text: element.candidate?.detail || '-'})
    ]);
}

function sideValue(attribute, field, side, value) {
    const node = document.querySelector(`[${attribute}="${field}"][data-pr-side="${side}"]`);
    if (node) {
        node.textContent = value === null || value === undefined || value === '' ? '-' : String(value);
    }
}

function renderManifest(sideName, side) {
    const manifest = side?.manifest;
    sideValue('data-pr-manifest', 'bundleHash', sideName, manifest ? manifest.bundleHash
        : t('promptRelease.compare.notInBuild'));
    sideValue('data-pr-manifest', 'vocabularyVersion', sideName, manifest?.vocabularyVersion);
    sideValue('data-pr-manifest', 'rollbackTargets', sideName, manifest ? list(manifest.rollbackTargets) : null);
    sideValue('data-pr-manifest', 'declaredModelProfiles', sideName, manifest ? list(manifest.declaredModelProfiles)
        : null);
    sideValue('data-pr-manifest', 'problemIds', sideName, manifest ? list(manifest.problemIds) : null);
}

function renderEvaluation(sideName, side) {
    const evidence = side?.evidence;
    if (!evidence || !evidence.evaluationReference) {
        sideValue('data-pr-eval', 'evaluationReference', sideName, t('promptRelease.compare.noEvaluation'));
    } else {
        sideValue('data-pr-eval', 'evaluationReference', sideName, evidence.evaluationReference);
    }
    sideValue('data-pr-eval', 'evaluationState', sideName, evidence?.evaluationState);
    sideValue('data-pr-eval', 'evaluationForThisBundle', sideName, evidence ? yesNo(evidence.evaluationForThisBundle)
        : null);
    sideValue('data-pr-eval', 'evaluationRunReference', sideName, evidence?.evaluationRunReference);
    sideValue('data-pr-eval', 'tevvGateState', sideName, evidence?.tevvGateState);
    sideValue('data-pr-eval', 'qualityGateState', sideName, evidence?.qualityGateState);
    // N-GOV-3: the families the bundle requires and the ones the evaluation left uncovered, next to the counts.
    sideValue('data-pr-eval', 'scenarios', sideName, evidence
        ? t('promptRelease.evidence.scenarioFamilies', number(evidence.coveredScenarioCount),
            number(evidence.requiredScenarioCount), list(evidence.requiredScenarioFamilies),
            list(evidence.uncoveredScenarioFamilies)) : null);
}

function outcomeRow(comparison, outcome) {
    const which = outcome.bundleVersion === comparison.candidate?.bundleVersion
        ? t('promptRelease.compare.thisBundle') : t('promptRelease.compare.otherBundle');
    return el('tr', {}, [
        el('td', {}, el('a', {class: 'pi-link pi-code', title: which,
            href: detailHref(comparison.registryScope, comparison.promptKey, outcome.bundleVersion),
            text: outcome.bundleVersion})),
        el('td', {text: t(`promptRelease.stage.${outcome.stage}`)}),
        el('td', {class: 'pi-code', text: outcome.action || '-'}),
        el('td', {class: 'pi-number', text: number(outcome.packages)}),
        el('td', {class: 'pi-number', text: number(outcome.failed)}),
        el('td', {class: 'pi-number', text: number(outcome.passed)}),
        el('td', {class: 'pi-number', text: number(outcome.notInspected)})
    ]);
}

function changeChip(changed) {
    return el('span', {class: `pi-chip pi-chip-${changed ? 'unverifiable' : 'neutral'}`,
        text: t(changed ? 'promptRelease.compare.changed' : 'promptRelease.compare.same')});
}

function actionChangeRow(change) {
    const changed = change.decisionAction !== change.shadowAction;
    return el('tr', {class: changed ? 'pr-changed' : null}, [
        el('td', {class: 'pi-code', text: change.decisionAction || '-'}),
        el('td', {class: 'pi-code', text: change.shadowAction || '-'}),
        el('td', {class: 'pi-number', text: number(change.requests)}),
        el('td', {}, changeChip(changed))
    ]);
}

/** A sealed package opened on the inspection screen, where the inspector's reading of it is. */
function sealLink(packageId, word) {
    return el('a', {class: 'pi-link', href: `${inspectionRoot}/packages/${encodeURIComponent(packageId)}`, text: word});
}

function pairRow(pair) {
    const changed = pair.decisionAction !== pair.shadowAction;
    return el('tr', {class: changed ? 'pr-changed' : null, 'data-pr-pair': pair.requestId}, [
        el('td', {class: 'pi-code', text: pair.requestId}),
        el('td', {text: formatTime(pair.capturedAt)}),
        el('td', {class: 'pi-code', text: pair.decisionBundleVersion || '-'}),
        el('td', {class: 'pi-code', text: pair.decisionAction || '-'}),
        el('td', {class: 'pi-code', text: pair.shadowBundleVersion || '-'}),
        el('td', {class: 'pi-code', text: pair.shadowAction || '-'}),
        el('td', {}, changeChip(changed)),
        el('td', {class: 'pr-chips'}, [sealLink(pair.decisionPackageId, t('promptRelease.compare.decisionSeal')),
            sealLink(pair.shadowPackageId, t('promptRelease.compare.shadowSeal'))])
    ]);
}

/** N-SHD-1: each shadow run paired with the decision of its request, and the counts per decision and shadow action. */
function renderCases(cases) {
    const value = cases || {shadows: 0, paired: 0, changed: 0, changes: [], pairs: []};
    const unpaired = value.shadows - value.paired;
    document.querySelector('[data-pr-cases]').textContent = !value.shadows ? t('promptRelease.compare.noShadow')
        : [t('promptRelease.compare.cases', number(value.shadows), number(value.paired), number(value.changed)),
            unpaired > 0 ? t('promptRelease.compare.unpaired', number(unpaired)) : ''].filter(Boolean).join(' ');
    fillTable(document.querySelector('[data-pr-action-changes]'), (value.changes || []).map(actionChangeRow), 4);
    fillTable(document.querySelector('[data-pr-pairs]'), (value.pairs || []).map(pairRow), 8);
}

async function load() {
    setStatus(status, t('promptRelease.common.loading'));
    try {
        const state = await defaults(currentState());
        form.elements.from.value = state.from;
        form.elements.to.value = state.to;
        if (!state.promptKey || !state.candidate) {
            fillTable(document.querySelector('[data-pr-elements]'), [], 5);
            setStatus(status, t('promptRelease.common.notFound'), 'error');
            return;
        }
        const compare = (base) => read('/compare' + query({registryScope: state.registryScope,
            promptKey: state.promptKey, base, candidate: state.candidate, from: dayStart(state.from),
            to: dayEnd(state.to)}));
        let comparison = await compare(state.base || state.candidate);
        const parent = comparison.candidate?.manifest?.parentVersion;
        if (!state.base && parent && (comparison.versions || []).includes(parent)) {
            comparison = await compare(parent);
        }
        options(form.elements.base, comparison.versions || [], comparison.base?.bundleVersion);
        options(form.elements.candidate, comparison.versions || [], comparison.candidate?.bundleVersion);
        form.dataset.promptKey = state.promptKey;
        form.dataset.registryScope = state.registryScope;
        const elements = document.querySelector('[data-pr-elements]');
        fillTable(elements, (comparison.elements || []).map(elementRow), 5);
        if (!(comparison.elements || []).length) {
            elements.querySelector('tbody td').textContent = t('promptRelease.compare.notInBuild');
        }
        renderManifest('base', comparison.base);
        renderManifest('candidate', comparison.candidate);
        renderCases(comparison.cases);
        fillTable(document.querySelector('[data-pr-outcomes]'),
            (comparison.outcomes || []).map((outcome) => outcomeRow(comparison, outcome)), 7);
        renderEvaluation('base', comparison.base);
        renderEvaluation('candidate', comparison.candidate);
        setStatus(status, '');
    } catch (error) {
        setStatus(status, t('promptRelease.common.error'), 'error');
    }
}

form.addEventListener('submit', (event) => {
    event.preventDefault();
    window.location.search = query({
        registryScope: form.dataset.registryScope, promptKey: form.dataset.promptKey,
        base: form.elements.base.value, candidate: form.elements.candidate.value,
        from: form.elements.from.value, to: form.elements.to.value
    });
});

load();
