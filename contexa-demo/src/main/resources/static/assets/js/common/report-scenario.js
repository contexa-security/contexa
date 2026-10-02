import { currentLanguage, t } from './i18n.js';
import { badge, byId, element } from './ui.js';
import { scenarioEvidenceCopy } from './scenario-evidence-copy.js';

export function renderReportScenario(report) {
    const frozen = report.payload.execution.run.manifest.journeyStep;
    byId('report-scenario').hidden = !frozen;
    if (!frozen) return;
    const journey = frozen.journey;
    const scenario = journey.snapshot.scenario;
    const oracle = journey.snapshot.evaluation.oracle;
    byId('report-scenario-name').textContent = `${scenario.definition.display.title[currentLanguage()]} · ${scenario.key} v${scenario.version}`;
    byId('report-scenario-link').href = `/journey.html?id=${journey.id}&step=${frozen.stepId}`;
    byId('report-scenario-actions').replaceChildren(...oracle.allowedFinalResponses.map(value => badge(t(`review.action.${value}`))));
    byId('report-scenario-evidence').replaceChildren(...oracle.requiredEvidence.map(value => element('li',
        scenarioEvidenceCopy[value]?.[currentLanguage() === 'en' ? 1 : 0] || value)));
}
