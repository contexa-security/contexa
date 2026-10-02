import { request } from './http.js';
import { currentLanguage, t } from './i18n.js';
import { element } from './ui.js';

const query = new URLSearchParams(location.search);
let reference = query.has('journey') && query.has('step') ? { journeyId: query.get('journey'), stepId: query.get('step') } : null;
let journey;

function render() {
    let node = document.getElementById('journey-context');
    if (!reference || !journey) { node?.remove(); return; }
    if (!node) {
        node = element('nav', null, 'notice'); node.id = 'journey-context';
        document.querySelector('.page-heading')?.after(node);
    }
    const link = element('a', t('journey.return'));
    link.href = `/journey.html?id=${encodeURIComponent(reference.journeyId)}&step=${encodeURIComponent(reference.stepId)}`;
    node.replaceChildren(element('strong', journey.snapshot.scenario.definition.display.title[currentLanguage()]),
        document.createTextNode(' · '), link);
}

export function journeyReference() { return reference; }
export function journeyStepContext() {
    if (!reference || !journey) return null;
    const step = journey.snapshot.scenario.definition.requestPlan.find(value => value.stepId === reference.stepId);
    return step ? { ...step, account: journey.snapshot.account } : null;
}

export async function setJourneyReference(value = reference) {
    reference = value || null;
    if (reference) journey = (await request(`/api/lab/journeys/${encodeURIComponent(reference.journeyId)}`)).journey;
    render();
}

document.addEventListener('lab:language', render);
