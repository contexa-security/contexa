import '../common/shell.js';
import { currentLanguage, t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { byId, element, errorText, notice } from '../common/ui.js';
import { operationCopy, scenarioCopy, selectorCopy } from '../common/scenario-copy.js';

const key = new URLSearchParams(location.search).get('scenario') || 'S01';
let scenarios = [];
let selected;
let criteria;
const copy = (catalog, value) => catalog[value]?.[currentLanguage() === 'en' ? 1 : 0] || value;

function render() {
    byId('scenario-nav').replaceChildren(...scenarios.map(scenario => {
        const link = element('a');
        link.href = `/explore.html?scenario=${encodeURIComponent(scenario.key)}`;
        link.append(element('span', scenario.key, 'mono'), element('span', scenario.display.title[currentLanguage()]));
        if (scenario.key === selected?.key) link.setAttribute('aria-current', 'page');
        return link;
    }));
    if (!selected) return;
    byId('scenario-panel').hidden = false;
    byId('scenario-title').textContent = selected.definition.display.title[currentLanguage()];
    byId('scenario-description').textContent = copy(scenarioCopy, selected.key);
    byId('scenario-version').textContent = `${selected.key} · ${t('explore.version')} ${selected.version}`;
    byId('scenario-plan').replaceChildren(...selected.definition.requestPlan.map(step => {
        const item = element('li');
        const content = element('div');
        content.append(element('strong', copy(operationCopy, step.operation)), element('p', copy(selectorCopy, step.selector), 'small muted'));
        item.append(content); return item;
    }));
    byId('scenario-hash').textContent = `SHA-256 · ${selected.contentSha256}`;
    byId('scenario-conditions').textContent = JSON.stringify({ initialState: selected.definition.initialState,
        conditions: selected.definition.conditions, mutableConditions: selected.definition.mutableConditions }, null, 2);
    byId('scenario-criteria').textContent = criteria ? JSON.stringify(criteria, null, 2) : t('loading');
    byId('scenario-continue').href = `/journey.html?scenario=${selected.key}`;
}

byId('scenario-criteria-details').addEventListener('toggle', async event => {
    if (!event.target.open || !selected || criteria) return;
    try { criteria = await request(`/api/lab/scenarios/${selected.id}/criteria`); render(); }
    catch (error) { byId('scenario-criteria').textContent = errorText(error); }
});
document.addEventListener('lab:language', render);
try {
    scenarios = await request('/api/lab/scenarios');
    const summary = scenarios.find(value => value.key === key);
    if (!summary) throw new Error('Unknown scenario');
    selected = await request(`/api/lab/scenarios/${summary.id}`);
    render();
} catch (error) { notice(byId('explore-feedback'), errorText(error), 'warning'); }
