import { currentLanguage, t } from './i18n.js';
import { request } from './http.js';
import { approvalReferences, comparisonApprovedTargets, loadComparisonApprovals, lockApprovals, setApprovalReferences } from './comparison-approvals.js';
import { byId, element, notice } from './ui.js';
import { journeyStepContext } from './journey-link.js';
import { selectJourneyRecords } from './journey-selection.js';

let groups = [];
let projects = [];
let selected = new Set();
let failure = false;
let locked = false;
let loading = false;

function currentGroups() {
    const step = journeyStepContext();
    if (!step) return groups;
    const approved = comparisonApprovedTargets(step.account, byId('purpose').value);
    return groups.map(group => ({ ...group,
        records: selectJourneyRecords(group.records, projects, step.selector, approved)
    })).filter(group => group.records.length);
}

export function batchSelectionValid() {
    const step = journeyStepContext();
    if (!step) return !failure && selected.size <= 50;
    const known = new Set(currentGroups().flatMap(group => group.records.map(value => value.id)));
    const type = step.operation === 'EXPORT_CUSTOMERS' ? 'CUSTOMER' : 'DOCUMENT';
    return !failure && !loading && byId('resource-type').value === type
        && selected.size <= step.maxItems && [...selected].every(id => known.has(id));
}

function render() {
    const step = journeyStepContext();
    const maximum = Math.min(50, step?.maxItems ?? 50);
    const visibleGroups = currentGroups();
    const known = new Set(visibleGroups.flatMap(group => group.records.map(value => value.id)));
    const display = [...visibleGroups];
    const missing = [...selected].filter(id => !known.has(id));
    if (missing.length) display.push({ title: { ko: '현재 목록에서 미확인', en: 'Not in the current catalog' },
        records: missing.map(id => ({ id, title: { ko: id, en: id } })) });
    byId('batch-targets').replaceChildren(...display.map(group => {
        const section = element('section');
        section.append(element('h3', group.title[currentLanguage()]));
        for (const value of group.records) {
            const label = element('label', null, 'batch-option');
            const input = document.createElement('input'); input.type = 'checkbox'; input.value = value.id;
            input.checked = selected.has(value.id); input.disabled = loading || locked || (!input.checked && selected.size >= maximum);
            input.addEventListener('change', () => {
                if (input.checked) selected.add(value.id); else selected.delete(value.id);
                render();
                [...byId('batch-targets').querySelectorAll('input')].find(node => node.value === value.id)?.focus();
                document.dispatchEvent(new Event('lab:batch-selection'));
            });
            label.append(input, element('span', value.title[currentLanguage()])); section.append(label);
        }
        return section;
    }));
    if (!display.length) byId('batch-targets').append(element('p', t(loading ? 'loading' : 'batch.empty'), 'empty'));
    byId('batch-count').textContent = t('batch.selected').replace('{n}', String(selected.size));
    lockApprovals(locked || loading);
    byId('resource-type').disabled = locked || loading || Boolean(step);
    byId('batch-refresh').disabled = locked || loading;
    byId('batch-limit').textContent = t(step ? 'journey.max' : 'batch.limit').replace('{n}', String(maximum));
    notice(byId('batch-catalog-feedback'), failure ? t('journey.noCatalog')
        : step && missing.length ? t('batch.scenario.selectionChanged')
            : step && !loading && !visibleGroups.length ? t('batch.scenario.empty') : '', 'warning');
}

export function batchSelection() {
    return { resourceType: byId('resource-type').value, targetIds: [...selected].sort(),
        baselineApprovalId: approvalReferences()?.baselineApprovalId || null, contexaApprovalId: approvalReferences()?.contexaApprovalId || null };
}

export function setBatchSelection(value) {
    selected = new Set(value?.targetIds || []);
    setApprovalReferences(value);
    if (value) byId('resource-type').value = value.resourceType;
    render();
}

export function lockBatchSelection(value) {
    if (locked === value) return;
    locked = value; render();
}

export async function loadBatchCatalog() {
    if (loading) return;
    loading = true; failure = false;
    render();
    try {
        const origins = await request('/api/lab/identity');
        projects = await request('/api/work/projects', { origin: origins.baselineUrl });
        if (byId('resource-type').value === 'DOCUMENT') {
            groups = await Promise.all(projects.map(async project => ({ title: project.title,
                records: await request(`/api/work/projects/${project.id}/documents`, { origin: origins.baselineUrl }) })));
        } else {
            const catalog = await request('/api/work/customers', { origin: origins.baselineUrl });
            groups = projects.map(project => ({ title: project.title, records: catalog.customers
                .filter(value => value.projectId === project.id).map(value => ({ ...value, title: value.name })) }));
        }
        await loadComparisonApprovals(origins);
    } catch { failure = true; groups = []; }
    finally { loading = false; render(); document.dispatchEvent(new Event('lab:batch-selection')); }
}

byId('resource-type').addEventListener('change', () => { selected.clear(); void loadBatchCatalog(); });
document.addEventListener('lab:approval-selection', () => { render(); document.dispatchEvent(new Event('lab:batch-selection')); });
byId('purpose').addEventListener('change', () => { render(); document.dispatchEvent(new Event('lab:batch-selection')); });
byId('batch-refresh').addEventListener('click', () => void loadBatchCatalog());
document.addEventListener('lab:language', render);
