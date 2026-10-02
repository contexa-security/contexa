import { currentLanguage, t } from './i18n.js';
import { request } from './http.js';
import { byId, element, notice } from './ui.js';

let groups = [];
let selected = '';
let locked = false;
let loading = false;
let failure = null;
let resourceType = 'DOCUMENT';

function text(value) {
    return value?.[currentLanguage()] || value?.ko || value?.en || t('unknown');
}

function render() {
    const picker = byId('document-id');
    selected = picker.value || selected;
    picker.replaceChildren();
    const placeholder = element('option', t(loading ? 'working' : 'compare.choose.document'));
    placeholder.value = '';
    picker.append(placeholder);
    for (const group of groups) {
        const options = document.createElement('optgroup');
        options.label = text(group.project.title);
        for (const document of group.documents) {
            const option = element('option', text(document.title));
            option.value = document.id;
            options.append(option);
        }
        picker.append(options);
    }
    if (locked && selected && ![...picker.options].some(option => option.value === selected)) {
        const retained = element('option', t('compare.saved.document'));
        retained.value = selected;
        picker.append(retained);
    }
    picker.value = selected;
    picker.disabled = locked || loading || !groups.length;
    byId('resource-type').disabled = locked || loading;
    byId('catalog-retry').hidden = !failure;
    byId('catalog-retry').disabled = loading;
    byId('catalog-signin').hidden = !failure || ![401, 403].includes(failure.status);
    notice(byId('catalog-feedback'), failure ? t('compare.catalog.failed')
        : !loading && !groups.length ? t('compare.catalog.empty') : '', failure ? 'warning' : '');
}

export async function loadComparisonTargets(type = resourceType) {
    if (loading) return;
    resourceType = type;
    byId('resource-type').value = type;
    loading = true;
    failure = null;
    render();
    try {
        const identity = await request('/api/lab/identity');
        const origin = identity.baselineUrl;
        const projects = await request('/api/work/projects', { origin });
        if (resourceType === 'CUSTOMER') {
            const catalog = await request('/api/work/customers', { origin });
            groups = projects.map(project => ({ project, documents: catalog.customers
                .filter(customer => customer.projectId === project.id)
                .map(customer => ({ ...customer, title: customer.name })) }));
        } else {
            groups = await Promise.all(projects.map(async project => ({
                project,
                documents: await request(`/api/work/projects/${encodeURIComponent(project.id)}/documents`, { origin })
            })));
        }
        groups = groups.filter(group => group.documents.length);
    } catch (error) {
        failure = error;
        groups = [];
    } finally {
        loading = false;
        render();
        document.dispatchEvent(new Event('lab:comparison-targets'));
    }
}

export function selectComparisonTarget(id) {
    selected = id || '';
    byId('document-id').value = selected;
}

export function lockComparisonTarget(value) {
    locked = value;
    render();
}

export function comparisonTargetName(id, version) {
    const document = groups.flatMap(group => group.documents).find(item => item.id === id);
    return document && (version == null || version === document.version)
        ? text(document.title) : t('compare.saved.document');
}

byId('document-id').addEventListener('change', () => { selected = byId('document-id').value; });
byId('catalog-retry').addEventListener('click', () => void loadComparisonTargets());
byId('resource-type').addEventListener('change', () => {
    selected = '';
    groups = [];
    byId('document-id').value = '';
    void loadComparisonTargets(byId('resource-type').value);
});
document.addEventListener('lab:language', render);
