import { ExportSelection } from '../common/export-selection.js';
import { t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { badge, busy, byId, element, notice } from '../common/ui.js';
import { initializeWork, query, showWorkError, translated } from '../common/work.js';

let catalog;
let selection;
let projects = [];

function renderProjects() {
    const selected = byId('project').value;
    const options = [element('option', t('customer.all.projects'))];
    options[0].value = '';
    projects.forEach(project => {
        const option = element('option', translated(project.title));
        option.value = project.id;
        options.push(option);
    });
    byId('project').replaceChildren(...options);
    byId('project').value = selected;
}

function render() {
    renderProjects();
    if (!catalog) return;
    const rows = byId('customer-list');
    rows.replaceChildren();
    byId('customer-count').textContent = t('customer.count').replace('{n}', String(catalog.customers.length));
    byId('customer-empty').hidden = catalog.customers.length > 0;
    catalog.customers.forEach(customer => {
        const row = element('tr');
        const name = element('th');
        name.scope = 'row';
        const link = element('a', translated(customer.name));
        link.href = `/customer.html?id=${encodeURIComponent(customer.id)}`;
        name.append(link, element('span', customer.id, 'mono customer-id'));
        const assignment = element('td');
        const assigned = catalog.assignedProjects.includes(customer.projectId);
        assignment.append(badge(t(assigned ? 'work.assigned' : 'work.other'), assigned ? 'good' : ''),
                element('span', customer.projectId.toUpperCase(), 'customer-project'));
        const action = element('td');
        const open = element('a', t('customer.open'), 'text-action');
        open.href = link.href;
        open.setAttribute('aria-label', `${translated(customer.name)}: ${t('customer.open')}`);
        action.append(open);
        const select = element('td');
        select.append(selection.checkbox(customer.id, translated(customer.name)));
        row.append(select, name, element('td', translated(customer.industry)), element('td', translated(customer.region)), assignment, action);
        rows.append(row);
    });
}

async function search() {
    notice(byId('feedback'), t('work.loading'));
    byId('customer-list').setAttribute('aria-busy', 'true');
    try {
        catalog = await request(`/api/work/customers?project=${encodeURIComponent(byId('project').value)}&search=${encodeURIComponent(byId('search').value)}`);
        const params = new URLSearchParams({ project: byId('project').value, search: byId('search').value });
        history.replaceState(null, '', `/customers.html?${params}`);
        selection.setItems(catalog.customers);
        notice(byId('feedback'));
        render();
    } catch (error) { showWorkError(error); }
    finally { byId('customer-list').removeAttribute('aria-busy'); }
}

byId('search-form').addEventListener('submit', event => {
    event.preventDefault();
    void busy(event.submitter, search);
});
document.addEventListener('lab:language', render);
notice(byId('feedback'), t('work.loading'));
try {
    const identity = await initializeWork();
    selection = new ExportSelection(identity, 'CUSTOMER');
    projects = await request('/api/work/projects');
    renderProjects();
    byId('project').value = query.get('project') || '';
    byId('search').value = query.get('search') || '';
    await search();
} catch (error) { showWorkError(error); }
