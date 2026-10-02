import { ExportSelection } from '../common/export-selection.js';
import { t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { badge, busy, byId, element, notice } from '../common/ui.js';
import { countLabel, initializeWork, query, showWorkError, translated } from '../common/work.js';

const projectId = query.get('project');
let documents = [];
let selection;
let project;
function render() {
    if (project) { byId('page-title').textContent = translated(project.title); byId('page-title').removeAttribute('data-i18n'); }
    const list = byId('document-list');
    list.replaceChildren();
    byId('document-count').textContent = countLabel(documents.length);
    if (!documents.length) { list.append(element('p', t('work.empty'), 'empty')); return; }
    documents.forEach(document => {
        const row = element('div', null, 'document-row');
        const info = element('div');
        const heading = element('h3');
        const link = element('a', translated(document.title));
        link.href = `/document.html?id=${encodeURIComponent(document.id)}`;
        heading.append(link);
        info.append(heading, element('p', translated(document.summary)));
        row.append(selection.checkbox(document.id, translated(document.title)), info,
            badge(t(`work.${document.sensitivity}`), document.sensitivity === 'CONFIDENTIAL' ? 'warning' : ''));
        list.append(row);
    });
}
async function search() {
    notice(byId('feedback'), t('work.loading'));
    try {
        documents = await request(`/api/work/projects/${encodeURIComponent(projectId)}/documents?search=${encodeURIComponent(byId('search').value)}`);
        selection.setItems(documents);
        notice(byId('feedback')); render();
    } catch (error) { showWorkError(error); }
}
byId('search-form').addEventListener('submit', event => {
    event.preventDefault(); void busy(event.submitter, search);
});
document.addEventListener('lab:language', render);
try {
    const identity = await initializeWork();
    selection = new ExportSelection(identity, 'DOCUMENT');
    const projects = await request('/api/work/projects');
    project = projects.find(item => item.id === projectId);
    if (!project) throw new Error('PROJECT_NOT_FOUND');
    await search();
} catch (error) { showWorkError(error); }
