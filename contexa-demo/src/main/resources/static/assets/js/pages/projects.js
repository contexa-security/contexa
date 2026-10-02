import { t } from '../common/i18n.js';
import { request } from '../common/http.js';
import { badge, byId, element, notice } from '../common/ui.js';
import { countLabel, initializeWork, showWorkError, translated } from '../common/work.js';

let projects;
function render() {
    if (!projects) return;
    const list = byId('project-list');
    list.replaceChildren();
    if (!projects.length) { list.append(element('p', t('work.empty'), 'empty')); return; }
    projects.forEach(project => {
        const row = element('div', null, 'project-row');
        const symbol = element('span', project.code.split('-')[0], 'project-symbol');
        symbol.setAttribute('aria-hidden', 'true');
        const info = element('div');
        const title = element('div', null, 'project-title');
        title.append(element('h3', translated(project.title)), badge(t(project.assigned ? 'work.assigned' : 'work.other'), project.assigned ? 'good' : ''));
        const detail = element('div', null, 'project-detail');
        detail.append(element('span', project.code), element('span', countLabel(project.documentCount)));
        info.append(title, element('p', translated(project.summary), 'muted small'), detail);
        const link = element('a', t('work.open'), 'button secondary compact');
        link.href = `/documents.html?project=${encodeURIComponent(project.id)}`;
        link.setAttribute('aria-label', `${translated(project.title)}: ${t('work.open')}`);
        row.append(symbol, info, link);
        list.append(row);
    });
}
document.addEventListener('lab:language', render);
notice(byId('feedback'), t('work.loading'));
try {
    await initializeWork();
    projects = await request('/api/work/projects');
    notice(byId('feedback'));
    render();
}
catch (error) { showWorkError(error); }
