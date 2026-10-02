import { t } from '../common/i18n.js';
import { ApiError, request } from '../common/http.js';
import { sendBusinessCommand } from '../common/business-http.js';
import { CommandDraft } from '../common/command-draft.js';
import { approvalError } from '../common/approval-ui.js';
import { busy, byId, element, notice } from '../common/ui.js';
import { initializeWork, query, translated } from '../common/work.js';

let draft;
let projects = [];
let targets = [];
let loading = 0;
const selected = new Set();
let requestedSelection = null;

function render() {
    const projectId = byId('project').value;
    const all = element('option', t('customer.all.projects'));
    all.value = '';
    byId('project').replaceChildren(all, ...projects.map(project => {
        const option = element('option', translated(project.title));
        option.value = project.id;
        return option;
    }));
    byId('project').value = projects.some(project => project.id === projectId) ? projectId : '';
    const list = byId('target-list');
    list.replaceChildren();
    targets.forEach(target => {
        const label = element('label', null, 'approval-target-option');
        const checkbox = element('input');
        checkbox.type = 'checkbox'; checkbox.value = target.id; checkbox.checked = selected.has(target.id);
        checkbox.addEventListener('change', () => {
            if (checkbox.checked) selected.add(target.id); else selected.delete(target.id);
            renderCount();
        });
        const text = element('span');
        const project = projects.find(value => value.id === target.projectId);
        text.append(element('strong', translated(target.title || target.name)),
            element('small', `${project ? translated(project.title) : target.projectId} · v${target.version}`));
        label.append(checkbox, text);
        list.append(label);
    });
    renderCount();
}
function renderCount() {
    byId('target-count').textContent = t('approval.selected.count').replace('{n}', String(selected.size));
}
async function loadTargets() {
    const generation = ++loading;
    byId('submit-approval').disabled = true;
    notice(byId('feedback'), t('work.loading'));
    try {
        const projectId = byId('project').value;
        const project = encodeURIComponent(projectId);
        const type = byId('resource-type').value;
        let result;
        if (type === 'DOCUMENT' && !projectId) {
            result = (await Promise.all(projects.map(value => request(`/api/work/projects/${encodeURIComponent(value.id)}/documents`)))).flat();
        } else result = await request(type === 'DOCUMENT' ? `/api/work/projects/${project}/documents` : `/api/work/customers?project=${project}`);
        if (generation !== loading) return;
        targets = type === 'DOCUMENT' ? result : result.customers;
        if (requestedSelection?.some(id => !targets.some(target => target.id === id))) {
            notice(byId('feedback'), t('approval.selection.unavailable'), 'warning');
            return;
        }
        requestedSelection = null;
        for (const id of selected) if (!targets.some(target => target.id === id)) selected.delete(id);
        notice(byId('feedback'));
        render();
        byId('submit-approval').disabled = false;
    } catch (error) { if (generation === loading) approvalError(error); }
}
for (const id of ['resource-type', 'project']) byId(id).addEventListener('change', () => { requestedSelection = null; selected.clear(); void loadTargets(); });
byId('approval-form').addEventListener('submit', event => {
    event.preventDefault();
    if (!selected.size) { notice(byId('feedback'), t('approval.select.required'), 'warning'); return; }
    void busy(byId('submit-approval'), async () => {
        try {
            const input = draft.prepare({ resourceType: byId('resource-type').value, targetIds: [...selected].sort(),
                purpose: byId('purpose').value, reason: byId('reason').value, validForSeconds: Number(byId('validity').value) });
            const result = await sendBusinessCommand('/api/work/approvals', input, data => Boolean(data?.request?.id));
            if (!result.ok) throw new ApiError(result.status, result.data);
            location.assign(`/approval.html?id=${encodeURIComponent(result.data.request.id)}&request=${encodeURIComponent(result.requestId || '')}`);
        } catch (error) { approvalError(error); }
    });
});
document.addEventListener('lab:language', render);
notice(byId('feedback'), t('work.loading'));
try {
    const identity = await initializeWork();
    draft = new CommandDraft('approval-request', identity.username);
    if (query.get('new') === 'true') {
        draft.clear();
        const retained = new URLSearchParams(query);
        retained.delete('new');
        history.replaceState(null, '', `/approval-request.html?${retained}`);
    }
    projects = await request('/api/work/projects');
    render();
    const saved = draft.input();
    if (saved) {
        byId('resource-type').value = saved.resourceType;
        byId('purpose').value = saved.purpose;
        byId('reason').value = saved.reason;
        byId('validity').value = String(saved.validForSeconds);
        saved.targetIds.forEach(id => selected.add(id));
        requestedSelection = saved.targetIds;
    } else if (query.has('type') || query.has('id')) {
        const ids = query.getAll('id');
        if (!['DOCUMENT', 'CUSTOMER'].includes(query.get('type')) || !ids.length || ids.length > 50
                || new Set(ids).size !== ids.length || ids.some(id => !/^[a-z0-9-]{1,128}$/.test(id))) {
            notice(byId('feedback'), t('approval.selection.unavailable'), 'warning');
            throw new Error('INVALID_APPROVAL_SELECTION');
        }
        byId('resource-type').value = query.get('type');
        if ([...byId('purpose').options].some(option => option.value === query.get('purpose'))) {
            byId('purpose').value = query.get('purpose');
        }
        ids.forEach(id => selected.add(id));
        requestedSelection = ids;
    }
    await loadTargets();
} catch (error) { if (error.message !== 'INVALID_APPROVAL_SELECTION') approvalError(error); }
