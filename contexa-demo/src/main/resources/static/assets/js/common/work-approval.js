import { dateTime, t } from './i18n.js';
import { request } from './http.js';
import { byId } from './ui.js';
import { querySelection } from './work-form-options.js';

export class WorkApprovalSelection {
    constructor(identity, resourceType, resource, initialId = null) {
        this.identity = identity;
        this.resourceType = resourceType;
        this.resources = Array.isArray(resource) ? resource : [resource];
        this.selected = initialId;
        this.views = [];
        this.available = false;
        byId('work-approval').addEventListener('change', () => {
            this.selected = byId('work-approval').value || null;
            const selected = this.views.find(view => view.request.id === this.selected);
            if (selected) byId('purpose').value = selected.request.purpose;
            this.render();
            document.dispatchEvent(new CustomEvent('lab:approval'));
        });
        byId('purpose').addEventListener('change', () => this.render());
        document.addEventListener('lab:language', () => this.render());
    }

    async load() {
        try {
            this.views = (await request('/api/work/approvals')).filter(view =>
                view.request.requester === this.identity.username && view.request.resourceType === this.resourceType &&
                this.resources.every(resource => view.request.targets.some(target => target.id === resource.id && target.version === resource.version)));
            this.available = true;
            const selected = this.views.find(view => view.request.id === this.selected);
            if (selected && !querySelection('purpose', 'purpose')) byId('purpose').value = selected.request.purpose;
        } catch {
            this.available = false;
        }
        this.render();
    }

    value() {
        return this.selected;
    }

    render() {
        const select = byId('work-approval');
        select.replaceChildren(new Option(t('approval.link.none'), ''));
        this.views.forEach(view => {
            const request = view.request;
            const option = new Option(`${t(`approval.purpose.${request.purpose}`)} · ${t(`approval.status.${view.effectiveStatus}`)} · ${dateTime(request.expiresAt)}`, request.id);
            option.disabled = view.effectiveStatus !== 'APPROVED' && request.id !== this.selected;
            select.append(option);
        });
        if (this.selected && !this.views.some(view => view.request.id === this.selected)) {
            select.append(new Option(t('approval.status.UNAVAILABLE'), this.selected));
        }
        select.value = this.selected || '';
        const required = ['APPROVED_BULK_DELIVERY', 'EMERGENCY_MAINTENANCE'].includes(byId('purpose').value);
        byId('work-approval-hint').textContent = t(!this.available ? 'approval.link.unavailable' : required ? 'approval.link.required' : 'approval.link.note');
        const link = byId('work-approval-detail');
        link.hidden = !this.selected;
        if (this.selected) link.href = `/approval.html?id=${encodeURIComponent(this.selected)}`;
        const parameters = new URLSearchParams({ new: 'true', type: this.resourceType, purpose: byId('purpose').value });
        this.resources.forEach(resource => parameters.append('id', resource.id));
        document.querySelectorAll('a[data-work-approval-new]').forEach(anchor => {
            anchor.href = `/approval-request.html?${parameters}`;
        });
    }
}
