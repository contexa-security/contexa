import { t } from './i18n.js';
import { byId, element, notice } from './ui.js';

const key = 'lab.exportSelection';
export class ExportSelection {
    constructor(identity, type) {
        this.identity = identity;
        this.type = type;
        this.items = [];
        let saved;
        try { saved = JSON.parse(sessionStorage.getItem(key) || 'null'); } catch { saved = null; }
        this.selected = new Set(saved?.username === identity.username && saved.type === type && Array.isArray(saved.ids) ? saved.ids.slice(0, 50) : []);
        byId('select-visible').addEventListener('click', () => {
            if (this.items.length > 50) { notice(byId('feedback'), t('export.limit'), 'warning'); return; }
            this.selected = new Set(this.items.map(item => item.id));
            this.update();
        });
        byId('clear-selection').addEventListener('click', () => { this.selected.clear(); this.update(); });
        byId('export-selected').addEventListener('click', () => {
            if (!this.selected.size) return;
            const params = new URLSearchParams({ type: this.type });
            [...this.selected].sort().forEach(id => params.append('id', id));
            location.assign(`/export.html?${params}`);
        });
        document.addEventListener('lab:language', () => this.update());
    }

    setItems(items) {
        this.items = items;
        const visible = new Set(items.map(item => item.id));
        this.selected = new Set([...this.selected].filter(id => visible.has(id)));
        this.update();
    }

    checkbox(id, label) {
        const input = element('input');
        input.type = 'checkbox';
        input.className = 'export-choice';
        input.value = id;
        input.checked = this.selected.has(id);
        input.setAttribute('aria-label', `${t('export.select')}: ${label}`);
        input.addEventListener('change', () => {
            if (input.checked && this.selected.size >= 50) {
                input.checked = false;
                notice(byId('feedback'), t('export.limit'), 'warning');
                return;
            }
            if (input.checked) this.selected.add(id);
            else this.selected.delete(id);
            this.update();
        });
        return input;
    }

    update() {
        byId('selection-count').textContent = t('export.selected.count').replace('{n}', String(this.selected.size));
        byId('export-selected').disabled = !this.selected.size;
        byId('select-visible').disabled = !this.items.length;
        byId('clear-selection').disabled = !this.selected.size;
        document.querySelectorAll('.export-choice').forEach(input => { input.checked = this.selected.has(input.value); });
        try { sessionStorage.setItem(key, JSON.stringify({ username: this.identity.username, type: this.type, ids: [...this.selected] })); }
        catch { notice(byId('feedback'), t('export.selection.storage'), 'warning'); }
    }
}
