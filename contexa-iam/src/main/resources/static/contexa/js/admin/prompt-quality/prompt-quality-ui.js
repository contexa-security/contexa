import { $$, escapeHtml, text } from '../verification-ui-common.js';
import { t } from './prompt-quality-i18n.js';

export function renderEmpty(message) {
    return `<div class="pqa-empty"><p>${escapeHtml(message)}</p></div>`;
}

export function renderList(items, emptyMessage) {
    const values = Array.isArray(items) ? items : [];
    if (!values.length) {
        return renderEmpty(emptyMessage);
    }
    return `<ul class="pqa-clean-list">${values.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

export function renderHelp(label, message) {
    return `
        <aside class="pqa-help-inline">
            <strong>${escapeHtml(label)}</strong>
            <span>${escapeHtml(message)}</span>
        </aside>
    `;
}

export function renderDisclosure(title, bodyHtml, open = false) {
    return `
        <details class="pqa-disclosure" ${open ? 'open' : ''}>
            <summary>${escapeHtml(title)}</summary>
            <div class="pqa-disclosure-body">${bodyHtml}</div>
        </details>
    `;
}

export function toast(root, tone, message) {
    const target = ensureToast(root);
    target.className = `pqa-toast ${tone || 'info'}`;
    target.textContent = message;
    target.hidden = false;
    window.setTimeout(() => {
        target.hidden = true;
    }, 4200);
}

export function showActionTooltip(root, anchor, message, tone = 'info') {
    if (!root || !anchor || !message) {
        return;
    }
    const target = ensureActionTooltip(root);
    target.textContent = message;
    target.className = `pqa-action-tooltip ${tone || 'info'} is-visible`;
    target.hidden = false;
    const rect = anchor.getBoundingClientRect();
    const top = Math.max(12, rect.top - target.offsetHeight - 12);
    const left = Math.min(
            Math.max(12, rect.left + (rect.width / 2) - (target.offsetWidth / 2)),
            Math.max(12, window.innerWidth - target.offsetWidth - 12));
    target.style.top = `${top}px`;
    target.style.left = `${left}px`;
    window.clearTimeout(target.__pqaTimer);
    target.__pqaTimer = window.setTimeout(() => {
        target.hidden = true;
        target.classList.remove('is-visible');
    }, 3600);
}

export function openConfirmModal(root, options) {
    const modal = ensureModal(root);
    modal.querySelector('[data-pqa-modal-title]').textContent =
            options.title || t('enterprise.pqa.common.modal.confirm.title');
    modal.querySelector('[data-pqa-modal-message]').textContent =
            options.message || t('enterprise.pqa.common.modal.confirm.message');
    const reasonWrap = modal.querySelector('[data-pqa-modal-reason-wrap]');
    const reasonInput = modal.querySelector('[data-pqa-modal-reason]');
    const reasonError = modal.querySelector('[data-pqa-modal-reason-error]');
    const reasonLabelEl = modal.querySelector('[data-pqa-modal-reason-label]');
    if (reasonLabelEl) {
        reasonLabelEl.textContent = options.reasonLabel || t('enterprise.pqa.common.modal.reasonLabel');
    }
    if (reasonWrap && reasonInput && reasonError) {
        reasonWrap.hidden = !options.requireReason;
        reasonInput.value = '';
        reasonInput.placeholder = options.reasonPlaceholder
                || t('enterprise.pqa.common.modal.reasonPlaceholder');
        reasonError.hidden = true;
    }
    const confirm = modal.querySelector('[data-pqa-modal-confirm]');
    confirm.textContent = options.confirmLabel || t('enterprise.pqa.common.modal.confirmAction');
    confirm.onclick = () => {
        const reason = reasonInput?.value?.trim() || '';
        if (options.requireReason && !reason) {
            if (reasonError) {
                reasonError.hidden = false;
                reasonError.textContent = t('enterprise.pqa.common.modal.reasonError');
            }
            reasonInput?.focus();
            return;
        }
        closeModal();
        options.onConfirm?.(reason);
    };
    const cancel = modal.querySelector('[data-pqa-modal-close]');
    if (cancel) {
        cancel.textContent = options.cancelLabel || t('enterprise.pqa.common.modal.cancel');
    }
    modal.hidden = false;
    if (options.requireReason) {
        reasonInput?.focus();
    }
    else {
        confirm.focus();
    }
}

export function closeModal() {
    const modal = document.querySelector('[data-pqa-modal-root]');
    if (modal) {
        modal.hidden = true;
    }
}

export function setButtonLoading(button, loading, label) {
    if (!button) {
        return;
    }
    if (loading) {
        button.dataset.originalLabel = button.textContent;
        button.textContent = label || t('enterprise.pqa.common.button.loading');
        button.disabled = true;
        button.classList.add('is-loading');
        return;
    }
    button.textContent = button.dataset.originalLabel || button.textContent;
    button.disabled = false;
    button.classList.remove('is-loading');
}

export function actionButton(action, label, blocked = false, reason = '') {
    const message = reason || (blocked
            ? t('enterprise.pqa.common.action.tooltip.blocked', label)
            : t('enterprise.pqa.common.action.tooltip.ready', label));
    return `<button class="pqa-action-button ${blocked ? 'is-disabled' : ''}"
                    type="button"
                    data-pqa-action="${escapeHtml(action)}"
                    ${blocked ? `data-pqa-disabled-reason="${escapeHtml(message)}"` : `data-pqa-action-message="${escapeHtml(message)}"`}
                    aria-disabled="${blocked ? 'true' : 'false'}"
                    aria-label="${escapeHtml(message)}">${escapeHtml(label)}</button>`;
}

const ACTION_LABEL_KEYS = Object.freeze({
    ENABLE_ZERO_TRUST: 'enterprise.pqa.common.action.enableZeroTrust',
    REQUEST_REVERIFY: 'enterprise.pqa.common.action.requestReverify',
    DISABLE_ZERO_TRUST: 'enterprise.pqa.common.action.disableZeroTrust',
    BLOCK_RESOURCE: 'enterprise.pqa.common.action.blockResource',
    SUSPEND: 'enterprise.pqa.common.action.suspend',
    RETIRE: 'enterprise.pqa.common.action.retire',
    APPROVE: 'enterprise.pqa.common.action.approve',
    ROLLBACK: 'enterprise.pqa.common.action.rollback',
    RETIRE_RECIPE: 'enterprise.pqa.common.action.retireRecipe'
});

export function labelForAction(action) {
    const key = ACTION_LABEL_KEYS[action];
    return key ? t(key) : text(action);
}

export function wireTabs(root = document) {
    $$(root, '[data-pqa-tabs]').forEach(group => {
        const buttons = $$(group, '[data-pqa-tab]');
        const scope = group.parentElement || root;
        const panels = $$(scope, '[data-pqa-tab-panel]');
        const activate = (key) => {
            buttons.forEach(button => {
                const active = button.dataset.pqaTab === key;
                button.classList.toggle('active', active);
                button.setAttribute('aria-selected', String(active));
            });
            panels.forEach(panel => {
                panel.hidden = panel.dataset.pqaTabPanel !== key;
            });
        };
        buttons.forEach(button => {
            button.type = button.type || 'button';
            button.addEventListener('click', () => activate(button.dataset.pqaTab));
        });
        const first = buttons.find(button => button.classList.contains('active')) || buttons[0];
        if (first) {
            activate(first.dataset.pqaTab);
        }
    });
}

export function renderActionResult(result) {
    if (!result) {
        return `<span class="pqa-muted">${escapeHtml(t('enterprise.pqa.common.actionResult.empty'))}</span>`;
    }
    const tone = result.allowed === false ? 'blocked' : 'ready';
    const status = result.status || t('enterprise.pqa.common.actionResult.default');
    const message = result.message
            || result.nextAction
            || t('enterprise.pqa.common.actionResult.fallbackMessage');
    return `
        <span class="pqa-badge ${tone}">${escapeHtml(status)}</span>
        <small>${escapeHtml(message)}</small>
    `;
}

function ensureToast(root) {
    let target = root.querySelector('[data-pqa-toast]');
    if (!target) {
        target = document.createElement('div');
        target.setAttribute('data-pqa-toast', '');
        target.hidden = true;
        root.appendChild(target);
    }
    return target;
}

function ensureActionTooltip(root) {
    let target = document.querySelector('[data-pqa-action-tooltip]');
    if (!target) {
        target = document.createElement('div');
        target.setAttribute('data-pqa-action-tooltip', '');
        target.className = 'pqa-action-tooltip';
        target.hidden = true;
        document.body.appendChild(target);
    }
    return target;
}

function ensureModal(root) {
    let modal = document.querySelector('[data-pqa-modal-root]');
    if (!modal) {
        modal = document.createElement('section');
        modal.className = 'pqa-modal-backdrop';
        modal.setAttribute('data-pqa-modal-root', '');
        modal.hidden = true;
        modal.innerHTML = `
            <div class="pqa-modal" role="dialog" aria-modal="true">
                <h2 data-pqa-modal-title></h2>
                <p data-pqa-modal-message></p>
                <label class="pqa-modal-field" data-pqa-modal-reason-wrap hidden>
                    <span data-pqa-modal-reason-label></span>
                    <textarea data-pqa-modal-reason rows="3"></textarea>
                    <small data-pqa-modal-reason-error hidden></small>
                </label>
                <div class="pqa-modal-actions">
                    <button type="button" class="pqa-secondary-button" data-pqa-modal-close></button>
                    <button type="button" class="pqa-link-button" data-pqa-modal-confirm></button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        modal.addEventListener('click', event => {
            if (event.target.matches('[data-pqa-modal-root], [data-pqa-modal-close]')) {
                closeModal();
            }
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape') {
                closeModal();
            }
        });
    }
    return modal;
}
