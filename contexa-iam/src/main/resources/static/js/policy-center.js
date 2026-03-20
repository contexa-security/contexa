/**
 * Policy Center - Unified policy management client logic
 */
const PolicyCenter = {

    /**
     * Set button loading state
     * @param {HTMLButtonElement} button
     * @param {boolean} isLoading
     */
    setLoading(button, isLoading) {
        if (!button) return;
        if (isLoading) {
            if (!button.dataset.originalHtml) {
                button.dataset.originalHtml = button.innerHTML;
            }
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        } else {
            if (button.dataset.originalHtml) {
                button.innerHTML = button.dataset.originalHtml;
                delete button.dataset.originalHtml;
            }
            button.disabled = false;
        }
    },

    /**
     * Get CSRF token from meta tag
     */
    getCsrfToken() {
        return document.querySelector('meta[name="_csrf"]')?.content;
    },

    /**
     * Define resource and setup policy - redirect to workbench modal flow
     * @param {HTMLButtonElement} button
     */
    defineResource(button) {
        const resourceId = button.dataset.resourceId;
        if (!resourceId) return;
        window.location.href = '/admin/workbench/resources?highlight=' + resourceId;
    },

    /**
     * Exclude resource from management (AJAX)
     * @param {HTMLButtonElement} button
     */
    async excludeResource(button) {
        const resourceId = button.dataset.resourceId;
        this.setLoading(button, true);
        try {
            const response = await fetch('/admin/workbench/resources/' + resourceId + '/exclude', {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': this.getCsrfToken() }
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);

            this.updateRowAfterExclude(button, resourceId);
            showToast('Resource excluded from management.', 'success');
        } catch (error) {
            showToast('Exclude failed: ' + error.message, 'error');
            this.setLoading(button, false);
        }
    },

    /**
     * Restore resource to management (AJAX)
     * @param {HTMLButtonElement} button
     */
    async restoreResource(button) {
        const resourceId = button.dataset.resourceId;
        this.setLoading(button, true);
        try {
            const response = await fetch('/admin/workbench/resources/' + resourceId + '/restore', {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': this.getCsrfToken() }
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);

            this.updateRowAfterRestore(button, resourceId);
            showToast('Resource restored to management.', 'success');
        } catch (error) {
            showToast('Restore failed: ' + error.message, 'error');
            this.setLoading(button, false);
        }
    },

    /**
     * Update row UI after exclude
     */
    updateRowAfterExclude(button, resourceId) {
        const row = button.closest('tr');
        if (!row) return;

        const badge = row.querySelector('.pc-badge');
        if (badge) {
            badge.className = 'pc-badge pc-status-excluded';
            badge.innerHTML = '<i class="fas fa-ban"></i> <span>Excluded</span>';
        }

        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineResource(this)"]');
        if (defineBtn) defineBtn.closest('div').style.display = 'none';

        const actionDiv = button.closest('div');
        actionDiv.innerHTML =
            '<button type="button" class="pc-action pc-action-restore w-full text-center" ' +
            'data-resource-id="' + resourceId + '" onclick="PolicyCenter.restoreResource(this)">' +
            '<i class="fas fa-undo"></i> <span>Restore</span></button>';
    },

    /**
     * Update row UI after restore
     */
    updateRowAfterRestore(button, resourceId) {
        const row = button.closest('tr');
        if (!row) return;

        const badge = row.querySelector('.pc-badge');
        if (badge) {
            badge.className = 'pc-badge pc-status-needs';
            badge.innerHTML = '<i class="fas fa-question-circle"></i> <span>Needs Def.</span>';
        }

        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineResource(this)"]');
        if (defineBtn) defineBtn.closest('div').style.display = '';

        const actionDiv = button.closest('div');
        actionDiv.innerHTML =
            '<button type="button" class="pc-action pc-action-exclude w-full text-center" ' +
            'data-resource-id="' + resourceId + '" onclick="PolicyCenter.excludeResource(this)">' +
            '<i class="fas fa-ban"></i> <span>Exclude</span></button>';
    },

    /**
     * Select role card for quick policy creation
     * @param {HTMLElement} card
     */
    selectRole(card) {
        document.querySelectorAll('.pc-role-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');

        const roleId = card.dataset.roleId;
        const roleName = card.dataset.roleName;

        if (typeof showToast === 'function') {
            showToast('Role "' + roleName + '" selected. Use the buttons below to proceed.', 'info');
        }
    }
};
