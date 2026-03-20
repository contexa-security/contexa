/**
 * Policy Center - Unified policy management client logic
 */
const PolicyCenter = {

    selectedRoleId: null,
    selectedRoleName: null,

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
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 처리 중...';
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
     * Define resource - redirect to resource workbench for full modal flow
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
            showToast('리소스가 관리 제외 처리되었습니다.', 'success');
        } catch (error) {
            showToast('관리 제외 실패: ' + error.message, 'error');
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
            showToast('리소스가 관리 대상으로 복원되었습니다.', 'success');
        } catch (error) {
            showToast('관리 복원 실패: ' + error.message, 'error');
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
            badge.innerHTML = '<i class="fas fa-ban"></i> <span>관리 제외</span>';
        }

        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineResource(this)"]');
        if (defineBtn) defineBtn.closest('div').style.display = 'none';

        const actionDiv = button.closest('div');
        actionDiv.innerHTML =
            '<button type="button" class="pc-action pc-action-restore w-full text-center" ' +
            'data-resource-id="' + resourceId + '" onclick="PolicyCenter.restoreResource(this)">' +
            '<i class="fas fa-undo"></i> <span>관리 복원</span></button>';
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
            badge.innerHTML = '<i class="fas fa-question-circle"></i> <span>정의 필요</span>';
        }

        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineResource(this)"]');
        if (defineBtn) defineBtn.closest('div').style.display = '';

        const actionDiv = button.closest('div');
        actionDiv.innerHTML =
            '<button type="button" class="pc-action pc-action-exclude w-full text-center" ' +
            'data-resource-id="' + resourceId + '" onclick="PolicyCenter.excludeResource(this)">' +
            '<i class="fas fa-ban"></i> <span>관리 제외</span></button>';
    },

    /**
     * Select role card for quick policy creation
     * @param {HTMLElement} card
     */
    selectRole(card) {
        document.querySelectorAll('.pc-role-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');

        this.selectedRoleId = card.dataset.roleId;
        this.selectedRoleName = card.dataset.roleName;

        const wizardBtn = document.getElementById('btn-start-wizard');
        if (wizardBtn) {
            wizardBtn.disabled = false;
            wizardBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        }
    },

    /**
     * Start policy wizard with the selected role
     */
    startWizardWithRole() {
        if (!this.selectedRoleId) {
            showToast('역할을 먼저 선택해 주세요.', 'error');
            return;
        }
        const form = document.getElementById('wizardRoleForm');
        if (form) {
            document.getElementById('wizardRoleId').value = this.selectedRoleId;
            form.submit();
        }
    }
};
