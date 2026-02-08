/**
 * '권한 정의 & 정책 설정' 버튼 클릭 시 모달만 열기 (서버 호출 없음)
 * @param {HTMLButtonElement} button 클릭된 버튼 요소
 */
function defineAndSetupPolicy(button) {
    const tableRow = button.closest('tr');
    if (!tableRow) {
        showToast('오류: 테이블 행을 찾을 수 없습니다.', 'error');
        return;
    }

    const inputCell = tableRow.querySelector('.resource-inputs-cell');
    if (!inputCell) {
        showToast('오류: 입력 필드 컨테이너(.resource-inputs-cell)를 찾을 수 없습니다.', 'error');
        return;
    }

    const resourceId = button.dataset.resourceId;
    const friendlyNameInput = inputCell.querySelector('input[name="friendlyName"]');
    const descriptionTextarea = inputCell.querySelector('textarea[name="description"]');

    if (!friendlyNameInput.value.trim()) {
        showToast('친화적 이름은 필수 항목입니다.', 'error');
        friendlyNameInput.focus();
        return;
    }

    showPolicySetupModal(resourceId, friendlyNameInput.value, descriptionTextarea.value);
}


/**
 * 버튼의 로딩 상태를 설정하고 UI를 변경하는 헬퍼 함수
 * @param {HTMLButtonElement} button
 * @param {boolean} isLoading
 */
function setLoading(button, isLoading) {
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
}


function showPolicySetupModal(resourceId, friendlyName, description) {
    const modal = document.getElementById('policySetupModal');
    if (!modal) return;
    document.getElementById('modal-permission-name').textContent = friendlyName;
    modal.dataset.resourceId = resourceId;
    modal.dataset.friendlyName = friendlyName;
    modal.dataset.description = description || '';
    modal.classList.remove('hidden');
}

function closePolicySetupModal() {
    document.getElementById('policySetupModal').classList.add('hidden');
}

async function definePermission(modal) {
    const resourceId = modal.dataset.resourceId;
    try {
        const formData = new URLSearchParams();
        formData.append('friendlyName', modal.dataset.friendlyName);
        formData.append('description', modal.dataset.description);

        const response = await fetch(`/admin/workbench/resources/${resourceId}/define`, {
            method: 'POST',
            headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name="_csrf"]')?.content },
            body: formData
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        return result;
    } catch (error) {
        showToast('권한 생성 실패: ' + error.message, 'error');
        return null;
    }
}

async function selectQuickGrant() {
    const modal = document.getElementById('policySetupModal');
    const result = await definePermission(modal);
    if (result) {
        document.getElementById('quickGrantPermissionId').value = result.permissionId;
        document.getElementById('quickGrantForm').submit();
    }
}

async function selectAdvancedPolicy() {
    const modal = document.getElementById('policySetupModal');
    const result = await definePermission(modal);
    if (result) {
        document.getElementById('advancedPolicyResourceId').value = modal.dataset.resourceId;
        document.getElementById('advancedPolicyPermissionId').value = result.permissionId;
        document.getElementById('advancedPolicyForm').submit();
    }
}


/**
 * 관리 제외 (AJAX)
 * @param {HTMLButtonElement} button
 */
async function excludeResource(button) {
    const resourceId = button.dataset.resourceId;
    setLoading(button, true);
    try {
        const response = await fetch(`/admin/workbench/resources/${resourceId}/exclude`, {
            method: 'POST',
            headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name="_csrf"]')?.content }
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        updateRowAfterExclude(button);
        showToast('리소스가 관리 제외 처리되었습니다.', 'success');
    } catch (error) {
        showToast('관리 제외 실패: ' + error.message, 'error');
        setLoading(button, false);
    }
}

/**
 * 관리 복원 (AJAX)
 * @param {HTMLButtonElement} button
 */
async function restoreResource(button) {
    const resourceId = button.dataset.resourceId;
    setLoading(button, true);
    try {
        const response = await fetch(`/admin/workbench/resources/${resourceId}/restore`, {
            method: 'POST',
            headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name="_csrf"]')?.content }
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        updateRowAfterRestore(button);
        showToast('리소스가 관리 대상으로 복원되었습니다.', 'success');
    } catch (error) {
        showToast('관리 복원 실패: ' + error.message, 'error');
        setLoading(button, false);
    }
}

/**
 * exclude 성공 후 해당 행의 상태 배지 + 버튼을 동적으로 변경
 */
function updateRowAfterExclude(button) {
    const row = button.closest('tr');
    if (!row) return;
    const resourceId = button.dataset.resourceId;

    const statusBadge = row.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.className = 'status-badge bg-slate-500/20 text-slate-400 border-slate-500/30';
        statusBadge.innerHTML = '<i class="fas fa-ban"></i> <span>관리 제외</span>';
    }

    const defineBtn = row.querySelector('[onclick="defineAndSetupPolicy(this)"]');
    if (defineBtn) {
        defineBtn.closest('div').style.display = 'none';
    }

    const actionContainer = button.closest('.space-y-2');
    if (actionContainer) {
        const excludeDiv = button.closest('div');
        excludeDiv.innerHTML =
            '<button type="button" class="action-badge-restore w-full text-center" ' +
            'data-resource-id="' + resourceId + '" onclick="restoreResource(this)">' +
            '<i class="fas fa-undo"></i> <span>관리 복원</span></button>';
    }
}

/**
 * restore 성공 후 해당 행의 상태 배지 + 버튼을 동적으로 변경
 */
function updateRowAfterRestore(button) {
    const row = button.closest('tr');
    if (!row) return;
    const resourceId = button.dataset.resourceId;

    const statusBadge = row.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.className = 'status-badge bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
        statusBadge.innerHTML = '<i class="fas fa-question-circle"></i> <span>정의 필요</span>';
    }

    const defineBtn = row.querySelector('[onclick="defineAndSetupPolicy(this)"]');
    if (defineBtn) {
        defineBtn.closest('div').style.display = '';
    }

    const actionContainer = button.closest('.space-y-2');
    if (actionContainer) {
        const restoreDiv = button.closest('div');
        restoreDiv.innerHTML =
            '<button type="button" class="action-badge-secondary w-full text-center" ' +
            'data-resource-id="' + resourceId + '" onclick="excludeResource(this)">' +
            '<i class="fas fa-ban"></i> <span>관리 제외</span></button>';
    }
}
