/**
 * '권한 정의 & 정책 설정' 버튼 클릭 시 실행되는 메인 함수
 * @param {HTMLButtonElement} button 클릭된 버튼 요소
 */
async function defineAndSetupPolicy(button) {
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

    // [호출] 로딩 상태 시작
    setLoading(button, true);

    try {
        const formData = new FormData();
        formData.append('friendlyName', friendlyNameInput.value);
        formData.append('description', descriptionTextarea.value);

        const response = await fetch(`/admin/workbench/resources/${resourceId}/define`, {
            method: 'POST',
            headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name="_csrf"]')?.content },
            body: new URLSearchParams(formData)
        });

        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        showPolicySetupModal(resourceId, result.permissionId, result.permissionName);

    } catch (error) {
        showToast('권한 생성 중 오류: ' + error.message, 'error');
    } finally {
        // [호출] 로딩 상태 해제
        setLoading(button, false);
    }
}


/**
 * [함수 정의] 버튼의 로딩 상태를 설정하고 UI를 변경하는 헬퍼 함수
 * @param {HTMLButtonElement} button - 상태를 변경할 버튼 요소
 * @param {boolean} isLoading - 로딩 상태 여부
 */
function setLoading(button, isLoading) {
    if (!button) return;

    if (isLoading) {
        // 버튼의 원래 내용을 데이터 속성에 저장 (한 번만)
        if (!button.dataset.originalHtml) {
            button.dataset.originalHtml = button.innerHTML;
        }
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 처리 중...';
    } else {
        // 저장해둔 원래 내용으로 복원
        if (button.dataset.originalHtml) {
            button.innerHTML = button.dataset.originalHtml;
            delete button.dataset.originalHtml;
        }
        button.disabled = false;
    }
}


// --- 나머지 헬퍼 함수들 (showPolicySetupModal, closePolicySetupModal 등) ---
function showPolicySetupModal(resourceId, permissionId, permissionName) {
    const modal = document.getElementById('policySetupModal');
    if (!modal) return;
    document.getElementById('modal-permission-name').textContent = permissionName;
    document.getElementById('quickGrantPermissionId').value = permissionId;
    document.getElementById('advancedPolicyResourceId').value = resourceId;
    document.getElementById('advancedPolicyPermissionId').value = permissionId;
    modal.classList.remove('hidden');
}

function closePolicySetupModal() {
    document.getElementById('policySetupModal').classList.add('hidden');
}

function selectQuickGrant() {
    // 빠른 권한 부여(마법사) 폼을 제출
    document.getElementById('quickGrantForm').submit();
}

function selectAdvancedPolicy() {
    // 상세 정책 설정(빌더) 폼을 제출
    document.getElementById('advancedPolicyForm').submit();
}