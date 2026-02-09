/**
 * [최종 수정본] 권한 부여 마법사 클라이언트 애플리케이션
 * 모든 UI 요소 검색 및 이벤트 바인딩 로직의 안정성을 확보하고, 보고된 모든 문법 오류를 수정했습니다.
 */

// 1. 상태 관리 클래스
class PolicyWizardState {
    constructor(contextId) {
        this.currentStep = 1;
        this.totalSteps = 3;
        this.contextId = contextId;
        // window.preselectedPermission은 HTML의 인라인 스크립트에서 설정됩니다.
        this.isPermissionPreselected = !!window.preselectedPermission;
    }

    nextStep() {
        let next = this.currentStep + 1;
        if (this.isPermissionPreselected && this.currentStep === 1) {
            next = 3;
        }
        if (next <= this.totalSteps) {
            this.currentStep = next;
        }
    }

    prevStep() {
        let prev = this.currentStep - 1;
        if (this.isPermissionPreselected && this.currentStep === 3) {
            prev = 1;
        }
        if (prev >= 1) {
            this.currentStep = prev;
        }
    }
}

// 2. UI 렌더링 클래스
class PolicyWizardUI {
    constructor() {
        this.elements = {};
    }

    queryElements() {
        this.elements.steps = document.querySelectorAll('.wizard-card');
        this.elements.indicators = document.querySelectorAll('.step-item');
        this.elements.prevBtn = document.getElementById('prev-btn');
        this.elements.nextBtn = document.getElementById('next-btn');
        this.elements.commitBtn = document.getElementById('commit-btn');
    }

    updateView(state) {
        if (!this.elements.steps || !this.elements.indicators) return;

        this.elements.steps.forEach((stepEl, index) => {
            const stepNum = index + 1;
            if (stepNum === 2 && state.isPermissionPreselected) {
                stepEl.style.display = 'none';
            } else {
                stepEl.style.display = stepNum === state.currentStep ? 'block' : 'none';
            }
        });

        this.elements.indicators.forEach((indicatorEl, index) => {
            const stepNum = index + 1;
            indicatorEl.classList.remove('step-active', 'step-complete', 'step-inactive');
            if (state.isPermissionPreselected && stepNum === 2) {
                indicatorEl.classList.add('step-complete');
            } else if (stepNum < state.currentStep) {
                indicatorEl.classList.add('step-complete');
            } else if (stepNum === state.currentStep) {
                indicatorEl.classList.add('step-active');
            } else {
                indicatorEl.classList.add('step-inactive');
            }
        });

        if (this.elements.prevBtn) this.elements.prevBtn.disabled = state.currentStep === 1;
        if (this.elements.nextBtn) this.elements.nextBtn.style.display = state.currentStep === state.totalSteps ? 'none' : 'inline-block';
        if (this.elements.commitBtn) this.elements.commitBtn.style.display = state.currentStep === state.totalSteps ? 'inline-block' : 'none';
    }

    generateReviewSummary() {
        const summaryEl = document.getElementById('review-summary');
        if (!summaryEl) return;

        const selectedRoles = Array.from(document.querySelectorAll('input[name="selectedRoleIds"]:checked'))
            .map(chk => {
                const label = chk.parentElement.querySelector('p.font-semibold');
                return label ? label.textContent : '';
            });
        const subjectsText = selectedRoles.length > 0 ? selectedRoles.join(', ') : '선택된 역할 없음';

        let permissionsText = '선택된 권한 없음';
        if (window.preselectedPermission) {
            permissionsText = window.preselectedPermission.friendlyName || window.preselectedPermission.name;
        } else {
            const selectedPerms = Array.from(document.querySelectorAll('input[name="permissions"]:checked')).map(chk => chk.parentElement.querySelector('p.font-semibold').textContent);
            if (selectedPerms.length > 0) permissionsText = selectedPerms.join(', ');
        }

        summaryEl.innerHTML = `
            <div class="space-y-3">
                <div><p class="font-semibold text-gray-400">대상 역할 (To Roles):</p><p class="text-sm pl-2">${subjectsText}</p></div>
                <div><p class="font-semibold text-gray-400">부여할 권한 (Permission):</p><p class="text-sm pl-2">${permissionsText}</p></div>
                <div><p class="font-semibold text-gray-400">결과 (Effect):</p><p class="text-sm pl-2 text-green-400 font-bold">역할에 권한이 추가됩니다.</p></div>
            </div>`;
    }

    setLoading(button, isLoading, originalText) {
        if (!button) return;
        button.disabled = isLoading;
        // [수정] 문자열을 작은따옴표(')로 감싸서 문법 오류를 원천적으로 방지합니다.
        button.innerHTML = isLoading
            ? '<i class="fas fa-spinner fa-spin mr-2"></i> 처리 중...'
            : originalText;
    }
}

// 3. API 통신 클래스
class WizardApi {
    constructor(contextId) { this.basePath = `/admin/policy-wizard/${contextId}`; }
    async fetchApi(path, options = {}) {
        try {
            const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
            const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;
            const fetchOptions = { method: 'POST', ...options, headers: { ...options.headers } };
            if (options.body) fetchOptions.headers['Content-Type'] = 'application/json';
            if (csrfToken && csrfHeader) fetchOptions.headers[csrfHeader] = csrfToken;
            const response = await fetch(this.basePath + path, fetchOptions);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: `서버 오류 (상태: ${response.status})` }));
                throw new Error(errorData.message);
            }
            return response.status === 204 ? null : response.json();
        } catch (error) {
            console.error(`API Error fetching ${this.basePath + path}:`, error);
            throw error;
        }
    }
    getFilteredPermissions(roleIds) {
        const params = roleIds.map(id => `roleIds=${id}`).join('&');
        return this.fetchApi(`/available-permissions?${params}`, { method: 'GET' });
    }
    commitPolicy(data) { return this.fetchApi('/commit', { body: JSON.stringify(data) }); }
}

// 4. 메인 애플리케이션 클래스
class PolicyWizardApp {
    constructor() {
        const contextIdEl = document.getElementById('wizardContextId');
        if (!contextIdEl) { console.error('Wizard Context ID를 찾을 수 없습니다.'); return; }
        this.state = new PolicyWizardState(contextIdEl.value);
        this.ui = new PolicyWizardUI();
        this.api = new WizardApi(contextIdEl.value);
    }

    init() {
        this.ui.queryElements();
        this.bindEventListeners();
        this.ui.updateView(this.state);
    }

    bindEventListeners() {
        if (this.ui.elements.nextBtn) this.ui.elements.nextBtn.addEventListener('click', () => this.handleNextStep());
        if (this.ui.elements.prevBtn) this.ui.elements.prevBtn.addEventListener('click', () => this.handlePrevStep());
        if (this.ui.elements.commitBtn) this.ui.elements.commitBtn.addEventListener('click', () => this.handleCommit());
    }

    async handleNextStep() {
        if (this.state.currentStep >= this.state.totalSteps) return;

        // Step 1에서 유효성 검사
        if (this.state.currentStep === 1 && !this.state.isPermissionPreselected) {
            const selectedRoleChecks = document.querySelectorAll('input[name="selectedRoleIds"]:checked');
            if (selectedRoleChecks.length === 0) {
                showToast('하나 이상의 역할을 선택해야 합니다.', 'error');
                return;
            }
            // Step 2로 이동 전, 선택된 역할에 이미 등록된 권한을 제외한 목록 로드
            const roleIds = Array.from(selectedRoleChecks).map(chk => Number(chk.value));
            await this.loadFilteredPermissions(roleIds);
        }
        // Step 2에서 유효성 검사 (isPermissionPreselected가 false일 때만 실행됨)
        else if (this.state.currentStep === 2) {
            const permissionIds = document.querySelectorAll('input[name="permissions"]:checked');
            if(permissionIds.length === 0) {
                showToast('하나 이상의 권한을 선택해야 합니다.', 'error');
                return;
            }
        }

        // 유효성 검사 통과 후 단계 이동
        this.state.nextStep();
        if (this.state.currentStep === this.state.totalSteps) {
            this.ui.generateReviewSummary();
        }
        this.ui.updateView(this.state);
    }

    async loadFilteredPermissions(roleIds) {
        try {
            const permissions = await this.api.getFilteredPermissions(roleIds);
            this.renderPermissionList(permissions);
        } catch (error) {
            showToast('권한 목록을 불러오는데 실패했습니다.', 'error');
        }
    }

    renderPermissionList(permissions) {
        const container = document.getElementById('permission-list-container');
        if (!container) return;

        if (permissions.length === 0) {
            container.innerHTML = '<p class="text-center py-8" style="color: #94a3b8;">선택된 역할에 추가할 수 있는 권한이 없습니다.</p>';
            return;
        }

        container.innerHTML = permissions.map(perm => `
            <div class="flex items-start p-3 permission-item rounded-lg shadow-sm">
                <input type="checkbox" name="permissions" id="perm-${perm.id}" value="${perm.id}" class="h-5 w-5 mt-1">
                <label for="perm-${perm.id}" class="ml-4 flex-1 cursor-pointer">
                    <p class="font-semibold" style="color: #e2e8f0;">${perm.friendlyName || perm.name}</p>
                    <p class="text-xs font-mono" style="color: #94a3b8;">(ID: ${perm.name})</p>
                </label>
            </div>
        `).join('');
    }

    handlePrevStep() {
        if (this.state.currentStep <= 1) return;
        this.state.prevStep();
        this.ui.updateView(this.state);
    }

    async handleCommit() {
        const policyName = document.getElementById('policyName').value;
        const policyDescription = document.getElementById('policyDescription').value;
        if (!policyName) {
            showToast('정책 이름은 필수입니다.', 'error');
            return;
        }

        const selectedRoleIds = Array.from(document.querySelectorAll('input[name="selectedRoleIds"]:checked')).map(chk => Number(chk.value));
        if (selectedRoleIds.length === 0) {
            showToast('하나 이상의 역할을 선택해야 합니다.', 'error');
            return;
        }

        let permissionIds = [];
        if (window.preselectedPermission) {
            permissionIds.push(window.preselectedPermission.id);
        } else {
            // 또는 2단계에서 선택한 권한 ID들을 수집
            permissionIds = Array.from(document.querySelectorAll('input[name="permissions"]:checked')).map(chk => Number(chk.value));
        }

        if (permissionIds.length === 0) {
            showToast('하나 이상의 권한을 선택해야 합니다.', 'error');
            return;
        }

        this.ui.setLoading(this.ui.elements.commitBtn, true, '정책 생성 및 적용');
        try {
            const payload = { policyName, policyDescription, selectedRoleIds, permissionIds };
            const result = await this.api.commitPolicy(payload);
            showToast(result.message || '요청이 성공적으로 처리되었습니다.', 'success');
            setTimeout(() => { window.location.href = '/admin/roles'; }, 1500);
        } catch (error) {
            showToast(`처리 실패: ${error.message}`, 'error');
            this.ui.setLoading(this.ui.elements.commitBtn, false, '정책 생성 및 적용');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    if(typeof showToast !== 'function') {
        window.showToast = (message, type) => alert(`[${type.toUpperCase()}] ${message}`);
    }
    const app = new PolicyWizardApp();
    if (app.state) {
        app.init();
    }
});