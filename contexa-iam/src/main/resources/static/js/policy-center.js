/**
 * Policy Center - Unified policy management client logic
 * Integrates: resource-workbench.js + policy-wizard.js + policydetails.js + AI streaming
 */
const PolicyCenter = {

    getCsrfToken() {
        return document.querySelector('meta[name="_csrf"]')?.content;
    },

    getCsrfHeader() {
        return document.querySelector('meta[name="_csrf_header"]')?.content || 'X-CSRF-TOKEN';
    },

    // ================================================================
    // TAB 1: RESOURCES - Ported from resource-workbench.js
    // ================================================================

    setLoading(button, isLoading) {
        if (!button) return;
        if (isLoading) {
            if (!button.dataset.originalHtml) button.dataset.originalHtml = button.innerHTML;
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

    defineAndSetupPolicy(button) {
        const tableRow = button.closest('tr');
        if (!tableRow) { showToast('테이블 행을 찾을 수 없습니다.', 'error'); return; }
        const inputCell = tableRow.querySelector('.resource-inputs-cell');
        if (!inputCell) { showToast('입력 필드를 찾을 수 없습니다.', 'error'); return; }
        const resourceId = button.dataset.resourceId;
        const friendlyNameInput = inputCell.querySelector('input[name="friendlyName"]');
        const descriptionTextarea = inputCell.querySelector('textarea[name="description"]');
        if (!friendlyNameInput.value.trim()) {
            showToast('친화적 이름은 필수 항목입니다.', 'error');
            friendlyNameInput.focus();
            return;
        }
        this.showPolicySetupModal(resourceId, friendlyNameInput.value, descriptionTextarea.value, {
            resourceType: button.dataset.resourceType || '',
            resourceIdentifier: button.dataset.resourceIdentifier || '',
            httpMethod: button.dataset.httpMethod || ''
        });
    },

    showPolicySetupModal(resourceId, friendlyName, description, resourceMeta) {
        const modal = document.getElementById('policySetupModal');
        if (!modal) return;
        document.getElementById('modal-permission-name').textContent = friendlyName;
        modal.dataset.resourceId = resourceId;
        modal.dataset.friendlyName = friendlyName;
        modal.dataset.description = description || '';
        modal.dataset.resourceType = (resourceMeta && resourceMeta.resourceType) || '';
        modal.dataset.resourceIdentifier = (resourceMeta && resourceMeta.resourceIdentifier) || '';
        modal.dataset.httpMethod = (resourceMeta && resourceMeta.httpMethod) || '';
        modal.classList.remove('hidden');
    },

    closePolicySetupModal() {
        document.getElementById('policySetupModal').classList.add('hidden');
    },

    async definePermission(modal) {
        const resourceId = modal.dataset.resourceId;
        try {
            const formData = new URLSearchParams();
            formData.append('friendlyName', modal.dataset.friendlyName);
            formData.append('description', modal.dataset.description);
            const response = await fetch('/admin/workbench/resources/' + resourceId + '/define', {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': this.getCsrfToken() },
                body: formData
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);
            return result;
        } catch (error) {
            showToast('권한 생성 실패: ' + error.message, 'error');
            return null;
        }
    },

    async selectQuickMode() {
        const modal = document.getElementById('policySetupModal');
        const result = await this.definePermission(modal);
        if (!result) return;

        this.closePolicySetupModal();

        sessionStorage.setItem('quickModeContext', JSON.stringify({
            resourceId: modal.dataset.resourceId,
            friendlyName: modal.dataset.friendlyName,
            permissionId: result.permissionId,
            permissionName: result.permissionName || '',
            resourceType: modal.dataset.resourceType || '',
            resourceIdentifier: modal.dataset.resourceIdentifier || '',
            httpMethod: modal.dataset.httpMethod || ''
        }));

        window.location.href = '/admin/policy-center?tab=create';
    },

    async selectAIWizard() {
        const modal = document.getElementById('policySetupModal');
        const result = await this.definePermission(modal);
        if (!result) return;

        this.closePolicySetupModal();

        sessionStorage.setItem('aiWizardContext', JSON.stringify({
            resourceId: modal.dataset.resourceId,
            friendlyName: modal.dataset.friendlyName,
            description: modal.dataset.description || '',
            permissionId: result.permissionId,
            resourceType: modal.dataset.resourceType || '',
            resourceIdentifier: modal.dataset.resourceIdentifier || '',
            httpMethod: modal.dataset.httpMethod || ''
        }));

        window.location.href = '/admin/policy-center?tab=create';
    },

    async excludeResource(button) {
        const resourceId = button.dataset.resourceId;
        this.setLoading(button, true);
        try {
            const response = await fetch('/admin/workbench/resources/' + resourceId + '/exclude', {
                method: 'POST', headers: { 'X-CSRF-TOKEN': this.getCsrfToken() }
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);
            this.updateRowAfterExclude(button, resourceId);
            showToast('리소스가 제외 처리되었습니다.', 'success');
        } catch (error) {
            showToast('제외 실패: ' + error.message, 'error');
            this.setLoading(button, false);
        }
    },

    async restoreResource(button) {
        const resourceId = button.dataset.resourceId;
        this.setLoading(button, true);
        try {
            const response = await fetch('/admin/workbench/resources/' + resourceId + '/restore', {
                method: 'POST', headers: { 'X-CSRF-TOKEN': this.getCsrfToken() }
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message);
            this.updateRowAfterRestore(button, resourceId);
            showToast('리소스가 관리 대상으로 복원되었습니다.', 'success');
        } catch (error) {
            showToast('복원 실패: ' + error.message, 'error');
            this.setLoading(button, false);
        }
    },

    updateRowAfterExclude(button, resourceId) {
        const row = button.closest('tr');
        if (!row) return;
        const badge = row.querySelector('.status-badge');
        if (badge) {
            badge.className = 'status-badge bg-slate-500/20 text-slate-400 border-slate-500/30';
            badge.innerHTML = '<i class="fas fa-ban"></i> <span>제외</span>';
        }
        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineAndSetupPolicy(this)"]');
        if (defineBtn) defineBtn.closest('div').style.display = 'none';
        const actionDiv = button.closest('div');
        actionDiv.innerHTML = '<button type="button" class="action-badge-restore w-full text-center" data-resource-id="' + resourceId + '" onclick="PolicyCenter.restoreResource(this)"><i class="fas fa-undo"></i> <span>복원</span></button>';
    },

    updateRowAfterRestore(button, resourceId) {
        const row = button.closest('tr');
        if (!row) return;
        const badge = row.querySelector('.status-badge');
        if (badge) {
            badge.className = 'status-badge bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
            badge.innerHTML = '<i class="fas fa-exclamation-circle"></i> <span>정책 미완료</span>';
        }
        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineAndSetupPolicy(this)"]');
        if (defineBtn) defineBtn.closest('div').style.display = '';
        const actionDiv = button.closest('div');
        actionDiv.innerHTML = '<button type="button" class="action-badge-secondary w-full text-center" data-resource-id="' + resourceId + '" onclick="PolicyCenter.excludeResource(this)"><i class="fas fa-ban"></i> <span>제외</span></button>';
    },

    // ================================================================
    // TAB 2: CREATE - Sub-tab switching
    // ================================================================

    // ================================================================
    // TAB 2: CREATE - Resource Selection Flow
    // ================================================================

    CreateFlow: {
        selectedResource: null,

        init() {
            this.selectedResource = null;
            const guide = document.getElementById('create-no-resource-guide');
            const banner = document.getElementById('create-resource-banner');
            const modeNav = document.getElementById('create-mode-nav');

            // Check for resource context from Resources tab
            const aiCtx = sessionStorage.getItem('aiWizardContext');
            const quickCtx = sessionStorage.getItem('quickModeContext');

            if (aiCtx) {
                sessionStorage.removeItem('aiWizardContext');
                try {
                    const ctx = JSON.parse(aiCtx);
                    this.activateWithResource(ctx);
                    const aiBtn = document.querySelector('.pc-subtab-btn[onclick*="ai"]');
                    if (aiBtn) PolicyCenter.switchCreateMode('ai', aiBtn);
                    // Pre-fill AI query
                    setTimeout(() => {
                        const textarea = document.getElementById('ai-query-input');
                        if (textarea) {
                            const parts = [];
                            if (ctx.resourceType && ctx.resourceIdentifier) {
                                parts.push(ctx.resourceType + ' ' + (ctx.httpMethod || '') + ' ' + ctx.resourceIdentifier);
                            }
                            parts.push('"' + (ctx.friendlyName || '') + '"');
                            if (ctx.description) parts.push('(' + ctx.description + ')');
                            textarea.value = parts.join(' ') + ' 리소스에 대한 최적의 접근 정책을 생성해줘';
                        }
                    }, 100);
                } catch (e) { console.error('Failed to parse AI context', e); }
            } else if (quickCtx) {
                sessionStorage.removeItem('quickModeContext');
                try {
                    const ctx = JSON.parse(quickCtx);
                    this.activateWithResource(ctx);
                    const quickBtn = document.querySelector('.pc-subtab-btn[onclick*="quick"]');
                    if (quickBtn) PolicyCenter.switchCreateMode('quick', quickBtn);
                } catch (e) { console.error('Failed to parse quick context', e); }
            } else {
                // No resource context - show guide
                if (guide) guide.style.display = '';
                if (banner) banner.classList.add('hidden');
                if (modeNav) modeNav.classList.add('hidden');
                document.querySelectorAll('.pc-subtab-content').forEach(c => c.classList.remove('active'));
            }
        },

        activateWithResource(ctx) {
            this.selectedResource = ctx;
            const guide = document.getElementById('create-no-resource-guide');
            const banner = document.getElementById('create-resource-banner');
            const modeNav = document.getElementById('create-mode-nav');

            if (guide) guide.style.display = 'none';
            if (banner) banner.classList.remove('hidden');
            if (modeNav) modeNav.classList.remove('hidden');

            document.getElementById('create-selected-name').textContent = ctx.friendlyName || 'Resource';
            document.getElementById('create-selected-identifier').textContent =
                (ctx.resourceType || '') + ' ' + (ctx.httpMethod || '') + ' ' + (ctx.resourceIdentifier || '');

            // Pre-select permission in Wizard
            if (ctx.permissionId) {
                PolicyCenter.Wizard.selectedPerms.clear();
                PolicyCenter.Wizard.selectedPerms.set(Number(ctx.permissionId), ctx.friendlyName || 'Permission');
            }
        }
    },

    switchCreateMode(mode, btn) {
        document.querySelectorAll('.pc-subtab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.pc-subtab-content').forEach(c => c.classList.remove('active'));
        if (btn) btn.classList.add('active');
        const panel = document.getElementById('create-' + mode);
        if (panel) panel.classList.add('active');
        if (mode === 'quick') this.Wizard.init();
        if (mode === 'ai') this.AI.init();
    },

    // ================================================================
    // TAB 2: QUICK MODE - Inline Wizard (server-side search)
    // ================================================================

    Wizard: {
        currentStep: 1,
        selectedRoles: new Map(),
        selectedPerms: new Map(),
        roleSearchTimeout: null,
        permSearchTimeout: null,

        init() {
            this.currentStep = 1;
            this.selectedRoles.clear();
            // Keep pre-selected permissions from CreateFlow (resource context)
            // selectedPerms is set by CreateFlow.selectResource() before Wizard.init() is called
            this.updateStepUI();
            this.loadRoles('');
        },

        async loadRoles(keyword) {
            const list = document.getElementById('role-list');
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>로딩 중...</p></div>';
            try {
                const resp = await fetch('/admin/policy-center/api/roles?keyword=' + encodeURIComponent(keyword || '') + '&size=50');
                const page = await resp.json();
                this.renderRoleList(page.content || []);
            } catch (e) {
                console.error('Failed to load roles', e);
                list.innerHTML = '<div class="pc-empty"><p>로딩 실패</p></div>';
            }
        },

        renderRoleList(roles) {
            const list = document.getElementById('role-list');
            if (!roles.length) { list.innerHTML = '<div class="pc-empty"><p>역할이 없습니다.</p></div>'; return; }
            list.innerHTML = roles.map(r => {
                const rid = Number(r.id);
                const checked = this.selectedRoles.has(rid) ? 'checked' : '';
                const selectedClass = this.selectedRoles.has(rid) ? ' selected' : '';
                const safeName = this.escapeHtml(r.roleName).replace(/'/g, "\\'");
                return '<div class="wizard-item' + selectedClass + '" onclick="PolicyCenter.Wizard.toggleRole(' + rid + ', \'' + safeName + '\')">' +
                    '<input type="checkbox" ' + checked + ' onclick="PolicyCenter.Wizard.toggleRole(' + rid + ', \'' + safeName + '\'); event.stopPropagation();">' +
                    '<div class="wizard-item-info"><div class="wizard-item-name">' + this.escapeHtml(r.roleName) + '</div>' +
                    '<div class="wizard-item-desc">' + this.escapeHtml(r.roleDesc || '') + '</div></div></div>';
            }).join('');
        },

        toggleRole(id, name) {
            id = Number(id);
            if (this.selectedRoles.has(id)) this.selectedRoles.delete(id);
            else this.selectedRoles.set(id, name);
            this.renderRoleChips();
            this.loadRoles(document.getElementById('role-search')?.value || '');
        },

        renderRoleChips() {
            const container = document.getElementById('role-chips');
            container.innerHTML = Array.from(this.selectedRoles.entries()).map(([id, name]) =>
                '<span class="wizard-chip">' + this.escapeHtml(name) + ' <span class="chip-remove" onclick="event.stopPropagation(); PolicyCenter.Wizard.toggleRole(' + id + ', \'' + this.escapeHtml(name) + '\')">&times;</span></span>'
            ).join('');
        },

        searchRoles(keyword) {
            clearTimeout(this.roleSearchTimeout);
            this.roleSearchTimeout = setTimeout(() => this.loadRoles(keyword), 400);
        },

        async loadPermissions(keyword) {
            const list = document.getElementById('perm-list');
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>로딩 중...</p></div>';
            const roleIds = Array.from(this.selectedRoles.keys()).join(',');
            try {
                const resp = await fetch('/admin/policy-center/api/available-permissions?roleIds=' + roleIds + '&keyword=' + encodeURIComponent(keyword || '') + '&size=50');
                const page = await resp.json();
                this.renderPermList(page.content || []);
            } catch (e) {
                console.error('Failed to load permissions', e);
                list.innerHTML = '<div class="pc-empty"><p>로딩 실패</p></div>';
            }
        },

        renderPermList(perms) {
            const list = document.getElementById('perm-list');
            if (!perms.length) { list.innerHTML = '<div class="pc-empty"><p>추가 가능한 권한이 없습니다.</p></div>'; return; }
            list.innerHTML = perms.map(p => {
                const pid = Number(p.id);
                const checked = this.selectedPerms.has(pid) ? 'checked' : '';
                const selectedClass = this.selectedPerms.has(pid) ? ' selected' : '';
                const safeName = this.escapeHtml(p.name || p.friendlyName || '').replace(/'/g, "\\'");
                return '<div class="wizard-item' + selectedClass + '" onclick="PolicyCenter.Wizard.togglePerm(' + pid + ', \'' + safeName + '\')">' +
                    '<input type="checkbox" ' + checked + ' onclick="PolicyCenter.Wizard.togglePerm(' + pid + ', \'' + safeName + '\'); event.stopPropagation();">' +
                    '<div class="wizard-item-info"><div class="wizard-item-name">' + this.escapeHtml(p.friendlyName || p.name) + '</div>' +
                    '<div class="wizard-item-desc">' + this.escapeHtml(p.description || '') + '</div></div></div>';
            }).join('');
        },

        togglePerm(id, name) {
            id = Number(id);
            if (this.selectedPerms.has(id)) this.selectedPerms.delete(id);
            else this.selectedPerms.set(id, name);
            this.renderPermChips();
            this.loadPermissions(document.getElementById('perm-search')?.value || '');
        },

        renderPermChips() {
            const container = document.getElementById('perm-chips');
            container.innerHTML = Array.from(this.selectedPerms.entries()).map(([id, name]) =>
                '<span class="wizard-chip">' + this.escapeHtml(name) + ' <span class="chip-remove" onclick="event.stopPropagation(); PolicyCenter.Wizard.togglePerm(' + id + ', \'' + this.escapeHtml(name) + '\')">&times;</span></span>'
            ).join('');
        },

        searchPermissions(keyword) {
            clearTimeout(this.permSearchTimeout);
            this.permSearchTimeout = setTimeout(() => this.loadPermissions(keyword), 400);
        },

        nextStep() {
            if (this.currentStep === 1) {
                if (this.selectedRoles.size === 0) { showToast('하나 이상의 역할을 선택하세요.', 'error'); return; }
                this.currentStep = 2;
                this.loadPermissions('');
            } else if (this.currentStep === 2) {
                if (this.selectedPerms.size === 0) { showToast('하나 이상의 권한을 선택하세요.', 'error'); return; }
                this.currentStep = 3;
                this.renderReviewSummary();
            }
            this.updateStepUI();
        },

        prevStep() {
            if (this.currentStep > 1) { this.currentStep--; this.updateStepUI(); }
        },

        updateStepUI() {
            for (let i = 1; i <= 3; i++) {
                const panel = document.getElementById('wizard-step-' + i);
                const stepEl = document.querySelector('.wizard-step[data-step="' + i + '"]');
                if (panel) { panel.classList.remove('active'); if (i === this.currentStep) panel.classList.add('active'); }
                if (stepEl) {
                    stepEl.classList.remove('active', 'completed');
                    if (i === this.currentStep) stepEl.classList.add('active');
                    else if (i < this.currentStep) stepEl.classList.add('completed');
                }
            }
            document.querySelectorAll('.wizard-step-line').forEach((line, idx) => {
                line.classList.remove('completed');
                if (idx + 1 < this.currentStep) line.classList.add('completed');
            });
        },

        renderReviewSummary() {
            const summary = document.getElementById('quick-review-summary');
            const roleNames = Array.from(this.selectedRoles.values()).map(n => '<span class="wizard-chip">' + this.escapeHtml(n) + '</span>').join(' ');
            const permNames = Array.from(this.selectedPerms.values()).map(n => '<span class="wizard-chip">' + this.escapeHtml(n) + '</span>').join(' ');
            summary.innerHTML = '<div class="mb-3"><p class="text-xs font-semibold mb-1" style="color:#94a3b8;">역할 (' + this.selectedRoles.size + '개)</p><div class="flex flex-wrap gap-1">' + roleNames + '</div></div>' +
                '<div><p class="text-xs font-semibold mb-1" style="color:#94a3b8;">권한 (' + this.selectedPerms.size + '개)</p><div class="flex flex-wrap gap-1">' + permNames + '</div></div>';
            const nameInput = document.getElementById('quick-policy-name');
            if (!nameInput.value) nameInput.value = 'Permission Assignment - ' + new Date().toISOString().slice(0, 16);
        },

        async createPolicy() {
            const name = document.getElementById('quick-policy-name').value.trim();
            if (!name) { showToast('정책명을 입력하세요.', 'error'); return; }
            const btn = document.getElementById('quick-create-btn');
            PolicyCenter.setLoading(btn, true);
            try {
                const resp = await fetch('/admin/policy-center/api/quick-create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': PolicyCenter.getCsrfToken() },
                    body: JSON.stringify({
                        policyName: name,
                        description: document.getElementById('quick-policy-desc').value,
                        roleIds: Array.from(this.selectedRoles.keys()),
                        permissionIds: Array.from(this.selectedPerms.keys()),
                        effect: document.getElementById('quick-policy-effect').value
                    })
                });
                const result = await resp.json();
                if (!resp.ok) throw new Error(result.message);
                showToast('정책이 성공적으로 생성되었습니다.', 'success');
                setTimeout(() => window.location.href = '/admin/policy-center?tab=list', 1500);
            } catch (e) {
                showToast('정책 생성 실패: ' + e.message, 'error');
                PolicyCenter.setLoading(btn, false);
            }
        },

        escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }
    },

    // ================================================================
    // TAB 2: MANUAL MODE - Dynamic form (from policydetails.html)
    // ================================================================

    Manual: {
        addTarget() {
            const container = document.getElementById('targets-container');
            const idx = container.getElementsByClassName('target-block').length;
            const block = document.createElement('div');
            block.className = 'target-block grid grid-cols-12 gap-2 items-center';
            block.innerHTML =
                '<div class="col-span-3"><select name="targets[' + idx + '].targetType" onchange="PolicyCenter.Manual.toggleHttpMethod(this)" class="modern-select"><option value="URL">URL</option><option value="METHOD">METHOD</option></select></div>' +
                '<div class="col-span-2"><select name="targets[' + idx + '].httpMethod" class="http-method-select modern-select"><option value="ALL">ALL</option><option value="GET">GET</option><option value="POST">POST</option><option value="PUT">PUT</option><option value="DELETE">DELETE</option></select></div>' +
                '<div class="col-span-6"><input type="text" name="targets[' + idx + '].targetIdentifier" class="modern-input" placeholder="/admin/** or com.example.*" required /></div>' +
                '<div class="col-span-1 text-center"><button type="button" onclick="PolicyCenter.Manual.removeElement(this, \'.target-block\')" class="remove-btn">&times;</button></div>';
            container.appendChild(block);
        },

        addRule() {
            const container = document.getElementById('rules-container');
            const idx = container.getElementsByClassName('rule-block').length;
            const block = document.createElement('div');
            block.className = 'rule-block p-4 rounded-lg space-y-3 relative';
            block.style = 'background: rgba(30, 41, 59, 0.4); border: 1px solid rgba(71, 85, 105, 0.3);';
            block.innerHTML =
                '<button type="button" onclick="PolicyCenter.Manual.removeRule(this)" class="remove-btn">&times;</button>' +
                '<h3 class="font-semibold" style="color: #e2e8f0;">규칙(Rule) #' + (idx + 1) + '</h3>' +
                '<div><label class="manual-form-label">규칙 설명</label><input type="text" name="rules[' + idx + '].description" class="modern-input" /></div>' +
                '<div><label class="manual-form-label">조건 (AND 결합)</label><div class="conditions-list space-y-2 mt-2"></div>' +
                '<button type="button" onclick="PolicyCenter.Manual.addCondition(this)" class="add-btn mt-2"><i class="fas fa-plus"></i> 조건 추가</button></div>';
            container.appendChild(block);
        },

        addCondition(button) {
            const ruleBlock = button.closest('.rule-block');
            const condList = ruleBlock.querySelector('.conditions-list');
            const ruleIdx = Array.from(document.querySelectorAll('.rule-block')).indexOf(ruleBlock);
            const condIdx = condList.children.length;
            const block = document.createElement('div');
            block.className = 'condition-block grid grid-cols-12 gap-2 items-center';
            block.innerHTML =
                '<div class="col-span-3"><select name="rules[' + ruleIdx + '].conditions[' + condIdx + '].authorizationPhase" class="modern-select text-sm"><option value="PRE_AUTHORIZE">사전 인가 (Pre)</option><option value="POST_AUTHORIZE">사후 인가 (Post)</option></select></div>' +
                '<div class="col-span-8"><input type="text" name="rules[' + ruleIdx + '].conditions[' + condIdx + '].expression" class="modern-input font-mono text-sm" placeholder="SpEL expression" /></div>' +
                '<div class="col-span-1 text-center"><button type="button" onclick="PolicyCenter.Manual.removeElement(this, \'.condition-block\')" class="remove-btn">&times;</button></div>';
            condList.appendChild(block);
        },

        toggleHttpMethod(selectEl) {
            const block = selectEl.closest('.target-block');
            const methodSelect = block.querySelector('.http-method-select');
            if (selectEl.value === 'URL') { methodSelect.style.display = 'block'; }
            else { methodSelect.style.display = 'none'; methodSelect.value = 'ALL'; }
        },

        removeElement(button, selector) {
            const el = button.closest(selector);
            const parent = el.parentNode;
            el.remove();
            if (selector === '.target-block') this.updateTargetIndices();
            else if (selector === '.condition-block') {
                const ruleBlock = parent.closest('.rule-block');
                if (ruleBlock) this.updateConditionIndices(ruleBlock);
            }
        },

        removeRule(button) {
            button.closest('.rule-block').remove();
            this.updateRuleIndices();
        },

        updateTargetIndices() {
            const blocks = document.getElementById('targets-container').getElementsByClassName('target-block');
            for (let i = 0; i < blocks.length; i++) {
                const b = blocks[i];
                const ts = b.querySelector('select[name*="targetType"]'); if (ts) ts.name = 'targets[' + i + '].targetType';
                const ms = b.querySelector('select[name*="httpMethod"]'); if (ms) ms.name = 'targets[' + i + '].httpMethod';
                const ti = b.querySelector('input[name*="targetIdentifier"]'); if (ti) ti.name = 'targets[' + i + '].targetIdentifier';
            }
        },

        updateRuleIndices() {
            const blocks = document.getElementById('rules-container').getElementsByClassName('rule-block');
            for (let i = 0; i < blocks.length; i++) {
                const b = blocks[i];
                b.querySelector('h3').textContent = '규칙(Rule) #' + (i + 1);
                const descInput = b.querySelector('input[name*=".description"]'); if (descInput) descInput.name = 'rules[' + i + '].description';
                this.updateConditionIndicesForRule(b, i);
            }
        },

        updateConditionIndices(ruleBlock) {
            const ruleIdx = Array.from(document.querySelectorAll('.rule-block')).indexOf(ruleBlock);
            this.updateConditionIndicesForRule(ruleBlock, ruleIdx);
        },

        updateConditionIndicesForRule(ruleBlock, ruleIdx) {
            const conds = ruleBlock.querySelectorAll('.condition-block');
            conds.forEach((c, j) => {
                const ps = c.querySelector('select[name*="authorizationPhase"]'); if (ps) ps.name = 'rules[' + ruleIdx + '].conditions[' + j + '].authorizationPhase';
                const ei = c.querySelector('input[name*="expression"]'); if (ei) ei.name = 'rules[' + ruleIdx + '].conditions[' + j + '].expression';
            });
        },

        initHttpMethodVisibility() {
            document.querySelectorAll('.target-block').forEach(block => {
                const typeSelect = block.querySelector('select[name*="targetType"]');
                if (typeSelect) this.toggleHttpMethod(typeSelect);
            });
        }
    },

    // ================================================================
    // TAB 2: AI MODE - SSE Streaming Policy Generation
    // ================================================================

    AI: {
        generatedPolicyData: null,
        _cachedMaps: null,
        _cachedPolicySummaries: null,
        _cachedAvailableItems: null,
        _filteredCount: 0,
        _wasFallback: false,
        _pickerType: null,
        _pickerSelection: new Map(),
        _searchTimeout: null,

        // ---- Initialization & Dashboard ----

        async init() {
            this.initExampleChips();
            this.loadContextDashboard();
        },

        async loadContextDashboard() {
            try {
                const resp = await fetch('/admin/policy-center/api/stats');
                const stats = await resp.json();
                const el = (id) => document.getElementById(id);
                el('ai-stat-roles-count').textContent = stats.roleCount || 0;
                el('ai-stat-perms-count').textContent = stats.permissionCount || 0;
                el('ai-stat-conditions-count').textContent = stats.conditionCount || 0;
                el('ai-stat-policies-count').textContent = stats.policyCount || 0;

                // Resource stats
                el('ai-stat-resource-total').textContent = stats.resourceTotal || 0;
                const unprotected = stats.resourcePermissionCreated || 0;
                el('ai-stat-resource-unprotected').textContent = unprotected;
                el('ai-stat-resource-connected').textContent = stats.resourcePolicyConnected || 0;
                el('ai-stat-resource-needs-def').textContent = stats.resourceNeedsDefinition || 0;

                // Unprotected warning
                if (unprotected > 0) {
                    document.getElementById('ai-unprotected-warning').classList.remove('hidden');
                    document.getElementById('ai-unprotected-count').textContent = unprotected;
                }
            } catch (e) {
                console.error('Failed to load system stats', e);
            }
        },

        initExampleChips() {
            document.querySelectorAll('.ai-example-chip').forEach(chip => {
                chip.addEventListener('click', () => {
                    document.getElementById('ai-query-input').value = chip.dataset.query;
                    document.getElementById('ai-query-input').focus();
                });
            });
        },

        // ---- AI Generation ----

        async generate() {
            const queryInput = document.getElementById('ai-query-input');
            const query = queryInput.value.trim();
            if (!query) { showToast('정책 요구사항을 입력하세요.', 'error'); queryInput.focus(); return; }

            const btn = document.getElementById('ai-generate-btn');
            const cancelBtn = document.getElementById('ai-cancel-btn');
            const progress = document.getElementById('ai-progress-section');
            const result = document.getElementById('ai-result-section');

            btn.disabled = true;
            cancelBtn.classList.remove('hidden');
            progress.classList.remove('hidden');
            result.classList.add('hidden');
            this.generatedPolicyData = null;
            this._filteredCount = 0;
            this._wasFallback = false;

            this.updateProgress('collect', 10, 'Collecting system data...');

            try {
                if (typeof ContexaLLM !== 'undefined' && ContexaLLM.analyzeStreaming) {
                    this.updateProgress('analyze', 40, 'AI analyzing policy requirements...');
                    await ContexaLLM.analyzeStreaming(
                        '/api/ai/policies/generate/stream',
                        { naturalLanguageQuery: query },
                        {
                            modalTitle: 'AI 정책 분석 진행 중',
                            initialLoadingText: 'Analyzing policy requirements...',
                            analysisCompleteText: 'Analysis complete',
                            generatingResultText: 'Generating policy...',
                            finalCompleteText: 'Policy generated',
                            autoHideDelay: 1000,
                            timeoutMs: 300000,
                            onComplete: (response) => {
                                this.updateProgress('generate', 80, 'Building policy card...');
                                this.handleAIComplete(response, query);
                            },
                            onError: (error) => {
                                showToast('AI 정책 생성 실패: ' + (error.message || error), 'error');
                            }
                        }
                    );
                } else {
                    this.updateProgress('analyze', 40, 'Sending request to AI...');
                    const response = await fetch('/api/ai/policies/generate/stream', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken()
                        },
                        body: JSON.stringify({ naturalLanguageQuery: query })
                    });
                    const text = await response.text();
                    const jsonMatch = text.match(/###FINAL_RESPONSE###([\s\S]*)/);
                    if (jsonMatch) {
                        try {
                            const parsed = JSON.parse(jsonMatch[1].replace(/^data:\s*/gm, '').replace('[DONE]', '').trim());
                            this.updateProgress('generate', 80, 'Building policy card...');
                            this.handleAIComplete(parsed, query);
                        } catch (parseErr) {
                            console.error('AI response parse failed', parseErr);
                            showToast('AI 응답 파싱 실패. 다시 시도하세요.', 'error');
                        }
                    } else {
                        showToast('AI 응답을 파싱할 수 없습니다.', 'error');
                    }
                }
            } catch (e) {
                showToast('AI 정책 생성 실패: ' + e.message, 'error');
            } finally {
                btn.disabled = false;
                cancelBtn.classList.add('hidden');
                progress.classList.add('hidden');
            }
        },

        updateProgress(step, percent, message) {
            const steps = ['collect', 'analyze', 'generate'];
            const idx = steps.indexOf(step);
            document.querySelectorAll('.ai-progress-step').forEach((el, i) => {
                el.classList.remove('active', 'completed');
                if (i < idx) el.classList.add('completed');
                else if (i === idx) el.classList.add('active');
            });
            const fill = document.getElementById('ai-progress-fill');
            if (fill) fill.style.width = percent + '%';
            const msg = document.getElementById('ai-progress-message');
            if (msg) msg.textContent = message;
        },

        cancel() {
            // ContexaLLM handles abort internally; just reset UI
            document.getElementById('ai-generate-btn').disabled = false;
            document.getElementById('ai-cancel-btn').classList.add('hidden');
            document.getElementById('ai-progress-section').classList.add('hidden');
        },

        // ---- AI Response Handler ----

        async handleAIComplete(response, query) {
            if (!response) { showToast('AI 응답이 비어 있습니다.', 'warning'); return; }

            const processed = this.preprocessPolicyResponse(response);
            if (!processed || !processed.policyData) {
                console.error('AI response preprocessing failed:', response);
                this._wasFallback = true;
                this.createFallbackPolicy(query);
                return;
            }

            const validatedData = await this.validateAndFilterAIResponse(processed.policyData);
            if (!validatedData) {
                showToast('AI 응답 검증에 실패했습니다.', 'error');
                return;
            }

            this.generatedPolicyData = validatedData;
            this._cachedMaps = {
                roles: processed.roleIdToNameMap || {},
                permissions: processed.permissionIdToNameMap || {},
                conditions: processed.conditionIdToNameMap || {}
            };

            // Render all sections
            this.renderPolicyCard(validatedData, this._cachedMaps);
            this.renderConfidence(validatedData);
            this.checkConflicts(validatedData);
            this.simulateImpact(validatedData);

            document.getElementById('ai-result-section').classList.remove('hidden');
            this.updateProgress('generate', 100, 'Complete!');
        },

        preprocessPolicyResponse(response) {
            if (!response) return null;
            if (response.policyData && response.roleIdToNameMap !== undefined) {
                return { policyData: response.policyData, roleIdToNameMap: response.roleIdToNameMap || {}, permissionIdToNameMap: response.permissionIdToNameMap || {}, conditionIdToNameMap: response.conditionIdToNameMap || {} };
            }
            if (response.policyData && response.policyData.roleIdToNameMap !== undefined) {
                return { policyData: response.policyData, roleIdToNameMap: response.policyData.roleIdToNameMap || {}, permissionIdToNameMap: response.policyData.permissionIdToNameMap || {}, conditionIdToNameMap: response.policyData.conditionIdToNameMap || {} };
            }
            if (response.policyName && response.roleIds !== undefined) {
                return { policyData: response, roleIdToNameMap: this.createIdToNameMap('role', response.roleIds || []), permissionIdToNameMap: this.createIdToNameMap('permission', response.permissionIds || []), conditionIdToNameMap: this.createIdToNameMap('condition', Object.keys(response.conditions || {})) };
            }
            if (response.data && typeof response.data === 'object') {
                return this.preprocessPolicyResponse(response.data);
            }
            if (response.generatedPolicy || response.policyConfidenceScore !== undefined) {
                if (response.policyData) { return { policyData: response.policyData, roleIdToNameMap: response.roleIdToNameMap || {}, permissionIdToNameMap: response.permissionIdToNameMap || {}, conditionIdToNameMap: response.conditionIdToNameMap || {} }; }
                if (typeof response.generatedPolicy === 'string') { try { return this.preprocessPolicyResponse(JSON.parse(response.generatedPolicy)); } catch (e) { console.error('generatedPolicy parse failed:', e.message); } }
            }
            console.error('Unknown AI response structure:', Object.keys(response));
            return null;
        },

        async validateAndFilterAIResponse(policyData) {
            const validatedData = { ...policyData };
            this._filteredCount = 0;
            try {
                const availableItems = await this.fetchAvailableItems();
                this._cachedAvailableItems = availableItems;
                const availableRoleIds = new Set(availableItems.roles.map(r => r.id));
                const availablePermissionIds = new Set(availableItems.permissions.map(p => p.id));
                const availableConditionIds = new Set(availableItems.conditions.map(c => c.id));

                if (validatedData.roleIds && Array.isArray(validatedData.roleIds)) {
                    const orig = validatedData.roleIds.length;
                    validatedData.roleIds = validatedData.roleIds.filter(id => availableRoleIds.has(id));
                    this._filteredCount += orig - validatedData.roleIds.length;
                } else { validatedData.roleIds = []; }

                if (validatedData.permissionIds && Array.isArray(validatedData.permissionIds)) {
                    const orig = validatedData.permissionIds.length;
                    validatedData.permissionIds = validatedData.permissionIds.filter(id => availablePermissionIds.has(id));
                    this._filteredCount += orig - validatedData.permissionIds.length;
                } else { validatedData.permissionIds = []; }

                if (validatedData.conditions && typeof validatedData.conditions === 'object') {
                    const filtered = {};
                    Object.keys(validatedData.conditions).forEach(id => {
                        if (availableConditionIds.has(parseInt(id))) filtered[id] = validatedData.conditions[id];
                        else this._filteredCount++;
                    });
                    validatedData.conditions = filtered;
                } else { validatedData.conditions = {}; }
            } catch (e) {
                console.error('Validation fallback:', e);
                if (!Array.isArray(validatedData.roleIds)) validatedData.roleIds = [];
                if (!Array.isArray(validatedData.permissionIds)) validatedData.permissionIds = [];
                if (!validatedData.conditions || typeof validatedData.conditions !== 'object') validatedData.conditions = {};
            }
            if (!validatedData.policyName) validatedData.policyName = 'AI Generated Policy - ' + new Date().toISOString().slice(0, 16);
            if (!validatedData.effect) validatedData.effect = 'ALLOW';
            if (this._filteredCount > 0) showToast('AI 응답에서 ' + this._filteredCount + '개 존재하지 않는 항목이 제거되었습니다.', 'warning');
            return validatedData;
        },

        async fetchAvailableItems() {
            if (this._cachedAvailableItems) return this._cachedAvailableItems;
            const [rolesResp, permsResp, condsResp] = await Promise.all([
                fetch('/admin/policy-center/api/roles?size=10000'),
                fetch('/admin/policy-center/api/available-permissions?size=10000'),
                fetch('/admin/policy-center/api/conditions')
            ]);
            const rolesPage = await rolesResp.json();
            const permsPage = await permsResp.json();
            const conditions = await condsResp.json();
            this._cachedAvailableItems = { roles: rolesPage.content || [], permissions: permsPage.content || [], conditions: conditions || [] };
            return this._cachedAvailableItems;
        },

        createIdToNameMap(type, ids) {
            if (!ids || !Array.isArray(ids)) return {};
            const map = {};
            const src = type === 'role' ? (window.allRoles || []) : type === 'permission' ? (window.allPermissions || []) : type === 'condition' ? (window.allConditions || []) : [];
            ids.forEach(id => { const item = src.find(x => x.id == id); if (item) map[id] = type === 'role' ? (item.roleName || item.name) : type === 'permission' ? (item.friendlyName || item.name) : item.name; });
            return map;
        },

        createFallbackPolicy(query) {
            const fallback = { policyName: 'AI Generated Policy (' + new Date().toISOString().slice(0, 16) + ')', description: 'Requirement: "' + (query || '') + '"', effect: 'ALLOW', roleIds: [], permissionIds: [], conditions: {}, aiActionEnabled: false, allowedActions: [], customConditionSpel: '' };
            this.generatedPolicyData = fallback;
            this._cachedMaps = { roles: {}, permissions: {}, conditions: {} };
            this.renderPolicyCard(fallback, this._cachedMaps);
            this.renderConfidence(fallback);
            document.getElementById('ai-result-section').classList.remove('hidden');
            showToast('기본 정책이 생성되었습니다. 필요에 따라 수정해주세요.', 'warning');
        },

        // ---- Interactive Policy Card ----

        renderPolicyCard(data, maps) {
            document.getElementById('ai-card-name').value = data.policyName || '';
            document.getElementById('ai-card-effect').value = data.effect || 'ALLOW';
            document.getElementById('ai-card-description').value = data.description || '';

            this.renderChips('ai-card-roles', (data.roleIds || []).map(id => ({ id, name: maps.roles[id] || maps.roles[String(id)] || 'ID:' + id })), 'role');
            this.renderChips('ai-card-permissions', (data.permissionIds || []).map(id => ({ id, name: maps.permissions[id] || maps.permissions[String(id)] || 'ID:' + id })), 'permission');
            this.renderChips('ai-card-conditions', Object.keys(data.conditions || {}).map(id => ({ id, name: maps.conditions[id] || maps.conditions[String(id)] || 'ID:' + id })), 'condition');

            const spelSection = document.getElementById('ai-card-spel-section');
            if (data.customConditionSpel) {
                spelSection.classList.remove('hidden');
                document.getElementById('ai-card-spel').value = data.customConditionSpel;
            } else {
                spelSection.classList.add('hidden');
            }
        },

        renderChips(containerId, items, type) {
            const container = document.getElementById(containerId);
            if (!items.length) {
                container.innerHTML = '<span class="ai-card-chips-empty">없음 (None)</span>';
                return;
            }
            container.innerHTML = items.map(item =>
                '<span class="ai-card-chip">' +
                this.escapeHtml(item.name) +
                ' <span class="chip-id">#' + item.id + '</span>' +
                ' <span class="chip-remove" onclick="PolicyCenter.AI.removeChip(\'' + type + '\', ' + item.id + ')">&times;</span>' +
                '</span>'
            ).join('');
        },

        removeChip(type, id) {
            if (!this.generatedPolicyData) return;
            if (type === 'role') {
                this.generatedPolicyData.roleIds = (this.generatedPolicyData.roleIds || []).filter(r => r !== id);
            } else if (type === 'permission') {
                this.generatedPolicyData.permissionIds = (this.generatedPolicyData.permissionIds || []).filter(p => p !== id);
            } else if (type === 'condition') {
                delete this.generatedPolicyData.conditions[String(id)];
            }
            this.renderPolicyCard(this.generatedPolicyData, this._cachedMaps || { roles: {}, permissions: {}, conditions: {} });
            this.renderConfidence(this.generatedPolicyData);
            this.checkConflicts(this.generatedPolicyData);
            this.simulateImpact(this.generatedPolicyData);
        },

        syncCardToData() {
            if (!this.generatedPolicyData) return;
            this.generatedPolicyData.policyName = document.getElementById('ai-card-name').value;
            this.generatedPolicyData.effect = document.getElementById('ai-card-effect').value;
            this.generatedPolicyData.description = document.getElementById('ai-card-description').value;
            const spel = document.getElementById('ai-card-spel');
            if (spel) this.generatedPolicyData.customConditionSpel = spel.value;
        },

        // ---- Item Picker Modal ----

        async openItemPicker(type) {
            this._pickerType = type;
            this._pickerSelection = new Map();
            const titleMap = { role: '역할 추가 (Add Roles)', permission: '권한 추가 (Add Permissions)', condition: '조건 추가 (Add Conditions)' };
            document.getElementById('ai-item-picker-title').textContent = titleMap[type] || 'Select Items';
            const searchInput = document.getElementById('ai-item-picker-search');
            searchInput.value = '';
            document.getElementById('ai-item-picker-overlay').classList.remove('hidden');
            await this.loadPickerItems(type, '');

            // Remove previous listener to prevent duplicate binding
            const newSearch = searchInput.cloneNode(true);
            searchInput.parentNode.replaceChild(newSearch, searchInput);
            newSearch.addEventListener('input', (e) => {
                clearTimeout(this._searchTimeout);
                this._searchTimeout = setTimeout(() => this.loadPickerItems(type, e.target.value), 300);
            });
        },

        async loadPickerItems(type, keyword) {
            const list = document.getElementById('ai-item-picker-list');
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>로딩 중...</p></div>';

            try {
                let items = [];
                if (type === 'role') {
                    const resp = await fetch('/admin/policy-center/api/roles?keyword=' + encodeURIComponent(keyword || '') + '&size=50');
                    const page = await resp.json();
                    items = (page.content || []).map(r => ({ id: r.id, name: r.roleName, desc: r.roleDesc || '' }));
                } else if (type === 'permission') {
                    const resp = await fetch('/admin/policy-center/api/available-permissions?keyword=' + encodeURIComponent(keyword || '') + '&size=50');
                    const page = await resp.json();
                    items = (page.content || []).map(p => ({ id: p.id, name: p.friendlyName || p.name, desc: p.description || '' }));
                } else if (type === 'condition') {
                    const resp = await fetch('/admin/policy-center/api/conditions?keyword=' + encodeURIComponent(keyword || ''));
                    const conditions = await resp.json();
                    items = (conditions || []).map(c => ({ id: c.id, name: c.name, desc: c.description || '' }));
                }

                // Exclude already selected items
                const existingIds = new Set();
                if (this.generatedPolicyData) {
                    if (type === 'role') (this.generatedPolicyData.roleIds || []).forEach(id => existingIds.add(id));
                    else if (type === 'permission') (this.generatedPolicyData.permissionIds || []).forEach(id => existingIds.add(id));
                    else if (type === 'condition') Object.keys(this.generatedPolicyData.conditions || {}).forEach(id => existingIds.add(parseInt(id)));
                }

                const available = items.filter(i => !existingIds.has(i.id));
                if (!available.length) {
                    list.innerHTML = '<div class="pc-empty"><p>추가 가능한 항목이 없습니다.</p></div>';
                    return;
                }

                list.innerHTML = available.map(item => {
                    const checked = this._pickerSelection.has(item.id) ? 'checked' : '';
                    const selClass = this._pickerSelection.has(item.id) ? ' selected' : '';
                    return '<div class="wizard-item' + selClass + '" onclick="PolicyCenter.AI.togglePickerItem(' + item.id + ', \'' + this.escapeHtml(item.name).replace(/'/g, "\\'") + '\')">' +
                        '<input type="checkbox" ' + checked + ' onclick="event.stopPropagation()">' +
                        '<div class="wizard-item-info"><div class="wizard-item-name">' + this.escapeHtml(item.name) + '</div>' +
                        '<div class="wizard-item-desc">' + this.escapeHtml(item.desc) + '</div></div></div>';
                }).join('');
            } catch (e) {
                console.error('Failed to load picker items', e);
                list.innerHTML = '<div class="pc-empty"><p>로딩 실패</p></div>';
            }
        },

        togglePickerItem(id, name) {
            if (this._pickerSelection.has(id)) this._pickerSelection.delete(id);
            else this._pickerSelection.set(id, name);
            // Update checkbox state locally without API re-call
            const list = document.getElementById('ai-item-picker-list');
            list.querySelectorAll('.wizard-item').forEach(item => {
                const cb = item.querySelector('input[type="checkbox"]');
                const itemName = item.querySelector('.wizard-item-name');
                if (!itemName) return;
                // Match by checking onclick attribute for the id
                const onclick = item.getAttribute('onclick') || '';
                if (onclick.includes('(' + id + ',')) {
                    const selected = this._pickerSelection.has(id);
                    if (cb) cb.checked = selected;
                    if (selected) item.classList.add('selected');
                    else item.classList.remove('selected');
                }
            });
        },

        applyPickerSelection() {
            if (!this.generatedPolicyData || this._pickerSelection.size === 0) {
                this.closeItemPicker();
                return;
            }
            this.syncCardToData();

            this._pickerSelection.forEach((name, id) => {
                if (this._pickerType === 'role') {
                    if (!this.generatedPolicyData.roleIds.includes(id)) this.generatedPolicyData.roleIds.push(id);
                    if (this._cachedMaps) this._cachedMaps.roles[id] = name;
                } else if (this._pickerType === 'permission') {
                    if (!this.generatedPolicyData.permissionIds.includes(id)) this.generatedPolicyData.permissionIds.push(id);
                    if (this._cachedMaps) this._cachedMaps.permissions[id] = name;
                } else if (this._pickerType === 'condition') {
                    if (!this.generatedPolicyData.conditions[String(id)]) this.generatedPolicyData.conditions[String(id)] = ['true'];
                    if (this._cachedMaps) this._cachedMaps.conditions[id] = name;
                }
            });

            this.renderPolicyCard(this.generatedPolicyData, this._cachedMaps);
            this.renderConfidence(this.generatedPolicyData);
            this.checkConflicts(this.generatedPolicyData);
            this.simulateImpact(this.generatedPolicyData);
            this.closeItemPicker();
        },

        closeItemPicker() {
            document.getElementById('ai-item-picker-overlay').classList.add('hidden');
            this._pickerSelection.clear();
        },

        // ---- Conflict Detection ----

        async checkConflicts(policyData) {
            const panel = document.getElementById('ai-conflict-panel');
            const listEl = document.getElementById('ai-conflict-list');
            const conflicts = [];

            try {
                if (!this._cachedPolicySummaries) {
                    const resp = await fetch('/admin/policy-center/api/policy-summaries');
                    this._cachedPolicySummaries = await resp.json();
                }

                const summaries = this._cachedPolicySummaries;

                // Check name duplicates
                summaries.filter(p => p.name === policyData.policyName).forEach(p => {
                    conflicts.push({ severity: 'high', message: '"' + p.name + '" 정책명이 이미 존재합니다 (Policy #' + p.id + ')' });
                });

                // Check similar names (partial match)
                if (policyData.policyName) {
                    const lower = policyData.policyName.toLowerCase();
                    summaries.filter(p => p.name && p.name.toLowerCase().includes(lower) && p.name !== policyData.policyName).forEach(p => {
                        conflicts.push({ severity: 'low', message: '유사한 정책명 발견: "' + p.name + '" (Policy #' + p.id + ')' });
                    });
                }
            } catch (e) {
                console.error('Failed to check conflicts', e);
            }

            if (conflicts.length === 0) {
                panel.classList.add('hidden');
            } else {
                panel.classList.remove('hidden');
                listEl.innerHTML = conflicts.map(c =>
                    '<div class="ai-conflict-item">' +
                    '<span class="ai-conflict-severity ' + c.severity + '">' + c.severity.toUpperCase() + '</span>' +
                    '<span class="ai-conflict-message">' + this.escapeHtml(c.message) + '</span>' +
                    '</div>'
                ).join('');
            }
        },

        // ---- Impact Simulation ----

        simulateImpact(policyData) {
            const content = document.getElementById('ai-simulation-content');
            const roleCount = (policyData.roleIds || []).length;
            const permCount = (policyData.permissionIds || []).length;
            const condCount = Object.keys(policyData.conditions || {}).length;

            // Risk calculation
            let riskScore = 0;
            const warnings = [];
            if (roleCount > 3) { riskScore += 2; warnings.push('Many roles affected (' + roleCount + ')'); }
            if (permCount > 5) { riskScore += 1; warnings.push('Many permissions granted (' + permCount + ')'); }
            if (condCount === 0) { riskScore += 2; warnings.push('No conditions - policy applies unconditionally'); }
            if (policyData.effect === 'DENY') { riskScore += 1; warnings.push('DENY effect - may block legitimate access'); }

            // Check for sensitive permissions
            if (this._cachedAvailableItems) {
                const perms = this._cachedAvailableItems.permissions || [];
                const selectedPerms = perms.filter(p => (policyData.permissionIds || []).includes(p.id));
                const sensitive = selectedPerms.filter(p => {
                    const name = (p.friendlyName || p.name || '').toLowerCase();
                    return name.includes('delete') || name.includes('admin') || name.includes('write') || name.includes('modify');
                });
                if (sensitive.length > 0) { riskScore += 2; warnings.push(sensitive.length + ' sensitive permission(s) detected'); }
            }

            const riskLevel = riskScore >= 4 ? 'high' : riskScore >= 2 ? 'medium' : 'low';
            const riskLabel = { high: '고위험 (High Risk)', medium: '중위험 (Medium Risk)', low: '저위험 (Low Risk)' };

            content.innerHTML =
                '<div class="ai-sim-grid">' +
                '<div class="ai-sim-stat"><div class="ai-sim-stat-value">' + roleCount + '</div><div class="ai-sim-stat-label">영향받는 역할 (Roles)</div></div>' +
                '<div class="ai-sim-stat"><div class="ai-sim-stat-value">' + permCount + '</div><div class="ai-sim-stat-label">부여 권한 (Permissions)</div></div>' +
                '<div class="ai-sim-stat"><div class="ai-sim-stat-value">' + condCount + '</div><div class="ai-sim-stat-label">적용 조건 (Conditions)</div></div>' +
                '</div>' +
                '<div class="ai-sim-risk risk-' + riskLevel + '">' +
                '<strong>' + riskLabel[riskLevel] + '</strong>' +
                (warnings.length > 0 ? '<ul style="margin:0.5rem 0 0 1rem;font-size:0.75rem;">' + warnings.map(w => '<li>' + w + '</li>').join('') + '</ul>' : '') +
                '</div>';
        },

        // ---- Confidence ----

        renderConfidence(policyData) {
            let score = 100;
            const deductions = [];

            if (this._filteredCount > 0) { score -= this._filteredCount * 10; deductions.push(this._filteredCount + ' invalid ID(s) removed'); }
            if (!(policyData.roleIds || []).length) { score -= 30; deductions.push('No roles assigned'); }
            if (!(policyData.permissionIds || []).length) { score -= 30; deductions.push('No permissions assigned'); }
            if (Object.keys(policyData.conditions || {}).length === 0) { score -= 10; deductions.push('No conditions - policy may be too broad'); }
            if (this._wasFallback) { score -= 40; deductions.push('Fallback policy was generated'); }

            score = Math.max(0, Math.min(100, score));
            const level = score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
            const color = { high: '#22c55e', medium: '#f59e0b', low: '#ef4444' };

            const fill = document.getElementById('ai-confidence-fill');
            fill.style.width = score + '%';
            fill.className = 'ai-confidence-fill ' + level;

            const valueEl = document.getElementById('ai-confidence-value');
            valueEl.textContent = score + '%';
            valueEl.style.color = color[level];

            const dedEl = document.getElementById('ai-confidence-deductions');
            if (deductions.length > 0) {
                dedEl.classList.remove('hidden');
                dedEl.innerHTML = '<ul>' + deductions.map(d => '<li>' + d + '</li>').join('') + '</ul>';
            } else {
                dedEl.classList.add('hidden');
            }
        },

        // ---- Save Confirmation ----

        confirmSave() {
            this.syncCardToData();
            const data = this.generatedPolicyData;
            if (!data) { showToast('저장할 정책 데이터가 없습니다.', 'error'); return; }
            if (!(data.roleIds || []).length) { showToast('역할이 지정되지 않았습니다.', 'error'); return; }
            if (!(data.permissionIds || []).length) { showToast('권한이 지정되지 않았습니다.', 'error'); return; }

            const maps = this._cachedMaps || { roles: {}, permissions: {}, conditions: {} };
            const roleNames = (data.roleIds || []).map(id => maps.roles[id] || maps.roles[String(id)] || 'ID:' + id).join(', ');
            const permNames = (data.permissionIds || []).map(id => maps.permissions[id] || maps.permissions[String(id)] || 'ID:' + id).join(', ');

            document.getElementById('ai-confirm-summary').innerHTML =
                '<div class="ai-confirm-row"><div class="ai-confirm-label">정책명</div><div class="ai-confirm-value">' + this.escapeHtml(data.policyName) + '</div></div>' +
                '<div class="ai-confirm-row"><div class="ai-confirm-label">효과</div><div class="ai-confirm-value">' + data.effect + '</div></div>' +
                '<div class="ai-confirm-row"><div class="ai-confirm-label">역할 (' + (data.roleIds || []).length + ')</div><div class="ai-confirm-value">' + this.escapeHtml(roleNames) + '</div></div>' +
                '<div class="ai-confirm-row"><div class="ai-confirm-label">권한 (' + (data.permissionIds || []).length + ')</div><div class="ai-confirm-value">' + this.escapeHtml(permNames) + '</div></div>';

            // Show warnings if any
            const warningEl = document.getElementById('ai-confirm-warnings');
            const conflictPanel = document.getElementById('ai-conflict-panel');
            if (!conflictPanel.classList.contains('hidden')) {
                warningEl.innerHTML = '<div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:0.5rem;padding:0.75rem;margin-top:0.75rem;"><strong style="color:#fbbf24;">Warning:</strong> <span style="color:#e2e8f0;">충돌/중복이 감지되었습니다. 저장 전 확인하세요.</span></div>';
            } else {
                warningEl.innerHTML = '';
            }

            document.getElementById('ai-confirm-overlay').classList.remove('hidden');
        },

        async executeSave() {
            this.syncCardToData();
            const data = this.generatedPolicyData;
            const btn = document.querySelector('#ai-confirm-overlay .modern-btn-primary');
            if (btn) btn.disabled = true;

            try {
                const resp = await fetch('/api/policies/build-from-business-rule', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken()
                    },
                    body: JSON.stringify(data)
                });

                if (!resp.ok) {
                    const error = await resp.json();
                    throw new Error(error.message || 'Save failed');
                }

                this.closeConfirmModal();
                showToast('정책이 성공적으로 저장되었습니다.', 'success');
                setTimeout(() => window.location.href = '/admin/policy-center?tab=list', 1500);
            } catch (e) {
                showToast('정책 저장 실패: ' + e.message, 'error');
                if (btn) btn.disabled = false;
            }
        },

        closeConfirmModal() {
            document.getElementById('ai-confirm-overlay').classList.add('hidden');
        },

        // ---- Utilities ----

        reset() {
            this.generatedPolicyData = null;
            this._cachedMaps = null;
            this._cachedPolicySummaries = null;
            this._cachedAvailableItems = null;
            this._filteredCount = 0;
            this._wasFallback = false;
            document.getElementById('ai-query-input').value = '';
            document.getElementById('ai-result-section').classList.add('hidden');
            document.getElementById('ai-progress-section').classList.add('hidden');
            document.getElementById('ai-conflict-panel').classList.add('hidden');
        },

        escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    PolicyCenter.Manual.initHttpMethodVisibility();

    // Initialize Create tab - resource selection flow
    const createTab = document.getElementById('tab-create');
    if (createTab && createTab.classList.contains('active')) {
        PolicyCenter.CreateFlow.init();
    }
});
