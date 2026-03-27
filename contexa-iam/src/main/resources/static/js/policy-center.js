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
        modal.dataset.multiMode = 'false';
        document.getElementById('modal-permission-name').textContent = friendlyName;
        modal.dataset.resourceId = resourceId;
        modal.dataset.friendlyName = friendlyName;
        modal.dataset.description = description || '';
        modal.dataset.resourceType = (resourceMeta && resourceMeta.resourceType) || '';
        modal.dataset.resourceIdentifier = (resourceMeta && resourceMeta.resourceIdentifier) || '';
        modal.dataset.httpMethod = (resourceMeta && resourceMeta.httpMethod) || '';
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
    },

    closePolicySetupModal() {
        var modal = document.getElementById('policySetupModal');
        modal.classList.add('hidden');
        modal.style.display = 'none';
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
        if (modal.dataset.multiMode === 'true') {
            return this.selectQuickModeMulti();
        }
        const result = await this.definePermission(modal);
        if (!result) return;

        this.closePolicySetupModal();

        const ctx = {
            resourceId: modal.dataset.resourceId,
            friendlyName: modal.dataset.friendlyName,
            permissionId: result.permissionId,
            permissionName: result.permissionName || '',
            resourceType: modal.dataset.resourceType || '',
            resourceIdentifier: modal.dataset.resourceIdentifier || '',
            httpMethod: modal.dataset.httpMethod || ''
        };

        this.switchToCreateTab(ctx, 'quick');
    },

    async selectQuickModeMulti() {
        var modal = document.getElementById('policySetupModal');
        // Show loading state in modal
        var modalTitle = modal.querySelector('h2');
        var originalTitle = modalTitle ? modalTitle.textContent : '';
        if (modalTitle) modalTitle.textContent = 'Processing...';
        modal.querySelectorAll('button').forEach(function(b) { b.disabled = true; });

        try {
            var ctxArr = await this._batchDefineAndBuildContext();
            modal.classList.add('hidden');
            modal.style.display = 'none';

            // Restore modal title
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });

            // Activate Create tab with multi-resource context
            PolicyCenter.CreateFlow.activateWithResources(ctxArr);

            // Switch tab
            document.querySelectorAll('.pc-tab-btn').forEach(function(b) { b.classList.remove('active'); });
            document.querySelectorAll('.pc-tab-content').forEach(function(c) { c.classList.remove('active'); });
            var createBtn = document.querySelector('.pc-tab-btn[href*="tab=create"]');
            if (createBtn) createBtn.classList.add('active');
            document.getElementById('tab-create').classList.add('active');

            var modeBtn = document.querySelector('.pc-mode-card[onclick*="quick"]');
            PolicyCenter.switchCreateMode('quick', modeBtn);

        } catch (e) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
            showToast('Batch permission creation failed: ' + e.message, 'error');
        }
    },

    async selectAIWizard() {
        const modal = document.getElementById('policySetupModal');
        if (modal.dataset.multiMode === 'true') {
            return this.selectAIWizardMulti();
        }
        const result = await this.definePermission(modal);
        if (!result) return;

        this.closePolicySetupModal();

        const ctx = {
            resourceId: modal.dataset.resourceId,
            friendlyName: modal.dataset.friendlyName,
            description: modal.dataset.description || '',
            permissionId: result.permissionId,
            resourceType: modal.dataset.resourceType || '',
            resourceIdentifier: modal.dataset.resourceIdentifier || '',
            httpMethod: modal.dataset.httpMethod || ''
        };

        this.switchToCreateTab(ctx, 'ai');
    },

    async selectAIWizardMulti() {
        var modal = document.getElementById('policySetupModal');
        // Show loading state in modal
        var modalTitle = modal.querySelector('h2');
        var originalTitle = modalTitle ? modalTitle.textContent : '';
        if (modalTitle) modalTitle.textContent = 'Processing...';
        modal.querySelectorAll('button').forEach(function(b) { b.disabled = true; });

        try {
            var ctxArr = await this._batchDefineAndBuildContext();
            modal.classList.add('hidden');
            modal.style.display = 'none';

            // Restore modal title
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });

            PolicyCenter.CreateFlow.activateWithResources(ctxArr);

            document.querySelectorAll('.pc-tab-btn').forEach(function(b) { b.classList.remove('active'); });
            document.querySelectorAll('.pc-tab-content').forEach(function(c) { c.classList.remove('active'); });
            var createBtn = document.querySelector('.pc-tab-btn[href*="tab=create"]');
            if (createBtn) createBtn.classList.add('active');
            document.getElementById('tab-create').classList.add('active');

            var modeBtn = document.querySelector('.pc-mode-card[onclick*="ai"]');
            PolicyCenter.switchCreateMode('ai', modeBtn);

            // Pre-fill AI query with resource summary
            var queryInput = document.getElementById('ai-query-input');
            if (queryInput) {
                var summary = '[Target Resources: ' + ctxArr.length + ' selected]\n';
                ctxArr.forEach(function(c) {
                    summary += '- ' + c.resourceType + ' ' + c.httpMethod + ' ' + c.resourceIdentifier + '\n';
                });
                queryInput.value = summary;
            }
        } catch (e) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
            showToast('Batch permission creation failed: ' + e.message, 'error');
        }
    },

    // Shared batch define logic for multi-resource mode (BUG 5,6,7,13,18 fix)
    async _batchDefineAndBuildContext() {
        var requests = [];
        PolicyCenter.MultiSelect.selectedResources.forEach(function(r) {
            requests.push({
                resourceId: r.id,
                friendlyName: r.friendlyName || r.resourceIdentifier,
                description: ''
            });
        });

        var token = PolicyCenter.getCsrfToken();
        var header = PolicyCenter.getCsrfHeader();
        var headers = { 'Content-Type': 'application/json' };
        headers[header] = token;

        var resp = await fetch('/admin/workbench/resources/define-batch', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(requests)
        });
        if (!resp.ok) throw new Error('Server error: ' + resp.status);
        var results = await resp.json();

        // Only include results that have a permissionId
        var permResults = results.filter(function(r) { return r.permissionId; });
        if (permResults.length === 0) {
            throw new Error('No permissions could be created');
        }

        return permResults.map(function(r) {
            var resource = PolicyCenter.MultiSelect.selectedResources.get(r.resourceId);
            return {
                resourceId: r.resourceId,
                permissionId: r.permissionId,
                permissionName: r.permissionName,
                resourceType: resource ? resource.resourceType : '',
                resourceIdentifier: resource ? resource.resourceIdentifier : '',
                httpMethod: resource ? resource.httpMethod : ''
            };
        });
    },

    switchToCreateTab(ctx, mode) {
        // Switch tab without page reload
        document.querySelectorAll('.pc-tab-content').forEach(c => c.classList.remove('active'));
        document.querySelectorAll('.pc-tab-btn').forEach(b => b.classList.remove('active'));
        const createTab = document.getElementById('tab-create');
        if (createTab) createTab.classList.add('active');
        const createBtn = document.querySelector('.pc-tab-btn[href*="tab=create"]');
        if (createBtn) createBtn.classList.add('active');

        // Activate resource context and mode
        PolicyCenter.CreateFlow.activateWithResource(ctx);
        const modeBtn = document.querySelector('.pc-mode-card[onclick*="' + mode + '"]');
        PolicyCenter.switchCreateMode(mode, modeBtn);

        // Pre-fill AI query if AI mode
        if (mode === 'ai') {
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
        }

        // Update URL without reload
        history.pushState(null, '', '/admin/policy-center?tab=create');
    },

    switchToResourcesTab() {
        document.querySelectorAll('.pc-tab-content').forEach(c => c.classList.remove('active'));
        document.querySelectorAll('.pc-tab-btn').forEach(b => b.classList.remove('active'));
        const resTab = document.getElementById('tab-resources');
        if (resTab) resTab.classList.add('active');
        const resBtn = document.querySelector('.pc-tab-btn[href*="tab=resources"]');
        if (resBtn) resBtn.classList.add('active');
        history.pushState(null, '', '/admin/policy-center?tab=resources');
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
            badge.innerHTML = '<i class="fas fa-exclamation-circle"></i> <span>정책 미 설정</span>';
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
                    const aiBtn = document.querySelector('.pc-mode-card[onclick*="ai"]');
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
                    const quickBtn = document.querySelector('.pc-mode-card[onclick*="quick"]');
                    if (quickBtn) PolicyCenter.switchCreateMode('quick', quickBtn);
                } catch (e) { console.error('Failed to parse quick context', e); }
            } else {
                // No resource context - show guide
                if (guide) guide.style.display = '';
                if (banner) banner.classList.add('hidden');
                if (modeNav) { modeNav.classList.add('hidden'); modeNav.style.display = 'none'; }
                document.querySelectorAll('.pc-subtab-content').forEach(c => c.classList.remove('active'));
            }
        },

        activateWithResource(ctx) {
            this.selectedResource = ctx;
            const guide = document.getElementById('create-no-resource-guide');
            const banner = document.getElementById('create-resource-banner');
            const modeNav = document.getElementById('create-mode-nav');

            // Reset multi-mode display
            var singleName = document.getElementById('create-selected-name');
            var singleId = document.getElementById('create-selected-identifier');
            if (singleName) singleName.style.display = '';
            if (singleId) singleId.style.display = '';
            var multiBanner = document.getElementById('create-multi-banner');
            if (multiBanner) { multiBanner.classList.add('hidden'); multiBanner.style.display = 'none'; }

            if (guide) guide.style.display = 'none';
            if (banner) banner.classList.remove('hidden');
            if (modeNav) { modeNav.classList.remove('hidden'); modeNav.style.display = 'flex'; }

            document.getElementById('create-selected-name').textContent = ctx.friendlyName || 'Resource';
            document.getElementById('create-selected-identifier').textContent =
                (ctx.resourceType || '') + ' ' + (ctx.httpMethod || '') + ' ' + (ctx.resourceIdentifier || '');

            // Store pre-selected permission for QuickPanel (applied after init)
            if (ctx.permissionId) {
                PolicyCenter.QuickPanel._preSelectedPerm = {
                    id: Number(ctx.permissionId),
                    name: ctx.friendlyName || 'Permission'
                };
            }
        },

        activateWithResources: function(ctxArr) {
            this.selectedResources = ctxArr;
            this.selectedResource = ctxArr[0]; // Keep first for compatibility

            // Hide guide, show banner
            var guide = document.getElementById('create-no-resource-guide');
            var banner = document.getElementById('create-resource-banner');
            if (guide) guide.style.display = 'none';
            if (banner) banner.classList.remove('hidden');

            // Hide single display, show multi display
            var singleName = document.getElementById('create-selected-name');
            var singleId = document.getElementById('create-selected-identifier');
            var multiBanner = document.getElementById('create-multi-banner');

            if (singleName) singleName.style.display = 'none';
            if (singleId) singleId.style.display = 'none';
            if (multiBanner) {
                multiBanner.classList.remove('hidden');
                multiBanner.style.display = 'flex';
                document.getElementById('create-multi-count').textContent = ctxArr.length + ' resources selected';
            }

            // Show mode navigation
            var modeNav = document.getElementById('create-mode-nav');
            if (modeNav) { modeNav.classList.remove('hidden'); modeNav.style.display = 'flex'; }
            var modeCards = document.querySelectorAll('.pc-mode-card');
            modeCards.forEach(function(c) { c.classList.remove('hidden'); });

            // Pre-select all permissions for QuickPanel
            PolicyCenter.QuickPanel._preSelectedPerms = ctxArr.map(function(c) {
                return { id: c.permissionId, name: c.permissionName };
            });
        }
    },

    switchCreateMode(mode, btn) {
        document.querySelectorAll('.pc-mode-card').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.pc-subtab-content').forEach(c => c.classList.remove('active'));
        if (btn) btn.classList.add('active');
        const panel = document.getElementById('create-' + mode);
        if (panel) panel.classList.add('active');
        if (mode === 'quick') this.QuickPanel.init();
        if (mode === 'ai') this.AI.init();
    },

    // ================================================================
    // TAB 2: QUICK MODE - 2-Panel Layout (Role + Permission)
    // ================================================================

    QuickPanel: {
        selectedRoles: new Map(),
        selectedPerms: new Map(),
        rolePermissionMap: {},
        userManualPerms: new Set(),
        allPermissions: [],
        roleColors: ['#818cf8','#f472b6','#34d399','#fbbf24','#60a5fa','#a78bfa','#fb923c','#2dd4bf','#f87171','#e879f9'],
        roleSearchTimeout: null,
        permSearchTimeout: null,
        initialMappingDone: false,

        init() {
            this.selectedRoles.clear();
            this.selectedPerms.clear();
            this.rolePermissionMap = {};
            this.userManualPerms.clear();
            this.allPermissions = [];
            this.initialMappingDone = false;

            if (this._preSelectedPerm) {
                this.selectedPerms.set(this._preSelectedPerm.id, this._preSelectedPerm.name);
                this.userManualPerms.add(this._preSelectedPerm.id);
                this._preSelectedPerm = null;
            }

            if (this._preSelectedPerms && this._preSelectedPerms.length > 0) {
                var self = this;
                this._preSelectedPerms.forEach(function(p) {
                    if (p.id) {
                        self.selectedPerms.set(p.id, p.name);
                        self.userManualPerms.add(p.id);
                    }
                });
                this._preSelectedPerms = null;
            }

            const roleCount = document.getElementById('qp-role-count');
            const permCount = document.getElementById('qp-perm-count');
            if (roleCount) roleCount.textContent = '0개 선택';
            if (permCount) permCount.textContent = this.selectedPerms.size + '개 선택';

            this.loadRoles('');
            this.loadPermissions('');
            this.updateSummary();
            this.updateCreateButtonState();
        },

        getRoleColor(roleId) {
            const keys = Array.from(this.selectedRoles.keys());
            const idx = keys.indexOf(Number(roleId));
            return this.roleColors[(idx >= 0 ? idx : keys.length) % this.roleColors.length];
        },

        // === Role Panel ===

        async loadRoles(keyword) {
            const list = document.getElementById('qp-role-list');
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>Loading...</p></div>';
            try {
                const resp = await fetch('/admin/policy-center/api/roles?keyword=' + encodeURIComponent(keyword || '') + '&size=50');
                const page = await resp.json();
                this.renderRoleList(page.content || []);
            } catch (e) {
                list.innerHTML = '<div class="pc-empty"><p>Loading failed</p></div>';
            }
        },

        renderRoleList(roles) {
            const list = document.getElementById('qp-role-list');
            if (!roles.length) { list.innerHTML = '<div class="pc-empty"><p>No roles found.</p></div>'; return; }
            roles.sort((a, b) => {
                const aS = this.selectedRoles.has(Number(a.id)) ? 0 : 1;
                const bS = this.selectedRoles.has(Number(b.id)) ? 0 : 1;
                return aS - bS;
            });
            list.innerHTML = roles.map(r => {
                const rid = Number(r.id);
                const sel = this.selectedRoles.has(rid);
                const color = sel ? this.getRoleColor(rid) : '';
                const colorDot = sel ? '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + color + ';margin-right:6px;flex-shrink:0;"></span>' : '';
                const safeName = this.escapeHtml(r.roleName).replace(/'/g, "\\'");
                return '<div class="qp-item' + (sel ? ' selected' : '') + '" onclick="PolicyCenter.QuickPanel.toggleRole(' + rid + ',\'' + safeName + '\')"' +
                    ' onmouseenter="PolicyCenter.QuickPanel.showRoleTooltip(event,' + rid + ')" onmouseleave="PolicyCenter.QuickPanel.hideRoleTooltip()">' +
                    '<input type="checkbox" ' + (sel ? 'checked' : '') + ' onclick="PolicyCenter.QuickPanel.toggleRole(' + rid + ',\'' + safeName + '\');event.stopPropagation();">' +
                    '<div class="qp-item-info"><div class="qp-item-name">' + colorDot + this.escapeHtml(r.roleName) + '</div>' +
                    '<div class="qp-item-desc">' + this.escapeHtml(r.roleDesc || '') + '</div></div></div>';
            }).join('');
        },

        toggleRole(id, name) {
            id = Number(id);
            if (this.selectedRoles.has(id)) {
                this.selectedRoles.delete(id);
                const roleMapped = (this.rolePermissionMap[id] || []).map(Number);
                roleMapped.forEach(pid => {
                    if (this.userManualPerms.has(pid)) return;
                    const stillMapped = Array.from(this.selectedRoles.keys()).some(
                        rid => (this.rolePermissionMap[rid] || []).map(Number).includes(pid)
                    );
                    if (!stillMapped) this.selectedPerms.delete(pid);
                });
            } else {
                this.selectedRoles.set(id, name);
            }
            this.renderRoleChips();
            this.loadRoles(document.getElementById('qp-role-search')?.value || '');
            this.onRoleSelectionChanged();
        },

        renderRoleChips() {
            document.getElementById('qp-role-count').textContent = this.selectedRoles.size + '개 선택';
        },

        searchRoles(keyword) {
            clearTimeout(this.roleSearchTimeout);
            this.roleSearchTimeout = setTimeout(() => this.loadRoles(keyword), 400);
        },

        onRoleSelectionChanged() {
            this.initialMappingDone = false;
            this.loadPermissions(document.getElementById('qp-perm-search')?.value || '');
            this.updateSummary();
            this.updateCreateButtonState();
        },

        // === Permission Panel ===

        async loadPermissions(keyword) {
            const list = document.getElementById('qp-perm-list');
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>Loading...</p></div>';
            const roleIdArr = Array.from(this.selectedRoles.keys());
            const roleParam = roleIdArr.length > 0 ? '&roleIds=' + roleIdArr.join(',') : '';
            try {
                const resp = await fetch('/admin/policy-center/api/available-permissions?keyword=' + encodeURIComponent(keyword || '') + roleParam + '&size=50');
                const page = await resp.json();
                this.rolePermissionMap = page.rolePermissionMap || {};
                this.allPermissions = page.content || [];

                if (!this.initialMappingDone) {
                    this.initialMappingDone = true;
                    const allMapped = new Set();
                    Object.values(this.rolePermissionMap).forEach(ids => ids.forEach(id => allMapped.add(Number(id))));
                    this.allPermissions.forEach(p => {
                        const pid = Number(p.id);
                        if (allMapped.has(pid) && !this.selectedPerms.has(pid) && !this.userManualPerms.has(pid)) {
                            this.selectedPerms.set(pid, p.name || p.friendlyName || '');
                        }
                    });
                }

                this.renderPermChips();
                this.renderPermList(this.allPermissions);
                this.updateSummary();
                this.updateCreateButtonState();
            } catch (e) {
                list.innerHTML = '<div class="pc-empty"><p>Loading failed</p></div>';
            }
        },

        renderPermList(perms) {
            const list = document.getElementById('qp-perm-list');
            if (!perms.length) { list.innerHTML = '<div class="pc-empty"><p>No permissions found.</p></div>'; return; }

            const roleMap = this.rolePermissionMap;
            const permRoleMap = {};
            for (const [rid, pids] of Object.entries(roleMap)) {
                pids.forEach(pid => {
                    if (!permRoleMap[pid]) permRoleMap[pid] = [];
                    const roleName = this.selectedRoles.get(Number(rid));
                    if (roleName) permRoleMap[pid].push({ id: Number(rid), name: roleName, color: this.getRoleColor(Number(rid)) });
                });
            }

            perms.sort((a, b) => {
                const aS = this.selectedPerms.has(Number(a.id)) ? 0 : 1;
                const bS = this.selectedPerms.has(Number(b.id)) ? 0 : 1;
                return aS - bS;
            });

            list.innerHTML = perms.map(p => {
                const pid = Number(p.id);
                const sel = this.selectedPerms.has(pid);
                const safeName = this.escapeHtml(p.name || p.friendlyName || '').replace(/'/g, "\\'");
                const displayName = this.escapeHtml(p.friendlyName || p.name);
                const roles = permRoleMap[pid] || [];
                const rolesToggle = (sel && roles.length > 0)
                    ? '<span class="qp-roles-toggle" onclick="event.stopPropagation();PolicyCenter.QuickPanel.togglePermRoles(' + pid + ')"><i class="fas fa-users"></i> ' + roles.length + '</span>'
                    : '';
                const rolesDiv = (sel && roles.length > 0)
                    ? '<div class="qp-perm-roles" id="qp-perm-roles-' + pid + '" style="display:none;">' +
                      roles.map(r => '<span class="qp-perm-role-badge" style="--role-color:' + r.color + ';">' + this.escapeHtml(r.name) + '</span>').join('') + '</div>'
                    : '';

                return '<div class="qp-item' + (sel ? ' selected' : '') + '" onclick="PolicyCenter.QuickPanel.togglePerm(' + pid + ',\'' + safeName + '\')">' +
                    '<input type="checkbox" ' + (sel ? 'checked' : '') + ' onclick="PolicyCenter.QuickPanel.togglePerm(' + pid + ',\'' + safeName + '\');event.stopPropagation();">' +
                    '<div class="qp-item-info"><div class="qp-item-name">' + displayName + rolesToggle + '</div>' +
                    '<div class="qp-item-desc">' + this.escapeHtml(p.description || '') + '</div>' +
                    rolesDiv + '</div></div>';
            }).join('');
        },

        togglePermRoles(pid) {
            const el = document.getElementById('qp-perm-roles-' + pid);
            if (el) el.style.display = el.style.display === 'none' ? 'flex' : 'none';
        },

        togglePerm(id, name) {
            id = Number(id);
            if (this.selectedPerms.has(id)) {
                this.selectedPerms.delete(id);
                this.userManualPerms.delete(id);
            } else {
                this.selectedPerms.set(id, name);
                this.userManualPerms.add(id);
            }
            this.renderPermChips();
            this.renderPermList(this.allPermissions);
            this.updateSummary();
            this.updateCreateButtonState();
        },

        renderPermChips() {
            document.getElementById('qp-perm-count').textContent = this.selectedPerms.size + '개 선택';
        },

        searchPermissions(keyword) {
            clearTimeout(this.permSearchTimeout);
            this.permSearchTimeout = setTimeout(() => this.loadPermissions(keyword), 400);
        },

        // === Summary & Create ===

        updateSummary() {
            const nameInput = document.getElementById('qp-policy-name');
            if (nameInput && !nameInput.value && (this.selectedRoles.size > 0 || this.selectedPerms.size > 0)) {
                nameInput.value = 'Policy - ' + new Date().toISOString().slice(0, 16);
            }
        },

        updateCreateButtonState() {
            const btn = document.getElementById('qp-create-btn');
            if (btn) btn.disabled = !(this.selectedRoles.size > 0 || this.selectedPerms.size > 0);
        },

        async createPolicy() {
            const name = document.getElementById('qp-policy-name').value.trim();
            if (!name) { showToast('정책명을 입력하세요.', 'error'); return; }
            if (this.selectedRoles.size === 0 && this.selectedPerms.size === 0) {
                showToast('역할 또는 권한을 하나 이상 선택하세요.', 'error'); return;
            }
            const btn = document.getElementById('qp-create-btn');
            PolicyCenter.setLoading(btn, true);
            try {
                const resp = await fetch('/admin/policy-center/api/quick-create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': PolicyCenter.getCsrfToken() },
                    body: JSON.stringify({
                        policyName: name,
                        description: document.getElementById('qp-policy-desc').value,
                        roleIds: Array.from(this.selectedRoles.keys()),
                        permissionIds: Array.from(this.selectedPerms.keys()),
                        effect: document.getElementById('qp-policy-effect').value
                    })
                });
                const result = await resp.json();
                if (!resp.ok) throw new Error(result.message);
                if (result.warning) {
                    showToast(result.warning, 'warning');
                    setTimeout(() => {
                        showToast('정책이 성공적으로 생성되었습니다.', 'success');
                        setTimeout(() => window.location.href = '/admin/policy-center?tab=list', 1500);
                    }, 2000);
                } else {
                    showToast('정책이 성공적으로 생성되었습니다.', 'success');
                    setTimeout(() => window.location.href = '/admin/policy-center?tab=list', 1500);
                }
            } catch (e) {
                showToast('정책 생성 실패: ' + e.message, 'error');
                PolicyCenter.setLoading(btn, false);
            }
        },

        showRoleTooltip(event, roleId) {
            this.hideRoleTooltip();
            const permIds = (this.rolePermissionMap[roleId] || []).map(Number);
            if (permIds.length === 0) return;
            const permNames = this.allPermissions
                .filter(p => permIds.includes(Number(p.id)))
                .map(p => p.friendlyName || p.name);
            if (permNames.length === 0) return;

            const roleName = this.selectedRoles.get(Number(roleId)) || '';
            const color = this.getRoleColor(roleId);
            const tip = document.createElement('div');
            tip.className = 'qp-role-tooltip';
            tip.id = 'qp-role-tooltip-active';
            tip.innerHTML = '<div class="qp-role-tooltip-title"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + color + ';"></span>' + this.escapeHtml(roleName) + ' (' + permNames.length + ')</div>' +
                '<div class="qp-role-tooltip-list">' + permNames.slice(0, 10).map(n => '<span>' + this.escapeHtml(n) + '</span>').join('') +
                (permNames.length > 10 ? '<span style="color:#64748b;">+' + (permNames.length - 10) + ' more</span>' : '') + '</div>';

            document.body.appendChild(tip);
            const rect = event.currentTarget.getBoundingClientRect();
            tip.style.left = (rect.right + 8) + 'px';
            tip.style.top = rect.top + 'px';
            const tipRect = tip.getBoundingClientRect();
            if (tipRect.right > window.innerWidth) tip.style.left = (rect.left - tipRect.width - 8) + 'px';
            if (tipRect.bottom > window.innerHeight) tip.style.top = (window.innerHeight - tipRect.height - 8) + 'px';
        },

        hideRoleTooltip() {
            const existing = document.getElementById('qp-role-tooltip-active');
            if (existing) existing.remove();
        },

        escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }
    },

    // Backward compatibility
    Wizard: { init() { PolicyCenter.QuickPanel.init(); } },

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
            let query = queryInput.value.trim();
            if (!query) { showToast('정책 요구사항을 입력하세요.', 'error'); queryInput.focus(); return; }

            // Inject selected resource context into query
            const res = PolicyCenter.CreateFlow.selectedResource;
            if (res) {
                const ctx = '[Target Resource: ' +
                    (res.resourceType || '') + ' ' +
                    (res.httpMethod || '') + ' ' +
                    (res.resourceIdentifier || '') +
                    ', Name: "' + (res.friendlyName || '') + '"' +
                    (res.description ? ', Description: ' + res.description : '') +
                    (res.permissionId ? ', PermissionID: ' + res.permissionId : '') +
                    ']';
                query = ctx + '\n' + query;
            }

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

            // Collect available items (roles, permissions, conditions) for AI context
            let availableItems = null;
            try {
                const items = await this.fetchAvailableItems();
                availableItems = {
                    roles: (items.roles || []).map(r => ({ id: r.id, name: r.roleName || r.name, description: r.roleDesc || r.description || '' })),
                    permissions: (items.permissions || []).map(p => ({ id: p.id, name: p.friendlyName || p.name, targetType: p.targetType || '', description: p.description || '' })),
                    conditions: (items.conditions || []).map(c => ({ id: c.id, name: c.name, description: c.description || '', isCompatible: c.isCompatible !== false }))
                };
            } catch (e) {
                console.error('Failed to collect available items', e);
            }

            const requestPayload = { naturalLanguageQuery: query, availableItems: availableItems };

            try {
                if (typeof ContexaLLM !== 'undefined' && ContexaLLM.analyzeStreaming) {
                    this.updateProgress('analyze', 40, 'AI analyzing policy requirements...');
                    await ContexaLLM.analyzeStreaming(
                        '/api/ai/policies/generate/stream',
                        requestPayload,
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
                        body: JSON.stringify(requestPayload)
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

            // Auto-include selected resource's permission
            const res = PolicyCenter.CreateFlow.selectedResource;
            if (res && res.permissionId) {
                const pid = Number(res.permissionId);
                if (!validatedData.permissionIds.includes(pid)) {
                    validatedData.permissionIds.push(pid);
                }
                if (!processed.permissionIdToNameMap[pid] && !processed.permissionIdToNameMap[String(pid)]) {
                    processed.permissionIdToNameMap[pid] = res.friendlyName || 'Permission #' + pid;
                }
            }

            // Store reasoning from AI response
            validatedData.reasoning = processed.policyData.reasoning || response.reasoning || '';
            validatedData.source = 'AI_GENERATED';

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

            // AI reasoning
            const reasoningSection = document.getElementById('ai-card-reasoning-section');
            if (reasoningSection) {
                if (data.reasoning) {
                    reasoningSection.classList.remove('hidden');
                    document.getElementById('ai-card-reasoning').textContent = data.reasoning;
                } else {
                    reasoningSection.classList.add('hidden');
                }
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

// Multi-Resource Selection module
PolicyCenter.MultiSelect = {
    selectedResources: new Map(),
    currentPage: 0,
    searchTimeout: null,

    openResourcePicker: function() {
        this.selectedResources.clear();
        this.currentPage = 0;
        document.getElementById('rp-keyword').value = '';
        document.getElementById('rp-status').value = 'NEEDS_DEFINITION';
        document.getElementById('rp-select-all').checked = false;
        var rpModal = document.getElementById('resourcePickerModal');
        rpModal.classList.remove('hidden');
        rpModal.style.display = 'flex';
        this.loadPage(0);
        this.updateCount();
    },

    close: function() {
        var rpModal = document.getElementById('resourcePickerModal');
        rpModal.classList.add('hidden');
        rpModal.style.display = 'none';
    },

    search: function() {
        var self = this;
        if (this.searchTimeout) clearTimeout(this.searchTimeout);
        this.searchTimeout = setTimeout(function() {
            self.currentPage = 0;
            self.loadPage(0);
        }, 400);
    },

    loadPage: function(page) {
        var self = this;
        this.currentPage = page;
        var keyword = document.getElementById('rp-keyword').value;
        var status = document.getElementById('rp-status').value;
        var serviceOwner = document.getElementById('rp-service-owner').value;
        var url = '/admin/policy-center/api/resources?page=' + page + '&size=15';
        if (keyword) url += '&keyword=' + encodeURIComponent(keyword);
        if (status) url += '&status=' + encodeURIComponent(status);
        if (serviceOwner) url += '&serviceOwner=' + encodeURIComponent(serviceOwner);

        fetch(url).then(function(r) { return r.json(); }).then(function(data) {
            self.renderTable(data.content);
            self.renderPagination(data.number, data.totalPages);
        });
    },

    renderTable: function(resources) {
        var self = this;
        var tbody = document.getElementById('rp-table-body');
        if (!resources || resources.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="padding:2rem;text-align:center;color:#64748b;">No resources found</td></tr>';
            return;
        }
        var html = '';
        resources.forEach(function(r) {
            var checked = self.selectedResources.has(r.id) ? ' checked' : '';
            html += '<tr style="border-bottom:1px solid rgba(71,85,105,0.2);cursor:pointer;"'
                + ' data-id="' + r.id + '"'
                + ' data-identifier="' + self.escapeHtml(r.resourceIdentifier) + '"'
                + ' data-type="' + (r.resourceType || '') + '"'
                + ' data-http="' + (r.httpMethod || 'ANY') + '"'
                + ' data-status="' + (r.status || '') + '"'
                + ' data-friendly="' + self.escapeHtml(r.friendlyName || '') + '"'
                + ' onclick="PolicyCenter.MultiSelect.toggleResource(' + r.id + ', this)">';
            html += '<td style="padding:0.5rem;"><input type="checkbox"' + checked + ' onclick="event.stopPropagation();" onchange="PolicyCenter.MultiSelect.toggleResource(' + r.id + ', this.closest(\'tr\'))"></td>';
            html += '<td style="padding:0.5rem;color:#e2e8f0;font-size:0.8125rem;font-family:monospace;word-break:break-all;">' + self.escapeHtml(r.resourceIdentifier) + '</td>';
            html += '<td style="padding:0.5rem;"><span class="badge neutral" style="font-size:0.7rem;">' + (r.resourceType || '-') + '</span></td>';
            html += '<td style="padding:0.5rem;color:#94a3b8;font-size:0.8125rem;">' + (r.httpMethod || 'ANY') + '</td>';
            html += '<td style="padding:0.5rem;"><span class="badge ' + self.statusClass(r.status) + '" style="font-size:0.7rem;">' + (r.status || '-') + '</span></td>';
            html += '</tr>';
        });
        tbody.innerHTML = html;
        document.getElementById('rp-select-all').checked = false;
    },

    renderPagination: function(current, total) {
        var div = document.getElementById('rp-pagination');
        if (total <= 1) { div.innerHTML = ''; return; }
        var html = '';
        var start = Math.max(0, current - 2);
        var end = Math.min(total, start + 5);
        if (current > 0) html += '<button class="button secondary small" onclick="PolicyCenter.MultiSelect.loadPage(' + (current - 1) + ')">&laquo;</button>';
        for (var i = start; i < end; i++) {
            var cls = i === current ? 'button primary small' : 'button secondary small';
            html += '<button class="' + cls + '" onclick="PolicyCenter.MultiSelect.loadPage(' + i + ')">' + (i + 1) + '</button>';
        }
        if (current < total - 1) html += '<button class="button secondary small" onclick="PolicyCenter.MultiSelect.loadPage(' + (current + 1) + ')">&raquo;</button>';
        div.innerHTML = html;
    },

    toggleResource: function(id, trEl) {
        if (this.selectedResources.has(id)) {
            this.selectedResources.delete(id);
            if (trEl) trEl.querySelector('input[type=checkbox]').checked = false;
        } else {
            // Read from data attributes instead of fragile cell indices
            this.selectedResources.set(id, {
                id: id,
                resourceIdentifier: trEl.dataset.identifier || '',
                resourceType: trEl.dataset.type || '',
                httpMethod: trEl.dataset.http || 'ANY',
                status: trEl.dataset.status || '',
                friendlyName: trEl.dataset.friendly || ''
            });
            if (trEl) trEl.querySelector('input[type=checkbox]').checked = true;
        }
        this.updateCount();
    },

    toggleAll: function(checked) {
        var self = this;
        var rows = document.querySelectorAll('#rp-table-body tr');
        rows.forEach(function(tr) {
            var cb = tr.querySelector('input[type=checkbox]');
            if (!cb) return;
            var onclick = tr.getAttribute('onclick');
            if (!onclick) return;
            var match = onclick.match(/toggleResource\((\d+)/);
            if (!match) return;
            var id = parseInt(match[1]);
            if (checked && !self.selectedResources.has(id)) {
                self.toggleResource(id, tr);
            } else if (!checked && self.selectedResources.has(id)) {
                self.toggleResource(id, tr);
            }
        });
    },

    updateCount: function() {
        var count = this.selectedResources.size;
        document.getElementById('rp-selected-count').textContent = count + ' selected';
        document.getElementById('rp-confirm-btn').disabled = count === 0;
    },

    confirm: function() {
        if (this.selectedResources.size === 0) return;
        this.close();
        this.showPolicySetupModalMulti();
    },

    showPolicySetupModalMulti: function() {
        var modal = document.getElementById('policySetupModal');
        var nameEl = document.getElementById('modal-permission-name');
        if (nameEl) nameEl.textContent = this.selectedResources.size + ' resources selected';
        modal.dataset.multiMode = 'true';
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
    },

    showSelectedPopover: function() {
        var list = document.getElementById('selected-resources-list');
        var html = '<table style="width:100%;border-collapse:collapse;">';
        html += '<thead><tr style="border-bottom:1px solid rgba(71,85,105,0.4);">';
        html += '<th style="padding:0.4rem 0.5rem;text-align:left;color:#94a3b8;font-size:0.75rem;">Identifier</th>';
        html += '<th style="padding:0.4rem 0.5rem;text-align:left;color:#94a3b8;font-size:0.75rem;width:70px;">Type</th>';
        html += '<th style="padding:0.4rem 0.5rem;text-align:left;color:#94a3b8;font-size:0.75rem;width:70px;">HTTP</th>';
        html += '</tr></thead><tbody>';
        var self = this;
        this.selectedResources.forEach(function(r) {
            html += '<tr style="border-bottom:1px solid rgba(71,85,105,0.15);">';
            html += '<td style="padding:0.4rem 0.5rem;color:#e2e8f0;font-size:0.8rem;font-family:monospace;word-break:break-all;">' + self.escapeHtml(r.resourceIdentifier) + '</td>';
            html += '<td style="padding:0.4rem 0.5rem;"><span class="badge neutral" style="font-size:0.7rem;">' + self.escapeHtml(r.resourceType) + '</span></td>';
            html += '<td style="padding:0.4rem 0.5rem;color:#94a3b8;font-size:0.8rem;">' + self.escapeHtml(r.httpMethod) + '</td>';
            html += '</tr>';
        });
        html += '</tbody></table>';
        list.innerHTML = html;
        var popover = document.getElementById('selectedResourcesPopover');
        popover.classList.remove('hidden');
        popover.style.display = 'flex';
    },

    statusClass: function(status) {
        if (status === 'NEEDS_DEFINITION') return 'warning';
        if (status === 'PERMISSION_CREATED') return 'info';
        if (status === 'POLICY_CONNECTED') return 'success';
        return 'neutral';
    },

    escapeHtml: function(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
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
