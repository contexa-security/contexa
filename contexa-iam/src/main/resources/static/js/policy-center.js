/**
 * Policy Center - Unified policy management client logic
 * Integrates: resource-workbench.js + policy-wizard.js + policydetails.js + AI streaming
 */
const PolicyCenter = {

    // Read i18n message from hidden div
    _i18n: function(key, fallback) {
        var el = document.getElementById('i18nPolicyCenter');
        if (el && el.dataset[key]) return el.dataset[key];
        return fallback || key;
    },

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
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + PolicyCenter._i18n('loading', 'Processing...');
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
        if (!tableRow) { showToast(PolicyCenter._i18n('tableRowNotFound', 'Table row not found.'), 'error'); return; }
        const inputCell = tableRow.querySelector('.resource-inputs-cell');
        if (!inputCell) { showToast(PolicyCenter._i18n('inputFieldNotFound', 'Input field not found.'), 'error'); return; }
        const resourceId = button.dataset.resourceId;
        const friendlyNameInput = inputCell.querySelector('input[name="friendlyName"]');
        const descriptionTextarea = inputCell.querySelector('textarea[name="description"]');
        if (!friendlyNameInput.value.trim()) {
            showToast(PolicyCenter._i18n('nameRequired', 'Friendly name is required.'), 'error');
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
            showToast(PolicyCenter._i18n('defineError', 'Permission creation failed: ') + error.message, 'error');
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
        var modalTitle = modal.querySelector('h2');
        var originalTitle = modalTitle ? modalTitle.textContent : '';
        if (modalTitle) modalTitle.textContent = PolicyCenter._i18n('processing', 'Processing...');
        modal.querySelectorAll('button').forEach(function(b) { b.disabled = true; });

        try {
            var ctxArr = await this._batchDefineAndBuildContext();
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
            modal.classList.add('hidden');
            modal.style.display = 'none';

            PolicyCenter.CreateFlow.activateWithResources(ctxArr);
            document.querySelectorAll('.pc-tab-content').forEach(function(c) { c.classList.remove('active'); });
            document.querySelectorAll('.pc-tab-btn').forEach(function(b) { b.classList.remove('active'); });
            var createTab = document.getElementById('tab-create');
            if (createTab) createTab.classList.add('active');
            var createBtn = document.querySelector('.pc-tab-btn[href*="tab=create"]');
            if (createBtn) createBtn.classList.add('active');
            var modeBtn = document.querySelector('.pc-mode-card[onclick*="quick"]');
            PolicyCenter.switchCreateMode('quick', modeBtn);
            history.pushState(null, '', '/admin/policy-center?tab=create');
            PolicyCenter.MultiSelect.updateBar();

        } catch (e) {
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
            modal.classList.add('hidden');
            modal.style.display = 'none';
            showToast(PolicyCenter._i18n('policyCreateFailed', 'Batch creation failed: ') + e.message, 'error');
        }
    },

    async selectAIWizard() {
        const modal = document.getElementById('policySetupModal');
        if (modal.dataset.multiMode === 'true') {
            showToast(PolicyCenter._i18n('aiSingleOnly', 'AI mode supports single resource only. Please use Quick mode for multiple resources.'), 'error');
            return;
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
        if (modalTitle) modalTitle.textContent = PolicyCenter._i18n('processing', 'Processing...');
        modal.querySelectorAll('button').forEach(function(b) { b.disabled = true; });

        try {
            var ctxArr = await this._batchDefineAndBuildContext();
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
            modal.classList.add('hidden');
            modal.style.display = 'none';

            PolicyCenter.CreateFlow.activateWithResources(ctxArr);
            document.querySelectorAll('.pc-tab-content').forEach(function(c) { c.classList.remove('active'); });
            document.querySelectorAll('.pc-tab-btn').forEach(function(b) { b.classList.remove('active'); });
            var createTab = document.getElementById('tab-create');
            if (createTab) createTab.classList.add('active');
            var createBtn = document.querySelector('.pc-tab-btn[href*="tab=create"]');
            if (createBtn) createBtn.classList.add('active');
            var modeBtn = document.querySelector('.pc-mode-card[onclick*="ai"]');
            PolicyCenter.switchCreateMode('ai', modeBtn);
            history.pushState(null, '', '/admin/policy-center?tab=create');
            PolicyCenter.MultiSelect.updateBar();

            // Pre-fill AI query with first resource context (AI mode supports single policy only)
            var queryInput = document.getElementById('ai-query-input');
            if (queryInput && ctxArr.length > 0) {
                var first = ctxArr[0];
                queryInput.value = '[' + (first.resourceType || 'URL') + ' ' + (first.httpMethod || '') + ' ' + (first.resourceIdentifier || '') + '] ';
            }
        } catch (e) {
            if (modalTitle) modalTitle.textContent = originalTitle;
            modal.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
            modal.classList.add('hidden');
            modal.style.display = 'none';
            showToast(PolicyCenter._i18n('policyCreateFailed', 'Batch creation failed: ') + e.message, 'error');
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
        if (!resp.ok) throw new Error(PolicyCenter._i18n('policyCreateFailed', 'Server error') + ': ' + resp.status);
        var results = await resp.json();

        // Only include results that have a permissionId
        var permResults = results.filter(function(r) { return r.permissionId; });
        if (permResults.length === 0) {
            throw new Error(PolicyCenter._i18n('multiNoPermissions', 'No permissions could be created'));
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
                    textarea.value = parts.join(' ') + PolicyCenter._i18n('generatePromptSuffix', ' Generate optimal access policy for this resource');
                }
            }, 100);
        }

        // Update URL without reload
        history.pushState(null, '', '/admin/policy-center?tab=create');
        PolicyCenter.MultiSelect.updateBar();
    },

    switchToResourcesTab() {
        document.querySelectorAll('.pc-tab-content').forEach(c => c.classList.remove('active'));
        document.querySelectorAll('.pc-tab-btn').forEach(b => b.classList.remove('active'));
        const resTab = document.getElementById('tab-resources');
        if (resTab) resTab.classList.add('active');
        const resBtn = document.querySelector('.pc-tab-btn[href*="tab=resources"]');
        if (resBtn) resBtn.classList.add('active');
        history.pushState(null, '', '/admin/policy-center?tab=resources');
        PolicyCenter.MultiSelect.updateBar();
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
            showToast(PolicyCenter._i18n('excludeSuccess', 'Resource has been excluded.'), 'success');
        } catch (error) {
            showToast(PolicyCenter._i18n('excludeError', 'Exclude failed: ') + error.message, 'error');
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
            showToast(PolicyCenter._i18n('restoreSuccess', 'Resource has been restored to managed.'), 'success');
        } catch (error) {
            showToast(PolicyCenter._i18n('restoreError', 'Restore failed: ') + error.message, 'error');
            this.setLoading(button, false);
        }
    },

    updateRowAfterExclude(button, resourceId) {
        const row = button.closest('tr');
        if (!row) return;
        const badge = row.querySelector('.status-badge');
        if (badge) {
            badge.className = 'status-badge bg-slate-500/20 text-slate-400 border-slate-500/30';
            badge.innerHTML = '<i class="fas fa-ban"></i> <span>' + PolicyCenter._i18n('statusExcluded', 'Excluded') + '</span>';
        }
        row.dataset.resStatus = 'EXCLUDED';
        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineAndSetupPolicy(this)"]');
        if (defineBtn) defineBtn.closest('div').style.display = 'none';
        const actionDiv = button.closest('div');
        actionDiv.innerHTML = '<button type="button" class="action-badge-restore w-full text-center" data-resource-id="' + resourceId + '" onclick="PolicyCenter.restoreResource(this)"><i class="fas fa-undo"></i> <span>' + PolicyCenter._i18n('btnRestore', 'Restore') + '</span></button>';
        // Hide and disable checkbox for EXCLUDED
        const cb = row.querySelector('.res-cb');
        if (cb) { cb.checked = false; cb.disabled = true; cb.style.display = 'none'; }
        // Remove from selection if selected
        const id = parseInt(row.dataset.resId);
        if (!isNaN(id) && PolicyCenter.MultiSelect.selectedResources.has(id)) {
            PolicyCenter.MultiSelect.selectedResources.delete(id);
            PolicyCenter.MultiSelect.updateBar();
        }
    },

    updateRowAfterRestore(button, resourceId) {
        const row = button.closest('tr');
        if (!row) return;
        const badge = row.querySelector('.status-badge');
        if (badge) {
            badge.className = 'status-badge bg-red-500/20 text-red-400 border-red-500/30';
            badge.innerHTML = '<i class="fas fa-exclamation-circle"></i> <span>' + PolicyCenter._i18n('statusUnset', 'Unset') + '</span>';
        }
        row.dataset.resStatus = 'NEEDS_DEFINITION';
        const defineBtn = row.querySelector('[onclick="PolicyCenter.defineAndSetupPolicy(this)"]');
        if (defineBtn) {
            defineBtn.closest('div').style.display = '';
            defineBtn.disabled = false;
            defineBtn.classList.remove('opacity-40', 'cursor-not-allowed');
        }
        const actionDiv = button.closest('div');
        actionDiv.innerHTML = '<button type="button" class="action-badge-secondary w-full text-center" data-resource-id="' + resourceId + '" onclick="PolicyCenter.excludeResource(this)"><i class="fas fa-ban"></i> <span>' + PolicyCenter._i18n('btnExclude', 'Exclude') + '</span></button>';
        // Re-enable checkbox for NEEDS_DEFINITION
        var cb = row.querySelector('.res-cb');
        if (cb) {
            cb.disabled = false;
            cb.style.display = '';
        } else {
            // Checkbox was never rendered (e.g. POLICY_CONNECTED row) - create it
            var cbTd = row.querySelector('td:first-child');
            if (cbTd) {
                var newCb = document.createElement('input');
                newCb.type = 'checkbox';
                newCb.className = 'res-cb res-styled-cb';
                newCb.dataset.id = resourceId;
                newCb.onchange = function() { PolicyCenter.MultiSelect.toggleResource(newCb); };
                cbTd.appendChild(newCb);
            }
        }
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
                            textarea.value = parts.join(' ') + PolicyCenter._i18n('generatePromptSuffix', ' Generate optimal access policy for this resource');
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
            this.selectedResources = null;
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

            // Render CRUD panel based on resource httpMethod
            PolicyCenter.QuickPanel._renderCrud([ctx]);
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
                var countTpl = PolicyCenter._i18n('multiBatchInfo', '{0} resources selected');
                document.getElementById('create-multi-count').textContent = countTpl.replace(/\{0}/g, ctxArr.length);
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

            // Render CRUD panel for all resources
            PolicyCenter.QuickPanel._renderCrud(ctxArr);
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
        selectedSpel: null,
        spelSearchTimeout: null,
        _selectedCruds: new Set(),

        _httpMethodToCrud: function(httpMethod) {
            if (!httpMethod) return 'READ';
            var m = httpMethod.toUpperCase();
            if (m === 'GET') return 'READ';
            if (m === 'POST') return 'WRITE';
            if (m === 'PUT' || m === 'PATCH') return 'UPDATE';
            if (m === 'DELETE') return 'DELETE';
            return 'READ';
        },

        _renderCrud: function(ctxArr) {
            var autoItems = document.getElementById('qp-crud-auto-items');
            var emptyEl = document.getElementById('qp-crud-empty');
            if (!autoItems) return;
            if (!ctxArr || ctxArr.length === 0) {
                autoItems.innerHTML = '';
                if (emptyEl) emptyEl.style.display = '';
                return;
            }
            if (emptyEl) emptyEl.style.display = 'none';

            var allCruds = ['READ', 'WRITE', 'UPDATE', 'DELETE'];
            var crudNames = { READ: 'Read', WRITE: 'Write', UPDATE: 'Update', DELETE: 'Delete' };
            var crudColors = { READ: '#4ade80', WRITE: '#60a5fa', UPDATE: '#fbbf24', DELETE: '#f87171' };
            var crudIcons = { READ: 'fa-eye', WRITE: 'fa-plus', UPDATE: 'fa-pen', DELETE: 'fa-trash' };
            var methodColors = { GET: '#4ade80', POST: '#60a5fa', PUT: '#fbbf24', PATCH: '#fbbf24', DELETE: '#f87171', ANY: '#94a3b8' };

            if (ctxArr.length === 1) {
                // Single resource: 4 CRUD checkboxes (existing behavior)
                var recommended = new Set();
                recommended.add(this._httpMethodToCrud(ctxArr[0].httpMethod));
                this._selectedCruds = new Set(recommended);
                this._selectedCrudsPerResource = null;

                autoItems.innerHTML = allCruds.map(function(c) {
                    var isRec = recommended.has(c);
                    return '<label style="display:inline-flex;align-items:center;gap:0.5rem;padding:0.5rem 0.875rem;border-radius:0.5rem;cursor:pointer;transition:all 0.2s;' +
                        'background:' + (isRec ? crudColors[c] + '15' : 'rgba(30,41,59,0.4)') + ';border:1px solid ' + (isRec ? crudColors[c] + '40' : 'rgba(71,85,105,0.3)') + ';">' +
                        '<input type="checkbox" class="qp-crud-cb" value="' + c + '"' + (isRec ? ' checked' : '') +
                        ' onchange="PolicyCenter.QuickPanel._onCrudChange()" style="accent-color:' + crudColors[c] + ';width:1rem;height:1rem;">' +
                        '<i class="fas ' + crudIcons[c] + '" style="font-size:0.75rem;color:' + crudColors[c] + ';"></i> ' +
                        '<span style="font-size:0.8125rem;font-weight:600;color:' + (isRec ? crudColors[c] : '#94a3b8') + ';">' + crudNames[c] + '</span>' +
                        (isRec ? '<span style="font-size:0.625rem;color:#64748b;margin-left:0.25rem;">*</span>' : '') +
                        '</label>';
                }).join('');
            } else {
                // Multi resource: per-resource CRUD cards
                this._selectedCruds = null;
                this._selectedCrudsPerResource = new Map();
                var self = this;

                autoItems.innerHTML = ctxArr.map(function(ctx, idx) {
                    var rec = self._httpMethodToCrud(ctx.httpMethod);
                    self._selectedCrudsPerResource.set(String(ctx.resourceId), new Set([rec]));
                    var method = (ctx.httpMethod || 'ANY').toUpperCase();
                    var mColor = methodColors[method] || '#94a3b8';

                    return '<div class="qp-res-crud-card" data-res-id="' + ctx.resourceId + '" style="padding:0.75rem;border-radius:0.625rem;' +
                        'background:rgba(15,23,42,0.6);border:1px solid rgba(71,85,105,0.3);margin-bottom:0.5rem;">' +
                        '<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;">' +
                        '<span style="font-size:0.6875rem;padding:0.125rem 0.5rem;border-radius:0.25rem;font-weight:700;' +
                        'background:' + mColor + '20;color:' + mColor + ';border:1px solid ' + mColor + '40;">' + method + '</span>' +
                        '<span style="font-family:monospace;font-size:0.8125rem;color:#e2e8f0;word-break:break-all;">' +
                        PolicyCenter.escapeHtml(ctx.resourceIdentifier || '') + '</span></div>' +
                        '<div style="display:flex;gap:0.375rem;flex-wrap:wrap;">' +
                        allCruds.map(function(c) {
                            var isRec = c === rec;
                            return '<label style="display:inline-flex;align-items:center;gap:0.375rem;padding:0.25rem 0.625rem;border-radius:0.375rem;cursor:pointer;' +
                                'background:' + (isRec ? crudColors[c] + '15' : 'rgba(30,41,59,0.4)') + ';border:1px solid ' + (isRec ? crudColors[c] + '40' : 'rgba(71,85,105,0.2)') + ';">' +
                                '<input type="checkbox" class="qp-res-crud-cb" data-res-id="' + ctx.resourceId + '" value="' + c + '"' + (isRec ? ' checked' : '') +
                                ' onchange="PolicyCenter.QuickPanel._onMultiCrudChange()" style="accent-color:' + crudColors[c] + ';width:0.875rem;height:0.875rem;">' +
                                '<span style="font-size:0.75rem;font-weight:600;color:' + (isRec ? crudColors[c] : '#64748b') + ';">' + crudNames[c] + '</span></label>';
                        }).join('') +
                        '</div></div>';
                }).join('');
            }

            this._updateCrudCount();
        },

        _onCrudChange: function() {
            // Single resource mode
            this._selectedCruds = new Set();
            document.querySelectorAll('.qp-crud-cb:checked').forEach(function(cb) {
                PolicyCenter.QuickPanel._selectedCruds.add(cb.value);
            });
            this._updateCrudCount();
            this.updateCreateButtonState();
        },

        _onMultiCrudChange: function() {
            // Multi resource mode
            this._selectedCrudsPerResource = new Map();
            var self = this;
            document.querySelectorAll('.qp-res-crud-card').forEach(function(card) {
                var resId = card.dataset.resId;
                var cruds = new Set();
                card.querySelectorAll('.qp-res-crud-cb:checked').forEach(function(cb) {
                    cruds.add(cb.value);
                });
                self._selectedCrudsPerResource.set(resId, cruds);
            });
            this._updateCrudCount();
            this.updateCreateButtonState();
        },

        _updateCrudCount: function() {
            var countEl = document.getElementById('qp-perm-count');
            if (!countEl) return;
            if (this._selectedCrudsPerResource) {
                // Multi mode: count total selected across all resources
                var total = 0;
                this._selectedCrudsPerResource.forEach(function(s) { total += s.size; });
                countEl.textContent = total + PolicyCenter._i18n('selectedSuffix', ' selected');
            } else if (this._selectedCruds) {
                countEl.textContent = this._selectedCruds.size + PolicyCenter._i18n('selectedSuffix', ' selected');
            }
        },

        async _createBatchPolicies() {
            if (this.selectedRoles.size === 0) {
                showToast(PolicyCenter._i18n('selectRoleRequired', 'Please select at least one role.'), 'error');
                return;
            }
            var ctxArr = PolicyCenter.CreateFlow.selectedResources;
            if (!ctxArr || ctxArr.length === 0) return;

            var btn = document.getElementById('qp-create-btn');
            PolicyCenter.setLoading(btn, true);

            try {
                var items = [];
                var self = this;
                ctxArr.forEach(function(ctx) {
                    var cruds = self._selectedCrudsPerResource.get(String(ctx.resourceId));
                    items.push({
                        resourceId: ctx.resourceId,
                        permissionId: ctx.permissionId,
                        permissionName: ctx.permissionName || '',
                        resourceIdentifier: ctx.resourceIdentifier || '',
                        resourceType: ctx.resourceType || 'URL',
                        httpMethod: ctx.httpMethod || 'ANY',
                        crudPermissions: cruds ? Array.from(cruds) : []
                    });
                });

                var resp = await fetch('/admin/policy-center/api/batch-create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': PolicyCenter.getCsrfToken() },
                    body: JSON.stringify({
                        roleIds: Array.from(this.selectedRoles.keys()),
                        effect: document.getElementById('qp-policy-effect').value,
                        items: items
                    })
                });
                var result = await resp.json();
                if (!resp.ok) throw new Error(result.message || PolicyCenter._i18n('policyCreateFailed', 'Batch creation failed'));

                // Show batch result modal
                PolicyCenter.BatchResult.show(result.results || [], result.created || 0, result.total || items.length);
            } catch (e) {
                PolicyCenter.MultiSelect.selectedResources.clear();
                showToast(PolicyCenter._i18n('policyCreateFailed', 'Batch creation failed: ') + e.message, 'error');
                PolicyCenter.setLoading(btn, false);
            }
        },

        init() {
            this.selectedRoles.clear();
            this.selectedPerms.clear();
            this.rolePermissionMap = {};
            this.userManualPerms.clear();
            this.allPermissions = [];
            this.initialMappingDone = false;
            this.selectedSpel = null;
            this._cachedSpels = [];

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
            const spelCount = document.getElementById('qp-spel-count');
            if (roleCount) roleCount.textContent = '0' + PolicyCenter._i18n('selectedSuffix', ' selected');
            if (permCount) permCount.textContent = this.selectedPerms.size + PolicyCenter._i18n('selectedSuffix', ' selected');
            if (spelCount) spelCount.textContent = '-';

            this.loadRoles('');
            this.loadPermissions('');
            this.loadSpelPermissions('');
            this.updateDisabledState();
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
            if (!list) return;
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>Loading...</p></div>';
            try {
                const resp = await fetch('/admin/policy-center/api/roles?keyword=' + encodeURIComponent(keyword || '') + '&size=50');
                const page = await resp.json();
                this.renderRoleList(page.content || []);
            } catch (e) {
                if (list) list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('loadFailed', 'Loading failed') + '</p></div>';
            }
        },

        renderRoleList(roles) {
            const list = document.getElementById('qp-role-list');
            if (!list) return;
            if (!roles.length) { list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('noItemsAvailable', 'No items found.') + '</p></div>'; return; }
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
            var el = document.getElementById('qp-role-count');
            if (el) el.textContent = this.selectedRoles.size + PolicyCenter._i18n('selectedSuffix', ' selected');
        },

        searchRoles(keyword) {
            clearTimeout(this.roleSearchTimeout);
            this.roleSearchTimeout = setTimeout(() => this.loadRoles(keyword), 400);
        },

        onRoleSelectionChanged() {
            this.initialMappingDone = false;
            this.loadPermissions(document.getElementById('qp-perm-search')?.value || '');
            this.updateDisabledState();
            this.updateSummary();
            this.updateCreateButtonState();
        },

        // === Permission Panel ===

        async loadPermissions(keyword) {
            const list = document.getElementById('qp-perm-list');
            if (!list) return;
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
                if (list) list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('loadFailed', 'Loading failed') + '</p></div>';
            }
        },

        renderPermList(perms) {
            const list = document.getElementById('qp-perm-list');
            if (!list) return;
            if (!perms.length) { list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('noItemsAvailable', 'No items found.') + '</p></div>'; return; }

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
            this.updateDisabledState();
            this.updateSummary();
            this.updateCreateButtonState();
        },

        renderPermChips() {
            var el = document.getElementById('qp-perm-count');
            if (el) el.textContent = this.selectedPerms.size + PolicyCenter._i18n('selectedSuffix', ' selected');
        },

        searchPermissions(keyword) {
            clearTimeout(this.permSearchTimeout);
            this.permSearchTimeout = setTimeout(() => this.loadPermissions(keyword), 400);
        },

        // === SpEL Expression Permissions ===

        async loadSpelPermissions(keyword) {
            const list = document.getElementById('qp-spel-list');
            if (!list) return;
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>Loading...</p></div>';
            try {
                const resp = await fetch('/admin/policy-center/api/spel-permissions?keyword=' + encodeURIComponent(keyword || ''));
                const data = await resp.json();
                this._cachedSpels = data || [];
                this.renderSpelList(this._cachedSpels);
            } catch (e) {
                if (list) list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('loadFailed', 'Loading failed') + '</p></div>';
            }
        },

        renderSpelList(spels) {
            const list = document.getElementById('qp-spel-list');
            if (!list) return;
            if (!spels.length) { list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('noItemsAvailable', 'No items found.') + '</p></div>'; return; }
            list.innerHTML = spels.map(s => {
                const sid = Number(s.id);
                const sel = this.selectedSpel && this.selectedSpel.id === sid;
                const safeName = this.escapeHtml(s.name).replace(/'/g, "\\'");
                return '<div class="qp-item' + (sel ? ' selected' : '') + '" onclick="PolicyCenter.QuickPanel.toggleSpel(' + sid + ',\'' + safeName + '\')">' +
                    '<input type="checkbox" ' + (sel ? 'checked' : '') + ' onclick="PolicyCenter.QuickPanel.toggleSpel(' + sid + ',\'' + safeName + '\');event.stopPropagation();">' +
                    '<div class="qp-item-info"><div class="qp-item-name">' + this.escapeHtml(s.name) + '</div>' +
                    '<div class="qp-item-desc" style="font-family:monospace;color:#a78bfa;">' + this.escapeHtml(s.expression) + '</div>' +
                    (s.description ? '<div class="qp-item-desc">' + this.escapeHtml(s.description) + '</div>' : '') +
                    '</div></div>';
            }).join('');
        },

        toggleSpel(id, name) {
            id = Number(id);
            if (this.selectedSpel && this.selectedSpel.id === id) {
                this.selectedSpel = null;
            } else {
                this.selectedSpel = { id: id, name: name };
            }
            var countEl = document.getElementById('qp-spel-count');
            if (countEl) countEl.textContent = this.selectedSpel ? this.selectedSpel.name : '-';
            this.renderSpelList(this._cachedSpels || []);
            this.updateDisabledState();
            this.updateSummary();
            this.updateCreateButtonState();
        },

        searchSpel(keyword) {
            clearTimeout(this.spelSearchTimeout);
            this.spelSearchTimeout = setTimeout(() => this.loadSpelPermissions(keyword), 400);
        },

        // === Mutual Exclusion ===

        updateDisabledState() {
            var spelOverlay = document.getElementById('qp-spel-disabled-overlay');
            var roleOverlay = document.getElementById('qp-role-disabled-overlay');
            var permOverlay = document.getElementById('qp-perm-disabled-overlay');
            var hasSpel = this.selectedSpel !== null;
            var hasRolePerm = this.selectedRoles.size > 0 || this.selectedPerms.size > 0;

            if (spelOverlay) spelOverlay.style.display = hasRolePerm ? '' : 'none';
            if (roleOverlay) roleOverlay.style.display = hasSpel ? '' : 'none';
            if (permOverlay) permOverlay.style.display = hasSpel ? '' : 'none';
        },

        // === Summary & Create ===

        updateSummary() {
            const nameInput = document.getElementById('qp-policy-name');
            if (nameInput && !nameInput.value && (this.selectedRoles.size > 0 || this.selectedSpel)) {
                var ctx = PolicyCenter.CreateFlow.selectedResource;
                var effect = (document.getElementById('qp-policy-effect')?.value || 'ALLOW').toUpperCase();
                var roleName = this.selectedRoles.size > 0 ? Array.from(this.selectedRoles.values())[0] : '';
                var crud = this._selectedCruds && this._selectedCruds.size > 0 ? Array.from(this._selectedCruds).join('_') : '';
                var resource = ctx && ctx.resourceIdentifier ? ctx.resourceIdentifier.replace(/[\/{}]/g, '_').replace(/^_+|_+$/g, '') : '';
                nameInput.value = [effect, roleName, crud, resource].filter(Boolean).join('_').substring(0, 200);
            }
        },

        updateCreateButtonState() {
            const btn = document.getElementById('qp-create-btn');
            if (btn) btn.disabled = !(this.selectedRoles.size > 0 || this.selectedPerms.size > 0 || this.selectedSpel);
        },

        async createPolicy() {
            // Multi-resource batch mode
            if (this._selectedCrudsPerResource && this._selectedCrudsPerResource.size > 0
                && Array.from(this._selectedCrudsPerResource.values()).some(function(s) { return s.size > 0; })) {
                return this._createBatchPolicies();
            }

            const name = document.getElementById('qp-policy-name').value.trim();
            if (!name) { showToast(PolicyCenter._i18n('policyNameRequired', 'Please enter a policy name.'), 'error'); return; }
            if (!this.selectedSpel && this.selectedRoles.size === 0) {
                showToast(PolicyCenter._i18n('selectRoleRequired', 'Please select at least one role.'), 'error'); return;
            }
            const btn = document.getElementById('qp-create-btn');
            PolicyCenter.setLoading(btn, true);

            // Pre-creation validation
            try {
                const quickRequest = {
                    policyName: name,
                    description: document.getElementById('qp-policy-desc').value,
                    effect: document.getElementById('qp-policy-effect').value,
                    roleIds: this.selectedSpel ? [] : Array.from(this.selectedRoles.keys()),
                    permissionIds: this.selectedSpel ? [] : Array.from(this.selectedPerms.keys()),
                    crudPermissions: this.selectedSpel ? [] : (this._selectedCruds ? Array.from(this._selectedCruds) : []),
                    spelId: this.selectedSpel ? this.selectedSpel.id : null,
                    sourceType: PolicyCenter.ManualTarget._context ? 'MANUAL' : 'RESOURCE',
                    manualTargetType: PolicyCenter.ManualTarget._context?.manualTargetType || null,
                    manualTargetIdentifier: PolicyCenter.ManualTarget._context?.manualTargetIdentifier || null,
                    manualHttpMethod: PolicyCenter.ManualTarget._context?.manualHttpMethod || null,
                    manualTargetOrder: PolicyCenter.ManualTarget._context?.manualTargetOrder || 0
                };
                const validation = await PolicyCenter.Validation.validateQuickPolicy(quickRequest);
                if (!validation.canCreate) {
                    await PolicyCenter.ValidationModal.show(validation, false);
                    PolicyCenter.setLoading(btn, false);
                    return;
                }
                if (validation.conflicts.length > 0 || validation.duplicates.length > 0) {
                    var proceed = await PolicyCenter.ValidationModal.show(validation, true);
                    if (!proceed) {
                        PolicyCenter.setLoading(btn, false);
                        return;
                    }
                }
            } catch (valErr) {
                console.error('Pre-creation validation error', valErr);
                showToast(PolicyCenter._i18n('validationChecking', 'Validation check failed'), 'warning');
            }

            try {
                const resp = await fetch('/admin/policy-center/api/quick-create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': PolicyCenter.getCsrfToken() },
                    body: JSON.stringify(Object.assign({
                        policyName: name,
                        description: document.getElementById('qp-policy-desc').value,
                        roleIds: this.selectedSpel ? [] : Array.from(this.selectedRoles.keys()),
                        permissionIds: this.selectedSpel ? [] : Array.from(this.selectedPerms.keys()),
                        crudPermissions: this.selectedSpel ? [] : (this._selectedCruds ? Array.from(this._selectedCruds) : []),
                        effect: document.getElementById('qp-policy-effect').value,
                        spelId: this.selectedSpel ? this.selectedSpel.id : null
                    }, PolicyCenter.ManualTarget._context || {}))
                });
                const result = await resp.json();
                if (!resp.ok) throw new Error(result.message);
                PolicyCenter.ManualTarget._context = null;
                if (result.warning) {
                    showToast(result.warning, 'warning');
                    setTimeout(() => {
                        showToast(PolicyCenter._i18n('policyCreated', 'Policy created successfully.'), 'success');
                        setTimeout(() => { window.location.href = '/admin/policy-center?tab=list'; }, 1500);
                    }, 2000);
                } else {
                    showToast(PolicyCenter._i18n('policyCreated', 'Policy created successfully.'), 'success');
                    setTimeout(() => { window.location.href = '/admin/policy-center?tab=list'; }, 1500);
                }
            } catch (e) {
                PolicyCenter.MultiSelect.selectedResources.clear();
                showToast(PolicyCenter._i18n('policyCreateFailed', 'Policy creation failed: ') + e.message, 'error');
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
                '<input type="hidden" name="targets[' + idx + '].targetOrder" value="0" />' +
                '<input type="hidden" name="targets[' + idx + '].sourceType" value="RESOURCE" />' +
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
                '<h3 class="font-semibold" style="color: #e2e8f0;">' + PolicyCenter._i18n('ruleLabel', 'Rule #') + (idx + 1) + '</h3>' +
                '<div><label class="manual-form-label">' + PolicyCenter._i18n('ruleDescLabel', 'Rule Description') + '</label><input type="text" name="rules[' + idx + '].description" class="modern-input" /></div>' +
                '<div><label class="manual-form-label">' + PolicyCenter._i18n('conditionsLabel', 'Conditions (AND)') + '</label><div class="conditions-list space-y-2 mt-2"></div>' +
                '<button type="button" onclick="PolicyCenter.Manual.addCondition(this)" class="add-btn mt-2"><i class="fas fa-plus"></i> ' + PolicyCenter._i18n('addCondition', 'Add Condition') + '</button></div>';
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
                '<div class="col-span-3"><select name="rules[' + ruleIdx + '].conditions[' + condIdx + '].authorizationPhase" class="modern-select text-sm"><option value="PRE_AUTHORIZE">' + PolicyCenter._i18n('preAuthorize', 'Pre-Authorize') + '</option><option value="POST_AUTHORIZE">' + PolicyCenter._i18n('postAuthorize', 'Post-Authorize') + '</option></select></div>' +
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
                b.querySelector('h3').textContent = PolicyCenter._i18n('ruleLabel', 'Rule #') + (i + 1);
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
        },

        async validateAndSubmit(event) {
            event.preventDefault();
            var form = document.getElementById('manual-create-form');
            var formData = new FormData(form);
            var policyDto = {
                name: formData.get('name'),
                description: formData.get('description'),
                effect: formData.get('effect'),
                priority: parseInt(formData.get('priority')) || 100,
                targets: [],
                rules: []
            };
            form.querySelectorAll('.target-block').forEach(function(tb, ti) {
                policyDto.targets.push({
                    targetType: formData.get('targets[' + ti + '].targetType'),
                    targetIdentifier: formData.get('targets[' + ti + '].targetIdentifier'),
                    httpMethod: formData.get('targets[' + ti + '].httpMethod')
                });
            });
            form.querySelectorAll('.rule-block').forEach(function(rb, ri) {
                var conditions = [];
                rb.querySelectorAll('.condition-block').forEach(function(cb, ci) {
                    conditions.push({
                        expression: formData.get('rules[' + ri + '].conditions[' + ci + '].expression'),
                        authorizationPhase: formData.get('rules[' + ri + '].conditions[' + ci + '].authorizationPhase')
                    });
                });
                policyDto.rules.push({ description: formData.get('rules[' + ri + '].description'), conditions: conditions });
            });

            try {
                var validation = await PolicyCenter.Validation.validateBeforeCreate(policyDto);
                if (!validation.canCreate) {
                    await PolicyCenter.ValidationModal.show(validation, false);
                    return false;
                }
                if (validation.conflicts.length > 0 || validation.duplicates.length > 0) {
                    var proceed = await PolicyCenter.ValidationModal.show(validation, true);
                    if (!proceed) return false;
                }
            } catch (valErr) {
                console.error('Pre-creation validation error', valErr);
            }
            form.removeAttribute('onsubmit');
            form.submit();
            return false;
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
            if (!query) { showToast(PolicyCenter._i18n('policyQueryRequired', 'Please enter policy requirements.'), 'error'); queryInput.focus(); return; }

            // Inject selected resource context into query (single resource only)
            var res = PolicyCenter.CreateFlow.selectedResource;
            if (res) {
                var ctx = '[Target Resource: ' +
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
                    permissions: (items.permissions || []).map(p => ({ id: p.id, name: p.friendlyName || p.name, targetType: p.targetType || '', resourceIdentifier: p.linkedResourceIdentifier || '', httpMethod: p.actionType || '', description: p.description || '' })),
                    conditions: (items.conditions || []).map(c => ({ id: c.id, name: c.name, description: c.description || '' }))
                };
            } catch (e) {
                console.error('Failed to collect available items', e);
            }

            const requestPayload = { naturalLanguageQuery: query, availableItems: availableItems };

            try {
                if (typeof ContexaLLM !== 'undefined' && ContexaLLM.analyzeStreaming) {
                    this.updateProgress('analyze', 40, 'AI analyzing policy requirements...');
                    await ContexaLLM.analyzeStreaming(
                        '/admin/api/ai/policies/generate/stream',
                        requestPayload,
                        {
                            modalTitle: PolicyCenter._i18n('aiAnalyzing', 'AI policy analysis in progress'),
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
                                showToast(PolicyCenter._i18n('aiGenerateError', 'AI policy generation failed: ') + (error.message || error), 'error');
                            }
                        }
                    );
                } else {
                    this.updateProgress('analyze', 40, 'Sending request to AI...');
                    const response = await fetch('/admin/api/ai/policies/generate/stream', {
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
                            showToast(PolicyCenter._i18n('aiParseError', 'Failed to parse AI response. Please try again.'), 'error');
                        }
                    } else {
                        showToast(PolicyCenter._i18n('aiParseError', 'Failed to parse AI response. Please try again.'), 'error');
                    }
                }
            } catch (e) {
                showToast(PolicyCenter._i18n('aiGenerateError', 'AI policy generation failed: ') + e.message, 'error');
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
            if (!response) { showToast(PolicyCenter._i18n('aiEmptyResponse', 'AI response is empty.'), 'warning'); return; }

            const processed = this.preprocessPolicyResponse(response);
            if (!processed || !processed.policyData) {
                console.error('AI response preprocessing failed:', response);
                this._wasFallback = true;
                this.createFallbackPolicy(query);
                return;
            }

            const validatedData = await this.validateAndFilterAIResponse(processed.policyData);
            if (!validatedData) {
                showToast(PolicyCenter._i18n('aiValidationFailed', 'AI response validation failed.'), 'error');
                return;
            }

            // Auto-include selected resource's permission (single resource only)
            var res = PolicyCenter.CreateFlow.selectedResource;
            if (res && res.permissionId) {
                var pid = Number(res.permissionId);
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
            if (this._filteredCount > 0) showToast(PolicyCenter._i18n('aiFiltered', '{0} non-existent items removed from AI response.').replace('{0}', this._filteredCount), 'warning');
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
            const fallback = { policyName: 'AI Generated Policy (' + new Date().toISOString().slice(0, 16) + ')', description: 'Requirement: "' + (query || '') + '"', effect: 'ALLOW', roleIds: [], crudPermissions: [], conditions: {}, aiActionEnabled: false, allowedActions: [], customConditionSpel: '' };
            this.generatedPolicyData = fallback;
            this._cachedMaps = { roles: {}, permissions: {}, conditions: {} };
            this.renderPolicyCard(fallback, this._cachedMaps);
            this.renderConfidence(fallback);
            document.getElementById('ai-result-section').classList.remove('hidden');
            showToast(PolicyCenter._i18n('aiFallback', 'A default policy has been created. Please modify as needed.'), 'warning');
        },

        // ---- Interactive Policy Card ----

        renderPolicyCard(data, maps) {
            document.getElementById('ai-card-name').value = data.policyName || '';
            document.getElementById('ai-card-effect').value = data.effect || 'ALLOW';
            document.getElementById('ai-card-description').value = data.description || '';

            var roleItems = (data.roleIds || []).map(id => ({ id, name: maps.roles[id] || maps.roles[String(id)] || 'ID:' + id }));
            var crudItems = (data.crudPermissions || []).map(c => ({ id: c, name: c }));
            var condItems = Object.keys(data.conditions || {}).map(id => ({ id, name: maps.conditions[id] || maps.conditions[String(id)] || 'ID:' + id }));

            this.renderChips('ai-card-roles', roleItems, 'role');
            this.renderCrudBadges('ai-card-permissions', crudItems);
            this.renderChips('ai-card-conditions', condItems, 'condition');

            // Update count spans
            var roleCountEl = document.getElementById('ai-role-count');
            var permCountEl = document.getElementById('ai-perm-count');
            var condCountEl = document.getElementById('ai-cond-count');
            if (roleCountEl) roleCountEl.textContent = roleItems.length;
            if (permCountEl) permCountEl.textContent = crudItems.length;
            if (condCountEl) condCountEl.textContent = condItems.length;

            var spelSection = document.getElementById('ai-card-spel-section');
            if (data.customConditionSpel) {
                spelSection.classList.remove('hidden');
                document.getElementById('ai-card-spel').value = data.customConditionSpel;
            } else {
                spelSection.classList.add('hidden');
            }

            // AI reasoning
            var reasoningSection = document.getElementById('ai-card-reasoning-section');
            if (reasoningSection) {
                if (data.reasoning) {
                    reasoningSection.classList.remove('hidden');
                    document.getElementById('ai-card-reasoning').textContent = data.reasoning;
                } else {
                    reasoningSection.classList.add('hidden');
                }
            }
        },

        renderCrudBadges(containerId, items) {
            var container = document.getElementById(containerId);
            if (!container) return;
            var crudColors = { READ: '#4ade80', WRITE: '#60a5fa', UPDATE: '#fbbf24', DELETE: '#f87171' };
            if (!items.length) {
                container.innerHTML = '<span class="ai-card-chips-empty">' + PolicyCenter._i18n('none', 'None') + '</span>';
                return;
            }
            container.innerHTML = items.map(function(item) {
                var color = crudColors[item.name] || '#94a3b8';
                return '<span style="display:inline-flex;align-items:center;gap:0.375rem;padding:0.25rem 0.75rem;border-radius:0.375rem;' +
                    'background:' + color + '15;border:1px solid ' + color + '40;color:' + color + ';font-weight:600;font-size:0.8125rem;">' +
                    item.name + '</span>';
            }).join(' ');
        },

        renderChips(containerId, items, type) {
            const container = document.getElementById(containerId);
            if (!items.length) {
                container.innerHTML = '<span class="ai-card-chips-empty">' + PolicyCenter._i18n('none', 'None') + '</span>';
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
            const titleMap = { role: PolicyCenter._i18n('pickerTitleRole', 'Add Roles'), permission: PolicyCenter._i18n('pickerTitlePermission', 'Add Permissions'), condition: PolicyCenter._i18n('pickerTitleCondition', 'Add Conditions') };
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
            list.innerHTML = '<div class="pc-empty"><i class="fas fa-spinner fa-spin"></i><p>' + PolicyCenter._i18n('loading', 'Loading...') + '</p></div>';

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
                    list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('noItemsAvailable', 'No items available to add.') + '</p></div>';
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
                list.innerHTML = '<div class="pc-empty"><p>' + PolicyCenter._i18n('loadFailed', 'Loading failed') + '</p></div>';
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
                    conflicts.push({ severity: 'high', message: '"' + p.name + '" ' + PolicyCenter._i18n('conflictDuplicate', 'policy name already exists') + ' (Policy #' + p.id + ')' });
                });

                // Check similar names (partial match)
                if (policyData.policyName) {
                    const lower = policyData.policyName.toLowerCase();
                    summaries.filter(p => p.name && p.name.toLowerCase().includes(lower) && p.name !== policyData.policyName).forEach(p => {
                        conflicts.push({ severity: 'low', message: PolicyCenter._i18n('conflictSimilar', 'Similar policy name found:') + ' "' + p.name + '" (Policy #' + p.id + ')' });
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
            var warningsEl = document.getElementById('ai-warnings-list');
            if (!warningsEl) return;
            var roleCount = (policyData.roleIds || []).length;
            var permCount = (policyData.permissionIds || []).length;
            var condCount = Object.keys(policyData.conditions || {}).length;

            var warnings = [];
            if (roleCount > 3) warnings.push(PolicyCenter._i18n('simWarningManyRoles', 'Many roles affected ({0})').replace('{0}', roleCount));
            if (permCount > 5) warnings.push(PolicyCenter._i18n('simWarningManyPerms', 'Many permissions granted ({0})').replace('{0}', permCount));
            if (condCount === 0) warnings.push(PolicyCenter._i18n('simWarningNoConditions', 'No conditions - policy applies unconditionally'));
            if (policyData.effect === 'DENY') warnings.push(PolicyCenter._i18n('simWarningDeny', 'DENY effect - may block legitimate access'));

            // Check for sensitive permissions
            var sensitiveCount = 0;
            if (this._cachedAvailableItems) {
                var perms = this._cachedAvailableItems.permissions || [];
                var selectedPerms = perms.filter(function(p) { return (policyData.permissionIds || []).indexOf(p.id) !== -1; });
                var sensitive = selectedPerms.filter(function(p) {
                    var name = (p.friendlyName || p.name || '').toLowerCase();
                    return name.includes('delete') || name.includes('admin') || name.includes('write') || name.includes('modify');
                });
                sensitiveCount = sensitive.length;
            }
            if (sensitiveCount > 0) warnings.push(PolicyCenter._i18n('simWarningSensitive', '{0} sensitive permission(s) detected').replace('{0}', sensitiveCount));

            var html = '';
            warnings.forEach(function(w) {
                html += '<div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.375rem 0;color:#fbbf24;font-size:0.8125rem;"><i class="fas fa-exclamation-triangle" style="flex-shrink:0;margin-top:0.1rem;"></i><span>' + w + '</span></div>';
            });
            warningsEl.innerHTML = html;
        },

        // ---- Confidence ----

        renderConfidence(policyData) {
            var score = 100;

            if (this._filteredCount > 0) { score -= this._filteredCount * 10; }
            if (!(policyData.roleIds || []).length) { score -= 30; }
            if (!(policyData.permissionIds || []).length) { score -= 30; }
            if (Object.keys(policyData.conditions || {}).length === 0) { score -= 10; }
            if (this._wasFallback) { score -= 40; }

            score = Math.max(0, Math.min(100, score));
            var level = score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
            var color = { high: '#22c55e', medium: '#f59e0b', low: '#ef4444' };

            var fill = document.getElementById('ai-confidence-fill');
            fill.style.width = score + '%';
            fill.className = 'ai-confidence-fill ' + level;

            var valueEl = document.getElementById('ai-confidence-value');
            valueEl.textContent = score + '%';
            valueEl.style.color = color[level];

            // Completeness status text
            var statusEl = document.getElementById('ai-completeness-status');
            if (statusEl) {
                var statusText, statusColor;
                if (score >= 80) {
                    statusText = PolicyCenter._i18n('completenessGood', 'Good');
                    statusColor = '#22c55e';
                } else if (score >= 50) {
                    statusText = PolicyCenter._i18n('completenessFair', 'Fair');
                    statusColor = '#f59e0b';
                } else {
                    statusText = PolicyCenter._i18n('completenessInsufficient', 'Insufficient');
                    statusColor = '#ef4444';
                }
                statusEl.textContent = statusText;
                statusEl.style.color = statusColor;
                statusEl.style.fontWeight = '600';
                statusEl.style.fontSize = '0.8125rem';
            }
        },

        // ---- Save Confirmation ----

        confirmSave() {
            this.syncCardToData();
            const data = this.generatedPolicyData;
            if (!data) { showToast(PolicyCenter._i18n('aiNoData', 'No policy data. Please generate first.'), 'error'); return; }
            if (!(data.roleIds || []).length) { showToast(PolicyCenter._i18n('aiNeedRole', 'Please add at least one role.'), 'error'); return; }
            if (!(data.permissionIds || []).length) { showToast(PolicyCenter._i18n('aiNeedPerm', 'Please add at least one permission.'), 'error'); return; }

            const maps = this._cachedMaps || { roles: {}, permissions: {}, conditions: {} };
            const roleNames = (data.roleIds || []).map(id => maps.roles[id] || maps.roles[String(id)] || 'ID:' + id).join(', ');
            const permNames = (data.permissionIds || []).map(id => maps.permissions[id] || maps.permissions[String(id)] || 'ID:' + id).join(', ');

            document.getElementById('ai-confirm-summary').innerHTML =
                '<div class="ai-confirm-row"><div class="ai-confirm-label">' + PolicyCenter._i18n('confirmPolicyName', 'Policy Name') + '</div><div class="ai-confirm-value">' + this.escapeHtml(data.policyName) + '</div></div>' +
                '<div class="ai-confirm-row"><div class="ai-confirm-label">' + PolicyCenter._i18n('confirmEffect', 'Effect') + '</div><div class="ai-confirm-value">' + data.effect + '</div></div>' +
                '<div class="ai-confirm-row"><div class="ai-confirm-label">' + PolicyCenter._i18n('confirmRoles', 'Roles') + ' (' + (data.roleIds || []).length + ')</div><div class="ai-confirm-value">' + this.escapeHtml(roleNames) + '</div></div>' +
                '<div class="ai-confirm-row"><div class="ai-confirm-label">' + PolicyCenter._i18n('confirmPermissions', 'Permissions') + ' (' + (data.permissionIds || []).length + ')</div><div class="ai-confirm-value">' + this.escapeHtml(permNames) + '</div></div>';

            // Show warnings if any
            const warningEl = document.getElementById('ai-confirm-warnings');
            const conflictPanel = document.getElementById('ai-conflict-panel');
            if (!conflictPanel.classList.contains('hidden')) {
                warningEl.innerHTML = '<div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:0.5rem;padding:0.75rem;margin-top:0.75rem;"><strong style="color:#fbbf24;">Warning:</strong> <span style="color:#e2e8f0;">' + PolicyCenter._i18n('confirmConflictWarning', 'Conflicts/duplicates detected. Please review before saving.') + '</span></div>';
            } else {
                warningEl.innerHTML = '';
            }

            document.getElementById('ai-confirm-overlay').classList.remove('hidden');
        },

        async executeSave() {
            this.syncCardToData();
            var data = this.generatedPolicyData;
            var btn = document.querySelector('#ai-confirm-overlay .modern-btn-primary');
            if (btn) btn.disabled = true;

            try {
                var resp = await fetch('/admin/api/policies/build-from-business-rule', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken()
                    },
                    body: JSON.stringify(data)
                });
                if (!resp.ok) {
                    var error = await resp.json();
                    throw new Error(error.message || 'Save failed');
                }
                this.closeConfirmModal();
                showToast(PolicyCenter._i18n('aiSaveSuccess', 'Policy saved successfully.'), 'success');
                setTimeout(function() { window.location.href = '/admin/policy-center?tab=list'; }, 1500);
            } catch (e) {
                showToast(PolicyCenter._i18n('aiSaveError', 'Policy save failed: ') + e.message, 'error');
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

// Manual Target Entry module
PolicyCenter.ManualTarget = {
    _context: null,

    open: function() {
        var modal = document.getElementById('manualTargetModal');
        if (!modal) return;
        document.getElementById('mt-identifier').value = '';
        document.getElementById('mt-type').value = 'URL';
        document.getElementById('mt-http-method').value = 'ANY';
        document.getElementById('mt-order').value = '1';
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
        setTimeout(function() { document.getElementById('mt-identifier').focus(); }, 100);
    },

    close: function() {
        var modal = document.getElementById('manualTargetModal');
        if (!modal) return;
        modal.classList.add('hidden');
        modal.style.display = 'none';
    },

    submit: function() {
        var identifier = document.getElementById('mt-identifier').value.trim();
        var targetType = document.getElementById('mt-type').value;
        var httpMethod = document.getElementById('mt-http-method').value;
        var order = parseInt(document.getElementById('mt-order').value, 10);

        if (!identifier) {
            showToast(PolicyCenter._i18n('mtIdentifierRequired', 'Resource path is required.'), 'error');
            document.getElementById('mt-identifier').focus();
            return;
        }
        if (isNaN(order) || order < 1) {
            showToast(PolicyCenter._i18n('mtOrderInvalid', 'Order must be a positive integer (1 or higher).'), 'error');
            document.getElementById('mt-order').focus();
            return;
        }

        this._context = {
            sourceType: 'MANUAL',
            manualTargetType: targetType,
            manualTargetIdentifier: identifier,
            manualHttpMethod: httpMethod,
            manualTargetOrder: order
        };

        this.close();

        // Reuse existing switchToCreateTab flow
        PolicyCenter.switchToCreateTab({
            friendlyName: identifier,
            resourceType: targetType,
            resourceIdentifier: identifier,
            httpMethod: httpMethod,
            isManual: true
        }, 'quick');
    }
};

// Multi-Resource Selection module
PolicyCenter.MultiSelect = {
    selectedResources: new Map(),

    /** Initialize: sync checkboxes with in-memory state */
    init: function() {
        this._syncCheckboxes();
        this.updateBar();
    },

    /** Toggle a single resource checkbox */
    toggleResource: function(cbEl) {
        var tr = cbEl.closest('tr');
        var id = parseInt(tr.dataset.resId);
        if (isNaN(id)) return;
        if (cbEl.checked) {
            this.selectedResources.set(id, {
                id: id,
                resourceIdentifier: tr.dataset.resIdentifier || '',
                resourceType: tr.dataset.resType || '',
                httpMethod: tr.dataset.resHttp || 'ANY',
                status: tr.dataset.resStatus || '',
                friendlyName: tr.dataset.resFriendly || ''
            });
        } else {
            this.selectedResources.delete(id);
        }
        this.updateBar();
    },

    /** Toggle all checkboxes on current page */
    toggleAll: function(checked) {
        var self = this;
        document.querySelectorAll('.res-cb:not(:disabled)').forEach(function(cb) {
            cb.checked = checked;
            var tr = cb.closest('tr');
            var id = parseInt(tr.dataset.resId);
            if (isNaN(id)) return;
            if (checked) {
                self.selectedResources.set(id, {
                    id: id,
                    resourceIdentifier: tr.dataset.resIdentifier || '',
                    resourceType: tr.dataset.resType || '',
                    httpMethod: tr.dataset.resHttp || 'ANY',
                    status: tr.dataset.resStatus || '',
                    friendlyName: tr.dataset.resFriendly || ''
                });
            } else {
                self.selectedResources.delete(id);
            }
        });
        this.updateBar();
    },

    /** Update floating bar visibility, count, and individual button states */
    updateBar: function() {
        var bar = document.getElementById('res-floating-bar');
        var count = this.selectedResources.size;
        document.getElementById('res-bar-count').textContent = count;

        // Toggle individual "Create Permission & Policy" buttons
        var individualBtns = document.querySelectorAll('[onclick="PolicyCenter.defineAndSetupPolicy(this)"]');
        if (count >= 2) {
            // Disable individual buttons when multi-select active
            individualBtns.forEach(function(btn) {
                if (!btn.disabled) {
                    btn.dataset.wasEnabled = 'true';
                    btn.disabled = true;
                    btn.classList.add('opacity-30', 'cursor-not-allowed');
                }
            });
        } else {
            // Restore individual buttons
            individualBtns.forEach(function(btn) {
                if (btn.dataset.wasEnabled === 'true') {
                    btn.disabled = false;
                    btn.classList.remove('opacity-30', 'cursor-not-allowed');
                    delete btn.dataset.wasEnabled;
                }
            });
        }

        // Update floating bar info message
        var infoEl = document.getElementById('res-bar-info');
        if (infoEl) {
            var infoTpl = PolicyCenter._i18n('multiBatchInfo', count + ' resources selected - ' + count + ' policies will be created');
            infoEl.textContent = infoTpl.replace(/\{0}/g, count);
        }

        // Floating bar only visible when create tab is NOT active
        var createTab = document.getElementById('tab-create');
        var isCreateActive = createTab && createTab.classList.contains('active');

        if (count >= 2 && !isCreateActive) {
            bar.style.display = 'block';
            requestAnimationFrame(function() { bar.style.opacity = '1'; bar.style.transform = 'translate(-50%,-50%) scale(1)'; });
        } else {
            bar.style.opacity = '0';
            bar.style.transform = 'translate(-50%,-50%) scale(0.95)';
            setTimeout(function() { if (PolicyCenter.MultiSelect.selectedResources.size < 2 || isCreateActive) bar.style.display = 'none'; }, 300);
        }
        var selectAll = document.getElementById('res-select-all');
        if (selectAll) {
            var allCbs = document.querySelectorAll('.res-cb:not(:disabled)');
            var allChecked = allCbs.length > 0 && Array.from(allCbs).every(function(cb) { return cb.checked; });
            selectAll.checked = allChecked;
        }
    },

    /** Clear all selections */
    clearSelection: function() {
        this.selectedResources.clear();
        document.querySelectorAll('.res-cb').forEach(function(cb) { cb.checked = false; });
        var selectAll = document.getElementById('res-select-all');
        if (selectAll) selectAll.checked = false;
        this.updateBar();
    },

    /** Reset selected PERMISSION_CREATED resources to NEEDS_DEFINITION */
    resetPolicyStatus: async function() {
        // Collect checked checkboxes directly from DOM
        var ids = [];
        var hasOther = false;
        document.querySelectorAll('.res-cb:checked').forEach(function(cb) {
            var tr = cb.closest('tr');
            if (!tr) return;
            var id = parseInt(tr.dataset.resId);
            if (isNaN(id)) return;
            var status = tr.dataset.resStatus || '';
            if (status === 'PERMISSION_CREATED') {
                ids.push(id);
            } else {
                hasOther = true;
            }
        });
        if (ids.length === 0 && !hasOther) {
            showToast(PolicyCenter._i18n('resetSelectPolicyConnected', 'Please select resources with policy connected status.'), 'error');
            return;
        }
        if (hasOther) {
            showToast(PolicyCenter._i18n('resetOnlyPolicyConnected', 'Only resources with policy connected status can be reset. Please uncheck others.'), 'error');
            return;
        }
        try {
            var resp = await fetch('/admin/policy-center/api/reset-policy-status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': PolicyCenter.getCsrfToken() },
                body: JSON.stringify(ids)
            });
            var result = await resp.json();
            if (!resp.ok) throw new Error(result.message || 'Reset failed');

            ids.forEach(function(id) {
                var row = document.querySelector('tr[data-res-id="' + id + '"]');
                if (!row) return;

                // 1. Status badge -> NEEDS_DEFINITION
                var badge = row.querySelector('.status-badge');
                if (badge) {
                    badge.className = 'status-badge bg-red-500/20 text-red-400 border-red-500/30';
                    badge.innerHTML = '<i class="fas fa-exclamation-circle"></i> <span>' + PolicyCenter._i18n('statusUnset', 'Unset') + '</span>';
                }
                row.dataset.resStatus = 'NEEDS_DEFINITION';

                // 2. Enable "Create Permission & Policy" button
                var defineBtn = row.querySelector('[onclick="PolicyCenter.defineAndSetupPolicy(this)"]');
                if (defineBtn) {
                    defineBtn.disabled = false;
                    defineBtn.classList.remove('opacity-40', 'cursor-not-allowed');
                    defineBtn.closest('div').style.display = '';
                }

                // 3. Add "Exclude" button (NEEDS_DEFINITION has it, PERMISSION_CREATED doesn't)
                var actionDiv = row.querySelector('.space-y-2');
                if (actionDiv && !actionDiv.querySelector('[onclick*="excludeResource"]')) {
                    var excludeDiv = document.createElement('div');
                    excludeDiv.innerHTML = '<button type="button" class="action-badge-secondary w-full text-center" data-resource-id="' + id + '" onclick="PolicyCenter.excludeResource(this)"><i class="fas fa-ban"></i> <span>' + PolicyCenter._i18n('btnExclude', 'Exclude') + '</span></button>';
                    actionDiv.appendChild(excludeDiv);
                }

                // 4. Uncheck checkbox
                var cb = row.querySelector('.res-cb');
                if (cb) cb.checked = false;
            });

            this.selectedResources.clear();
            var selectAll = document.getElementById('res-select-all');
            if (selectAll) selectAll.checked = false;
            this.updateBar();
            showToast(ids.length + PolicyCenter._i18n('selectedSuffix', ' selected') + ' - ' + PolicyCenter._i18n('statusUnset', 'Reset'), 'success');
        } catch (e) {
            showToast(e.message, 'error');
        }
    },

    /** Open policy setup modal from floating bar */
    setupFromBar: function() {
        if (this.selectedResources.size === 0) return;
        // Hide floating bar immediately
        var bar = document.getElementById('res-floating-bar');
        if (bar) { bar.style.opacity = '0'; bar.style.display = 'none'; }

        var modal = document.getElementById('policySetupModal');
        var nameEl = document.getElementById('modal-permission-name');
        var countTpl = PolicyCenter._i18n('multiBatchInfo', '{0} resources selected');
        if (nameEl) nameEl.textContent = countTpl.replace(/\{0}/g, this.selectedResources.size);
        modal.dataset.multiMode = 'true';
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
    },

    /** Sync checkboxes on current page with in-memory Map state */
    _syncCheckboxes: function() {
        var self = this;
        document.querySelectorAll('.res-cb').forEach(function(cb) {
            var id = parseInt(cb.dataset.id);
            if (cb.disabled && self.selectedResources.has(id)) {
                self.selectedResources.delete(id);
                cb.checked = false;
            } else {
                cb.checked = self.selectedResources.has(id);
            }
        });
    }
};

PolicyCenter.escapeHtml = function(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
};

// ================================================================
// POLICY VALIDATION MODULE
// ================================================================

PolicyCenter.Validation = {

    checkHealth() {
        const btn = document.getElementById('policy-health-check-btn');
        if (btn) PolicyCenter.setLoading(btn, true);

        fetch('/admin/policy-center/api/validation-report', {
            headers: { [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken() }
        })
        .then(r => r.json())
        .then(report => {
            PolicyCenter.ConflictDetailModal._lastReport = report;
            this.renderHealthBanner(report);
            this.renderPolicyBadges(report);
            if (btn) PolicyCenter.setLoading(btn, false);
        })
        .catch(err => {
            console.error('Health check failed', err);
            if (btn) PolicyCenter.setLoading(btn, false);
        });
    },

    renderHealthBanner(report) {
        const banner = document.getElementById('policy-health-banner');
        if (!banner) return;
        banner.classList.remove('hidden');

        const icon = document.getElementById('health-status-icon');
        const text = document.getElementById('health-status-text');
        const conflictCount = document.getElementById('health-conflict-count');
        const duplicateCount = document.getElementById('health-duplicate-count');

        if (report.healthStatus === 'HEALTHY') {
            banner.style.borderColor = 'rgba(34,197,94,0.4)';
            icon.innerHTML = '<i class="fas fa-check-circle" style="color:#4ade80;font-size:1.2rem;"></i>';
            text.textContent = PolicyCenter._i18n('validationNoIssues', 'No conflicts or duplicates detected');
            text.style.color = '#4ade80';
        } else if (report.healthStatus === 'CRITICAL') {
            banner.style.borderColor = 'rgba(239,68,68,0.4)';
            icon.innerHTML = '<i class="fas fa-exclamation-triangle" style="color:#f87171;font-size:1.2rem;"></i>';
            text.textContent = PolicyCenter._i18n('validationCritical', 'CRITICAL');
            text.style.color = '#f87171';
        } else {
            banner.style.borderColor = 'rgba(251,191,36,0.4)';
            icon.innerHTML = '<i class="fas fa-exclamation-circle" style="color:#fbbf24;font-size:1.2rem;"></i>';
            text.textContent = PolicyCenter._i18n('validationWarning', 'WARNING');
            text.style.color = '#fbbf24';
        }

        conflictCount.innerHTML = '<i class="fas fa-bolt"></i> ' +
            PolicyCenter._i18n('validationConflict', 'Conflict') + ': ' + report.conflicts.length;
        duplicateCount.innerHTML = '<i class="fas fa-copy"></i> ' +
            PolicyCenter._i18n('validationDuplicate', 'Duplicate') + ': ' + report.duplicates.length;

        // Render conflict details
        const details = document.getElementById('health-details');
        if (report.conflicts.length > 0 || report.duplicates.length > 0) {
            details.classList.remove('hidden');
            let html = '';
            report.conflicts.forEach(c => {
                const severityColor = c.severity === 'CRITICAL' ? '#f87171' :
                    c.severity === 'HIGH' ? '#fb923c' :
                    c.severity === 'MEDIUM' ? '#fbbf24' : '#94a3b8';
                html += '<div class="flex items-center gap-2 py-1 text-xs" style="color:#cbd5e1;">' +
                    '<span class="status-badge" style="background:' + severityColor + '20;color:' + severityColor +
                    ';border-color:' + severityColor + '50;font-size:0.65rem;">' + c.severity + '</span>' +
                    '<span>' + PolicyCenter.escapeHtml(c.conflictDescription) + '</span>' +
                    '</div>';
            });
            report.duplicates.forEach(d => {
                html += '<div class="flex items-center gap-2 py-1 text-xs" style="color:#cbd5e1;">' +
                    '<span class="status-badge" style="background:rgba(168,85,247,0.2);color:#c084fc;border-color:rgba(168,85,247,0.3);font-size:0.65rem;">DUP</span>' +
                    '<span>' + PolicyCenter.escapeHtml(d.reason) + '</span>' +
                    '</div>';
            });
            details.innerHTML = html;
        } else {
            details.classList.add('hidden');
        }
    },

    renderPolicyBadges(report) {
        // Build conflict map: policyId -> list of conflicts
        const conflictMap = {};
        report.conflicts.forEach(c => {
            if (c.newPolicyId) {
                if (!conflictMap[c.newPolicyId]) conflictMap[c.newPolicyId] = [];
                conflictMap[c.newPolicyId].push(c);
            }
            if (c.existingPolicyId) {
                if (!conflictMap[c.existingPolicyId]) conflictMap[c.existingPolicyId] = [];
                conflictMap[c.existingPolicyId].push(c);
            }
        });

        // Build duplicate map
        const dupMap = {};
        report.duplicates.forEach(d => {
            d.policyIds.forEach(pid => {
                if (!dupMap[pid]) dupMap[pid] = [];
                dupMap[pid].push(d);
            });
        });

        // Update each policy row badge
        document.querySelectorAll('.policy-health-cell').forEach(cell => {
            const policyId = cell.id.replace('policy-health-', '');
            const conflicts = conflictMap[policyId] || [];
            const dups = dupMap[policyId] || [];

            let html = '';
            if (conflicts.length > 0) {
                const maxSeverity = this.maxSeverity(conflicts);
                const color = maxSeverity === 'CRITICAL' ? '#f87171' :
                    maxSeverity === 'HIGH' ? '#fb923c' : '#fbbf24';
                html += '<span class="status-badge conflict-badge" style="background:' + color + '20;color:' + color +
                    ';border-color:' + color + '50;font-size:0.65rem;cursor:pointer;" ' +
                    'title="' + conflicts.length + ' conflict(s)" data-policy-id="' + policyId + '">' +
                    '<i class="fas fa-bolt"></i> ' + conflicts.length + '</span> ';
            }
            if (dups.length > 0) {
                html += '<span class="status-badge" style="background:rgba(168,85,247,0.2);color:#c084fc;border-color:rgba(168,85,247,0.3);font-size:0.65rem;cursor:pointer;" ' +
                    'title="' + dups.length + ' duplicate(s)">' +
                    '<i class="fas fa-copy"></i> ' + dups.length + '</span>';
            }
            if (!html) {
                html = '<span class="text-xs" style="color:#4ade80;"><i class="fas fa-check"></i></span>';
            }
            cell.innerHTML = html;
        });

        // Bind click on conflict badges
        document.querySelectorAll('.conflict-badge').forEach(function(badge) {
            badge.addEventListener('click', function() {
                PolicyCenter.ConflictDetailModal.showForPolicy(this.dataset.policyId);
            });
        });
    },

    maxSeverity(conflicts) {
        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        for (const s of order) {
            if (conflicts.some(c => c.severity === s)) return s;
        }
        return 'LOW';
    },

    // Pre-creation validation for Quick mode
    async validateQuickPolicy(quickRequest) {
        try {
            const response = await fetch('/admin/policy-center/api/validate-quick', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken()
                },
                body: JSON.stringify(quickRequest)
            });
            return await response.json();
        } catch (err) {
            console.error('Quick validation failed', err);
            return { conflicts: [], duplicates: [], canCreate: true, blockedReason: null };
        }
    },

    // Impact analysis
    async analyzeImpact(policyDto) {
        try {
            const response = await fetch('/admin/policy-center/api/impact-analysis', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken()
                },
                body: JSON.stringify(policyDto)
            });
            return await response.json();
        } catch (err) {
            console.error('Impact analysis failed', err);
            return { affectedUserCount: 0, affectedUsers: [], affectedResources: [], accessChangeSummary: { gained: 0, lost: 0, changed: 0, unchanged: 0 } };
        }
    },

    // Policy simulation
    async simulate(candidatePolicy, testCases) {
        try {
            const response = await fetch('/admin/policy-center/api/simulate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken()
                },
                body: JSON.stringify({ candidatePolicy: candidatePolicy, testCases: testCases })
            });
            return await response.json();
        } catch (err) {
            console.error('Simulation failed', err);
            return { results: [], summary: { unchanged: 0, allowToDeny: 0, denyToAllow: 0, otherChanges: 0 } };
        }
    },

    // Policy matrix
    async getMatrix(resourceFilter, roleFilter) {
        try {
            const params = new URLSearchParams();
            if (resourceFilter) params.append('resourceFilter', resourceFilter);
            if (roleFilter) params.append('roleFilter', roleFilter);
            const response = await fetch('/admin/policy-center/api/matrix?' + params.toString(), {
                headers: { [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken() }
            });
            return await response.json();
        } catch (err) {
            console.error('Matrix load failed', err);
            return { resources: [], roles: [], cells: [], conflictCells: [] };
        }
    },

    // Pre-creation validation for Manual mode
    async validateBeforeCreate(policyDto) {
        try {
            const response = await fetch('/admin/policy-center/api/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken()
                },
                body: JSON.stringify(policyDto)
            });
            return await response.json();
        } catch (err) {
            console.error('Validation failed', err);
            return { conflicts: [], duplicates: [], canCreate: true, blockedReason: null };
        }
    }
};

// ================================================================
// TAB SWITCHING FOR CLIENT-SIDE TABS (Simulator, Matrix)
// ================================================================

PolicyCenter.switchTab = function(tabName) {
    // Hide ALL tabs (both server-side and client-side use active class)
    document.querySelectorAll('.pc-tab-content').forEach(function(c) {
        c.classList.remove('active');
        c.style.display = '';
    });
    document.querySelectorAll('.pc-tab-btn').forEach(function(b) {
        b.classList.remove('active');
    });

    var target = document.getElementById('tab-' + tabName);
    if (target) { target.classList.add('active'); }
    var btn = document.getElementById('tab-btn-' + tabName);
    if (btn) btn.classList.add('active');

    // Auto-load data on tab switch
    if (tabName === 'matrix') PolicyCenter.MatrixUI.load();

    // Refresh floating bar visibility based on current tab
    PolicyCenter.MultiSelect.updateBar();
};

// ================================================================
// SIMULATOR UI
// ================================================================

PolicyCenter.SimulatorUI = {
    _searchTimeout: null,
    _activeIndex: -1,

    _buildUserInput: function() {
        return '<div class="col-span-2" style="position:relative;">'
            + '<input type="text" class="modern-input sim-userSearch" placeholder="Search user..." '
            + 'oninput="if(typeof PolicyCenter!==\'undefined\')PolicyCenter.SimulatorUI.searchUser(this)" '
            + 'onkeydown="if(typeof PolicyCenter!==\'undefined\')PolicyCenter.SimulatorUI.handleKeydown(event,this)" '
            + 'autocomplete="off" />'
            + '<input type="hidden" class="sim-userId" />'
            + '<div class="sim-userDropdown hidden" style="position:absolute;top:100%;left:0;right:0;z-index:50;background:#1e293b;border:1px solid rgba(71,85,105,0.5);border-radius:0.5rem;max-height:12rem;overflow-y:auto;"></div>'
            + '</div>';
    },

    addTestCase: function() {
        var container = document.getElementById('sim-test-cases');
        container.insertAdjacentHTML('beforeend',
            '<div class="sim-case grid grid-cols-12 gap-3 mb-3 items-center">'
            + this._buildUserInput()
            + '<div class="col-span-2"><select class="modern-select sim-targetType" onchange="PolicyCenter.SimulatorUI.toggleTargetType(this)"><option value="URL">URL</option><option value="METHOD">METHOD</option></select></div>'
            + '<div class="col-span-4"><input type="text" class="modern-input sim-path" placeholder="/admin/dashboard" /></div>'
            + '<div class="col-span-3 sim-method-wrap"><select class="modern-select sim-method"><option value="GET">GET</option><option value="POST">POST</option><option value="PUT">PUT</option><option value="DELETE">DELETE</option></select></div>'
            + '<div class="col-span-1"><button type="button" onclick="this.closest(\'.sim-case\').remove()" class="remove-btn">&times;</button></div></div>');
    },

    toggleTargetType: function(selectEl) {
        var row = selectEl.closest('.sim-case');
        var methodWrap = row.querySelector('.sim-method-wrap');
        var pathInput = row.querySelector('.sim-path');
        if (selectEl.value === 'METHOD') {
            methodWrap.style.display = 'none';
            pathInput.placeholder = 'com.example.Service.method';
        } else {
            methodWrap.style.display = '';
            pathInput.placeholder = '/admin/dashboard';
        }
    },

    handleKeydown: function(event, input) {
        var dropdown = input.parentElement.querySelector('.sim-userDropdown');
        if (!dropdown || dropdown.classList.contains('hidden')) return;
        var items = dropdown.querySelectorAll('.sim-dropdown-item');
        if (!items.length) return;

        if (event.key === 'ArrowDown') {
            event.preventDefault();
            this._activeIndex = Math.min(this._activeIndex + 1, items.length - 1);
            this._highlightItem(items);
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            this._activeIndex = Math.max(this._activeIndex - 1, 0);
            this._highlightItem(items);
        } else if (event.key === 'Enter') {
            event.preventDefault();
            if (this._activeIndex >= 0 && this._activeIndex < items.length) {
                items[this._activeIndex].click();
            }
        } else if (event.key === 'Escape') {
            dropdown.classList.add('hidden');
            this._activeIndex = -1;
        }
    },

    _highlightItem: function(items) {
        items.forEach(function(el, i) {
            el.style.background = (i === PolicyCenter.SimulatorUI._activeIndex) ? 'rgba(99,102,241,0.3)' : 'transparent';
        });
        if (this._activeIndex >= 0 && items[this._activeIndex]) {
            items[this._activeIndex].scrollIntoView({ block: 'nearest' });
        }
    },

    searchUser: function(input) {
        var self = this;
        clearTimeout(this._searchTimeout);
        this._activeIndex = -1;
        var keyword = input.value.trim();
        var dropdown = input.closest('.sim-case') ? input.parentElement.querySelector('.sim-userDropdown') : null;
        if (!dropdown) return;
        if (keyword.length < 1) { dropdown.classList.add('hidden'); return; }

        this._searchTimeout = setTimeout(function() {
            fetch('/admin/access-center/api/users?keyword=' + encodeURIComponent(keyword) + '&size=10', {
                headers: { [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken() }
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var users = data.content || [];
                if (!users.length) { dropdown.innerHTML = '<div class="p-3 text-xs" style="color:#64748b;">' + PolicyCenter._i18n('simNoUsers', 'No users found') + '</div>'; dropdown.classList.remove('hidden'); return; }
                var html = '';
                users.forEach(function(u) {
                    html += '<div class="sim-dropdown-item p-2 cursor-pointer text-sm" style="color:#e2e8f0;" '
                        + 'onmouseover="this.style.background=\'rgba(99,102,241,0.2)\'" onmouseout="if(this!==document.querySelector(\'.sim-dropdown-item:nth-child(\'+(PolicyCenter.SimulatorUI._activeIndex+1)+\')\'))this.style.background=\'transparent\'" '
                        + 'onclick="PolicyCenter.SimulatorUI.selectUser(this,' + u.id + ',\'' + PolicyCenter.escapeHtml(u.username || u.name || String(u.id)) + '\')">'
                        + '<span class="font-mono text-xs" style="color:#94a3b8;">ID:' + u.id + '</span> '
                        + '<span>' + PolicyCenter.escapeHtml(u.username || u.name || '') + '</span></div>';
                });
                dropdown.innerHTML = html;
                dropdown.classList.remove('hidden');
            })
            .catch(function() { dropdown.classList.add('hidden'); });
        }, 300);
    },

    selectUser: function(el, userId, username) {
        var caseRow = el.closest('.sim-case') || el.closest('[class*="sim-case"]');
        if (!caseRow) { caseRow = el.parentElement.parentElement; }
        var searchInput = caseRow.querySelector('.sim-userSearch');
        var hiddenInput = caseRow.querySelector('.sim-userId');
        var dropdown = caseRow.querySelector('.sim-userDropdown');
        if (searchInput) searchInput.value = username + ' (ID:' + userId + ')';
        if (hiddenInput) hiddenInput.value = userId;
        if (dropdown) dropdown.classList.add('hidden');
        this._activeIndex = -1;
    },

    run: async function() {
        var cases = [];
        document.querySelectorAll('.sim-case').forEach(function(row) {
            var hiddenUserId = row.querySelector('.sim-userId');
            var userId = hiddenUserId ? hiddenUserId.value : null;
            var path = row.querySelector('.sim-path')?.value;
            var targetType = row.querySelector('.sim-targetType')?.value || 'URL';
            var method = row.querySelector('.sim-method')?.value;
            if (userId && path) cases.push({ userId: parseInt(userId), targetType: targetType, path: path, httpMethod: targetType === 'METHOD' ? null : (method || 'GET') });
        });
        var hasUnselectedUser = false;
        document.querySelectorAll('.sim-case').forEach(function(row) {
            var searchVal = row.querySelector('.sim-userSearch')?.value;
            var hiddenVal = row.querySelector('.sim-userId')?.value;
            if (searchVal && !hiddenVal) hasUnselectedUser = true;
        });
        if (hasUnselectedUser) { showToast(PolicyCenter._i18n('simSelectUser', 'Please select a user from the dropdown'), 'error'); return; }
        if (!cases.length) { showToast(PolicyCenter._i18n('simAddCase', 'Add at least one test case'), 'error'); return; }

        var btn = document.getElementById('sim-run-btn');
        PolicyCenter.setLoading(btn, true);

        var report = await PolicyCenter.Validation.simulate(null, cases);
        PolicyCenter.setLoading(btn, false);

        var resultsDiv = document.getElementById('sim-results');
        resultsDiv.classList.remove('hidden');

        // Summary cards - current policy evaluation mode (no candidate)
        var allowCount = 0, denyCount = 0, noneCount = 0;
        report.results.forEach(function(r) {
            var dec = r.currentResult.decision;
            if (dec === 'ALLOW') allowCount++;
            else if (dec === 'DENY') denyCount++;
            else noneCount++;
        });
        document.getElementById('sim-summary').innerHTML =
            '<div class="rounded-xl p-4 text-center" style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);"><div class="text-2xl font-bold" style="color:#4ade80;">' + allowCount + '</div><div class="text-xs mt-1" style="color:#64748b;">ALLOW</div></div>'
            + '<div class="rounded-xl p-4 text-center" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);"><div class="text-2xl font-bold" style="color:#f87171;">' + denyCount + '</div><div class="text-xs mt-1" style="color:#64748b;">DENY</div></div>'
            + '<div class="rounded-xl p-4 text-center" style="background:rgba(71,85,105,0.2);border:1px solid rgba(71,85,105,0.3);"><div class="text-2xl font-bold" style="color:#94a3b8;">' + noneCount + '</div><div class="text-xs mt-1" style="color:#64748b;">NONE</div></div>'
            + '<div class="rounded-xl p-4 text-center" style="background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.3);"><div class="text-2xl font-bold" style="color:#a78bfa;">' + report.results.length + '</div><div class="text-xs mt-1" style="color:#64748b;">Total</div></div>';

        // Results table
        var tbody = document.getElementById('sim-results-body');
        var html = '';
        report.results.forEach(function(r) {
            var dec = r.currentResult.decision;
            var bgStyle = dec === 'ALLOW' ? 'background:rgba(34,197,94,0.05);' :
                dec === 'DENY' ? 'background:rgba(239,68,68,0.05);' : '';
            var decColor = dec === 'ALLOW' ? '#4ade80' : dec === 'DENY' ? '#f87171' : '#94a3b8';
            var matchedPolicy = r.currentResult.matchedPolicyName || '-';
            var matchedExpr = r.currentResult.matchedExpression || '';
            html += '<tr style="border-color:rgba(71,85,105,0.3);' + bgStyle + '">'
                + '<td class="py-3 px-4" style="color:#e2e8f0;">' + PolicyCenter.escapeHtml(r.username || String(r.testCase.userId)) + '</td>'
                + '<td class="py-3 px-4 font-mono text-xs" style="color:#cbd5e1;">' + PolicyCenter.escapeHtml(r.testCase.path) + '</td>'
                + '<td class="py-3 px-4"><span class="status-badge ' + (r.testCase.httpMethod ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-purple-500/20 text-purple-400 border-purple-500/30') + ' text-xs">' + (r.testCase.httpMethod || 'METHOD') + '</span></td>'
                + '<td class="py-3 px-4"><span style="color:' + decColor + ';font-weight:600;">' + dec + '</span></td>'
                + '<td class="py-3 px-4 text-xs" style="color:#c4b5fd;">' + PolicyCenter.escapeHtml(matchedPolicy) + '</td>'
                + '<td class="py-3 px-4 font-mono text-xs" style="color:#94a3b8;max-width:300px;overflow:hidden;text-overflow:ellipsis;" title="' + PolicyCenter.escapeHtml(matchedExpr) + '">' + PolicyCenter.escapeHtml(matchedExpr || '-') + '</td>'
                + '</tr>';
        });
        tbody.innerHTML = html;
    }
};

// ================================================================
// MATRIX UI
// ================================================================

PolicyCenter.MatrixUI = {
    load: async function() {
        var resourceFilter = document.getElementById('matrix-resource-filter')?.value || '';
        var roleFilter = document.getElementById('matrix-role-filter')?.value || '';
        var container = document.getElementById('matrix-container');
        container.innerHTML = '<p class="text-sm p-6" style="color:#64748b;"><i class="fas fa-spinner fa-spin mr-1"></i> ' + PolicyCenter._i18n('loading', 'Loading...') + '</p>';

        var report = await PolicyCenter.Validation.getMatrix(resourceFilter, roleFilter);

        if (!report.resources.length || !report.roles.length) {
            container.innerHTML = '<p class="text-sm p-6" style="color:#64748b;">' + PolicyCenter._i18n('matrixNoData', 'No data matching the filter.') + '</p>';
            return;
        }

        // Build conflict map
        var conflictMap = {};
        report.conflictCells.forEach(function(c) { conflictMap[c.row + '_' + c.col] = c.severity; });

        var html = '<table class="min-w-full text-sm"><thead><tr>';
        html += '<th class="py-3 px-4 text-left text-white text-xs uppercase font-semibold" style="min-width:12rem;">Resource</th>';
        report.roles.forEach(function(role) {
            html += '<th class="py-3 px-3 text-center text-white text-xs uppercase font-semibold" style="min-width:6rem;">' + PolicyCenter.escapeHtml(role) + '</th>';
        });
        html += '</tr></thead><tbody>';

        report.resources.forEach(function(res, rowIdx) {
            if (!report.cells[rowIdx]) return;
            html += '<tr style="border-color:rgba(71,85,105,0.3);">';
            var isMethod = res.httpMethod === 'METHOD';
            var badgeClass = isMethod ? 'bg-purple-500/20 text-purple-400 border-purple-500/30' : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
            html += '<td class="py-3 px-4 font-mono text-xs" style="color:#cbd5e1;">'
                + '<span class="status-badge ' + badgeClass + ' text-xs mr-1">' + res.httpMethod + '</span>'
                + PolicyCenter.escapeHtml(res.identifier) + '</td>';

            report.cells[rowIdx].forEach(function(cell, colIdx) {
                var isConflict = conflictMap[rowIdx + '_' + colIdx];
                var borderStyle = isConflict ? 'border:2px solid #f87171;' : '';
                if (!cell) {
                    html += '<td class="py-3 px-3 text-center" style="' + borderStyle + '"><span class="text-xs" style="color:#334155;">-</span></td>';
                } else {
                    var bg = cell.access === 'ALLOW' ? (cell.inherited ? 'rgba(34,197,94,0.08)' : 'rgba(34,197,94,0.15)') : 'rgba(239,68,68,0.15)';
                    var color = cell.access === 'ALLOW' ? '#4ade80' : '#f87171';
                    var style = 'background:' + bg + ';color:' + color + ';' + borderStyle;
                    var label = cell.access + (cell.inherited ? ' *' : '');
                    var clickHandler = cell.policyId ? ' onclick="window.location.href=\'/admin/policies/' + cell.policyId + '\'"' : '';
                    html += '<td class="py-3 px-3 text-center cursor-pointer" style="' + style + '" title="' + PolicyCenter.escapeHtml(cell.policyName || '') + '"' + clickHandler + '>'
                        + '<span class="text-xs font-bold">' + label + '</span></td>';
                }
            });
            html += '</tr>';
        });

        html += '</tbody></table>';
        html += '<div class="mt-3 text-xs" style="color:#64748b;">'
            + report.resources.length + ' resources x ' + report.roles.length + ' roles'
            + (report.totalRoles > report.roles.length ? ' (total ' + report.totalRoles + ' roles)' : '')
            + '</div>';
        container.innerHTML = html;
    }
};

// ================================================================
// AI VALIDATION MODAL
// ================================================================

PolicyCenter.AIValidationModal = {
    currentPolicyId: null,

    open: async function(policyId) {
        this.currentPolicyId = policyId;
        var modal = document.getElementById('ai-validation-modal');
        modal.classList.remove('hidden');
        modal.style.display = 'flex';

        var itemsDiv = document.getElementById('ai-validation-items');
        itemsDiv.innerHTML = '<p class="text-sm" style="color:#64748b;"><i class="fas fa-spinner fa-spin mr-1"></i> ' + PolicyCenter._i18n('aiAnalyzing', 'Validating...') + '</p>';
        document.getElementById('ai-validation-blocked').classList.add('hidden');

        try {
            var response = await fetch('/admin/policy-center/api/' + policyId + '/ai-validation', {
                headers: { [PolicyCenter.getCsrfHeader()]: PolicyCenter.getCsrfToken() }
            });
            var report = await response.json();
            this.render(report, policyId);
        } catch (err) {
            itemsDiv.innerHTML = '<p class="text-sm" style="color:#f87171;">' + PolicyCenter._i18n('aiValidateError', 'Validation failed') + ': ' + PolicyCenter.escapeHtml(err.message) + '</p>';
        }
    },

    render: function(report, policyId) {
        var html = '';
        report.items.forEach(function(item) {
            var icon = item.result === 'PASS' ? '<i class="fas fa-check-circle" style="color:#4ade80;"></i>' :
                item.result === 'WARNING' ? '<i class="fas fa-exclamation-circle" style="color:#fbbf24;"></i>' :
                '<i class="fas fa-times-circle" style="color:#f87171;"></i>';
            var bgColor = item.result === 'PASS' ? 'rgba(34,197,94,0.1)' :
                item.result === 'WARNING' ? 'rgba(251,191,36,0.1)' : 'rgba(239,68,68,0.1)';
            html += '<div class="flex items-center gap-3 p-3 rounded-lg" style="background:' + bgColor + ';">'
                + icon + '<span class="text-sm font-semibold" style="color:#e2e8f0;">' + PolicyCenter.escapeHtml(item.checkName) + '</span>'
                + '<span class="text-xs ml-auto" style="color:#94a3b8;">' + PolicyCenter.escapeHtml(item.detail) + '</span></div>';
        });
        document.getElementById('ai-validation-items').innerHTML = html;

        var approveBtn = document.getElementById('ai-validation-approve-btn');
        var approveForm = document.getElementById('ai-validation-approve-form');
        var blockedDiv = document.getElementById('ai-validation-blocked');

        if (report.canApprove) {
            approveBtn.disabled = false;
            approveForm.action = '/admin/policies/' + policyId + '/approve';
            blockedDiv.classList.add('hidden');
        } else {
            approveBtn.disabled = true;
            blockedDiv.classList.remove('hidden');
            blockedDiv.innerHTML = '<i class="fas fa-ban mr-2"></i> ' + PolicyCenter.escapeHtml(report.blockedReason || 'Approval blocked');
        }
    },

    close: function() {
        var modal = document.getElementById('ai-validation-modal');
        modal.classList.add('hidden');
        modal.style.display = 'none';
    }
};

// ================================================================
// VALIDATION RESULT MODAL (#2 - 정책 생성 시 검증 결과 상세)
// ================================================================

PolicyCenter.ValidationModal = {
    _resolve: null,

    show: function(validation, allowProceed) {
        return new Promise(function(resolve) {
            PolicyCenter.ValidationModal._resolve = resolve;
            var modal = document.getElementById('validation-result-modal');
            modal.classList.remove('hidden');
            modal.style.display = 'flex';

            var content = document.getElementById('validation-result-content');
            var html = '';

            // Blocked reason
            if (!validation.canCreate && validation.blockedReason) {
                html += '<div class="p-4 rounded-xl" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#f87171;">'
                    + '<i class="fas fa-ban mr-2"></i><strong>' + PolicyCenter.escapeHtml(validation.blockedReason) + '</strong></div>';
            }

            // Conflicts
            if (validation.conflicts && validation.conflicts.length > 0) {
                html += '<h4 class="text-sm font-bold" style="color:#f87171;"><i class="fas fa-bolt mr-1"></i> '
                    + PolicyCenter._i18n('validationConflict', 'Conflict') + ' (' + validation.conflicts.length + ')</h4>';
                validation.conflicts.forEach(function(c) {
                    var severityColor = c.severity === 'CRITICAL' ? '#f87171' : c.severity === 'HIGH' ? '#fb923c' : '#fbbf24';
                    html += '<div class="flex items-start gap-3 p-3 rounded-lg" style="background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);">'
                        + '<span class="status-badge text-xs" style="background:' + severityColor + '20;color:' + severityColor + ';border-color:' + severityColor + '50;">' + c.severity + '</span>'
                        + '<div><div class="text-sm" style="color:#e2e8f0;">' + PolicyCenter.escapeHtml(c.conflictDescription) + '</div>'
                        + '<div class="text-xs mt-1" style="color:#94a3b8;">' + PolicyCenter.escapeHtml(c.existingPolicyName || '') + '</div></div></div>';
                });
            }

            // Duplicates
            if (validation.duplicates && validation.duplicates.length > 0) {
                html += '<h4 class="text-sm font-bold mt-3" style="color:#c084fc;"><i class="fas fa-copy mr-1"></i> '
                    + PolicyCenter._i18n('validationDuplicate', 'Duplicate') + ' (' + validation.duplicates.length + ')</h4>';
                validation.duplicates.forEach(function(d) {
                    html += '<div class="p-3 rounded-lg" style="background:rgba(30,41,59,0.6);border:1px solid rgba(168,85,247,0.3);">'
                        + '<span class="text-xs" style="color:#c084fc;">' + PolicyCenter.escapeHtml(d.type) + '</span> '
                        + '<span class="text-sm" style="color:#e2e8f0;">' + PolicyCenter.escapeHtml(d.reason) + '</span></div>';
                });
            }

            if (!html) {
                html = '<div class="p-4 rounded-xl" style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:#4ade80;">'
                    + '<i class="fas fa-check-circle mr-2"></i>' + PolicyCenter._i18n('validationNoIssues', 'No issues detected') + '</div>';
            }

            content.innerHTML = html;

            var proceedBtn = document.getElementById('validation-proceed-btn');
            if (allowProceed && validation.canCreate) {
                proceedBtn.classList.remove('hidden');
            } else {
                proceedBtn.classList.add('hidden');
            }
        });
    },

    proceed: function() {
        var modal = document.getElementById('validation-result-modal');
        modal.classList.add('hidden');
        modal.style.display = 'none';
        if (this._resolve) { var r = this._resolve; this._resolve = null; r(true); }
    },

    close: function() {
        var modal = document.getElementById('validation-result-modal');
        modal.classList.add('hidden');
        modal.style.display = 'none';
        if (this._resolve) { var r = this._resolve; this._resolve = null; r(false); }
    }
};

// ================================================================
// CONFLICT DETAIL MODAL (#3 - 배지 클릭 시 충돌 상세)
// ================================================================

PolicyCenter.ConflictDetailModal = {
    _lastReport: null,

    showForPolicy: function(policyId) {
        if (!this._lastReport) return;
        var conflicts = this._lastReport.conflicts.filter(function(c) {
            return c.newPolicyId == policyId || c.existingPolicyId == policyId;
        });
        var duplicates = this._lastReport.duplicates.filter(function(d) {
            return d.policyIds && d.policyIds.indexOf(parseInt(policyId)) >= 0;
        });
        this.render(conflicts, duplicates);
    },

    render: function(conflicts, duplicates) {
        var modal = document.getElementById('conflict-detail-modal');
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
        var content = document.getElementById('conflict-detail-content');
        var html = '';
        conflicts.forEach(function(c) {
            var severityColor = c.severity === 'CRITICAL' ? '#f87171' : c.severity === 'HIGH' ? '#fb923c' : '#fbbf24';
            html += '<div class="flex items-start gap-3 p-3 rounded-lg" style="background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);">'
                + '<span class="status-badge text-xs" style="background:' + severityColor + '20;color:' + severityColor + ';border-color:' + severityColor + '50;">' + c.severity + '</span>'
                + '<div><div class="text-sm" style="color:#e2e8f0;">' + PolicyCenter.escapeHtml(c.conflictDescription) + '</div>'
                + '<div class="text-xs mt-1" style="color:#94a3b8;">' + PolicyCenter.escapeHtml((c.newPolicyName || '') + ' vs ' + (c.existingPolicyName || '')) + '</div></div></div>';
        });
        duplicates.forEach(function(d) {
            html += '<div class="p-3 rounded-lg" style="background:rgba(30,41,59,0.6);border:1px solid rgba(168,85,247,0.3);">'
                + '<span class="status-badge text-xs" style="background:rgba(168,85,247,0.2);color:#c084fc;border-color:rgba(168,85,247,0.3);">' + (d.type || 'DUP') + '</span> '
                + '<span class="text-sm" style="color:#e2e8f0;">' + PolicyCenter.escapeHtml(d.reason) + '</span></div>';
        });
        if (!html) html = '<p class="text-sm" style="color:#64748b;">No details available.</p>';
        content.innerHTML = html;
    }
};

// ================================================================
// DELETE REASON MODAL (#5 - 삭제 시 변경 사유 입력)
// ================================================================

PolicyCenter.DeleteModal = {
    currentPolicyId: null,

    open: function(policyId) {
        this.currentPolicyId = policyId;
        document.getElementById('delete-reason-input').value = '';
        var modal = document.getElementById('delete-reason-modal');
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
    },

    close: function() {
        var modal = document.getElementById('delete-reason-modal');
        modal.classList.add('hidden');
        modal.style.display = 'none';
    },

    submit: function() {
        var reason = document.getElementById('delete-reason-input').value.trim();
        if (!reason) {
            showToast(PolicyCenter._i18n('deleteReasonRequired', 'Change reason is required'), 'error');
            return;
        }

        // Create a hidden form and submit
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = '/admin/policies/delete/' + this.currentPolicyId;

        var csrfMeta = document.querySelector('meta[name="_csrf"]');
        var csrfParamMeta = document.querySelector('meta[name="_csrf_parameter"]');
        if (csrfMeta && csrfParamMeta) {
            var csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = csrfParamMeta.content;
            csrfInput.value = csrfMeta.content;
            form.appendChild(csrfInput);
        }

        var reasonInput = document.createElement('input');
        reasonInput.type = 'hidden';
        reasonInput.name = 'changeReason';
        reasonInput.value = reason;
        form.appendChild(reasonInput);

        document.body.appendChild(form);
        PolicyCenter.MultiSelect.selectedResources.clear();
        form.submit();
    }
};

// ================================================================
// RESOURCE VIEW MODAL (multi-resource policy creation)
// ================================================================

PolicyCenter.ResourceViewModal = {
    open: function() {
        var ctxArr = PolicyCenter.CreateFlow.selectedResources;
        if (!ctxArr || ctxArr.length === 0) return;

        var modal = document.getElementById('resource-view-modal');
        document.getElementById('rv-count').textContent = '(' + ctxArr.length + ')';

        var methodColors = { GET: '#4ade80', POST: '#60a5fa', PUT: '#fbbf24', PATCH: '#fbbf24', DELETE: '#f87171', ANY: '#94a3b8' };
        var html = '<table style="width:100%;border-collapse:collapse;">';
        html += '<thead><tr style="border-bottom:1px solid rgba(71,85,105,0.4);">';
        html += '<th style="padding:0.5rem;text-align:left;color:#94a3b8;font-size:0.75rem;">' + PolicyCenter._i18n('rvType', 'Type') + '</th>';
        html += '<th style="padding:0.5rem;text-align:left;color:#94a3b8;font-size:0.75rem;">' + PolicyCenter._i18n('rvMethod', 'Method') + '</th>';
        html += '<th style="padding:0.5rem;text-align:left;color:#94a3b8;font-size:0.75rem;">' + PolicyCenter._i18n('rvResource', 'Resource') + '</th>';
        html += '</tr></thead><tbody>';

        ctxArr.forEach(function(ctx) {
            var method = (ctx.httpMethod || 'ANY').toUpperCase();
            var mColor = methodColors[method] || '#94a3b8';
            html += '<tr style="border-bottom:1px solid rgba(71,85,105,0.15);">';
            html += '<td style="padding:0.5rem;"><span style="font-size:0.7rem;padding:0.125rem 0.4rem;border-radius:0.25rem;background:rgba(99,102,241,0.15);color:#818cf8;">' + PolicyCenter.escapeHtml(ctx.resourceType || 'URL') + '</span></td>';
            html += '<td style="padding:0.5rem;"><span style="font-size:0.7rem;padding:0.125rem 0.4rem;border-radius:0.25rem;font-weight:700;background:' + mColor + '20;color:' + mColor + ';">' + method + '</span></td>';
            html += '<td style="padding:0.5rem;color:#e2e8f0;font-family:monospace;font-size:0.8125rem;">' + PolicyCenter.escapeHtml(ctx.resourceIdentifier || '') + '</td>';
            html += '</tr>';
        });
        html += '</tbody></table>';
        document.getElementById('rv-table-body').innerHTML = html;

        modal.style.display = 'flex';
    }
};

// ================================================================
// BATCH RESULT MODAL
// ================================================================

PolicyCenter.BatchResult = {
    show: function(results, created, total) {
        var modal = document.getElementById('batch-result-modal');
        document.getElementById('br-title').textContent = created + '/' + total + ' ' + PolicyCenter._i18n('policyCreated', 'policies created');

        var html = '';
        results.forEach(function(r) {
            var icon, color;
            if (r.status === 'CREATED') { icon = 'fa-check-circle'; color = '#4ade80'; }
            else if (r.status === 'SKIPPED') { icon = 'fa-exclamation-triangle'; color = '#fbbf24'; }
            else { icon = 'fa-times-circle'; color = '#f87171'; }

            html += '<div style="display:flex;align-items:center;gap:0.75rem;padding:0.625rem;border-radius:0.5rem;margin-bottom:0.375rem;' +
                'background:rgba(30,41,59,0.5);border:1px solid rgba(71,85,105,0.2);">' +
                '<i class="fas ' + icon + '" style="color:' + color + ';font-size:1rem;"></i>' +
                '<div style="flex:1;">' +
                '<div style="font-family:monospace;font-size:0.8125rem;color:#e2e8f0;">' + PolicyCenter.escapeHtml(r.resourceIdentifier || '') + '</div>' +
                (r.policyName ? '<div style="font-size:0.6875rem;color:#64748b;">' + PolicyCenter.escapeHtml(r.policyName) + '</div>' : '') +
                (r.reason ? '<div style="font-size:0.6875rem;color:' + color + ';">' + PolicyCenter.escapeHtml(r.reason) + '</div>' : '') +
                '</div>' +
                '<span style="font-size:0.6875rem;padding:0.125rem 0.5rem;border-radius:0.25rem;font-weight:600;' +
                'background:' + color + '20;color:' + color + ';">' +
                (r.status === 'CREATED' ? PolicyCenter._i18n('batchStatusCreated', 'Created')
                    : r.status === 'SKIPPED' ? PolicyCenter._i18n('batchStatusSkipped', 'Skipped')
                    : PolicyCenter._i18n('batchStatusError', 'Error')) + '</span></div>';
        });

        document.getElementById('br-body').innerHTML = html;
        PolicyCenter.MultiSelect.selectedResources.clear();
        modal.style.display = 'flex';
    },

    close: function() {
        var modal = document.getElementById('batch-result-modal');
        modal.style.display = 'none';
        window.location.href = '/admin/policy-center?tab=list';
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    PolicyCenter.Manual.initHttpMethodVisibility();
    PolicyCenter.MultiSelect.init();

    // Initialize Create tab - resource selection flow
    const createTab = document.getElementById('tab-create');
    if (createTab && createTab.classList.contains('active')) {
        PolicyCenter.CreateFlow.init();
    }
});
