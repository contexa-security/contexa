/**
 * Access Center - Unified access management client logic
 * Tabs: Users, Groups, Roles, Overview
 */
const AccessCenter = {

    activeTab: 'users',
    searchDebounceTimer: null,

    getCsrfToken() {
        return document.querySelector('meta[name="_csrf"]')?.content;
    },

    getCsrfHeader() {
        return document.querySelector('meta[name="_csrf_header"]')?.content || 'X-CSRF-TOKEN';
    },

    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    toggleClearBtn(input) {
        const clearBtn = input.parentElement.querySelector('.ac-search-clear');
        if (clearBtn) clearBtn.style.display = input.value.trim() ? 'block' : 'none';
    },

    clearSearch(clearBtn) {
        const input = clearBtn.parentElement.querySelector('.ac-search-input');
        if (input) {
            input.value = '';
            input.dispatchEvent(new Event('input'));
            clearBtn.style.display = 'none';
            input.focus();
        }
    },

    switchTab(tab) {
        this.activeTab = tab;

        document.querySelectorAll('.ac-tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.ac-tab-content').forEach(c => c.classList.remove('active'));

        const btns = document.querySelectorAll('.ac-tab-btn');
        const tabMap = { users: 0, groups: 1, roles: 2, overview: 3 };
        if (btns[tabMap[tab]]) btns[tabMap[tab]].classList.add('active');

        const content = document.getElementById('ac-tab-' + tab);
        if (content) content.classList.add('active');

        if (tab === 'users') this.Users.init();
        else if (tab === 'groups') this.Groups.init();
        else if (tab === 'roles') this.Roles.init();
    },

    async fetchJson(url, options) {
        try {
            const resp = await fetch(url, options);
            if (!resp.ok) {
                const text = await resp.text();
                throw new Error(text || ('HTTP ' + resp.status));
            }
            const contentType = resp.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                return await resp.json();
            }
            return null;
        } catch (e) {
            throw e;
        }
    },

    // ================================================================
    // TAB 1: USERS
    // ================================================================
    Users: {
        selectedUserId: null,
        activeSubTab: 'groups',
        userDetailCache: null,
        allGroupsCache: null,
        allRolesCache: null,

        init() {
            this.loadUsers('');
        },

        onSearch(keyword) {
            clearTimeout(AccessCenter.searchDebounceTimer);
            AccessCenter.searchDebounceTimer = setTimeout(() => {
                this.loadUsers(keyword.trim());
            }, 300);
        },

        async loadUsers(keyword) {
            const listEl = document.getElementById('ac-user-list');
            listEl.innerHTML =
                '<div class="ac-loading">' +
                '<i class="fas fa-spinner fa-spin"></i>' +
                '<p>검색 중...</p>' +
                '</div>';

            try {
                const data = await AccessCenter.fetchJson(
                    '/admin/access-center/api/users?keyword=' + encodeURIComponent(keyword) + '&size=20'
                );
                this.renderUserList(data.content || []);
            } catch (e) {
                listEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<p>사용자 목록을 불러올 수 없습니다.</p>' +
                    '</div>';
                showToast('사용자 검색 실패: ' + e.message, 'error');
            }
        },

        renderUserList(users) {
            const listEl = document.getElementById('ac-user-list');
            if (!users.length) {
                listEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-search"></i>' +
                    '<p>검색 결과가 없습니다.</p>' +
                    '</div>';
                return;
            }

            listEl.innerHTML = users.map(u =>
                '<div class="ac-list-item' + (String(this.selectedUserId) === String(u.id) ? ' selected' : '') + '" ' +
                'data-user-id="' + AccessCenter.escapeHtml(u.id) + '" ' +
                'onclick="AccessCenter.Users.selectUser(\'' + AccessCenter.escapeHtml(u.id) + '\')">' +
                '<div class="ac-list-item-icon user-icon"><i class="fas fa-user"></i></div>' +
                '<div class="ac-list-item-info">' +
                '<div class="ac-list-item-name">' + AccessCenter.escapeHtml(u.name || u.username) + '</div>' +
                '<div class="ac-list-item-sub">' + AccessCenter.escapeHtml(u.username) +
                (u.email ? ' / ' + AccessCenter.escapeHtml(u.email) : '') + '</div>' +
                '</div>' +
                '</div>'
            ).join('');
            console.log('[AccessCenter.Users.renderUserList] rendered count=', users.length,
                'selectedUserId=', this.selectedUserId,
                'ids=', users.map(u => u.id));
        },

        async selectUser(userId) {
            const targetId = String(userId);
            console.log('[AccessCenter.Users.selectUser] called userId=', userId,
                'previousSelected=', this.selectedUserId);
            this.selectedUserId = targetId;

            // Update selection using exact data-user-id match (substring matching on onclick caused multi-select bug)
            const allItems = document.querySelectorAll('#ac-user-list .ac-list-item');
            const matchedIds = [];
            allItems.forEach(el => {
                const itemId = el.getAttribute('data-user-id');
                const matched = itemId === targetId;
                el.classList.toggle('selected', matched);
                if (matched) matchedIds.push(itemId);
            });
            console.log('[AccessCenter.Users.selectUser] selection result totalItems=', allItems.length,
                'matchedCount=', matchedIds.length, 'matchedIds=', matchedIds);
            if (matchedIds.length > 1) {
                console.warn('[AccessCenter.Users.selectUser] multi-select detected for targetId=', targetId,
                    'matchedIds=', matchedIds);
            }

            const detailEl = document.getElementById('ac-user-detail');
            detailEl.innerHTML =
                '<div class="ac-loading">' +
                '<i class="fas fa-spinner fa-spin"></i>' +
                '<p>사용자 정보를 불러오는 중...</p>' +
                '</div>';
            detailEl.classList.add('active');

            try {
                const data = await AccessCenter.fetchJson(
                    '/admin/access-center/api/users/' + encodeURIComponent(userId) + '/detail'
                );
                this.userDetailCache = data;
                this.renderUserDetail(data);
            } catch (e) {
                detailEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<p>사용자 정보를 불러올 수 없습니다.</p>' +
                    '</div>';
                showToast('사용자 상세 조회 실패: ' + e.message, 'error');
            }
        },

        renderUserDetail(data) {
            const detailEl = document.getElementById('ac-user-detail');
            detailEl.classList.add('active');

            let html =
                '<div class="ac-detail-header">' +
                '<div class="ac-detail-avatar user-avatar"><i class="fas fa-user"></i></div>' +
                '<div class="ac-detail-title">' +
                '<div class="ac-detail-name">' + AccessCenter.escapeHtml(data.name || data.username) + '</div>' +
                '<div class="ac-detail-desc">' + AccessCenter.escapeHtml(data.username) +
                (data.email ? ' / ' + AccessCenter.escapeHtml(data.email) : '') + '</div>' +
                '</div>' +
                '</div>';

            html += '<div class="ac-detail-body">';

            // User meta info
            html +=
                '<div class="ac-user-meta">' +
                '<div class="ac-meta-item">' +
                '<span class="ac-meta-label">아이디</span>' +
                '<span class="ac-meta-value">' + AccessCenter.escapeHtml(data.username) + '</span>' +
                '</div>' +
                '<div class="ac-meta-item">' +
                '<span class="ac-meta-label">이름</span>' +
                '<span class="ac-meta-value">' + AccessCenter.escapeHtml(data.name || '-') + '</span>' +
                '</div>' +
                '<div class="ac-meta-item">' +
                '<span class="ac-meta-label">이메일</span>' +
                '<span class="ac-meta-value">' + AccessCenter.escapeHtml(data.email || '-') + '</span>' +
                '</div>' +
                '<div class="ac-meta-item">' +
                '<span class="ac-meta-label">상태</span>' +
                '<span class="ac-meta-value">' + AccessCenter.escapeHtml(data.enabled === false ? '비활성' : '활성') + '</span>' +
                '</div>' +
                '</div>';

            // Sub-tabs
            html +=
                '<nav class="ac-subtab-nav">' +
                '<button type="button" class="ac-subtab-btn' + (this.activeSubTab === 'groups' ? ' active' : '') + '" ' +
                'onclick="AccessCenter.Users.switchSubTab(\'groups\')"><i class="fas fa-layer-group"></i> 소속 그룹</button>' +
                '<button type="button" class="ac-subtab-btn' + (this.activeSubTab === 'roles' ? ' active' : '') + '" ' +
                'onclick="AccessCenter.Users.switchSubTab(\'roles\')"><i class="fas fa-user-shield"></i> 직접 역할</button>' +
                '<button type="button" class="ac-subtab-btn' + (this.activeSubTab === 'perms' ? ' active' : '') + '" ' +
                'onclick="AccessCenter.Users.switchSubTab(\'perms\')"><i class="fas fa-key"></i> 유효 권한</button>' +
                '</nav>';

            // Sub-tab: Groups
            html += '<div id="ac-user-subtab-groups" class="ac-subtab-content' + (this.activeSubTab === 'groups' ? ' active' : '') + '">';
            html +=
                '<div class="ac-section-header">' +
                '<h4>소속 그룹 관리</h4>' +
                '<button type="button" class="ac-btn-save" onclick="AccessCenter.Users.saveGroups()">' +
                '<i class="fas fa-save"></i> 저장</button>' +
                '</div>';
            html += '<div id="ac-user-groups-grid" class="ac-checkbox-grid">';
            html += '<div class="ac-spinner"><i class="fas fa-spinner fa-spin"></i> 그룹 목록을 불러오는 중...</div>';
            html += '</div>';
            html += '</div>';

            // Sub-tab: Roles
            html += '<div id="ac-user-subtab-roles" class="ac-subtab-content' + (this.activeSubTab === 'roles' ? ' active' : '') + '">';
            html +=
                '<div class="ac-section-header">' +
                '<h4>직접 역할 관리</h4>' +
                '<button type="button" class="ac-btn-save" onclick="AccessCenter.Users.saveRoles()">' +
                '<i class="fas fa-save"></i> 저장</button>' +
                '</div>';
            html += '<div id="ac-user-roles-grid" class="ac-checkbox-grid">';
            html += '<div class="ac-spinner"><i class="fas fa-spinner fa-spin"></i> 역할 목록을 불러오는 중...</div>';
            html += '</div>';
            html += '</div>';

            // Sub-tab: Effective Permissions
            html += '<div id="ac-user-subtab-perms" class="ac-subtab-content' + (this.activeSubTab === 'perms' ? ' active' : '') + '">';
            html +=
                '<div class="ac-section-header">' +
                '<h4>유효 권한 (읽기 전용)</h4>' +
                '</div>';
            html += '<div id="ac-user-perms-list">';
            this.renderPermissionsInline(data.permissions || []);
            html += '</div>';
            html += '</div>';

            html += '</div>'; // ac-detail-body
            detailEl.innerHTML = html;

            // Render permissions inline since we built the html as string
            const permsListEl = document.getElementById('ac-user-perms-list');
            if (permsListEl) {
                permsListEl.innerHTML = this.buildPermissionsHtml(data.permissions || []);
            }

            // Load checkboxes
            this.loadAllGroups();
            this.loadAllRoles();
        },

        buildPermissionsHtml(permissions) {
            if (!permissions.length) {
                return '<div class="ac-empty" style="min-height:120px;"><i class="fas fa-key"></i><p>유효 권한이 없습니다.</p></div>';
            }
            return permissions.map(p => {
                let sourceClass = 'direct';
                let sourceLabel = '직접';
                if (p.source === 'group') { sourceClass = 'group'; sourceLabel = '그룹'; }
                else if (p.source === 'hierarchy') { sourceClass = 'hierarchy'; sourceLabel = '계층'; }

                return '<div class="ac-perm-item">' +
                    '<div style="flex:1;min-width:0;">' +
                    '<div class="ac-perm-name" title="' + AccessCenter.escapeHtml(p.name || '') + '">' + AccessCenter.escapeHtml(p.friendlyName || p.name || p.permissionName) + '</div>' +
                    (p.description ? '<div class="ac-perm-desc">' + AccessCenter.escapeHtml(p.description) + '</div>' : '') +
                    '</div>' +
                    '<span class="ac-source-badge ' + sourceClass + '">' + sourceLabel +
                    (p.sourceName ? ' (' + AccessCenter.escapeHtml(p.sourceName) + ')' : '') + '</span>' +
                    '</div>';
            }).join('');
        },

        switchSubTab(tab) {
            this.activeSubTab = tab;
            document.querySelectorAll('.ac-subtab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.ac-subtab-content').forEach(c => c.classList.remove('active'));

            const btnIdx = { groups: 0, roles: 1, perms: 2 };
            const btns = document.querySelectorAll('#ac-user-detail .ac-subtab-btn');
            if (btns[btnIdx[tab]]) btns[btnIdx[tab]].classList.add('active');

            const contentEl = document.getElementById('ac-user-subtab-' + tab);
            if (contentEl) contentEl.classList.add('active');
        },

        async loadAllGroups() {
            const gridEl = document.getElementById('ac-user-groups-grid');
            if (!gridEl) return;

            try {
                if (!this.allGroupsCache) {
                    this.allGroupsCache = await AccessCenter.fetchJson('/admin/access-center/api/all-groups');
                }
                const userGroups = (this.userDetailCache?.groups || []).map(g => String(g.id));
                this.renderGroupCheckboxes(this.allGroupsCache || [], userGroups, gridEl);
            } catch (e) {
                gridEl.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-exclamation-triangle"></i><p>그룹 목록 로드 실패</p></div>';
            }
        },

        renderGroupCheckboxes(allGroups, userGroupIds, container) {
            if (!allGroups.length) {
                container.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-layer-group"></i><p>등록된 그룹이 없습니다.</p></div>';
                return;
            }
            container.innerHTML = allGroups.map(g => {
                const checked = userGroupIds.includes(String(g.id));
                return '<label class="ac-checkbox-item' + (checked ? ' checked' : '') + '">' +
                    '<input type="checkbox" name="userGroup" value="' + AccessCenter.escapeHtml(g.id) + '"' +
                    (checked ? ' checked' : '') +
                    ' onchange="this.parentElement.classList.toggle(\'checked\', this.checked)">' +
                    '<div><div>' + AccessCenter.escapeHtml(g.name) + '</div>' +
                    (g.description ? '<div class="ac-checkbox-desc">' + AccessCenter.escapeHtml(g.description) + '</div>' : '') +
                    '</div></label>';
            }).join('');
        },

        async loadAllRoles() {
            const gridEl = document.getElementById('ac-user-roles-grid');
            if (!gridEl) return;

            try {
                const [roles, allPerms] = await Promise.all([
                    AccessCenter.fetchJson('/admin/access-center/api/all-roles'),
                    AccessCenter.fetchJson('/admin/access-center/api/all-permissions')
                ]);
                this.allRolesCache = roles || [];
                // Filter out CRUD permissions (READ/WRITE/UPDATE/DELETE) — only non-CRUD remain
                const crudNames = new Set(['READ', 'WRITE', 'UPDATE', 'DELETE']);
                this.allExtraPermsCache = (allPerms || []).filter(p => !crudNames.has(p.name));
                const directRoles = (this.userDetailCache?.directRoles || []).map(r => String(r.id));
                this.renderRoleCheckboxes(this.allRolesCache, directRoles, gridEl);
            } catch (e) {
                gridEl.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-exclamation-triangle"></i><p>역할 목록 로드 실패</p></div>';
            }
        },

        renderRoleCheckboxes(allRoles, directRoleIds, container) {
            if (!allRoles.length) {
                container.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-user-shield"></i><p>등록된 역할이 없습니다.</p></div>';
                return;
            }
            var self = this;
            // CRUD is always shown in full so administrators can grant any verb to any user
            const allCruds = ['READ', 'WRITE', 'UPDATE', 'DELETE'];
            const crudLabels = { READ: 'Read', WRITE: 'Write', UPDATE: 'Update', DELETE: 'Delete' };
            const crudIcons = { READ: 'fa-eye', WRITE: 'fa-plus', UPDATE: 'fa-pen', DELETE: 'fa-trash' };
            const crudColors = { READ: '#4ade80', WRITE: '#60a5fa', UPDATE: '#fbbf24', DELETE: '#f87171' };

            // All non-CRUD permissions in the system (always shown, regardless of role mapping)
            const allExtras = self.allExtraPermsCache || [];

            container.innerHTML = allRoles.map(r => {
                const checked = directRoleIds.includes(String(r.id));
                // Mapping sets — these are auto-checked by default; non-mapped are unchecked but still shown
                const mappedCruds = new Set(r.crudPermissions || []);
                const mappedExtraIds = new Set((r.extraPermissions || []).map(p => String(p.id)));

                const crudHtml = allCruds.map(c => {
                    const isRead = c === 'READ';
                    const color = crudColors[c];
                    const isMapped = mappedCruds.has(c);
                    // READ always required (disabled+checked). Mapped CRUDs auto-checked. Non-mapped shown but unchecked.
                    return '<label class="ac-crud-chip' + (isMapped && !isRead ? ' mapped' : '') + '" data-crud="' + c + '" title="' + c + (isMapped && !isRead ? ' — 역할에 매핑됨' : '') + '">' +
                        '<input type="checkbox" class="ac-crud-cb" data-role-id="' + r.id + '" data-crud="' + c + '"' +
                        (isRead ? ' checked disabled' : (isMapped ? ' checked' : '')) +
                        '>' +
                        '<span class="ac-crud-chip-body" style="--crud-color:' + color + ';">' +
                        '<i class="fas ' + crudIcons[c] + '"></i>' +
                        '<span>' + crudLabels[c] + '</span>' +
                        (isMapped && !isRead ? '<i class="fas fa-link ac-mapped-mark" title="역할에 매핑된 권한"></i>' : '') +
                        '</span>' +
                        '</label>';
                }).join('');

                // Non-CRUD permissions section — show ALL non-CRUD permissions, mapped ones auto-checked
                const extrasHtml = allExtras.length
                    ? '<div class="ac-role-card-divider"></div>' +
                      '<div class="ac-role-card-section ac-extra-section" data-expanded="false">' +
                      '<button type="button" class="ac-extra-toggle" onclick="AccessCenter.Users.toggleExtraSection(this)">' +
                      '<span class="ac-extra-toggle-label">' +
                      '<i class="fas fa-puzzle-piece"></i> 권한 더보기 (' + allExtras.length + ')' +
                      '</span>' +
                      '<i class="fas fa-chevron-down ac-extra-toggle-arrow"></i>' +
                      '</button>' +
                      '<div class="ac-extra-group">' +
                      allExtras.map(p => {
                          const display = AccessCenter.escapeHtml(p.friendlyName || p.name);
                          const isMapped = mappedExtraIds.has(String(p.id));
                          const tooltip = AccessCenter.escapeHtml((p.name || '') + (p.description ? ' — ' + p.description : '') + (isMapped ? ' — 역할에 매핑됨' : ''));
                          return '<label class="ac-extra-chip' + (isMapped ? ' mapped' : '') + '" title="' + tooltip + '">' +
                              '<input type="checkbox" class="ac-extra-cb" data-role-id="' + r.id + '" data-perm-id="' + p.id + '"' + (isMapped ? ' checked' : '') + '>' +
                              '<span class="ac-extra-chip-body"><i class="fas fa-key"></i>' + display +
                              (isMapped ? '<i class="fas fa-link ac-mapped-mark" title="역할에 매핑된 권한"></i>' : '') +
                              '</span></label>';
                      }).join('') +
                      '</div></div>'
                    : '';

                return '<div class="ac-role-card" data-role-id="' + r.id +
                    '" data-mapped-cruds="' + AccessCenter.escapeHtml(Array.from(mappedCruds).join(',')) + '"' +
                    ' data-mapped-extra-ids="' + AccessCenter.escapeHtml(Array.from(mappedExtraIds).join(',')) + '"' +
                    (checked ? ' data-active="true"' : '') + '>' +
                    // Header: role name + master toggle
                    '<label class="ac-role-card-head">' +
                    '<input type="checkbox" name="userRole" value="' + r.id + '"' + (checked ? ' checked' : '') +
                    ' onchange="AccessCenter.Users.toggleRoleCrud(this)">' +
                    '<span class="ac-role-card-icon"><i class="fas fa-user-shield"></i></span>' +
                    '<span class="ac-role-card-meta">' +
                    '<span class="ac-role-card-name">' + AccessCenter.escapeHtml(r.name) + '</span>' +
                    (r.desc ? '<span class="ac-role-card-desc">' + AccessCenter.escapeHtml(r.desc) + '</span>' : '') +
                    '</span>' +
                    '</label>' +
                    // Divider
                    '<div class="ac-role-card-divider"></div>' +
                    // CRUD section: label + chip group (separately positioned below the role name)
                    '<div class="ac-role-card-section">' +
                    '<span class="ac-role-card-section-label"><i class="fas fa-key"></i> CRUD 권한</span>' +
                    '<div class="ac-crud-group">' + crudHtml + '</div>' +
                    '</div>' +
                    extrasHtml +
                    '</div>';
            }).join('');

            // Load existing CRUD + extra permission selections for checked roles
            if (self.selectedUserId) {
                directRoleIds.forEach(rid => {
                    AccessCenter.fetchJson('/admin/access-center/api/users/' + self.selectedUserId + '/roles/' + rid + '/cruds')
                        .then(cruds => {
                            if (!cruds) return;
                            // CRUD names go to ac-crud-cb (READ stays disabled+checked)
                            container.querySelectorAll('.ac-crud-cb[data-role-id="' + rid + '"]').forEach(cb => {
                                if (cb.dataset.crud !== 'READ') {
                                    cb.checked = cruds.includes(cb.dataset.crud);
                                }
                            });
                            // Look up the permission name from ALL non-CRUD permissions (not just role-mapped),
                            // because the user may have activated a non-mapped permission too
                            const extrasIndex = new Map();
                            (self.allExtraPermsCache || []).forEach(pp => extrasIndex.set(String(pp.id), pp));
                            container.querySelectorAll('.ac-extra-cb[data-role-id="' + rid + '"]').forEach(cb => {
                                const perm = extrasIndex.get(String(cb.dataset.permId));
                                if (perm) {
                                    cb.checked = cruds.includes(perm.name);
                                }
                            });
                        }).catch(() => {});
                });
            }
        },

        toggleRoleCrud(roleCheckbox) {
            const item = roleCheckbox.closest('.ac-role-card');
            if (!item) return;
            if (roleCheckbox.checked) {
                item.setAttribute('data-active', 'true');
                // Restore mapped-only checked state — non-mapped permissions remain unchecked (admin clicks to add)
                const mappedCruds = (item.dataset.mappedCruds || '').split(',').filter(Boolean);
                const mappedExtraIds = (item.dataset.mappedExtraIds || '').split(',').filter(Boolean);
                item.querySelectorAll('.ac-crud-cb').forEach(cb => {
                    if (cb.dataset.crud === 'READ') return; // READ always required
                    cb.checked = mappedCruds.includes(cb.dataset.crud);
                });
                item.querySelectorAll('.ac-extra-cb').forEach(cb => {
                    cb.checked = mappedExtraIds.includes(cb.dataset.permId);
                });
            } else {
                item.removeAttribute('data-active');
                item.querySelectorAll('.ac-crud-cb').forEach(cb => {
                    if (cb.dataset.crud !== 'READ') cb.checked = false;
                });
                item.querySelectorAll('.ac-extra-cb').forEach(cb => { cb.checked = false; });
            }
        },

        toggleExtraSection(btn) {
            const section = btn.closest('.ac-extra-section');
            if (!section) return;
            const expanded = section.getAttribute('data-expanded') === 'true';
            section.setAttribute('data-expanded', expanded ? 'false' : 'true');
        },

        async saveGroups() {
            if (!this.selectedUserId) return;
            const checkboxes = document.querySelectorAll('#ac-user-groups-grid input[name="userGroup"]:checked');
            const groupIds = Array.from(checkboxes).map(cb => cb.value);

            try {
                await AccessCenter.fetchJson('/admin/access-center/api/users/' + encodeURIComponent(this.selectedUserId) + '/groups', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [AccessCenter.getCsrfHeader()]: AccessCenter.getCsrfToken()
                    },
                    body: JSON.stringify({ groupIds: groupIds })
                });
                showToast('그룹 할당이 저장되었습니다.', 'success');
                this.selectUser(this.selectedUserId);
            } catch (e) {
                showToast('그룹 할당 저장 실패: ' + e.message, 'error');
            }
        },

        async saveRoles() {
            if (!this.selectedUserId) return;
            const roleAssignments = [];
            document.querySelectorAll('#ac-user-roles-grid input[name="userRole"]:checked').forEach(cb => {
                const roleId = cb.value;
                const item = cb.closest('.ac-role-card');
                const cruds = [];
                const extraIds = [];
                if (item) {
                    item.querySelectorAll('.ac-crud-cb:checked').forEach(crudCb => {
                        cruds.push(crudCb.dataset.crud);
                    });
                    item.querySelectorAll('.ac-extra-cb:checked').forEach(extraCb => {
                        extraIds.push(Number(extraCb.dataset.permId));
                    });
                }
                if (!cruds.includes('READ')) cruds.push('READ');
                roleAssignments.push({ roleId: Number(roleId), crudPermissions: cruds, extraPermissionIds: extraIds });
            });

            try {
                await AccessCenter.fetchJson('/admin/access-center/api/users/' + encodeURIComponent(this.selectedUserId) + '/roles', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [AccessCenter.getCsrfHeader()]: AccessCenter.getCsrfToken()
                    },
                    body: JSON.stringify({ roleAssignments: roleAssignments })
                });
                showToast('역할 할당이 저장되었습니다.', 'success');
                this.selectUser(this.selectedUserId);
            } catch (e) {
                showToast('역할 할당 저장 실패: ' + e.message, 'error');
            }
        },

        renderPermissionsInline(permissions) {
            // no-op: handled by buildPermissionsHtml
        }
    },

    // ================================================================
    // TAB 2: GROUPS
    // ================================================================
    Groups: {
        selectedGroupId: null,
        allGroups: null,
        allRolesCache: null,
        searchKeyword: '',

        init() {
            this.loadGroups();
        },

        onSearch(keyword) {
            this.searchKeyword = keyword.trim().toLowerCase();
            this.filterAndRender();
        },

        async loadGroups() {
            const listEl = document.getElementById('ac-group-list');
            listEl.innerHTML =
                '<div class="ac-loading">' +
                '<i class="fas fa-spinner fa-spin"></i>' +
                '<p>그룹 목록을 불러오는 중...</p>' +
                '</div>';

            try {
                this.allGroups = await AccessCenter.fetchJson('/admin/access-center/api/groups');
                this.filterAndRender();
            } catch (e) {
                listEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<p>그룹 목록을 불러올 수 없습니다.</p>' +
                    '</div>';
                showToast('그룹 목록 조회 실패: ' + e.message, 'error');
            }
        },

        filterAndRender() {
            const listEl = document.getElementById('ac-group-list');
            let groups = this.allGroups || [];
            if (this.searchKeyword) {
                groups = groups.filter(g =>
                    (g.name || '').toLowerCase().includes(this.searchKeyword) ||
                    (g.description || '').toLowerCase().includes(this.searchKeyword)
                );
            }

            if (!groups.length) {
                listEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-layer-group"></i>' +
                    '<p>' + (this.searchKeyword ? '검색 결과가 없습니다.' : '등록된 그룹이 없습니다.') + '</p>' +
                    '</div>';
                return;
            }

            const selectedKey = this.selectedGroupId != null ? String(this.selectedGroupId) : null;
            listEl.innerHTML = groups.map(g =>
                '<div class="ac-list-item' + (selectedKey !== null && selectedKey === String(g.id) ? ' selected' : '') + '" ' +
                'data-group-id="' + AccessCenter.escapeHtml(g.id) + '" ' +
                'onclick="AccessCenter.Groups.selectGroup(\'' + AccessCenter.escapeHtml(g.id) + '\')">' +
                '<div class="ac-list-item-icon group-icon"><i class="fas fa-layer-group"></i></div>' +
                '<div class="ac-list-item-info">' +
                '<div class="ac-list-item-name">' + AccessCenter.escapeHtml(g.name) + '</div>' +
                '<div class="ac-list-item-sub">' + AccessCenter.escapeHtml(g.description || '-') + '</div>' +
                '</div>' +
                (g.memberCount != null ? '<span class="ac-list-item-badge">' + g.memberCount + '명</span>' : '') +
                '</div>'
            ).join('');
            console.log('[AccessCenter.Groups.filterAndRender] rendered count=', groups.length,
                'selectedGroupId=', this.selectedGroupId,
                'ids=', groups.map(g => g.id));
        },

        async selectGroup(groupId) {
            const targetId = String(groupId);
            console.log('[AccessCenter.Groups.selectGroup] called groupId=', groupId,
                'previousSelected=', this.selectedGroupId);
            this.selectedGroupId = targetId;
            this.filterAndRender();
            const matchedCount = document.querySelectorAll('#ac-group-list .ac-list-item.selected').length;
            console.log('[AccessCenter.Groups.selectGroup] selection result matchedCount=', matchedCount);
            if (matchedCount > 1) {
                console.warn('[AccessCenter.Groups.selectGroup] multi-select detected for targetId=', targetId);
            }

            const detailEl = document.getElementById('ac-group-detail');
            detailEl.innerHTML =
                '<div class="ac-loading">' +
                '<i class="fas fa-spinner fa-spin"></i>' +
                '<p>그룹 정보를 불러오는 중...</p>' +
                '</div>';
            detailEl.classList.add('active');

            try {
                const data = await AccessCenter.fetchJson(
                    '/admin/access-center/api/groups/' + encodeURIComponent(groupId) + '/detail'
                );
                this.renderGroupDetail(data);
            } catch (e) {
                detailEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<p>그룹 정보를 불러올 수 없습니다.</p>' +
                    '</div>';
                showToast('그룹 상세 조회 실패: ' + e.message, 'error');
            }
        },

        async renderGroupDetail(data) {
            const detailEl = document.getElementById('ac-group-detail');

            let html =
                '<div class="ac-detail-header">' +
                '<div class="ac-detail-avatar group-avatar"><i class="fas fa-layer-group"></i></div>' +
                '<div class="ac-detail-title">' +
                '<div class="ac-detail-name">' + AccessCenter.escapeHtml(data.name) + '</div>' +
                '<div class="ac-detail-desc">' + AccessCenter.escapeHtml(data.description || '-') + '</div>' +
                '</div>' +
                '</div>';

            html += '<div class="ac-detail-body">';

            // Roles assignment
            html +=
                '<div class="ac-section-header">' +
                '<h4>역할 할당</h4>' +
                '<button type="button" class="ac-btn-save" onclick="AccessCenter.Groups.saveGroupRoles()">' +
                '<i class="fas fa-save"></i> 저장</button>' +
                '</div>';
            html += '<div id="ac-group-roles-grid" class="ac-checkbox-grid">';
            html += '<div class="ac-spinner"><i class="fas fa-spinner fa-spin"></i> 역할 목록을 불러오는 중...</div>';
            html += '</div>';

            // Members section
            if (data.members && data.members.length) {
                html += '<div style="margin-top:1.5rem;">';
                html += '<div class="ac-section-header"><h4>소속 사용자 (' + data.members.length + '명)</h4></div>';
                html += '<div class="ac-assigned-users">';
                html += data.members.map(m =>
                    '<div class="ac-assigned-user">' +
                    '<div class="ac-assigned-user-icon"><i class="fas fa-user"></i></div>' +
                    '<div>' +
                    '<div class="ac-assigned-user-name">' + AccessCenter.escapeHtml(m.name || m.username) + '</div>' +
                    '<div class="ac-assigned-user-sub">' + AccessCenter.escapeHtml(m.username) + '</div>' +
                    '</div>' +
                    '</div>'
                ).join('');
                html += '</div></div>';
            }

            html += '</div>';
            detailEl.innerHTML = html;

            // Load role checkboxes
            try {
                // Always re-fetch + load all non-CRUD permissions (regardless of role mapping)
                const [roles, allPerms] = await Promise.all([
                    AccessCenter.fetchJson('/admin/access-center/api/all-roles'),
                    AccessCenter.fetchJson('/admin/access-center/api/all-permissions')
                ]);
                this.allRolesCache = roles || [];
                const crudNames = new Set(['READ', 'WRITE', 'UPDATE', 'DELETE']);
                this.allExtraPermsCache = (allPerms || []).filter(p => !crudNames.has(p.name));

                const groupRoleIds = (data.roles || []).map(r => String(r.id));
                const gridEl = document.getElementById('ac-group-roles-grid');
                const allRoles = this.allRolesCache;
                const allExtras = this.allExtraPermsCache;

                if (!allRoles.length) {
                    gridEl.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-user-shield"></i><p>등록된 역할이 없습니다.</p></div>';
                } else {
                    var self = this;
                    const allCruds = ['READ', 'WRITE', 'UPDATE', 'DELETE'];
                    const crudLabels = { READ: 'Read', WRITE: 'Write', UPDATE: 'Update', DELETE: 'Delete' };
                    const crudIcons = { READ: 'fa-eye', WRITE: 'fa-plus', UPDATE: 'fa-pen', DELETE: 'fa-trash' };
                    const crudColors = { READ: '#4ade80', WRITE: '#60a5fa', UPDATE: '#fbbf24', DELETE: '#f87171' };

                    gridEl.innerHTML = allRoles.map(r => {
                        const checked = groupRoleIds.includes(String(r.id));
                        const mappedCruds = new Set(r.crudPermissions || []);
                        const mappedExtraIds = new Set((r.extraPermissions || []).map(p => String(p.id)));

                        const crudHtml = allCruds.map(c => {
                            const isRead = c === 'READ';
                            const color = crudColors[c];
                            const isMapped = mappedCruds.has(c);
                            return '<label class="ac-crud-chip' + (isMapped && !isRead ? ' mapped' : '') + '" data-crud="' + c + '" title="' + c + (isMapped && !isRead ? ' — 역할에 매핑됨' : '') + '">' +
                                '<input type="checkbox" class="ac-grp-crud-cb" data-role-id="' + r.id + '" data-crud="' + c + '"' +
                                (isRead ? ' checked disabled' : (isMapped ? ' checked' : '')) +
                                '>' +
                                '<span class="ac-crud-chip-body" style="--crud-color:' + color + ';">' +
                                '<i class="fas ' + crudIcons[c] + '"></i>' +
                                '<span>' + crudLabels[c] + '</span>' +
                                (isMapped && !isRead ? '<i class="fas fa-link ac-mapped-mark" title="역할에 매핑된 권한"></i>' : '') +
                                '</span>' +
                                '</label>';
                        }).join('');

                        const extrasHtml = allExtras.length
                            ? '<div class="ac-role-card-divider"></div>' +
                              '<div class="ac-role-card-section ac-extra-section" data-expanded="false">' +
                              '<button type="button" class="ac-extra-toggle" onclick="AccessCenter.Groups.toggleExtraSection(this)">' +
                              '<span class="ac-extra-toggle-label">' +
                              '<i class="fas fa-puzzle-piece"></i> 권한 더보기 (' + allExtras.length + ')' +
                              '</span>' +
                              '<i class="fas fa-chevron-down ac-extra-toggle-arrow"></i>' +
                              '</button>' +
                              '<div class="ac-extra-group">' +
                              allExtras.map(p => {
                                  const display = AccessCenter.escapeHtml(p.friendlyName || p.name);
                                  const isMapped = mappedExtraIds.has(String(p.id));
                                  const tooltip = AccessCenter.escapeHtml((p.name || '') + (p.description ? ' — ' + p.description : '') + (isMapped ? ' — 역할에 매핑됨' : ''));
                                  return '<label class="ac-extra-chip' + (isMapped ? ' mapped' : '') + '" title="' + tooltip + '">' +
                                      '<input type="checkbox" class="ac-grp-extra-cb" data-role-id="' + r.id + '" data-perm-id="' + p.id + '"' + (isMapped ? ' checked' : '') + '>' +
                                      '<span class="ac-extra-chip-body"><i class="fas fa-key"></i>' + display +
                                      (isMapped ? '<i class="fas fa-link ac-mapped-mark" title="역할에 매핑된 권한"></i>' : '') +
                                      '</span></label>';
                              }).join('') +
                              '</div></div>'
                            : '';

                        return '<div class="ac-role-card" data-role-id="' + r.id +
                            '" data-mapped-cruds="' + AccessCenter.escapeHtml(Array.from(mappedCruds).join(',')) + '"' +
                            ' data-mapped-extra-ids="' + AccessCenter.escapeHtml(Array.from(mappedExtraIds).join(',')) + '"' +
                            (checked ? ' data-active="true"' : '') + '>' +
                            '<label class="ac-role-card-head">' +
                            '<input type="checkbox" name="groupRole" value="' + r.id + '"' + (checked ? ' checked' : '') +
                            ' onchange="AccessCenter.Groups.toggleRoleCrud(this)">' +
                            '<span class="ac-role-card-icon"><i class="fas fa-user-shield"></i></span>' +
                            '<span class="ac-role-card-meta">' +
                            '<span class="ac-role-card-name">' + AccessCenter.escapeHtml(r.name) + '</span>' +
                            (r.desc ? '<span class="ac-role-card-desc">' + AccessCenter.escapeHtml(r.desc) + '</span>' : '') +
                            '</span>' +
                            '</label>' +
                            '<div class="ac-role-card-divider"></div>' +
                            '<div class="ac-role-card-section">' +
                            '<span class="ac-role-card-section-label"><i class="fas fa-key"></i> CRUD 권한</span>' +
                            '<div class="ac-crud-group">' + crudHtml + '</div>' +
                            '</div>' +
                            extrasHtml +
                            '</div>';
                    }).join('');

                    // Load existing CRUD + extra selections
                    if (self.selectedGroupId) {
                        // Build index of all non-CRUD permissions (not just role-mapped) for save-state restoration
                        const extrasIndex = new Map();
                        (self.allExtraPermsCache || []).forEach(pp => extrasIndex.set(String(pp.id), pp));
                        groupRoleIds.forEach(rid => {
                            AccessCenter.fetchJson('/admin/access-center/api/groups/' + self.selectedGroupId + '/roles/' + rid + '/cruds')
                                .then(cruds => {
                                    if (!cruds) return;
                                    gridEl.querySelectorAll('.ac-grp-crud-cb[data-role-id="' + rid + '"]').forEach(cb => {
                                        if (cb.dataset.crud !== 'READ') cb.checked = cruds.includes(cb.dataset.crud);
                                    });
                                    gridEl.querySelectorAll('.ac-grp-extra-cb[data-role-id="' + rid + '"]').forEach(cb => {
                                        const perm = extrasIndex.get(String(cb.dataset.permId));
                                        if (perm) cb.checked = cruds.includes(perm.name);
                                    });
                                }).catch(() => {});
                        });
                    }
                }
            } catch (e) {
                const gridEl = document.getElementById('ac-group-roles-grid');
                if (gridEl) gridEl.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-exclamation-triangle"></i><p>역할 목록 로드 실패</p></div>';
            }
        },

        toggleRoleCrud(roleCheckbox) {
            const item = roleCheckbox.closest('.ac-role-card');
            if (!item) return;
            if (roleCheckbox.checked) {
                item.setAttribute('data-active', 'true');
                // Only READ is auto-checked; admin must click any other CRUD or extra to activate
                item.querySelectorAll('.ac-grp-crud-cb').forEach(cb => {
                    if (cb.dataset.crud !== 'READ') cb.checked = false;
                });
                item.querySelectorAll('.ac-grp-extra-cb').forEach(cb => { cb.checked = false; });
            } else {
                item.removeAttribute('data-active');
                item.querySelectorAll('.ac-grp-crud-cb').forEach(cb => {
                    if (cb.dataset.crud !== 'READ') cb.checked = false;
                });
                item.querySelectorAll('.ac-grp-extra-cb').forEach(cb => { cb.checked = false; });
            }
        },

        toggleExtraSection(btn) {
            const section = btn.closest('.ac-extra-section');
            if (!section) return;
            const expanded = section.getAttribute('data-expanded') === 'true';
            section.setAttribute('data-expanded', expanded ? 'false' : 'true');
        },

        async saveGroupRoles() {
            if (!this.selectedGroupId) return;
            const roleAssignments = [];
            document.querySelectorAll('#ac-group-roles-grid input[name="groupRole"]:checked').forEach(cb => {
                const roleId = cb.value;
                const item = cb.closest('.ac-role-card');
                const cruds = [];
                const extraIds = [];
                if (item) {
                    item.querySelectorAll('.ac-grp-crud-cb:checked').forEach(crudCb => {
                        cruds.push(crudCb.dataset.crud);
                    });
                    item.querySelectorAll('.ac-grp-extra-cb:checked').forEach(extraCb => {
                        extraIds.push(Number(extraCb.dataset.permId));
                    });
                }
                if (!cruds.includes('READ')) cruds.push('READ');
                roleAssignments.push({ roleId: Number(roleId), crudPermissions: cruds, extraPermissionIds: extraIds });
            });

            try {
                await AccessCenter.fetchJson('/admin/access-center/api/groups/' + encodeURIComponent(this.selectedGroupId) + '/roles', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [AccessCenter.getCsrfHeader()]: AccessCenter.getCsrfToken()
                    },
                    body: JSON.stringify({ roleAssignments: roleAssignments })
                });
                showToast('그룹 역할이 저장되었습니다.', 'success');
                this.selectGroup(this.selectedGroupId);
            } catch (e) {
                showToast('그룹 역할 저장 실패: ' + e.message, 'error');
            }
        }
    },

    // ================================================================
    // TAB 3: ROLES
    // ================================================================
    Roles: {
        selectedRoleId: null,
        allRoles: null,
        allPermsCache: null,
        searchKeyword: '',

        init() {
            this.loadRoles();
        },

        onSearch(keyword) {
            this.searchKeyword = keyword.trim().toLowerCase();
            this.filterAndRender();
        },

        async loadRoles() {
            const listEl = document.getElementById('ac-role-list');
            listEl.innerHTML =
                '<div class="ac-loading">' +
                '<i class="fas fa-spinner fa-spin"></i>' +
                '<p>역할 목록을 불러오는 중...</p>' +
                '</div>';

            try {
                this.allRoles = await AccessCenter.fetchJson('/admin/access-center/api/roles');
                this.filterAndRender();
            } catch (e) {
                listEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<p>역할 목록을 불러올 수 없습니다.</p>' +
                    '</div>';
                showToast('역할 목록 조회 실패: ' + e.message, 'error');
            }
        },

        filterAndRender() {
            const listEl = document.getElementById('ac-role-list');
            let roles = this.allRoles || [];
            if (this.searchKeyword) {
                roles = roles.filter(r =>
                    (r.name || '').toLowerCase().includes(this.searchKeyword) ||
                    (r.desc || '').toLowerCase().includes(this.searchKeyword)
                );
            }

            if (!roles.length) {
                listEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-user-shield"></i>' +
                    '<p>' + (this.searchKeyword ? '검색 결과가 없습니다.' : '등록된 역할이 없습니다.') + '</p>' +
                    '</div>';
                return;
            }

            const selectedKey = this.selectedRoleId != null ? String(this.selectedRoleId) : null;
            listEl.innerHTML = roles.map(r =>
                '<div class="ac-list-item' + (selectedKey !== null && selectedKey === String(r.id) ? ' selected' : '') + '" ' +
                'data-role-id="' + AccessCenter.escapeHtml(r.id) + '" ' +
                'onclick="AccessCenter.Roles.selectRole(\'' + AccessCenter.escapeHtml(r.id) + '\')">' +
                '<div class="ac-list-item-icon role-icon"><i class="fas fa-user-shield"></i></div>' +
                '<div class="ac-list-item-info">' +
                '<div class="ac-list-item-name">' + AccessCenter.escapeHtml(r.name) + '</div>' +
                '<div class="ac-list-item-sub">' + AccessCenter.escapeHtml(r.desc || '-') + '</div>' +
                '</div>' +
                (r.permCount != null ? '<span class="ac-list-item-badge">' + r.permCount + '개 권한</span>' : '') +
                '</div>'
            ).join('');
            console.log('[AccessCenter.Roles.filterAndRender] rendered count=', roles.length,
                'selectedRoleId=', this.selectedRoleId,
                'ids=', roles.map(r => r.id));
        },

        async selectRole(roleId) {
            const targetId = String(roleId);
            console.log('[AccessCenter.Roles.selectRole] called roleId=', roleId,
                'previousSelected=', this.selectedRoleId);
            this.selectedRoleId = targetId;
            this.filterAndRender();
            const matchedCount = document.querySelectorAll('#ac-role-list .ac-list-item.selected').length;
            console.log('[AccessCenter.Roles.selectRole] selection result matchedCount=', matchedCount);
            if (matchedCount > 1) {
                console.warn('[AccessCenter.Roles.selectRole] multi-select detected for targetId=', targetId);
            }

            const detailEl = document.getElementById('ac-role-detail');
            detailEl.innerHTML =
                '<div class="ac-loading">' +
                '<i class="fas fa-spinner fa-spin"></i>' +
                '<p>역할 정보를 불러오는 중...</p>' +
                '</div>';
            detailEl.classList.add('active');

            try {
                const data = await AccessCenter.fetchJson(
                    '/admin/access-center/api/roles/' + encodeURIComponent(roleId) + '/detail'
                );
                this.renderRoleDetail(data);
            } catch (e) {
                detailEl.innerHTML =
                    '<div class="ac-empty">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<p>역할 정보를 불러올 수 없습니다.</p>' +
                    '</div>';
                showToast('역할 상세 조회 실패: ' + e.message, 'error');
            }
        },

        async renderRoleDetail(data) {
            const detailEl = document.getElementById('ac-role-detail');

            let html =
                '<div class="ac-detail-header">' +
                '<div class="ac-detail-avatar role-avatar"><i class="fas fa-user-shield"></i></div>' +
                '<div class="ac-detail-title">' +
                '<div class="ac-detail-name">' + AccessCenter.escapeHtml(data.name) + '</div>' +
                '<div class="ac-detail-desc">' + AccessCenter.escapeHtml(data.desc || '-') + '</div>' +
                '</div>' +
                '</div>';

            html += '<div class="ac-detail-body">';

            // Permission assignment
            html +=
                '<div class="ac-section-header">' +
                '<div class="ac-section-header-text">' +
                '<h4>권한 할당</h4>' +
                '<span class="ac-section-hint"><i class="fas fa-info-circle"></i> 체크된 권한은 사용자의 역할 할당 시 기본적으로 포함됩니다.</span>' +
                '</div>' +
                '<button type="button" class="ac-btn-save" onclick="AccessCenter.Roles.saveRolePermissions()">' +
                '<i class="fas fa-save"></i> 저장</button>' +
                '</div>';
            html += '<div class="ac-search-box" style="padding:0;border-bottom:none;margin-bottom:0.75rem;">' +
                '<i class="fas fa-search ac-search-icon"></i>' +
                '<input type="text" class="ac-search-input" id="ac-role-perm-search" placeholder="권한 검색..." ' +
                'oninput="AccessCenter.Roles.filterPermissions(this.value); AccessCenter.toggleClearBtn(this)">' +
                '<i class="fas fa-times ac-search-clear" onclick="AccessCenter.clearSearch(this)" style="display:none;"></i>' +
                '</div>';
            html += '<div id="ac-role-perms-grid" class="ac-checkbox-grid">';
            html += '<div class="ac-spinner"><i class="fas fa-spinner fa-spin"></i> 권한 목록을 불러오는 중...</div>';
            html += '</div>';

            // Direct users section
            if (data.directUsers && data.directUsers.length) {
                html += '<div style="margin-top:1.5rem;">';
                html += '<div class="ac-section-header"><h4>직접 할당된 사용자 (' + data.directUsers.length + '명)</h4></div>';
                html += '<div class="ac-assigned-users">';
                html += data.directUsers.map(u =>
                    '<div class="ac-assigned-user">' +
                    '<div class="ac-assigned-user-icon"><i class="fas fa-user"></i></div>' +
                    '<div>' +
                    '<div class="ac-assigned-user-name">' + AccessCenter.escapeHtml(u.name || u.username) + '</div>' +
                    '<div class="ac-assigned-user-sub">' + AccessCenter.escapeHtml(u.username) + '</div>' +
                    '</div>' +
                    '</div>'
                ).join('');
                html += '</div></div>';
            }

            html += '</div>';
            detailEl.innerHTML = html;

            // Load permission checkboxes
            try {
                if (!this.allPermsCache) {
                    this.allPermsCache = await AccessCenter.fetchJson('/admin/access-center/api/all-permissions');
                }
                const rolePermIds = (data.permissions || []).map(p => String(p.id));
                const gridEl = document.getElementById('ac-role-perms-grid');
                const allPerms = this.allPermsCache || [];

                if (!allPerms.length) {
                    gridEl.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-key"></i><p>등록된 권한이 없습니다.</p></div>';
                } else {
                    this._currentRolePermIds = rolePermIds;
                    this._renderPermGrid(allPerms, rolePermIds, gridEl, '');
                }
            } catch (e) {
                const gridEl = document.getElementById('ac-role-perms-grid');
                if (gridEl) gridEl.innerHTML = '<div class="ac-empty" style="min-height:100px;"><i class="fas fa-exclamation-triangle"></i><p>권한 목록 로드 실패</p></div>';
            }
        },

        _renderPermGrid(allPerms, rolePermIds, gridEl, keyword) {
            let filtered = allPerms;
            if (keyword) {
                const kw = keyword.toLowerCase();
                filtered = allPerms.filter(p =>
                    (p.friendlyName || '').toLowerCase().includes(kw) ||
                    (p.name || '').toLowerCase().includes(kw) ||
                    (p.description || '').toLowerCase().includes(kw)
                );
            }
            if (!filtered.length) {
                gridEl.innerHTML = '<div class="ac-empty" style="min-height:80px;"><i class="fas fa-search"></i><p>검색 결과가 없습니다.</p></div>';
                return;
            }
            // Sort: checked first
            filtered.sort((a, b) => {
                const aC = rolePermIds.includes(String(a.id)) ? 0 : 1;
                const bC = rolePermIds.includes(String(b.id)) ? 0 : 1;
                return aC - bC;
            });
            gridEl.innerHTML = filtered.map(p => {
                // READ permission is always required (forced checked + disabled)
                const isReadPerm = p.name === 'READ';
                const checked = isReadPerm || rolePermIds.includes(String(p.id));
                const displayName = AccessCenter.escapeHtml(p.friendlyName || p.name);
                const baseTooltip = (p.name || '') + (p.description ? ' - ' + p.description : '');
                const tooltip = AccessCenter.escapeHtml(isReadPerm ? baseTooltip + ' (필수 권한 — 변경 불가)' : baseTooltip);
                return '<label class="ac-checkbox-item' + (checked ? ' checked' : '') + (isReadPerm ? ' required' : '') + '" title="' + tooltip + '">' +
                    '<input type="checkbox" name="rolePerm" value="' + AccessCenter.escapeHtml(p.id) + '"' +
                    (checked ? ' checked' : '') + (isReadPerm ? ' disabled' : '') +
                    ' onchange="this.parentElement.classList.toggle(\'checked\', this.checked)">' +
                    '<div class="ac-checkbox-label-wrap"><div class="ac-checkbox-label-name">' + displayName +
                    (isReadPerm ? ' <span class="ac-required-badge">필수</span>' : '') +
                    '</div></div></label>';
            }).join('');
        },

        filterPermissions(keyword) {
            const gridEl = document.getElementById('ac-role-perms-grid');
            if (!gridEl || !this.allPermsCache) return;
            // Preserve current check state
            const checkedNow = new Set();
            document.querySelectorAll('#ac-role-perms-grid input[name="rolePerm"]:checked').forEach(cb => checkedNow.add(cb.value));
            const permIds = Array.from(checkedNow);
            this._renderPermGrid(this.allPermsCache, permIds, gridEl, keyword);
        },

        async saveRolePermissions() {
            if (!this.selectedRoleId) return;
            const checkboxes = document.querySelectorAll('#ac-role-perms-grid input[name="rolePerm"]:checked');
            const permissionIds = Array.from(checkboxes).map(cb => cb.value);

            try {
                await AccessCenter.fetchJson('/admin/access-center/api/roles/' + encodeURIComponent(this.selectedRoleId) + '/permissions', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [AccessCenter.getCsrfHeader()]: AccessCenter.getCsrfToken()
                    },
                    body: JSON.stringify({ permissionIds: permissionIds })
                });
                showToast('역할 권한이 저장되었습니다.', 'success');
                this.selectRole(this.selectedRoleId);
            } catch (e) {
                showToast('역할 권한 저장 실패: ' + e.message, 'error');
            }
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    // Detect active tab from server-side rendering
    const activeContent = document.querySelector('.ac-tab-content.active');
    if (activeContent) {
        const tabId = activeContent.id.replace('ac-tab-', '');
        AccessCenter.activeTab = tabId;
        if (tabId === 'users') AccessCenter.Users.init();
        else if (tabId === 'groups') AccessCenter.Groups.init();
        else if (tabId === 'roles') AccessCenter.Roles.init();
    } else {
        // Default: users tab
        AccessCenter.switchTab('users');
    }
});
