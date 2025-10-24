document.addEventListener('DOMContentLoaded', () => {
    // [오류 해결] debounce 함수를 스크립트 최상단에 선언하여 전역에서 참조 가능하도록 수정
    const debounce = (func, delay) => {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), delay);
        };
    };

    // --- 상태 관리 (State) ---
    class StudioState {
        constructor() {
            this.mode = 'view';
            this.selected = { subject: null };
            this.viewData = { assignments: [], effectivePermissions: [] };
            this.editData = { allAssignments: [], selectedAssignmentIds: new Set(), simulationResult: null };
            this.wizardContextId = null;
        }
        setMode(newMode) { this.mode = newMode; }
        // [오류 해결] selectSubject -> select 로 함수명 수정, 로직 보강
        select(subject) {
            this.selected.subject = (this.selected.subject?.id === subject?.id && this.selected.subject?.type === subject?.type) ? null : subject;
        }
        setViewData(assignments, effectivePermissions) { this.viewData = { assignments, effectivePermissions }; }
        setEditData(allAssignments, initialAssignmentIds) {
            this.editData.allAssignments = allAssignments;
            this.editData.selectedAssignmentIds = new Set(initialAssignmentIds);
        }
        toggleAssignment(id) {
            if (this.editData.selectedAssignmentIds.has(id)) this.editData.selectedAssignmentIds.delete(id);
            else this.editData.selectedAssignmentIds.add(id);
        }
        setSimulationResult(result) { this.editData.simulationResult = result; }
        setWizardContextId(id) { this.wizardContextId = id; }
        getSubject() { return this.selected.subject; }
    }

    // --- UI 렌더링 및 조작 ---
    class StudioUI {
        constructor(elements) { this.elements = elements; }

        setLoading(button, isLoading, originalText) {
            if (!button) return;
            button.disabled = isLoading;
            button.innerHTML = isLoading ? `<i class="fas fa-spinner fa-spin mr-2"></i> 처리 중...` : originalText;
        }

        render(state) {
            this.updateExplorerSelection(state);
            if (state.getSubject()) {
                this.elements.inspectorPlaceholder.classList.add('hidden');
                this.elements.inspectorContent.classList.remove('hidden');
                if (state.mode === 'view') {
                    this.renderViewMode(state);
                } else {
                    this.renderEditMode(state);
                }
            } else {
                this.showPlaceholder();
            }
        }

        showPlaceholder() {
            this.elements.inspectorPlaceholder.classList.remove('hidden');
            this.elements.inspectorContent.classList.add('hidden');
        }

        renderExplorer(data) {
            const sections = {
                '사용자': { items: data.users, type: 'USER', icon: 'fa-user' },
                '그룹': { items: data.groups, type: 'GROUP', icon: 'fa-users' },
            };
            this.elements.explorerListContainer.innerHTML = Object.entries(sections)
                .map(([title, { items, type, icon }]) => this.createAccordionSection(title, items, type, icon))
                .join('');
            this.bindAccordionEvents();
        }
        createAccordionSection(title, items, type, icon) {
            const contentHtml = items?.length
                ? items.map(item => this.createItemHtml(item, type, icon)).join('')
                : '<div class="p-2 text-xs text-slate-400">항목이 없습니다.</div>';
            return `<div class="accordion"><div class="accordion-header"><span class="font-bold">${title}</span><i class="fas fa-chevron-down accordion-icon"></i></div><div class="accordion-content">${contentHtml}</div></div>`;
        }
        createItemHtml(item, type, icon) {
            return `<div class="explorer-item" data-id="${item.id}" data-type="${type}" data-name="${item.name}" data-description="${item.description || ''}"><div class="item-icon"><i class="fas ${icon}"></i></div><div class="item-text"><div class="item-name">${item.name}</div><div class="item-description" title="${item.description || ''}">${item.description || ''}</div></div></div>`;
        }
        updateExplorerSelection(state) {
            this.elements.explorerListContainer.querySelectorAll('.explorer-item').forEach(el => {
                el.classList.toggle('selected', state.getSubject()?.id == el.dataset.id && state.getSubject()?.type === el.dataset.type);
            });
        }

        renderViewMode(state) {
            const subject = state.getSubject();
            const { assignments = [], effectivePermissions = [] } = state.viewData;
            const assignmentType = subject.type === 'USER' ? '그룹' : '역할';
            const html = `
                <div class="flex justify-between items-center mb-6">
                    <h3 class="font-bold text-xl text-slate-200">주체: ${subject.name} (조회)</h3>
                    <button id="edit-mode-btn" class="dark-btn-primary"><i class="fas fa-edit mr-2"></i>${assignmentType} 할당 변경</button>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <h4 class="font-semibold text-slate-300 mb-2">할당된 ${assignmentType} (${assignments.length})</h4>
                        <div class="space-y-2 p-2 rounded-md bg-slate-900/50 max-h-80 overflow-y-auto">
                            ${assignments.length ? assignments.map(a => `<div class="p-3 bg-slate-800 rounded-md text-sm">${a.name || a.roleName}</div>`).join('') : `<div class="p-3 text-slate-500 text-sm">할당된 ${assignmentType}이(가) 없습니다.</div>`}
                        </div>
                    </div>
                    <div>
                        <h4 class="font-semibold text-slate-300 mb-2">유효 권한 (${effectivePermissions.length})</h4>
                        <div class="space-y-2 p-2 rounded-md bg-slate-900/50 max-h-80 overflow-y-auto">
                           ${effectivePermissions.length ? effectivePermissions.map(p => `<div class="p-3 bg-slate-800 rounded-md text-sm"><p class="text-slate-200">${p.permissionDescription}</p><p class="text-xs text-slate-500 mt-1">획득 경로: ${p.origin}</p></div>`).join('') : '<div class="p-3 text-slate-500 text-sm">유효 권한이 없습니다.</div>'}
                        </div>
                    </div>
                </div>`;
            this.elements.inspectorContent.innerHTML = html;
        }

        renderEditMode(state) {
            const subject = state.getSubject();
            const { allAssignments, selectedAssignmentIds, simulationResult } = state.editData;
            const assignmentType = subject.type === 'USER' ? '그룹' : '역할';
            const html = `
                <div class="flex justify-between items-center mb-4">
                     <h3 class="font-bold text-xl text-slate-200">주체: ${subject.name} (편집)</h3>
                    <div>
                        <button id="cancel-edit-btn" class="dark-btn-secondary mr-2">취소</button>
                        <button id="save-assignments-btn" class="dark-btn-primary"><i class="fas fa-save mr-2"></i>저장</button>
                    </div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <h4 class="font-semibold text-slate-300 mb-2">전체 ${assignmentType} 목록</h4>
                        <div id="assignment-selection-list" class="space-y-2 p-2 rounded-md bg-slate-900/50 max-h-96 overflow-y-auto">
                            ${allAssignments.map(a => `
                                <div class="dark-checkbox-item"><input type="checkbox" id="assign-${a.id}" value="${a.id}" class="dark-checkbox assignment-checkbox" ${selectedAssignmentIds.has(a.id) ? 'checked' : ''}><label for="assign-${a.id}" class="text-slate-200">${a.name || a.roleName}</label></div>`).join('')}
                        </div>
                    </div>
                    <div id="simulation-result-container">${this.renderSimulationResult(simulationResult)}</div>
                </div>`;
            this.elements.inspectorContent.innerHTML = html;
        }

        renderSimulationResult(result) {
            if (!result) return '<div class="p-4 text-center text-slate-500">멤버십을 변경하여 권한 변동을 확인하세요.</div>';

            const gained = result.impactDetails?.filter(d => d.impactType === 'PERMISSION_GAINED') || [];
            const lost = result.impactDetails?.filter(d => d.impactType === 'PERMISSION_LOST') || [];

            let html = `<h4 class="font-semibold text-slate-300 mb-2">실시간 영향 분석</h4><div class="p-3 bg-slate-800 rounded-md text-center text-sm font-semibold mb-3">${result.summary}</div><div class="space-y-4 max-h-80 overflow-y-auto">`;
            if (gained.length) html += `<div><h5 class="font-bold text-green-400 mb-2"><i class="fas fa-plus-circle mr-2"></i>획득할 권한 (${gained.length})</h5><ul class="space-y-1 text-sm list-inside text-slate-300">${gained.map(d => `<li>${d.permissionDescription || 'N/A'}</li>`).join('')}</ul></div>`;
            if (lost.length) html += `<div class="mt-4"><h5 class="font-bold text-red-400 mb-2"><i class="fas fa-minus-circle mr-2"></i>상실할 권한 (${lost.length})</h5><ul class="space-y-1 text-sm list-inside text-slate-300">${lost.map(d => `<li>${d.permissionDescription || 'N/A'}</li>`).join('')}</ul></div>`;
            if (!gained.length && !lost.length) html += `<div class="text-center text-slate-500 text-sm p-4">권한 변경사항이 없습니다.</div>`;
            html += '</div>';
            return html;
        }

        filterExplorer(term) {
            const searchTerm = term.trim().toLowerCase();

            // 모든 아코디언과 아이템을 한 번에 가져오기
            const accordions = this.elements.explorerListContainer.querySelectorAll('.accordion');
            const allItems = this.elements.explorerListContainer.querySelectorAll('.explorer-item');

            // 검색어가 없으면 모두 표시
            if (!searchTerm) {
                accordions.forEach(acc => acc.style.display = '');
                allItems.forEach(item => item.style.display = '');
                const msg = this.elements.explorerListContainer.querySelector('.no-results-message');
                if (msg) msg.remove();
                return;
            }

            // 검색 실행
            let hasResults = false;
            const accordionVisibility = new Map();

            // 각 아이템 검사
            allItems.forEach(item => {
                const name = (item.dataset.name || '').toLowerCase();
                const desc = (item.dataset.description || '').toLowerCase();
                const matches = name.includes(searchTerm) || desc.includes(searchTerm);

                item.style.display = matches ? '' : 'none';

                if (matches) {
                    hasResults = true;
                    const parentAccordion = item.closest('.accordion');
                    if (parentAccordion) {
                        accordionVisibility.set(parentAccordion, true);
                    }
                }
            });

            // 아코디언 표시/숨김
            accordions.forEach(acc => {
                acc.style.display = accordionVisibility.has(acc) ? '' : 'none';
            });

            // 결과 없음 메시지
            let msg = this.elements.explorerListContainer.querySelector('.no-results-message');
            if (!hasResults) {
                if (!msg) {
                    msg = document.createElement('div');
                    msg.className = 'no-results-message';
                    msg.textContent = '검색 결과가 없습니다.';
                    this.elements.explorerListContainer.appendChild(msg);
                }
            } else if (msg) {
                msg.remove();
            }
        }

        bindAccordionEvents() {
            this.elements.explorerListContainer.querySelectorAll('.accordion-header').forEach(header => {
                header.addEventListener('click', () => {
                    const content = header.nextElementSibling;
                    const isOpen = header.classList.toggle('open');
                    header.querySelector('.accordion-icon').classList.toggle('rotate-180', isOpen);
                    content.style.maxHeight = isOpen ? `${content.scrollHeight}px` : '0px';
                });
            });
        }
    }

    // --- API 통신 ---
    class StudioAPI {
        async fetchApi(url, options = {}) {
            try {
                const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
                const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;
                const fetchOptions = { ...options, headers: { ...options.headers } };
                if (csrfToken && csrfHeader && options.method?.toUpperCase() !== 'GET') fetchOptions.headers[csrfHeader] = csrfToken;
                if (options.body) fetchOptions.headers['Content-Type'] = 'application/json';
                const response = await fetch(url, fetchOptions);
                if (!response.ok) {
                    const error = await response.json().catch(() => ({ message: `서버 오류: ${response.status}` }));
                    throw new Error(error.message);
                }
                const text = await response.text();
                return text ? JSON.parse(text) : null;
            } catch (error) {
                console.error(`API 오류: ${url}`, error);
                if (typeof showToast === 'function') showToast(error.message, 'error');
                throw error;
            }
        }
        getExplorerItems() { return this.fetchApi('/api/workbench/metadata/subjects'); }
        getSubjectDetails(subjectId, subjectType) { return this.fetchApi(`/admin/studio/api/subject-details?subjectId=${subjectId}&subjectType=${subjectType}`); }
        startEditSession(request) { return this.fetchApi('/admin/granting-wizard/start', { method: 'POST', body: JSON.stringify(request) }); }
        simulateChanges(contextId, changes) { return this.fetchApi(`/admin/granting-wizard/${contextId}/simulate`, { method: 'POST', body: JSON.stringify(changes) }); }
        commitChanges(contextId, changes) { return this.fetchApi(`/admin/granting-wizard/${contextId}/commit`, { method: 'POST', body: JSON.stringify(changes) }); }
    }

    // --- 애플리케이션 총괄 ---
    class StudioApp {
        constructor() {
            this.elements = {
                explorerListContainer: document.getElementById('explorer-list-container'),
                search: document.getElementById('explorer-search'),
                inspectorPlaceholder: document.getElementById('inspector-placeholder'),
                inspectorContent: document.getElementById('inspector-content'),
            };
            this.state = new StudioState();
            this.ui = new StudioUI(this.elements);
            this.api = new StudioAPI();
            this.fullData = {};
        }

        async init() {
            this.bindEventListeners();
            await this.loadInitialData();
        }

        async loadInitialData() {
            try {
                this.fullData = await this.api.getExplorerItems();
                this.ui.renderExplorer(this.fullData);
                this.ui.showPlaceholder();
            } catch (error) {
                console.error('초기 데이터 로딩 실패:', error);
            }
        }

        bindEventListeners() {
            this.elements.explorerListContainer.addEventListener('click', e => this.handleExplorerClick(e));
            this.elements.search.addEventListener('input', e => this.ui.filterExplorer(e.target.value));
            this.elements.inspectorContent.addEventListener('click', e => {
                const target = e.target;
                if (target.closest('#edit-mode-btn')) this.handleModeChange('edit');
                if (target.closest('#cancel-edit-btn')) this.handleModeChange('view');
                if (target.closest('#save-assignments-btn')) this.handleSaveAssignments();
                const selectionList = target.closest('#assignment-selection-list');
                if (selectionList && target.classList.contains('assignment-checkbox')) {
                    this.handleAssignmentChange(target);
                }
            });
        }

        async handleExplorerClick(e) {
            const itemEl = e.target.closest('.explorer-item');
            if (!itemEl) return;
            const { id, type, name, description } = itemEl.dataset;
            const subject = { id: Number(id), type, name, description };

            this.state.select(subject);
            this.state.setMode('view');
            this.ui.updateExplorerSelection(this.state);
            await this.updateInspectorView();
        }

        async updateInspectorView() {
            const subject = this.state.getSubject();
            if (!subject) {
                this.ui.showPlaceholder();
                return;
            }
            try {
                const details = await this.api.getSubjectDetails(subject.id, subject.type);
                this.state.setViewData(details.assignments, details.effectivePermissions);
                this.ui.render(this.state);
            } catch (error) {
                this.ui.showPlaceholder();
            }
        }

        async handleModeChange(mode) {
            const subject = this.state.getSubject();
            if (!subject) return;

            if (mode === 'edit') {
                try {
                    const initiation = await this.api.startEditSession({ subjectId: subject.id, subjectType: subject.type });
                    this.state.setWizardContextId(initiation.wizardContextId);

                    const assignmentTypeKey = subject.type === 'USER' ? 'groups' : 'roles';
                    const allAssignments = this.fullData[assignmentTypeKey] || [];
                    const initialAssignmentIds = this.state.viewData.assignments.map(a => a.id);
                    this.state.setEditData(allAssignments, initialAssignmentIds);
                    this.state.setSimulationResult(null);
                } catch (error) {
                    showToast('편집 모드 시작에 실패했습니다.', 'error');
                    return; // 모드 전환 실패
                }
            }
            this.state.setMode(mode);
            this.ui.render(this.state);
        }

        handleAssignmentChange = debounce(async (checkbox) => {
            this.state.toggleAssignment(Number(checkbox.value));
            const subject = this.state.getSubject();
            try {
                const changes = { added: Array.from(this.state.editData.selectedAssignmentIds).map(id => ({ targetId: Number(id), targetType: subject.type === 'USER' ? 'GROUP' : 'ROLE' })) };
                const result = await this.api.simulateChanges(this.state.wizardContextId, changes);
                this.state.setSimulationResult(result);
                this.ui.render(this.state);
            } catch (error) {
                console.error("시뮬레이션 실패", error);
            }
        }, 400);

        async handleSaveAssignments() {
            const subject = this.state.getSubject();
            if (!subject) return;

            const saveBtn = document.getElementById('save-assignments-btn');
            const originalText = saveBtn.innerHTML;
            this.ui.setLoading(saveBtn, true, originalText);

            try {
                const changes = { added: Array.from(this.state.editData.selectedAssignmentIds).map(id => ({ targetId: Number(id), targetType: subject.type === 'USER' ? 'GROUP' : 'ROLE' })) };
                await this.api.commitChanges(this.state.wizardContextId, changes);
                showToast("성공적으로 저장되었습니다.", "success");
                this.state.setMode('view');
                await this.updateInspectorView();
            } catch (error) {
                this.ui.setLoading(saveBtn, false, originalText);
            }
        }
    }

    new StudioApp().init();
});