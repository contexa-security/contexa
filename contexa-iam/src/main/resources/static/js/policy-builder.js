

(() => {
    console.log('🌟 policy-builder.js 스크립트 로드됨');

    document.addEventListener('DOMContentLoaded', () => {
        console.log('🌟 DOMContentLoaded 이벤트 발생 - PolicyBuilderApp 초기화 시작');

        try {

            class PolicyBuilderState {
                constructor() {
                    this.roles = new Map();
                    this.permissions = new Map();
                    this.conditions = new Map();
                    this.aiActionEnabled = false;
                    this.allowedActions = [];
                    this.customConditionSpel = "";
                }

                add(type, key, value) { this.getMap(type)?.set(key, value); }
                remove(type, key) { this.getMap(type)?.delete(key); }
                clear(type) { this.getMap(type)?.clear(); }

                getMap(type) {
                    const map = { role: this.roles, permission: this.permissions, condition: this.conditions }[type];
                    if (!map) throw new Error('유효하지 않은 상태 타입입니다: ' + type);
                    return map;
                }

                toDto() {
                    const policyNameEl = document.getElementById('policyNameInput');
                    const policyDescEl = document.getElementById('policyDescTextarea');
                    const policyEffectEl = document.getElementById('policyEffectSelect');
                    const customSpelEl = document.getElementById('customSpelInput');

                    return {
                        policyName: policyNameEl?.value || '',
                        description: policyDescEl?.value || '',
                        effect: policyEffectEl?.value || 'ALLOW',
                        roleIds: Array.from(this.roles.keys()).map(Number),
                        permissionIds: Array.from(this.permissions.keys()).map(Number),
                        conditions: Array.from(this.conditions.entries()).reduce((acc, [key, val]) => {
                            const templateId = key.split(':')[0];
                            acc[templateId] = [];
                            return acc;
                        }, {}),
                        aiActionEnabled: this.aiActionEnabled,
                        allowedActions: this.allowedActions,
                        customConditionSpel: customSpelEl?.value?.trim() || ''
                    };
                }
            }

            class PolicyBuilderUI {
                constructor(elements) {
                    this.elements = elements;
                }

                renderAll(state) {
                    this.renderChipZone('role', state.roles);
                    this.renderChipZone('permission', state.permissions);
                    this.renderChipZone('condition', state.conditions);
                    this.updatePreview(state);
                }

                renderChipZone(type, map) {
                    const canvasElId = type + 'sCanvas';
                    const canvasEl = this.elements[canvasElId];
                    const koreanTypeName = { role: '역할', permission: '권한', condition: '조건' }[type];

                    if (!canvasEl) {
                        console.error(`Canvas element not found: ${canvasElId}`);
                        return;
                    }

                    canvasEl.innerHTML = '';
                    if (map.size === 0) {
                        canvasEl.innerHTML = `<div class="canvas-placeholder"><i class="fas fa-hand-pointer"></i><span>왼쪽에서 ${koreanTypeName}을(를) 드래그하여 여기에 놓으세요</span></div>`;
                        return;
                    }

                    map.forEach((value, key) => {
                        const chip = document.createElement('span');
                        chip.className = 'policy-chip';
                        chip.dataset.key = String(key);
                        chip.dataset.type = type;

                        const removeBtn = document.createElement('button');
                        removeBtn.className = 'remove-chip-btn';
                        removeBtn.innerHTML = '&times;';
                        removeBtn.dataset.type = type;
                        removeBtn.dataset.key = String(key);

                        removeBtn.addEventListener('click', () => {
                            const event = new CustomEvent('removeChip', {
                                detail: { type, key: String(key) }
                            });
                            document.dispatchEvent(event);
                        });

                        if (type === 'permission' && value.targetType) {
                            const badge = document.createElement('span');
                            badge.textContent = value.targetType;
                            badge.style.cssText = value.targetType === 'URL'
                                ? 'background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); padding: 1px 6px; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; margin-right: 4px;'
                                : 'background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.3); padding: 1px 6px; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; margin-right: 4px;';
                            chip.appendChild(badge);
                        }
                        chip.appendChild(document.createTextNode(value.name + ' '));
                        chip.appendChild(removeBtn);

                        canvasEl.appendChild(chip);
                    });
                }

                updatePreview(state) {
                    if (!this.elements.policyPreview) return;

                    const rolesHtml = Array.from(state.roles.values()).map(r => `<span class="policy-chip-preview">${r.name}</span>`).join(' 또는 ') || '<span class="text-gray-400">모든 역할</span>';
                    const permissionsHtml = Array.from(state.permissions.values()).map(p => {
                        const badge = p.targetType ? `<span style="${p.targetType === 'URL' ? 'background:rgba(59,130,246,0.2);color:#60a5fa;border:1px solid rgba(59,130,246,0.3)' : 'background:rgba(139,92,246,0.2);color:#a78bfa;border:1px solid rgba(139,92,246,0.3)'};padding:1px 6px;border-radius:9999px;font-size:0.7rem;font-weight:600;margin-right:4px;">${p.targetType}</span> ` : '';
                        return `<span class="policy-chip-preview">${badge}${p.name}</span>`;
                    }).join(' 그리고 ') || '<span class="text-gray-400">모든 권한</span>';
                    const conditionsHtml = Array.from(state.conditions.values()).map(c => `<span class="policy-chip-preview condition">${c.name}</span>`).join(' 그리고 ');
                    const aiConditionHtml = state.aiActionEnabled && state.allowedActions.length > 0 ? `<span class="policy-chip-preview ai">AI 허용 액션: ${state.allowedActions.join(', ')}</span>` : '';
                    let fullConditionHtml = [conditionsHtml, aiConditionHtml].filter(Boolean).join(' 그리고 ');

                    const effect = this.elements.policyEffectSelect?.value || 'ALLOW';
                    const effectHtml = `<span class="font-bold ${effect === 'ALLOW' ? 'text-green-400' : 'text-red-400'}">${effect === 'ALLOW' ? '허용' : '거부'}</span>`;

                    this.elements.policyPreview.innerHTML = `
                        <div class="preview-section">
                            <div class="preview-label">역할 (WHO)</div>
                            <div>${rolesHtml}</div>
                        </div>
                        <div class="preview-section">
                            <div class="preview-label">🔑 권한 (무엇을)</div>
                            <div>${permissionsHtml}</div>
                        </div>
                        ${fullConditionHtml ? `
                        <div class="preview-section">
                            <div class="preview-label">⏰ 조건 (언제)</div>
                            <div>${fullConditionHtml}</div>
                        </div>
                        ` : ''}
                        <div class="preview-section">
                            <div class="preview-label">⚡ 결과</div>
                            <div class="text-lg">${effectHtml}</div>
                        </div>
                        <div class="mt-4 p-3 rounded-lg bg-gradient-to-r from-indigo-900/30 to-purple-900/30 border border-indigo-500/30">
                            <div class="text-sm text-indigo-300 font-semibold mb-2">📋 정책 요약</div>
                            <div class="text-indigo-100">
                                ${Array.from(state.roles.values()).map(s => s.name).join(', ') || '모든 역할'}이
                                ${Array.from(state.permissions.values()).map(p => p.name).join(', ') || '모든 리소스'}에 대해
                                ${fullConditionHtml ? `${Array.from(state.conditions.values()).map(c => c.name).join(', ')} 조건 하에서` : ''}
                                <strong>${effect === 'ALLOW' ? '접근이 허용' : '접근이 거부'}</strong>됩니다.
                            </div>
                        </div>
                    `;
                }

                setLoading(button, isLoading) {
                    if (!button) return;
                    const originalHtml = button.dataset.originalHtml || button.innerHTML;
                    if (isLoading) {
                        if (!button.dataset.originalHtml) button.dataset.originalHtml = originalHtml;
                        button.disabled = true;
                        button.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> 처리 중...';
                    } else {
                        button.disabled = false;
                        button.innerHTML = button.dataset.originalHtml || originalHtml;
                        delete button.dataset.originalHtml;
                    }
                }
            }

            class PolicyBuilderAPI {
                constructor() {
                    this.csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
                    this.csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;
                }

                async fetchApi(url, options = {}) {
                    const headers = {
                        'Content-Type': 'application/json',
                        ...(this.csrfToken && this.csrfHeader ? { [this.csrfHeader]: this.csrfToken } : {}),
                        ...options.headers
                    };
                    try {
                        const response = await fetch(url, { ...options, headers });
                        if (!response.ok) {
                            const errorData = await response.json().catch(() => ({ message: `서버 오류 (${response.status})` }));
                            throw new Error(errorData.message);
                        }
                        return response.status === 204 ? null : response.json();
                    } catch (error) {
                        if (typeof showToast === 'function') {
                            showToast(error.message, 'error');
                        } else {
                            console.error('Error:', error.message);
                        }
                        throw error;
                    }
                }

                savePolicy(dto) {
                    return this.fetchApi('/api/policies/build-from-business-rule', {
                        method: 'POST',
                        body: JSON.stringify(dto)
                    });
                }
            }

            class PolicyBuilderApp {
                constructor() {
                    this.state = new PolicyBuilderState();
                    this.elements = this.queryDOMElements();
                    this.ui = new PolicyBuilderUI(this.elements);
                    this.api = new PolicyBuilderAPI();
                    this.isStreaming = false; // 🎥 스트리밍 상태 관리
                    this.isProcessingQuery = false; // 이게 있는지 확인
                    this.init();
                }

                queryDOMElements() {
                    const elements = {};
                    const idMapping = {

                        naturalLanguageInput: 'naturalLanguageInput',
                        generateByAiBtn: 'generateByAiBtn',
                        thoughtProcessContainer: 'ai-thought-process-container',
                        thoughtProcessLog: 'ai-thought-process',
                        aiEnabledCheckbox: 'aiEnabledCheckbox',
                        aiActionContainer: 'aiActionContainer',
                        customSpelInput: 'customSpelInput',

                        rolesPalette: 'roles-palette',
                        permissionsPalette: 'permissionsPalette',
                        conditionsPalette: 'conditionsPalette',

                        rolesCanvas: 'roles-canvas',
                        permissionsCanvas: 'permissions-canvas',
                        conditionsCanvas: 'conditions-canvas',

                        policyNameInput: 'policyNameInput',
                        policyDescTextarea: 'policyDescTextarea',
                        policyEffectSelect: 'policyEffectSelect',
                        savePolicyBtn: 'savePolicyBtn',
                        policyPreview: 'policyPreview'
                    };

                    for (const [jsKey, htmlId] of Object.entries(idMapping)) {
                        elements[jsKey] = document.getElementById(htmlId);
                        if (!elements[jsKey]) {
                            console.warn(`Element not found: ${htmlId} (mapped to ${jsKey})`);
                        }
                    }
                    return elements;
                }

                init() {
                    console.log('=== PolicyBuilderApp init 시작 ===');

                    this.debugCloseButton();

                    if (!this.elements.savePolicyBtn) {
                        console.error("정책 빌더의 필수 UI 요소(저장 버튼)를 찾을 수 없습니다.");
                        return;
                    }

                    this.bindEventListeners();
                    this.initializeFromContext();
                    this.syncAiActionsWithEffect();
                    this.ui.renderAll(this.state);

                    console.log('=== PolicyBuilderApp init 완료 ===');
                }

                debugCloseButton() {
                    console.log('닫기 버튼 디버깅 시작');

                    const allButtons = document.querySelectorAll('button');
                    console.log('🔘 페이지의 모든 버튼 개수:', allButtons.length);

                    allButtons.forEach((btn, i) => {
                        console.log(`  ${i+1}. 버튼 클래스: "${btn.className}", 내용: "${btn.innerHTML.substring(0, 50)}"`);
                    });

                    const closeButton = document.querySelector('.close-button');
                    console.log('🚪 닫기 버튼 검색 결과:', closeButton);

                    if (closeButton) {
                        console.log('🚪 닫기 버튼 상세 정보:');
                        console.log('  - 클래스:', closeButton.className);
                        console.log('  - HTML:', closeButton.outerHTML);
                        console.log('  - 부모 요소:', closeButton.parentElement);
                        console.log('  - 표시 여부:', getComputedStyle(closeButton).display);
                        console.log('  - z-index:', getComputedStyle(closeButton).zIndex);
                    }

                    const allCloseButtons = document.querySelectorAll('.close-button');
                    console.log('🚪 close-button 클래스 요소 개수:', allCloseButtons.length);

                    const timesIcons = document.querySelectorAll('.fa-times');
                    console.log('fa-times 아이콘 개수:', timesIcons.length);

                    console.log('닫기 버튼 디버깅 완료');
                }

                bindEventListeners() {

                    console.log('닫기 버튼 이벤트 리스너 설정 시작');

                    const closeButton = document.querySelector('.close-button');
                    console.log('닫기 버튼 검색 결과:', closeButton);
                    console.log('닫기 버튼 HTML:', closeButton ? closeButton.outerHTML : 'null');

                    if (closeButton) {

                        closeButton.addEventListener('click', (e) => {
                            console.log('🚪🚪🚪 닫기 버튼 클릭 확인됨! 🚪🚪🚪');
                            console.log('이벤트 객체:', e);
                            console.log('타겟 요소:', e.target);

                            e.preventDefault();
                            e.stopPropagation();

                            this.isProcessingQuery = false;
                            this.isStreaming = false;

                            this.handleCloseModal();
                        });

                        console.log('닫기 버튼 이벤트 리스너 추가 완료');
                    } else {
                        console.warn('닫기 버튼을 찾을 수 없습니다');
                    }

                    document.addEventListener('click', (e) => {
                        console.log('🖱️ 문서 클릭 감지:', e.target);
                        console.log('🖱️ 클릭된 요소 클래스:', e.target.className);
                        console.log('🖱️ 클릭된 요소 태그:', e.target.tagName);

                        if (e.target.classList.contains('close-button') ||
                            e.target.closest('.close-button') ||
                            e.target.classList.contains('fa-times')) {

                            console.log('🚪🚪🚪 문서 레벨에서 닫기 버튼 클릭 감지! 🚪🚪🚪');

                            e.preventDefault();
                            e.stopPropagation();
                            this.handleCloseModal();
                        }

                    });

                    document.addEventListener('click', (e) => {
                        if (e.target.tagName === 'BUTTON') {
                            console.log('🔘 버튼 클릭 감지:', e.target);
                            console.log('🔘 버튼 클래스:', e.target.className);
                            console.log('🔘 버튼 내용:', e.target.innerHTML);
                        }
                    });

                    console.log('모든 클릭 감지 시스템 활성화 완료');

                    if (this.elements.generateByAiBtn) {
                        this.elements.generateByAiBtn.addEventListener('click', (e) => {
                            e.preventDefault();
                            this.handleGenerateByAI();
                        });
                        console.log('AI 생성 버튼 이벤트 리스너 추가 완료');
                    }

                    if (this.elements.aiEnabledCheckbox) {
                        this.elements.aiEnabledCheckbox.addEventListener('change', () => this.handleAiToggle());
                    }

                    // AI action checkboxes removed - isAllowed() only

                    if (this.elements.savePolicyBtn) {
                        this.elements.savePolicyBtn.addEventListener('click', () => this.handleSavePolicy());
                    }

                    if (this.elements.policyEffectSelect) {
                        this.elements.policyEffectSelect.addEventListener('change', () => {
                            this.syncAiActionsWithEffect();
                            this.ui.updatePreview(this.state);
                        });
                    }

                    ['rolesPalette', 'permissionsPalette', 'conditionsPalette'].forEach(jsKey => {
                        const element = this.elements[jsKey];
                        if (element) {
                            element.addEventListener('dragstart', this.handleDragStart.bind(this));
                        }
                    });

                    ['rolesCanvas', 'permissionsCanvas', 'conditionsCanvas'].forEach(jsKey => {
                        const canvas = this.elements[jsKey];
                        if (canvas) {
                            let type;
                            if (jsKey === 'rolesCanvas') type = 'role';
                            else if (jsKey === 'permissionsCanvas') type = 'permission';
                            else if (jsKey === 'conditionsCanvas') type = 'condition';

                            canvas.addEventListener('drop', async (e) => this.handleDrop(e, type));
                            canvas.addEventListener('dragover', this.allowDrop.bind(this));
                            canvas.addEventListener('dragleave', this.handleDragLeave.bind(this));
                        }
                    });

                    document.addEventListener('click', (e) => {
                        if (e.target.classList.contains('remove-chip-btn')) {
                            console.log('🖱️ 칩 X 버튼 클릭 감지:', e.target);
                            console.log('🖱️ 데이터:', { type: e.target.dataset.type, key: e.target.dataset.key });
                            this.handleChipRemove(e.target.dataset.type, e.target.dataset.key);
                        }
                    });
                }

                handleDragStart(e) {
                    const item = e.target.closest('.palette-item');
                    if (item?.classList.contains('disabled')) {
                        e.preventDefault();
                        return;
                    }
                    if (item) {
                        const info = item.dataset.info;
                        const type = item.dataset.type;
                        e.dataTransfer.setData("text/plain", info);
                        e.dataTransfer.setData("element-type", type);
                    }
                }

                allowDrop(e) {
                    e.preventDefault();
                    e.currentTarget.classList.add('drag-over');
                }

                handleDragLeave(e) {
                    e.currentTarget.classList.remove('drag-over');
                }

                async handleDrop(e, type) {
                    e.preventDefault();
                    e.currentTarget.classList.remove('drag-over');

                    if (this.isProcessingQuery || this.isStreaming) {
                        console.error('AI processing in progress, drop ignored');
                        this.showMessage('AI 분석이 진행 중입니다. 완료 후 다시 시도해주세요.', 'warning');
                        return;
                    }

                    const elementType = e.dataTransfer.getData("element-type");

                    if (elementType !== type) return;

                    const info = e.dataTransfer.getData("text/plain");
                    let id, name, targetType = '';
                    if (type === 'permission') {
                        const parts = info.split(':');
                        id = parts[0];
                        targetType = parts[1] || '';
                        name = parts.slice(2).join(':');
                    } else {
                        const [first, ...rest] = info.split(':');
                        id = first;
                        name = rest.join(':');
                    }

                    this.state.add(type, id, { id, name, targetType });
                    this.highlightPaletteItem(type, id);
                    this.ui.renderAll(this.state);
                }

                handleChipRemove(type, key) {
                    console.log(`🗑️ 칩 제거: ${type} ID=${key}`);

                    this.state.remove(type, key);

                    this.removeHighlightFromPaletteItem(type, key);

                    this.bruteForceRemoveSpecificHighlight(type, key);

                    this.ui.renderAll(this.state);

                    console.log(`칩 제거 완료: ${type} ID=${key}`);
                }

                bruteForceRemoveSpecificHighlight(type, id) {
                    console.log(`🔥 특정 하이라이트 브루트 포스 제거: ${type} ID=${id}`);

                    const targetItems = document.querySelectorAll(`[data-info^="${id}:"]`);

                    targetItems.forEach(item => {
                        if (item.classList.contains('palette-item')) {
                            console.log(`  ↳ 하이라이트 제거 대상: ${item.getAttribute('data-info')}`);

                            item.classList.remove('ai-selected');

                            const icon = item.querySelector('i');
                            if (icon) {
                                icon.className = '';
                                icon.classList.remove('text-green-400', 'fa-check-circle');
                                icon.removeAttribute('style');

                                const iconMap = {
                                    'role': 'fas fa-user-shield text-purple-400',
                                    'permission': 'fas fa-key text-yellow-400',
                                    'condition': 'fas fa-clock text-orange-400'
                                };
                                icon.className = iconMap[type] || icon.className;
                            }

                            const span = item.querySelector('span');
                            if (span) {
                                span.classList.remove('text-green-400', 'font-semibold');
                                span.removeAttribute('style');
                            }

                            item.removeAttribute('style');

                            console.log(`  ↳ 하이라이트 제거 완료: ${item.getAttribute('data-info')}`);
                        }
                    });
                }

                collectAvailableItems() {
                    const availableItems = {
                        roles: [],
                        permissions: [],
                        conditions: []
                    };

                    if (window.allRoles) {
                        availableItems.roles = window.allRoles.map(role => ({
                            id: role.id,
                            name: role.roleName,
                            description: role.description || ''
                        }));
                    }

                    if (window.allPermissions) {
                        availableItems.permissions = window.allPermissions.map(perm => ({
                            id: perm.id,
                            name: perm.friendlyName,
                            targetType: perm.targetType || '',
                            description: perm.description || ''
                        }));
                    }

                    if (window.allConditions) {
                        availableItems.conditions = window.allConditions.map(cond => ({
                            id: cond.id,
                            name: cond.name,
                            description: cond.description || '',
                            isCompatible: cond.isCompatible !== false
                        }));
                    }

                    console.log('📋 사용 가능한 항목들 수집 완료:', availableItems);
                    return availableItems;
                }

                async handleGenerateByAI() {

                    if (this.isProcessingQuery || this.isStreaming) {
                        this.showMessage('이미 AI 정책 생성이 진행 중입니다.', 'warning');
                        return;
                    }

                    const query = this.elements.naturalLanguageInput?.value;
                    if (!query || !query.trim()) {
                        this.showMessage('요구사항을 입력해주세요.', 'error');
                        return;
                    }

                    this.isProcessingQuery = true;
                    this.isStreaming = true;
                    this.ui.setLoading(this.elements.generateByAiBtn, true);

                    const availableItems = this.collectAvailableItems();

                    const queryMode = document.getElementById('ai-query-mode')?.value || 'streaming';

                    try {
                        if (queryMode === 'streaming') {

                            await this.startUnifiedStreamingAnalysisWithContexaLLM(query, availableItems);
                        } else {

                            await this.executeSyncAnalysisWithContexaLLM(query, availableItems);
                        }
                    } catch (error) {
                        console.error('AI policy generation failed:', error);
                        this.handleQueryError(error, query);
                    } finally {

                        this.isProcessingQuery = false;
                        this.isStreaming = false;
                        this.ui.setLoading(this.elements.generateByAiBtn, false);
                    }
                }

                async startUnifiedStreamingAnalysisWithContexaLLM(query, availableItems) {
                    const self = this;
                    let errorHandled = false;

                    const requestData = {
                        naturalLanguageQuery: query,
                        availableItems: availableItems
                    };

                    try {
                        await ContexaLLM.analyzeStreaming(
                            '/api/ai/policies/generate/stream',
                            requestData,
                            {
                                modalTitle: 'AI 정책 분석 진행 중',
                                initialLoadingText: 'AI가 정책 분석을 시작합니다...',
                                analysisCompleteText: 'LLM 분석 완료',
                                generatingResultText: '정책 데이터 생성중...',
                                finalCompleteText: 'AI 정책 분석 완료!',
                                autoHideDelay: 1500,
                                timeoutMs: 300000,
                                onProgress: (chunk) => {

                                },
                                onComplete: (response) => {
                                    self.handleAnalysisComplete(response, query);
                                },
                                onError: (error) => {
                                    if (!errorHandled) {
                                        errorHandled = true;
                                        console.error('Streaming analysis error:', error);
                                        self.handleQueryError(error, query);
                                    }
                                }
                            }
                        );
                    } catch (error) {
                        if (!errorHandled) {
                            throw error;
                        }
                    }
                }

                async executeSyncAnalysisWithContexaLLM(query, availableItems) {
                    const self = this;

                    const requestData = {
                        naturalLanguageQuery: query,
                        availableItems: availableItems
                    };

                    try {
                        const response = await ContexaLLM.analyze(
                            '/api/ai/policies/generate',
                            requestData,
                            {
                                showLoading: true,
                                container: document.querySelector('.policy-builder-container') || document.body,
                                loadingText: 'AI 정책 분석 중...',
                                subText: '잠시만 기다려 주세요',
                                onComplete: (result) => {

                                },
                                onError: (error) => {
                                    console.error('Sync analysis error:', error);
                                }
                            }
                        );

                        self.handleAnalysisComplete(response, query);

                    } catch (error) {
                        console.error('Sync analysis failed:', error);
                        self.handleQueryError(error, query);
                        throw error;
                    }
                }

                handleAnalysisComplete(response, query) {
                    if (response && !response.parseError) {
                        const processedResponse = this.preprocessPolicyResponse(response);

                        if (processedResponse && processedResponse.policyData) {
                            this.populateBuilderWithAIData(processedResponse);
                            this.showMessage('AI 정책 초안이 성공적으로 생성되었습니다!', 'success');
                        } else {
                            console.error('Processed response does not contain policyData:', processedResponse);
                            this.createFallbackPolicy(query);
                        }
                    } else if (response && response.parseError) {
                        console.error('JSON parse error:', response.errorMessage);
                        this.createFallbackPolicy(query);
                    } else {
                        console.warn('No response received from AI analysis');
                        this.showMessage('분석이 완료되었으나 결과가 없습니다.', 'warning');
                    }
                }

                createFallbackPolicy(query) {
                    console.error('AI response failed, creating fallback policy:', query);

                    const fallbackPolicyData = {
                        policyName: `AI Generated Policy (${new Date().toLocaleString()})`,
                        description: `Requirement: "${query}" - Default policy structure generated.`,
                        effect: 'ALLOW',
                        roleIds: [],
                        permissionIds: [],
                        conditions: {},
                        aiActionEnabled: false,
                        allowedActions: [],
                        customConditionSpel: '',
                        roleIdToNameMap: {},
                        permissionIdToNameMap: {},
                        conditionIdToNameMap: {}
                    };

                    const fallbackResponse = {
                        policyData: fallbackPolicyData,
                        roleIdToNameMap: {},
                        permissionIdToNameMap: {},
                        conditionIdToNameMap: {}
                    };

                    this.populateBuilderWithAIData(fallbackResponse);
                    this.showMessage('기본 정책이 생성되었습니다. 필요에 따라 수정해주세요.', 'warning');
                }



                handleQueryError(error, query) {
                    console.error('Policy generation error:', error);

                    let userMessage = 'AI 정책 생성에 실패했습니다';
                    let technicalDetails = '';

                    if (error instanceof TypeError) {
                        userMessage = '데이터 처리 중 오류가 발생했습니다';
                        technicalDetails = `TypeError: ${error.message}`;
                    } else if (error instanceof SyntaxError) {
                        userMessage = 'AI 응답 형식이 올바르지 않습니다';
                        technicalDetails = `SyntaxError: ${error.message}`;
                    } else if (error.name === 'NetworkError' || error.message?.includes('fetch')) {
                        userMessage = '네트워크 연결 오류가 발생했습니다';
                        technicalDetails = `Network: ${error.message}`;
                    } else if (error.message?.includes('JSON')) {
                        userMessage = 'AI 응답 파싱 중 오류가 발생했습니다';
                        technicalDetails = `JSON Parse: ${error.message}`;
                    } else {
                        userMessage = error.message || 'AI 정책 생성에 실패했습니다';
                        technicalDetails = error.toString();
                    }

                    this.showMessage(userMessage, 'error');

                    if (technicalDetails && technicalDetails !== userMessage) {
                        console.error('Technical details:', technicalDetails);
                    }

                    if (query) {
                        console.error('Failed query:', query.substring(0, 100) + (query.length > 100 ? '...' : ''));
                    }

                }

                createIdToNameMap(type, ids) {
                    if (!ids || !Array.isArray(ids)) return {};

                    const map = {};
                    const dataSource = type === 'role' ? window.allRoles :
                        type === 'permission' ? window.allPermissions :
                            type === 'condition' ? window.allConditions : [];

                    ids.forEach(id => {
                        const item = dataSource.find(item => item.id == id);
                        if (item) {
                            map[id] = type === 'role' ? item.roleName :
                                type === 'permission' ? item.friendlyName :
                                    type === 'condition' ? item.name : '';
                        }
                    });

                    return map;
                }

                validateAndFilterAIResponse(policyData) {
                    console.log('AI 응답 검증 시작:', policyData);

                    const availableItems = this.collectAvailableItems();
                    const validatedData = { ...policyData };

                    const availableRoleIds = new Set(availableItems.roles.map(r => r.id));
                    const availablePermissionIds = new Set(availableItems.permissions.map(p => p.id));
                    const availableConditionIds = new Set(availableItems.conditions.map(c => c.id));

                    if (validatedData.roleIds && Array.isArray(validatedData.roleIds)) {
                        const originalRoleIds = [...validatedData.roleIds];
                        validatedData.roleIds = validatedData.roleIds.filter(id => {
                            const exists = availableRoleIds.has(id);
                            if (!exists) {
                                console.warn(`존재하지 않는 역할 ID 제거: ${id}`);
                            }
                            return exists;
                        });

                        if (originalRoleIds.length !== validatedData.roleIds.length) {
                            console.log(`🔧 역할 필터링: ${originalRoleIds.length} → ${validatedData.roleIds.length}`);
                        }
                    }

                    if (validatedData.permissionIds && Array.isArray(validatedData.permissionIds)) {
                        const originalPermissionIds = [...validatedData.permissionIds];
                        validatedData.permissionIds = validatedData.permissionIds.filter(id => {
                            const exists = availablePermissionIds.has(id);
                            if (!exists) {
                                console.warn(`존재하지 않는 권한 ID 제거: ${id}`);
                            }
                            return exists;
                        });

                        if (originalPermissionIds.length !== validatedData.permissionIds.length) {
                            console.log(`🔧 권한 필터링: ${originalPermissionIds.length} → ${validatedData.permissionIds.length}`);
                        }
                    }

                    if (validatedData.conditions && typeof validatedData.conditions === 'object') {
                        const originalConditionIds = Object.keys(validatedData.conditions);
                        const filteredConditions = {};

                        originalConditionIds.forEach(id => {
                            if (availableConditionIds.has(parseInt(id))) {
                                filteredConditions[id] = validatedData.conditions[id];
                            } else {
                                console.warn(`존재하지 않는 조건 ID 제거: ${id}`);
                            }
                        });

                        validatedData.conditions = filteredConditions;

                        if (originalConditionIds.length !== Object.keys(filteredConditions).length) {
                            console.log(`🔧 조건 필터링: ${originalConditionIds.length} → ${Object.keys(filteredConditions).length}`);
                        }
                    }

                    console.log('AI 응답 검증 완료:', validatedData);
                    return validatedData;
                }

                preprocessPolicyResponse(response) {
                    console.log('🔥 [SERVER-RESPONSE] 정책 응답 전처리 시작:', response);

                    if (!response) {
                        console.error('응답이 없습니다');
                        return null;
                    }


                    if (response.policyData && response.roleIdToNameMap !== undefined) {
                        console.log('이미 올바른 AiGeneratedPolicyDraftDto 구조 (response 레벨)');
                        return {
                            policyData: response.policyData,
                            roleIdToNameMap: response.roleIdToNameMap || {},
                            permissionIdToNameMap: response.permissionIdToNameMap || {},
                            conditionIdToNameMap: response.conditionIdToNameMap || {}
                        };
                    }

                    if (response.policyData && response.policyData.roleIdToNameMap !== undefined) {
                        console.log('policyData 내부 통합 구조 감지 (서버 실제 응답)');
                        return {
                            policyData: response.policyData,
                            roleIdToNameMap: response.policyData.roleIdToNameMap || {},
                            permissionIdToNameMap: response.policyData.permissionIdToNameMap || {},
                            conditionIdToNameMap: response.policyData.conditionIdToNameMap || {}
                        };
                    }

                    if (response.policyName && response.roleIds !== undefined) {
                        console.log('BusinessPolicyDto 구조 감지 - AiGeneratedPolicyDraftDto로 래핑');
                        return {
                            policyData: response,
                            roleIdToNameMap: this.createIdToNameMap('role', response.roleIds || []),
                            permissionIdToNameMap: this.createIdToNameMap('permission', response.permissionIds || []),
                            conditionIdToNameMap: this.createIdToNameMap('condition', Object.keys(response.conditions || {}))
                        };
                    }

                    if (response.data && typeof response.data === 'object') {
                        console.log('중첩된 응답 구조 감지 - data 필드 추출');
                        return this.preprocessPolicyResponse(response.data);
                    }

                    if (response.generatedPolicy || response.policyConfidenceScore !== undefined) {
                        console.log('PolicyResponse 서버 구조 감지');

                        if (response.policyData) {
                            return {
                                policyData: response.policyData,
                                roleIdToNameMap: response.roleIdToNameMap || {},
                                permissionIdToNameMap: response.permissionIdToNameMap || {},
                                conditionIdToNameMap: response.conditionIdToNameMap || {}
                            };
                        }

                        if (typeof response.generatedPolicy === 'string') {
                            try {
                                const parsed = JSON.parse(response.generatedPolicy);
                                return this.preprocessPolicyResponse(parsed);
                            } catch (e) {
                                console.error('generatedPolicy 파싱 실패:', e.message);
                            }
                        }
                    }

                    console.error('알 수 없는 응답 구조:', Object.keys(response));
                    return null;
                }

                populateBuilderWithAIData(draftDto) {
                    console.log('🔥 AI 데이터로 빌더 채우기:', draftDto);

                    if (!draftDto) {
                        console.error('draftDto가 null 또는 undefined');
                        this.showMessage('AI 응답 데이터가 없습니다.', 'error');
                        return;
                    }

                    if (!draftDto.policyData) {
                        console.error('policyData가 없습니다. 응답 구조:', Object.keys(draftDto));
                        this.showMessage('AI가 정책 초안을 생성하지 못했습니다.', 'error');
                        return;
                    }

                    const policyData = draftDto.policyData;
                    if (!policyData.policyName && !policyData.description) {
                        console.error('policyData에 필수 필드가 없습니다:', policyData);
                        this.showMessage('AI가 생성한 정책 데이터가 불완전합니다.', 'error');
                        return;
                    }

                    console.log('데이터 검증 통과 - 빌더 채우기 시작');

                    const validatedData = this.validateAndFilterAIResponse(draftDto.policyData);
                    if (!validatedData) {
                        this.showMessage('AI 응답 검증에 실패했습니다.', 'error');
                        return;
                    }

                    const data = validatedData; // 검증된 데이터 사용
                    const maps = {
                        roles: draftDto.roleIdToNameMap || {},
                        permissions: draftDto.permissionIdToNameMap || {},
                        conditions: draftDto.conditionIdToNameMap || {}
                    };

                    console.log('🔥 이름 매핑 정보:', maps);

                    this.clearPaletteHighlights();

                    ['role', 'permission', 'condition'].forEach(type => this.state.clear(type));

                    if (this.elements.policyNameInput) {
                        this.elements.policyNameInput.value = data.policyName || '';
                    }
                    if (this.elements.policyDescTextarea) {
                        this.elements.policyDescTextarea.value = data.description || '';
                    }
                    if (this.elements.policyEffectSelect) {
                        this.elements.policyEffectSelect.value = data.effect || 'ALLOW';
                    }

                    const selectedRoleIds = [];
                    if (data.roleIds && Array.isArray(data.roleIds)) {
                        data.roleIds.forEach(id => {
                            const name = maps.roles[id] || `역할 (ID: ${id})`;
                            console.log(`🔥 역할 추가: ID=${id}, Name=${name}`);
                            this.state.add('role', String(id), { id, name });
                            selectedRoleIds.push(id);
                        });
                    }

                    const selectedPermissionIds = [];
                    if (data.permissionIds && Array.isArray(data.permissionIds)) {
                        data.permissionIds.forEach(id => {
                            const name = maps.permissions[id] || `권한 (ID: ${id})`;
                            const permItem = window.allPermissions?.find(p => p.id == id);
                            const targetType = permItem?.targetType || '';
                            console.log(`🔥 권한 추가: ID=${id}, Name=${name}`);
                            this.state.add('permission', String(id), { id, name, targetType });
                            selectedPermissionIds.push(id);
                        });
                    }

                    const selectedConditionIds = [];
                    if (data.conditions && typeof data.conditions === 'object') {
                        Object.keys(data.conditions).forEach(id => {
                            const name = maps.conditions[id] || `조건 (ID: ${id})`;
                            console.log(`🔥 조건 추가: ID=${id}, Name=${name}`);
                            this.state.add('condition', String(id), { id, name });
                            selectedConditionIds.push(id);
                        });
                    }

                    this.state.aiActionEnabled = data.aiActionEnabled || false;
                    this.state.allowedActions = this.state.aiActionEnabled ? ['ALLOW'] : [];
                    if (this.elements.aiEnabledCheckbox) {
                        this.elements.aiEnabledCheckbox.checked = this.state.aiActionEnabled;
                    }

                    this.handleAiToggle();
                    this.ui.renderAll(this.state);

                    console.log('🎨 UI 렌더링 완료, 하이라이트 적용 시작...');

                    setTimeout(() => {
                        selectedRoleIds.forEach(id => {
                            console.log(`🟢 역할 하이라이트 적용: ID=${id}`);
                            this.highlightPaletteItem('role', id);
                        });

                        selectedPermissionIds.forEach(id => {
                            console.log(`🟢 권한 하이라이트 적용: ID=${id}`);
                            this.highlightPaletteItem('permission', id);
                        });

                        selectedConditionIds.forEach(id => {
                            console.log(`🟢 조건 하이라이트 적용: ID=${id}`);
                            this.highlightPaletteItem('condition', id);
                        });

                        console.log('✨ 모든 하이라이트 적용 완료!');
                    }, 100); // 100ms 지연

                    console.log('🔥 최종 상태:', {
                        roles: Array.from(this.state.roles.entries()),
                        permissions: Array.from(this.state.permissions.entries()),
                        conditions: Array.from(this.state.conditions.entries())
                    });
                }

                highlightPaletteItem(type, id) {
                    const paletteMap = {
                        'role': '#roles-palette',
                        'permission': '#permissionsPalette',
                        'condition': '#conditionsPalette'
                    };

                    const paletteSelector = paletteMap[type];
                    if (!paletteSelector) return;

                    const palette = document.querySelector(paletteSelector);
                    if (!palette) return;

                    const paletteItems = palette.querySelectorAll('.palette-item');
                    paletteItems.forEach(item => {
                        const dataInfo = item.getAttribute('data-info');
                        if (dataInfo && dataInfo.startsWith(String(id) + ':')) {

                            item.classList.add('ai-selected');

                            const icon = item.querySelector('i');
                            if (icon) {
                                icon.className = 'fas fa-check-circle text-green-400';
                            }

                            const span = item.querySelector('span');
                            if (span) {
                                span.classList.add('text-green-400', 'font-semibold');
                            }

                            item.style.background = 'linear-gradient(135deg, rgba(34, 197, 94, 0.15), rgba(16, 185, 129, 0.1))';
                            item.style.borderColor = 'rgba(34, 197, 94, 0.4)';
                            item.style.boxShadow = '0 0 20px rgba(34, 197, 94, 0.3)';

                            console.log(`🟢 팔레트 하이라이트 적용: ${type} ID=${id}`);
                        }
                    });
                }

                clearPaletteHighlights() {
                    console.log('🧹 팔레트 하이라이트 제거 시작');
                    const palettes = ['#roles-palette', '#permissionsPalette', '#conditionsPalette'];
                    let totalCleared = 0;

                    const allHighlighted = document.querySelectorAll('.ai-selected');
                    console.log(`전체 페이지에서 ${allHighlighted.length}개 하이라이트 아이템 발견`);

                    allHighlighted.forEach(item => {
                        const dataInfo = item.getAttribute('data-info');
                        const type = item.getAttribute('data-type');
                        console.log(`🧹 전역 하이라이트 제거 중: ${dataInfo} (타입: ${type})`);

                        item.classList.remove('ai-selected');

                        const icon = item.querySelector('i');
                        if (icon && type) {

                            icon.className = '';

                            icon.classList.remove('text-green-400', 'fa-check-circle', 'fas', 'fa-user-shield', 'fa-key', 'fa-clock');

                            const iconMap = {
                                'role': 'fas fa-user-shield text-purple-400',
                                'permission': 'fas fa-key text-yellow-400',
                                'condition': 'fas fa-clock text-orange-400'
                            };
                            const originalIconClass = iconMap[type];
                            icon.className = originalIconClass;

                            icon.removeAttribute('style');
                            console.log(`🎨 아이콘 완전 복원: ${originalIconClass}`);
                        }

                        const span = item.querySelector('span');
                        if (span) {
                            span.classList.remove('text-green-400', 'font-semibold');

                            span.removeAttribute('style');
                            console.log('텍스트 스타일 완전 복원');
                        }

                        item.style.background = '';
                        item.style.borderColor = '';
                        item.style.boxShadow = '';
                        item.style.border = '';
                        item.style.transform = '';
                        item.style.filter = '';

                        item.removeAttribute('style');
                        console.log('🎨 모든 인라인 스타일 완전 제거');

                        totalCleared++;
                    });

                    palettes.forEach(paletteSelector => {
                        const palette = document.querySelector(paletteSelector);
                        if (!palette) {
                            console.log(`팔레트 찾을 수 없음: ${paletteSelector}`);
                            return;
                        }

                        const allItems = palette.querySelectorAll('.palette-item');
                        console.log(`${paletteSelector}에서 총 ${allItems.length}개 아이템 검사`);

                        allItems.forEach(item => {
                            const hasGreenIcon = item.querySelector('i.text-green-400');
                            const hasGreenText = item.querySelector('span.text-green-400');
                            const hasGreenBg = item.style.background && item.style.background.includes('rgba(34, 197, 94');
                            const isPreselected = item.classList.contains('preselected');

                            const allGreenTexts = item.querySelectorAll('.text-green-400');
                            const hasAnyGreenText = allGreenTexts.length > 0;

                            if (hasGreenIcon || hasGreenText || hasGreenBg || hasAnyGreenText || isPreselected) {
                                const dataInfo = item.getAttribute('data-info');
                                const type = item.getAttribute('data-type');
                                console.log(`🧹 잔여 초록 스타일 제거: ${dataInfo} (초록텍스트: ${allGreenTexts.length}개, preselected: ${isPreselected})`);

                                const icon = item.querySelector('i');
                                if (icon) {

                                    icon.className = '';

                                    icon.classList.remove('text-green-400', 'fa-check-circle', 'fas', 'fa-user-shield', 'fa-key', 'fa-clock');

                                    icon.removeAttribute('style');

                                    if (type) {
                                        const iconMap = {
                                            'role': 'fas fa-user-shield text-purple-400',
                                            'permission': 'fas fa-key text-yellow-400',
                                            'condition': 'fas fa-clock text-orange-400'
                                        };
                                        icon.className = iconMap[type];
                                        console.log(`  ↳ 아이콘 완전 복원: ${iconMap[type]}`);
                                    }
                                }

                                allGreenTexts.forEach(greenElement => {
                                    greenElement.classList.remove('text-green-400', 'font-semibold');
                                    console.log(`  ↳ 초록 텍스트 제거: ${greenElement.tagName}`);
                                });

                                const span = item.querySelector('span');
                                if (span) {
                                    span.classList.remove('text-green-400', 'font-semibold');

                                    span.removeAttribute('style');
                                    console.log(`  ↳ 텍스트 스타일 완전 제거`);
                                }

                                item.style.background = '';
                                item.style.borderColor = '';
                                item.style.boxShadow = '';
                                item.style.border = '';
                                item.style.transform = '';
                                item.style.filter = '';

                                item.removeAttribute('style');
                                item.classList.remove('ai-selected');
                                console.log(`  ↳ 모든 인라인 스타일 완전 제거`);

                                if (isPreselected) {
                                    console.log(`  ↳ preselected 클래스 제거`);

                                }

                                totalCleared++;
                            }
                        });
                    });

                    console.log(`총 ${totalCleared}개 팔레트 하이라이트 제거 완료`);

                    this.bruteForceRemoveAllHighlights();
                }

                bruteForceRemoveAllHighlights() {
                    console.log('🔥 브루트 포스 하이라이트 제거 시작');

                    document.querySelectorAll('.ai-selected').forEach(element => {
                        element.classList.remove('ai-selected');
                        element.removeAttribute('style');
                        console.log('  ↳ ai-selected 제거:', element.getAttribute('data-info'));
                    });

                    document.querySelectorAll('.text-green-400').forEach(element => {
                        element.classList.remove('text-green-400', 'font-semibold');
                        element.removeAttribute('style');
                        console.log('  ↳ text-green-400 제거:', element.tagName);
                    });

                    document.querySelectorAll('.fa-check-circle').forEach(icon => {
                        const paletteItem = icon.closest('.palette-item');
                        if (paletteItem && !paletteItem.classList.contains('preselected')) {
                            const type = paletteItem.getAttribute('data-type');
                            icon.className = '';
                            icon.removeAttribute('style');

                            if (type) {
                                const iconMap = {
                                    'role': 'fas fa-user-shield text-purple-400',
                                    'permission': 'fas fa-key text-yellow-400',
                                    'condition': 'fas fa-clock text-orange-400'
                                };
                                icon.className = iconMap[type];
                                console.log('  ↳ 아이콘 복원:', iconMap[type]);
                            }
                        }
                    });

                    document.querySelectorAll('.palette-item').forEach(item => {
                        if (item.style.background || item.style.borderColor || item.style.boxShadow) {
                            item.removeAttribute('style');
                            console.log('  ↳ palette-item 스타일 제거:', item.getAttribute('data-info'));
                        }
                    });

                    console.log('🔥 브루트 포스 하이라이트 제거 완료');
                }

                removeHighlightFromPaletteItem(type, id) {
                    const paletteMap = {
                        'role': '#roles-palette',
                        'permission': '#permissionsPalette',
                        'condition': '#conditionsPalette'
                    };

                    const paletteSelector = paletteMap[type];
                    if (!paletteSelector) return;

                    const palette = document.querySelector(paletteSelector);
                    if (!palette) return;

                    const paletteItems = palette.querySelectorAll('.palette-item');
                    paletteItems.forEach(item => {
                        const dataInfo = item.getAttribute('data-info');
                        if (dataInfo && dataInfo.startsWith(id + ':')) {

                            item.classList.remove('ai-selected');

                            const icon = item.querySelector('i');
                            const itemType = item.getAttribute('data-type');
                            if (icon && itemType) {

                                icon.className = '';

                                icon.classList.remove('text-green-400', 'fa-check-circle', 'fas', 'fa-user-shield', 'fa-key', 'fa-clock');

                                icon.removeAttribute('style');

                                const iconMap = {
                                    'role': 'fas fa-user-shield text-purple-400',
                                    'permission': 'fas fa-key text-yellow-400',
                                    'condition': 'fas fa-clock text-orange-400'
                                };
                                icon.className = iconMap[itemType] || icon.className;
                            }

                            const span = item.querySelector('span');
                            if (span) {
                                span.classList.remove('text-green-400', 'font-semibold');

                                span.removeAttribute('style');
                            }

                            item.style.background = '';
                            item.style.borderColor = '';
                            item.style.boxShadow = '';
                            item.style.border = '';
                            item.style.transform = '';
                            item.style.filter = '';

                            item.removeAttribute('style');

                            console.log(`🔴 팔레트 하이라이트 제거: ${type} ID=${id}`);
                        }
                    });
                }

                handleAiToggle() {
                    if (this.elements.aiEnabledCheckbox) {
                        this.state.aiActionEnabled = this.elements.aiEnabledCheckbox.checked;
                    }
                    if (this.elements.aiActionContainer) {
                        this.elements.aiActionContainer.classList.toggle('hidden', !this.state.aiActionEnabled);
                    }
                    // AI enabled = always use isAllowed() only
                    this.state.allowedActions = this.state.aiActionEnabled ? ['ALLOW'] : [];
                    this.ui.updatePreview(this.state);
                }

                syncAiActionsWithEffect() {
                    // AI action is always isAllowed(), no effect-based filtering needed
                }

                handleAiActionChange() {
                    // AI action is always isAllowed() only, no checkboxes to process
                }

                async handleSavePolicy() {
                    const dto = this.state.toDto();

                    if (!dto.policyName) {
                        this.showMessage('정책 이름은 필수입니다.', 'error');
                        return;
                    }
                    if (dto.roleIds.length === 0) {
                        this.showMessage('하나 이상의 역할을 선택해야 합니다.', 'error');
                        return;
                    }
                    if (dto.permissionIds.length === 0) {
                        this.showMessage('하나 이상의 권한을 선택해야 합니다.', 'error');
                        return;
                    }

                    this.ui.setLoading(this.elements.savePolicyBtn, true);
                    try {
                        const result = await this.api.savePolicy(dto);
                        this.showMessage(`정책 "${result.name}"이(가) 성공적으로 생성되었습니다.`, 'success');
                        setTimeout(() => window.location.href = '/admin/policies', 1500);
                    } catch (error) {
                        console.error('정책 저장 오류:', error);
                        this.showMessage('정책 저장 중 오류가 발생했습니다.', 'error');
                    } finally {
                        this.ui.setLoading(this.elements.savePolicyBtn, false);
                    }
                }

                initializeFromContext() {
                    if (window.resourceContext) {
                        const availableParamTypes = new Set(
                            (window.resourceContext.parameterTypes || []).map(p => p.type)
                        );
                        if (window.resourceContext.returnObjectType) {
                            availableParamTypes.add(window.resourceContext.returnObjectType);
                        }

                        this.elements.conditionsPalette.querySelectorAll('.palette-item').forEach(item => {

                            const requiredType = item.dataset.requiredType;

                            if (requiredType && !availableParamTypes.has(requiredType)) {
                                item.classList.add('disabled'); // 호환되지 않으면 비활성화
                                item.title = `이 조건은 '${requiredType}' 타입의 정보가 필요하지만, 현재 리소스는 제공하지 않습니다.`;
                            }
                        });
                    }
                    if (window.preselectedPermission) {
                        const perm = window.preselectedPermission;
                        this.state.add('permission', String(perm.id), { id: perm.id, name: perm.friendlyName, targetType: perm.targetType || '' });
                    }
                }

                showMessage(message, type) {
                    if (typeof showToast === 'function') {
                        showToast(message, type);
                    } else {

                        this.showToast(message, type);
                    }
                }

                showToast(message, type = 'info') {

                    const existingToast = document.querySelector('.policy-toast');
                    if (existingToast) {
                        existingToast.remove();
                    }

                    const toast = document.createElement('div');
                    toast.className = `policy-toast toast-${type}`;

                    const icons = {
                        success: 'fas fa-check-circle',
                        error: 'fas fa-exclamation-circle',
                        warning: 'fas fa-exclamation-triangle',
                        info: 'fas fa-info-circle'
                    };

                    const colors = {
                        success: 'bg-green-500',
                        error: 'bg-red-500',
                        warning: 'bg-yellow-500',
                        info: 'bg-blue-500'
                    };

                    toast.innerHTML = `
                        <div class="flex items-center space-x-3 p-4 rounded-lg shadow-lg ${colors[type] || colors.info} text-white">
                            <i class="${icons[type] || icons.info}"></i>
                            <span class="font-medium">${message}</span>
                        </div>
                    `;

                    toast.style.cssText = `
                        position: fixed;
                        top: 20px;
                        right: 20px;
                        z-index: 10000;
                        opacity: 0;
                        transform: translateX(100%);
                        transition: all 0.3s ease-in-out;
                        max-width: 400px;
                    `;

                    document.body.appendChild(toast);

                    setTimeout(() => {
                        toast.style.opacity = '1';
                        toast.style.transform = 'translateX(0)';
                    }, 10);

                    setTimeout(() => {
                        toast.style.opacity = '0';
                        toast.style.transform = 'translateX(100%)';
                        setTimeout(() => {
                            if (toast.parentNode) {
                                toast.parentNode.removeChild(toast);
                            }
                        }, 300);
                    }, 3000);
                }

                handleCloseModal() {
                    console.log('🚪🚪🚪 모달 닫기 메서드 호출됨 🚪🚪🚪');
                    console.log('🚪 현재 시간:', new Date().toLocaleTimeString());

                    try {

                        console.log('📊 닫기 전 하이라이트 상태:');
                        this.checkHighlightStatus();

                        this.resetAllStates();
                        console.log('상태 초기화 완료');

                        console.log('📊 초기화 후 하이라이트 상태:');
                        this.checkHighlightStatus();

                        console.log('🚪 정책 빌더 페이지를 닫습니다');
                        window.close();

                        setTimeout(() => {
                            console.log('🚪 페이지 닫기 시도');
                            window.close();

                            setTimeout(() => {
                                if (!window.closed) {
                                    console.log('🔙 뒤로가기 실행');
                                    window.history.back();
                                }
                            }, 100);
                        }, 100);

                    } catch (error) {
                        console.error('모달 닫기 중 오류:', error);

                        window.close();
                        if (!window.closed) window.history.back();
                    }
                }

                checkHighlightStatus() {
                    console.log('현재 하이라이트 상태 확인');
                    const aiSelected = document.querySelectorAll('.ai-selected');
                    const greenIcons = document.querySelectorAll('i.text-green-400');
                    const greenTexts = document.querySelectorAll('span.text-green-400');
                    const preselectedItems = document.querySelectorAll('.preselected');
                    const allGreenElements = document.querySelectorAll('.text-green-400');

                    console.log(`ai-selected 클래스: ${aiSelected.length}개`);
                    console.log(`초록 아이콘: ${greenIcons.length}개`);
                    console.log(`초록 텍스트: ${greenTexts.length}개`);
                    console.log(`preselected 아이템: ${preselectedItems.length}개`);
                    console.log(`모든 초록 요소: ${allGreenElements.length}개`);

                    aiSelected.forEach((item, i) => {
                        console.log(`${i+1}. ${item.getAttribute('data-info')} (${item.getAttribute('data-type')})`);
                    });

                    if (allGreenElements.length > 0) {
                        console.log('🟢 모든 초록 요소 상세:');
                        allGreenElements.forEach((element, i) => {
                            const parent = element.closest('.palette-item');
                            const dataInfo = parent ? parent.getAttribute('data-info') : 'N/A';
                            const isPreselected = parent ? parent.classList.contains('preselected') : false;
                            console.log(`  ${i+1}. ${element.tagName} - ${dataInfo} (preselected: ${isPreselected})`);
                        });
                    }

                    return {
                        aiSelected: aiSelected.length,
                        greenIcons: greenIcons.length,
                        greenTexts: greenTexts.length,
                        preselected: preselectedItems.length,
                        allGreen: allGreenElements.length
                    };
                }

                resetAllStates() {
                    console.log('🧹 모달 닫기 - 모든 상태 초기화 시작');

                    console.log('1️⃣ 팔레트 하이라이트 제거 중...');
                    this.clearPaletteHighlights();

                    ['role', 'permission', 'condition'].forEach(type => this.state.clear(type));

                    if (this.elements.policyNameInput) {
                        this.elements.policyNameInput.value = '';
                    }
                    if (this.elements.policyDescTextarea) {
                        this.elements.policyDescTextarea.value = '';
                    }
                    if (this.elements.policyEffectSelect) {
                        this.elements.policyEffectSelect.value = 'ALLOW';
                    }
                    if (this.elements.naturalLanguageInput) {
                        this.elements.naturalLanguageInput.value = '';
                    }
                    if (this.elements.customSpelInput) {
                        this.elements.customSpelInput.value = '';
                    }

                    this.state.aiActionEnabled = false;
                    this.state.allowedActions = [];

                    if (this.elements.aiEnabledCheckbox) {
                        this.elements.aiEnabledCheckbox.checked = false;
                    }

                    const thoughtContainer = document.getElementById('ai-thought-process-container');
                    if (thoughtContainer) {
                        thoughtContainer.classList.add('hidden');
                        const thoughtLog = document.getElementById('ai-thought-process');
                        if (thoughtLog) {
                            thoughtLog.innerHTML = '';
                        }
                    }

                    this.handleAiToggle();
                    this.ui.renderAll(this.state);

                    console.log('모든 상태 초기화 완료');
                }
            }

            const policyBuilderApp = new PolicyBuilderApp();

            window.resetPolicyBuilderStates = () => {
                if (policyBuilderApp) {
                    policyBuilderApp.isProcessingQuery = false;
                    policyBuilderApp.isStreaming = false;
                    if (policyBuilderApp.ui && policyBuilderApp.elements.generateByAiBtn) {
                        policyBuilderApp.ui.setLoading(policyBuilderApp.elements.generateByAiBtn, false);
                    }
                    console.log('🔥 전역 함수에서 AI 처리 상태 강제 초기화 완료');
                }

                policyBuilderApp.resetAllStates();
            };
            window.testHighlightClear = () => {
                console.log('🧪 하이라이트 제거 테스트 시작');
                policyBuilderApp.clearPaletteHighlights();
                console.log('🧪 하이라이트 제거 테스트 완료');
            };

            window.bruteForceRemoveHighlights = () => {
                console.log('🔥 전역 브루트 포스 하이라이트 제거 시작');

                document.querySelectorAll('.ai-selected').forEach(element => {
                    element.classList.remove('ai-selected');
                    element.removeAttribute('style');
                    console.log('  ↳ ai-selected 제거:', element.getAttribute('data-info'));
                });

                document.querySelectorAll('.text-green-400').forEach(element => {
                    const paletteItem = element.closest('.palette-item');
                    if (!paletteItem || !paletteItem.classList.contains('preselected')) {
                        element.classList.remove('text-green-400', 'font-semibold');
                        element.removeAttribute('style');
                        console.log('  ↳ text-green-400 제거:', element.tagName);
                    }
                });

                document.querySelectorAll('.fa-check-circle').forEach(icon => {
                    const paletteItem = icon.closest('.palette-item');
                    if (paletteItem && !paletteItem.classList.contains('preselected')) {
                        const type = paletteItem.getAttribute('data-type');
                        icon.className = '';
                        icon.removeAttribute('style');

                        if (type) {
                            const iconMap = {
                                'role': 'fas fa-user-shield text-purple-400',
                                'permission': 'fas fa-key text-yellow-400',
                                'condition': 'fas fa-clock text-orange-400'
                            };
                            icon.className = iconMap[type];
                            console.log('  ↳ 아이콘 복원:', iconMap[type]);
                        }
                    }
                });

                document.querySelectorAll('.palette-item').forEach(item => {
                    if (item.style.background || item.style.borderColor || item.style.boxShadow) {
                        item.removeAttribute('style');
                        console.log('  ↳ palette-item 스타일 제거:', item.getAttribute('data-info'));
                    }
                });

                console.log('🔥 전역 브루트 포스 하이라이트 제거 완료');
            };

            window.checkHighlightStatus = () => {
                console.log('현재 하이라이트 상태 확인');
                const aiSelected = document.querySelectorAll('.ai-selected');
                const greenIcons = document.querySelectorAll('i.text-green-400');
                const greenTexts = document.querySelectorAll('span.text-green-400');
                const preselectedItems = document.querySelectorAll('.preselected');
                const allGreenElements = document.querySelectorAll('.text-green-400');

                console.log(`ai-selected 클래스: ${aiSelected.length}개`);
                console.log(`초록 아이콘: ${greenIcons.length}개`);
                console.log(`초록 텍스트: ${greenTexts.length}개`);
                console.log(`preselected 아이템: ${preselectedItems.length}개`);
                console.log(`모든 초록 요소: ${allGreenElements.length}개`);

                aiSelected.forEach((item, i) => {
                    console.log(`${i+1}. ${item.getAttribute('data-info')} (${item.getAttribute('data-type')})`);
                });

                if (allGreenElements.length > 0) {
                    console.log('🟢 모든 초록 요소 상세:');
                    allGreenElements.forEach((element, i) => {
                        const parent = element.closest('.palette-item');
                        const dataInfo = parent ? parent.getAttribute('data-info') : 'N/A';
                        const isPreselected = parent ? parent.classList.contains('preselected') : false;
                        console.log(`  ${i+1}. ${element.tagName} - ${dataInfo} (preselected: ${isPreselected})`);
                    });
                }

                return {
                    aiSelected: aiSelected.length,
                    greenIcons: greenIcons.length,
                    greenTexts: greenTexts.length,
                    preselected: preselectedItems.length,
                    allGreen: allGreenElements.length
                };
            };
            window.handleCloseModal = () => {
                console.log('🚪 모달 닫기 버튼 클릭됨');

                try {
                    console.log('📊 닫기 전 하이라이트 상태:');
                    window.checkHighlightStatus();

                    if (policyBuilderApp) {
                        policyBuilderApp.isProcessingQuery = false;
                        policyBuilderApp.isStreaming = false;
                        if (policyBuilderApp.ui && policyBuilderApp.elements.generateByAiBtn) {
                            policyBuilderApp.ui.setLoading(policyBuilderApp.elements.generateByAiBtn, false);
                        }
                        console.log('🔥 AI 처리 상태 강제 초기화 완료');
                    }

                    if (typeof window.resetPolicyBuilderStates === 'function') {
                        window.resetPolicyBuilderStates();
                        console.log('상태 초기화 완료');

                        console.log('📊 초기화 후 하이라이트 상태:');
                        window.checkHighlightStatus();
                    }

                    setTimeout(() => {
                        console.log('🚪 페이지 닫기 시도');
                        window.close();
                        setTimeout(() => {
                            if (!window.closed) {
                                console.log('🔙 뒤로가기 실행');
                                window.history.back();
                            }
                        }, 100);
                    }, 100);

                } catch (error) {
                    console.error('모달 닫기 중 오류:', error);
                    window.close();
                    if (!window.closed) window.history.back();
                }
            };

            window.addEventListener('beforeunload', () => {
                policyBuilderApp.resetAllStates();
            });

            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    policyBuilderApp.handleCloseModal();
                }
            });

            console.log('🌟 PolicyBuilderApp 초기화 성공!');
        } catch (error) {
            console.error('PolicyBuilderApp 초기화 실패:', error);
        }
    });
})();
