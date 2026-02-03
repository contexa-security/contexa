/**
 * [완벽한 스트리밍 시스템] 지능형 정책 빌더 클라이언트 애플리케이션
 * - 한글 마커 지원 (===JSON_START===, ===JSON_END===)
 * - 자연스러운 한국어 AI 응답 처리
 * - 향상된 키워드 매핑 로직
 */

(() => {
    console.log('🌟 policy-builder.js 스크립트 로드됨');

    document.addEventListener('DOMContentLoaded', () => {
        console.log('🌟 DOMContentLoaded 이벤트 발생 - PolicyBuilderApp 초기화 시작');

        try {
            // --- 1. 상태 관리 클래스 ---
            class PolicyBuilderState {
                constructor() {
                    this.roles = new Map();
                    this.permissions = new Map();
                    this.conditions = new Map();
                    this.aiRiskAssessmentEnabled = false;
                    this.requiredTrustScore = 0.7;
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
                        aiRiskAssessmentEnabled: this.aiRiskAssessmentEnabled,
                        requiredTrustScore: this.requiredTrustScore,
                        customConditionSpel: customSpelEl?.value?.trim() || ''
                    };
                }
            }

            // --- 2. UI 렌더링 클래스 ---
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

                // PolicyBuilderUI 클래스의 renderChipZone 메서드 수정
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

                        // 버튼에 직접 이벤트 리스너 추가
                        removeBtn.addEventListener('click', () => {
                            const event = new CustomEvent('removeChip', {
                                detail: { type, key: String(key) }
                            });
                            document.dispatchEvent(event);
                        });

                        chip.appendChild(document.createTextNode(value.name + ' '));
                        chip.appendChild(removeBtn);

                        canvasEl.appendChild(chip);
                    });
                }

                updatePreview(state) {
                    if (!this.elements.policyPreview) return;

                    const rolesHtml = Array.from(state.roles.values()).map(r => `<span class="policy-chip-preview">${r.name}</span>`).join(' 또는 ') || '<span class="text-gray-400">모든 역할</span>';
                    const permissionsHtml = Array.from(state.permissions.values()).map(p => `<span class="policy-chip-preview">${p.name}</span>`).join(' 그리고 ') || '<span class="text-gray-400">모든 권한</span>';
                    const conditionsHtml = Array.from(state.conditions.values()).map(c => `<span class="policy-chip-preview condition">${c.name}</span>`).join(' 그리고 ');
                    const aiConditionHtml = state.aiRiskAssessmentEnabled ? `<span class="policy-chip-preview ai">AI 신뢰도 ${Math.round(state.requiredTrustScore * 100)}점 이상</span>` : '';
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

            // --- 3. API 통신 클래스 ---
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



                /**
                 * 3단계: 특정 리소스에 대한 실시간 조건 추천 API 호출
                 */
                async recommendConditions(resourceIdentifier, context = "") {
                    return this.fetchApi('/api/ai/policies/recommend-conditions', {
                        method: 'POST',
                        body: JSON.stringify({
                            resourceIdentifier: resourceIdentifier,
                            context: context
                        })
                    });
                }

                /**
                 * 개선: 권한명 기반 스마트 조건 매칭 API 호출
                 */
                async smartMatchConditions(permissionName, resourceIdentifier, context = "") {
                    return this.fetchApi('/api/ai/policies/smart-match-conditions', {
                        method: 'POST',
                        body: JSON.stringify({
                            permissionName: permissionName,
                            resourceIdentifier: resourceIdentifier,
                            context: context
                        })
                    });
                }

                savePolicy(dto) {
                    return this.fetchApi('/api/policies/build-from-business-rule', {
                        method: 'POST',
                        body: JSON.stringify(dto)
                    });
                }

                async generatePolicyFromText(query, availableItems = null) {
                    const requestBody = {
                        naturalLanguageQuery: query
                    };

                    // 사용 가능한 항목들이 있으면 포함
                    if (availableItems) {
                        requestBody.availableItems = availableItems;
                        console.log('🎯 AI에게 사용 가능한 항목들 전송:', availableItems);
                    }

                    return this.fetchApi('/api/ai/policies/generate-from-text', {
                        method: 'POST',
                        body: JSON.stringify(requestBody)
                    });
                }

                async generatePolicyFromTextStream(query, availableItems = null) {
                    const headers = {
                        'Content-Type': 'application/json',
                        'Accept': 'text/event-stream',
                        'Cache-Control': 'no-cache'
                    };

                    if (this.csrfToken && this.csrfHeader) {
                        headers[this.csrfHeader] = this.csrfToken;
                    }

                    const requestBody = {
                        naturalLanguageQuery: query
                    };

                    // 사용 가능한 항목들이 있으면 포함
                    if (availableItems) {
                        requestBody.availableItems = availableItems;
                        console.log('🎯 스트리밍 AI에게 사용 가능한 항목들 전송:', availableItems);
                    }

                    return fetch('/api/ai/policies/generate-from-text/stream', {
                        method: 'POST',
                        headers: headers,
                        body: JSON.stringify(requestBody)
                    });
                }
            }

            // --- 4. 메인 애플리케이션 클래스 ---
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
                        // AI 기능 UI
                        naturalLanguageInput: 'naturalLanguageInput',
                        generateByAiBtn: 'generateByAiBtn',
                        thoughtProcessContainer: 'ai-thought-process-container',
                        thoughtProcessLog: 'ai-thought-process',
                        aiEnabledCheckbox: 'aiEnabledCheckbox',
                        trustScoreContainer: 'trustScoreContainer',
                        trustScoreSlider: 'trustScoreSlider',
                        trustScoreValueSpan: 'trustScoreValueSpan',
                        customSpelInput: 'customSpelInput',
                        // 팔레트
                        rolesPalette: 'roles-palette',
                        permissionsPalette: 'permissionsPalette',
                        conditionsPalette: 'conditionsPalette',
                        // 캔버스
                        rolesCanvas: 'roles-canvas',
                        permissionsCanvas: 'permissions-canvas',
                        conditionsCanvas: 'conditions-canvas',
                        // 속성 및 저장
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

                    // 닫기 버튼 상태 확인
                    this.debugCloseButton();

                    if (!this.elements.savePolicyBtn) {
                        console.error("정책 빌더의 필수 UI 요소(저장 버튼)를 찾을 수 없습니다.");
                        return;
                    }

                    this.bindEventListeners();
                    this.initializeFromContext();
                    this.ui.renderAll(this.state);

                    console.log('=== PolicyBuilderApp init 완료 ===');
                }

                /**
                 * 닫기 버튼 디버깅 함수
                 */
                debugCloseButton() {
                    console.log('닫기 버튼 디버깅 시작');

                    // 1. 모든 버튼 찾기
                    const allButtons = document.querySelectorAll('button');
                    console.log('🔘 페이지의 모든 버튼 개수:', allButtons.length);

                    allButtons.forEach((btn, i) => {
                        console.log(`  ${i+1}. 버튼 클래스: "${btn.className}", 내용: "${btn.innerHTML.substring(0, 50)}"`);
                    });

                    // 2. 닫기 버튼 찾기
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

                    // 3. close-button 클래스를 가진 모든 요소 찾기
                    const allCloseButtons = document.querySelectorAll('.close-button');
                    console.log('🚪 close-button 클래스 요소 개수:', allCloseButtons.length);

                    // 4. fa-times 아이콘 찾기
                    const timesIcons = document.querySelectorAll('.fa-times');
                    console.log('fa-times 아이콘 개수:', timesIcons.length);

                    console.log('닫기 버튼 디버깅 완료');
                }

                bindEventListeners() {
                    // 🔥 닫기 버튼 테스트를 위한 강력한 이벤트 리스너
                    console.log('닫기 버튼 이벤트 리스너 설정 시작');

                    // 방법 1: 직접 선택자로 찾기
                    const closeButton = document.querySelector('.close-button');
                    console.log('닫기 버튼 검색 결과:', closeButton);
                    console.log('닫기 버튼 HTML:', closeButton ? closeButton.outerHTML : 'null');

                    if (closeButton) {
                        // 테스트용 간단한 클릭 이벤트
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

                    // 방법 2: 전체 문서에서 모든 클릭 감지 (백업)
                    document.addEventListener('click', (e) => {
                        console.log('🖱️ 문서 클릭 감지:', e.target);
                        console.log('🖱️ 클릭된 요소 클래스:', e.target.className);
                        console.log('🖱️ 클릭된 요소 태그:', e.target.tagName);

                        // 닫기 버튼 관련 클릭인지 확인
                        if (e.target.classList.contains('close-button') ||
                            e.target.closest('.close-button') ||
                            e.target.classList.contains('fa-times')) {

                            console.log('🚪🚪🚪 문서 레벨에서 닫기 버튼 클릭 감지! 🚪🚪🚪');

                            e.preventDefault();
                            e.stopPropagation();
                            this.handleCloseModal();
                        }
                        
                        // 🔥 스트리밍 모달 클릭 감지
                        if (e.target.classList.contains('streaming-modal') ||
                            e.target.classList.contains('streaming-close-btn') ||
                            e.target.closest('.streaming-close-btn')) {
                            
                            console.log('🔥 스트리밍 모달 클릭 감지 - 강제 숨기기 실행');
                            
                            e.preventDefault();
                            e.stopPropagation();
                            
                            if (typeof window.forceHideStreamingModal === 'function') {
                                window.forceHideStreamingModal();
                            }
                        }
                    });

                    // 방법 3: 모든 버튼 클릭 감지
                    document.addEventListener('click', (e) => {
                        if (e.target.tagName === 'BUTTON') {
                            console.log('🔘 버튼 클릭 감지:', e.target);
                            console.log('🔘 버튼 클래스:', e.target.className);
                            console.log('🔘 버튼 내용:', e.target.innerHTML);
                        }
                    });

                    console.log('모든 클릭 감지 시스템 활성화 완료');

                    // AI 기능 이벤트 리스너
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

                    if (this.elements.trustScoreSlider) {
                        this.elements.trustScoreSlider.addEventListener('input', () => this.handleTrustSlider());
                    }

                    if (this.elements.savePolicyBtn) {
                        this.elements.savePolicyBtn.addEventListener('click', () => this.handleSavePolicy());
                    }

                    if (this.elements.policyEffectSelect) {
                        this.elements.policyEffectSelect.addEventListener('change', () => this.ui.updatePreview(this.state));
                    }

                    // 드래그 앤 드롭 리스너 등록
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

                    // 칩 제거 리스너 (통합 버전)
                    document.addEventListener('click', (e) => {
                        if (e.target.classList.contains('remove-chip-btn')) {
                            console.log('🖱️ 칩 X 버튼 클릭 감지:', e.target);
                            console.log('🖱️ 데이터:', { type: e.target.dataset.type, key: e.target.dataset.key });
                            this.handleChipRemove(e.target.dataset.type, e.target.dataset.key);
                        }
                    });

                    // 커스텀 이벤트는 주석 처리 (중복 방지)
                    // document.addEventListener('removeChip', (e) => {
                    //     const { type, key } = e.detail;
                    //     this.handleChipRemove(type, key);
                    // });
                }

                // 드래그 앤 드롭 이벤트 핸들러
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

                    // 🔥 AI 처리 중 상태 확인 및 강제 초기화
                    if (this.isProcessingQuery || this.isStreaming) {
                        console.log('AI 처리 중 상태 감지됨, 상태 확인 후 처리');
                        
                        // 스트리밍 모달이 실제로 열려있는지 확인
                        const streamingModal = document.getElementById('streaming-modal');
                        const isModalVisible = streamingModal && streamingModal.classList.contains('show');
                        
                        if (!isModalVisible) {
                            // 모달이 닫혀있으면 상태 플래그를 강제 초기화
                            console.log('🔧 스트리밍 모달이 닫혀있으므로 상태 플래그 강제 초기화');
                            this.isProcessingQuery = false;
                            this.isStreaming = false;
                            this.ui.setLoading(this.elements.generateByAiBtn, false);
                        } else {
                            console.log('스트리밍이 실제로 진행 중이므로 드롭 무시');
                            return;
                        }
                    }

                    const elementType = e.dataTransfer.getData("element-type");

                    if (elementType !== type) return;

                    const info = e.dataTransfer.getData("text/plain");
                    const [id, ...nameParts] = info.split(':');
                    const name = nameParts.join(':');

                    // 🎯 개선: AI 검증 제거 - 사전 필터링으로 호환되는 조건만 표시되므로 즉시 추가
                    this.state.add(type, id, { id, name });
                    this.highlightPaletteItem(type, id);
                    this.ui.renderAll(this.state);
                }

                handleChipRemove(type, key) {
                    console.log(`🗑️ 칩 제거: ${type} ID=${key}`);

                    // 1. 상태에서 제거
                    this.state.remove(type, key);

                    // 2. 팔레트 하이라이트 제거
                    this.removeHighlightFromPaletteItem(type, key);

                    // 3. 브루트 포스로 해당 ID의 모든 하이라이트 제거
                    this.bruteForceRemoveSpecificHighlight(type, key);

                    // 4. UI 다시 렌더링
                    this.ui.renderAll(this.state);

                    console.log(`칩 제거 완료: ${type} ID=${key}`);
                }

                /**
                 * 특정 ID의 하이라이트만 브루트 포스로 제거
                 */
                bruteForceRemoveSpecificHighlight(type, id) {
                    console.log(`🔥 특정 하이라이트 브루트 포스 제거: ${type} ID=${id}`);

                    // 해당 ID를 가진 모든 요소 찾기
                    const targetItems = document.querySelectorAll(`[data-info^="${id}:"]`);

                    targetItems.forEach(item => {
                        if (item.classList.contains('palette-item')) {
                            console.log(`  ↳ 하이라이트 제거 대상: ${item.getAttribute('data-info')}`);

                            // ai-selected 클래스 제거
                            item.classList.remove('ai-selected');

                            // 아이콘 복원
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

                            // 텍스트 복원
                            const span = item.querySelector('span');
                            if (span) {
                                span.classList.remove('text-green-400', 'font-semibold');
                                span.removeAttribute('style');
                            }

                            // 모든 인라인 스타일 제거
                            item.removeAttribute('style');

                            console.log(`  ↳ 하이라이트 제거 완료: ${item.getAttribute('data-info')}`);
                        }
                    });
                }






                /**
                 * 현재 사용 가능한 모든 항목들을 수집
                 */
                collectAvailableItems() {
                    const availableItems = {
                        roles: [],
                        permissions: [],
                        conditions: []
                    };

                    // 전역 변수에서 데이터 수집 (HTML 템플릿에서 설정됨)
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

                // 🔥 AI Studio 방식으로 완전 리팩토링된 스트리밍 AI 처리
                async handleGenerateByAI() {
                    console.log('🚀 AI 정책 생성 시작 (일원화된 스트리밍 방식)');

                    // 🔥 이미 처리 중인지 확인
                    if (this.isProcessingQuery || this.isStreaming) {
                        this.showMessage('이미 AI 정책 생성이 진행 중입니다.', 'warning');
                        return;
                    }

                    // 🔥 상태 플래그 명확히 설정
                    this.isProcessingQuery = true;
                    this.isStreaming = true;

                    const query = this.elements.naturalLanguageInput?.value;
                    if (!query || !query.trim()) {
                        this.showMessage('요구사항을 입력해주세요.', 'error');
                        // 🔥 에러 시 상태 플래그 초기화
                        this.isProcessingQuery = false;
                        this.isStreaming = false;
                        return;
                    }

                    // 🎯 사용 가능한 항목들 수집
                    const availableItems = this.collectAvailableItems();

                    this.ui.setLoading(this.elements.generateByAiBtn, true);

                    try {
                        // 🎥 스트리밍 모달 표시
                        this.showStreamingProgressModal(query);
                        await new Promise(resolve => setTimeout(resolve, 100));

                        console.log('🌊 [일원화] 단일 스트리밍 호출 시작');

                        // 🔥 일원화된 스트리밍 호출 (SecurityCopilot 방식)
                        await this.startUnifiedStreamingAnalysis(query, availableItems);

                        console.log('[일원화] 스트리밍 완료');

                    } catch (error) {
                        console.error('AI 정책 생성 실패:', error);
                        this.handleQueryError(error, query);
                    } finally {
                        // 🔥 상태 플래그 정리
                        this.isProcessingQuery = false;
                        this.isStreaming = false;
                        this.ui.setLoading(this.elements.generateByAiBtn, false);
                    }
                }

                async startUnifiedStreamingAnalysis(query, availableItems) {
                    try {
                        console.log('🌊 일원화된 스트리밍 API 호출 시작...');
                        const response = await this.api.generatePolicyFromTextStream(query, availableItems);
                        
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                        }

                        const reader = response.body.getReader();
                        const decoder = new TextDecoder();
                        let buffer = '';
                        let markerBuffer = ''; // 🔥 마커 감지용 버퍼 추가
                        let finalResponseDetected = false; // 🔥 FINAL_RESPONSE 마커 감지 플래그
                        this.isStreaming = true;

                        while (this.isStreaming) {
                            const { done, value } = await reader.read();

                            if (done) {
                                console.log('🌊 스트리밍 완료 (연결 종료)');
                                this.isStreaming = false;
                                break;
                            }

                            const chunk = decoder.decode(value, { stream: true });
                            buffer += chunk;

                            // Server-Sent Event 형식 파싱
                            const lines = buffer.split('\n');
                            buffer = lines.pop() || '';

                            for (const line of lines) {
                                if (line.trim() === '') continue;

                                if (line.startsWith('data: ') || line.startsWith('data:')) {
                                    let data = line.startsWith('data: ') ? line.slice(6) : line.slice(5);

                                    if (data === '[DONE]') {
                                        console.log('🌊 스트리밍 완료 신호 수신');
                                        this.isStreaming = false;
                                        break;
                                    }

                                    // 🔥 마커 버퍼에 데이터 누적
                                    markerBuffer += data;

                                    // 🔥 ###FINAL_RESPONSE### 마커 감지 (플래그만 설정, 즉시 파싱 안함)
                                    if (markerBuffer.includes('###FINAL_RESPONSE###') && !finalResponseDetected) {
                                        console.log('📊 [DIAGNOSIS] PolicyGeneration FINAL_RESPONSE 마커 감지 - 스트리밍 완료 대기 중');
                                        finalResponseDetected = true;
                                        this.addStreamingStepImmediate('AI 정책 분석 완료! 결과 처리 중...');
                                    }
                                    

                                    
                                    // 🌊 일반 스트리밍 데이터 실시간 표시 (마커 감지 전까지만)
                                    if (data.trim() && !finalResponseDetected) {
                                        this.addStreamingStepImmediate(data.trim());
                                    }
                                }
                            }
                        }

                        // 🔥 스트리밍이 완료되면 자동으로 완료 처리
                        console.log('🌊 스트리밍 종료 - 완료 처리 시작');
                        
                        // 🔥 FINAL_RESPONSE 마커가 감지된 경우 JSON 파싱 처리
                        if (finalResponseDetected && markerBuffer.includes('###FINAL_RESPONSE###')) {
                            console.log('📊 [FINAL-PARSING] 스트리밍 완료 후 JSON 파싱 시작');
                            console.log('[DEBUG] 전체 markerBuffer 길이:', markerBuffer.length);
                            console.log('[DEBUG] 전체 markerBuffer 내용:', markerBuffer.substring(0, 200) + '...');
                            
                            const markerIndex = markerBuffer.indexOf('###FINAL_RESPONSE###');
                            if (markerIndex === -1) {
                                console.error('FINAL_RESPONSE 마커를 찾을 수 없습니다');
                                return;
                            }
                            
                            const jsonData = markerBuffer.substring(markerIndex + '###FINAL_RESPONSE###'.length);
                            console.log('[DEBUG] 추출된 원시 jsonData 길이:', jsonData.length);
                            console.log('[DEBUG] 추출된 원시 jsonData 앞 100자:', jsonData.substring(0, 100));
                            
                            // 🔥 안전한 JSON 정제
                            let cleanJsonData = jsonData.trim();
                            
                            // 백틱이나 기타 마커 제거
                            cleanJsonData = cleanJsonData.replace(/^```json\s*/, '');
                            cleanJsonData = cleanJsonData.replace(/```[\s\S]*$/, '');
                            cleanJsonData = cleanJsonData.trim();
                            
                            console.log('[DEBUG] 기본 정제 후:', cleanJsonData.substring(0, 100));
                            
                            // JSON 시작점 찾기
                            const jsonStartIndex = cleanJsonData.indexOf('{');
                            if (jsonStartIndex === -1) {
                                console.error('JSON 시작점을 찾을 수 없습니다. 원시 데이터:', cleanJsonData);
                                this.showMessage('AI 응답에서 유효한 JSON을 찾을 수 없습니다.', 'error');
                                return;
                            }
                            
                            // JSON 부분만 추출
                            cleanJsonData = cleanJsonData.substring(jsonStartIndex);
                            
                            // 🔥 ai-studio.js 스타일의 안전한 JSON 추출
                            cleanJsonData = this.extractCompleteJsonSafe(cleanJsonData);
                            
                            console.log('[DEBUG] 최종 정제된 JSON 길이:', cleanJsonData.length);
                            console.log('[DEBUG] 최종 정제된 JSON 앞 200자:', cleanJsonData.substring(0, 200));
                            
                            if (cleanJsonData && cleanJsonData.length > 0) {
                                try {
                                    const parsedResult = JSON.parse(cleanJsonData);
                                    console.log('[FINAL-PARSING] 스트리밍 완료 후 JSON 파싱 성공:', parsedResult);
                                    
                                    // 🔥 ai-studio.js 스타일의 안전한 응답 처리
                                    const processedResponse = this.preprocessPolicyResponse(parsedResult);
                                    
                                    if (processedResponse && processedResponse.policyData) {
                                        // 🔥 결과 표시 및 모달 닫기
                                        setTimeout(() => {
                                            this.populateBuilderWithAIData(processedResponse);
                                            this.showMessage('AI 정책 초안이 성공적으로 생성되었습니다!', 'success');
                                            
                                            setTimeout(() => {
                                                this.hideStreamingProgressModal();
                                            }, 1500);
                                        }, 500);
                                    } else {
                                        console.error('처리된 응답에 policyData가 없습니다:', processedResponse);
                                        this.createFallbackPolicy(query);
                                    }
                                    
                                    markerBuffer = ''; // 🔥 버퍼 초기화
                                    return; // JSON 처리 완료
                                } catch (error) {
                                    console.error('[FINAL-PARSING] 스트리밍 완료 후 JSON 파싱 실패:', error);
                                    console.error('[FINAL-PARSING] 파싱 시도한 JSON:', cleanJsonData);
                                    this.createFallbackPolicy(query);
                                }
                            } else {
                                console.warn('[FALLBACK] JSON 데이터가 없습니다. Fallback 정책 생성');
                                this.createFallbackPolicy(query);
                            }
                        }
                        
                        this.stopStreamingProgress();

                    } catch (error) {
                        console.error('일원화된 스트리밍 실패:', error);
                        this.addStreamingStepImmediate('스트리밍 연결 오류: ' + error.message);
                        throw error;
                    }
                }

                /**
                 * 🔥 Fallback 정책 생성 - AI 실패 시 기본 정책 구조 제공
                 */
                createFallbackPolicy(query) {
                    console.log('[FALLBACK] AI 응답 실패 - 기본 정책 생성:', query);
                    
                    this.addStreamingStepImmediate('AI 응답 처리 실패. 기본 정책을 생성합니다...');
                    
                    // 기본 정책 데이터 생성
                    const fallbackPolicyData = {
                        policyName: `AI 생성 정책 (${new Date().toLocaleString()})`,
                        description: `요구사항: "${query}" - AI 분석을 통해 기본 정책 구조를 생성했습니다.`,
                        effect: 'ALLOW',
                        roleIds: [],
                        permissionIds: [],
                        conditions: {},
                        aiRiskAssessmentEnabled: false,
                        requiredTrustScore: 0.5,
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

                    setTimeout(() => {
                        this.populateBuilderWithAIData(fallbackResponse);
                        this.showMessage('기본 정책이 생성되었습니다. 필요에 따라 수정해주세요.', 'warning');
                        
                        setTimeout(() => {
                            this.hideStreamingProgressModal();
                        }, 1500);
                    }, 500);
                }

                // 스트리밍을 비동기로 독립 실행
                async startStreamingProgressAsync(query, availableItems) {
                    try {
                        console.log('🌊 스트리밍 비동기 시작');
                        await this.startStreamingProgress(query, availableItems);
                        console.log('스트리밍 완료');

                        // 스트리밍 완료 메시지 표시
                        this.showStreamingComplete();

                    } catch (error) {
                        console.error('🌊 스트리밍 오류:', error);
                        this.addStreamingStep('스트리밍 중 오류가 발생했습니다.');
                    } finally {
                        // 🔥 상태 플래그는 hideStreamingProgressModal에서 처리됨
                        console.log('🌊 스트리밍 비동기 완료');
                    }
                }

                showStreamingComplete() {
                    const streamingContent = document.getElementById('streaming-content');
                    if (!streamingContent) return;

                    const completeStep = document.createElement('div');
                    completeStep.className = 'streaming-step streaming-complete';
                    completeStep.style.borderLeftColor = '#22c55e';
                    completeStep.innerHTML = `
        <i class="fas fa-check-circle mr-2 text-green-400"></i>
        <span class="text-green-400 font-semibold">AI 정책 분석이 완료되었습니다.</span>
    `;

                    streamingContent.appendChild(completeStep);
                    streamingContent.scrollTop = streamingContent.scrollHeight;
                    
                    console.log('스트리밍 완료 메시지 표시됨');
                    // 🔥 상태 플래그 초기화는 stopStreamingProgress에서 처리
                }

                // 🗑️ [제거됨] startAIQueryAsync - 일원화된 스트리밍으로 대체됨

                handleQueryError(error, query) {
                    console.error('정책 생성 오류 상세:', error);
                    
                    // 🔥 ai-studio.js 스타일의 자세한 오류 분석
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

                    // 사용자 친화적 메시지 표시
                    this.showMessage(userMessage, 'error');

                    // 스트리밍 모달에 자세한 에러 메시지 추가
                    this.addStreamingStepImmediate(`${userMessage}`);
                    
                    if (technicalDetails && technicalDetails !== userMessage) {
                        this.addStreamingStepImmediate(`기술적 세부사항: ${technicalDetails}`);
                    }

                    // 쿼리 정보도 로깅
                    if (query) {
                        console.log('실패한 쿼리:', query);
                        this.addStreamingStepImmediate(`요청: ${query.substring(0, 100)}${query.length > 100 ? '...' : ''}`);
                    }

                    // 🔥 에러 메시지를 충분히 보여준 후 모달 닫기
                    setTimeout(() => {
                        console.log('에러 처리 완료 - 모달 닫기');
                        this.hideStreamingProgressModal();
                    }, 4000); // 더 자세한 정보를 보여주므로 시간 증가
                }

                // 🗑️ [제거됨] trySimpleStreaming - 일원화된 스트리밍으로 대체됨

// SSE 라인에서 데이터 추출
                extractDataFromSSE(line) {
                    if (line.startsWith('data: ')) {
                        return line.substring(6);
                    }
                    return '';
                                }

                // 🔥 완전한 JSON 객체 추출 (중괄호 쌍 매칭)
                extractCompleteJson(text) {
                    if (!text || !text.trim()) {
                        return text;
                    }
                    
                    text = text.trim();
                    
                    // JSON 시작점 찾기
                    const startIndex = text.indexOf('{');
                    if (startIndex === -1) {
                        return text; // { 가 없으면 원본 반환
                    }
                    
                    let braceCount = 0;
                    let inString = false;
                    let escapeNext = false;
                    
                    for (let i = startIndex; i < text.length; i++) {
                        const char = text[i];
                        
                        if (escapeNext) {
                            escapeNext = false;
                            continue;
                        }
                        
                        if (char === '\\') {
                            escapeNext = true;
                            continue;
                        }
                        
                        if (char === '"' && !escapeNext) {
                            inString = !inString;
                            continue;
                        }
                        
                        if (!inString) {
                            if (char === '{') {
                                braceCount++;
                            } else if (char === '}') {
                                braceCount--;
                                
                                // 완전한 JSON 객체 완성
                                if (braceCount === 0) {
                                    const completeJson = text.substring(startIndex, i + 1);
                                    console.log('🔥 완전한 JSON 추출 성공:', completeJson.substring(0, 100) + '...');
                                    return completeJson;
                                }
                            }
                        }
                    }
                    
                    // 완전하지 않은 JSON - 원본 반환하고 로그
                    console.warn('불완전한 JSON 감지, 원본 반환:', text.substring(0, 200) + '...');
                    return text;
                }

                // 🔥 JSON 끝에 있는 불필요한 텍스트 제거
                removeTextAfterJson(text) {
                    if (!text || !text.trim()) {
                        return text;
                    }
                    
                    text = text.trim();
                    
                    // JSON이 완료된 후 모든 텍스트 제거 (한국어, 마크다운, 기타 설명 텍스트)
                    // 정규식으로 } 다음에 오는 모든 내용 제거
                    text = text.replace(/}\s*```[\s\S]*$/, '}'); // } 후 ``` 및 모든 내용 제거
                    text = text.replace(/}\s*[가-힣][\s\S]*$/, '}'); // } 후 한국어 및 모든 내용 제거
                    text = text.replace(/}\s*[a-zA-Z][\s\S]*$/, '}'); // } 후 영어 설명 및 모든 내용 제거
                    text = text.replace(/}\s*이제[\s\S]*$/, '}'); // "이제" 키워드로 시작하는 설명 제거
                    text = text.replace(/}\s*정책[\s\S]*$/, '}'); // "정책" 키워드로 시작하는 설명 제거
                    
                    console.log('🔥 텍스트 제거 후 JSON:', text);
                    return text.trim();
                }

                // 🔥 개선된 JSON 추출 메서드
                extractSimpleJson(text) {
                    console.log('🔥 간단 JSON 추출 시도...');
                    console.log('🔥 전체 텍스트 길이:', text.length);

                    try {
                        // 1. 한국어 JSON 마커 방식 (최우선)
                        const koreanMarkerRegex = /===JSON_START===([\s\S]*?)===JSON_END===/;
                        const koreanMatch = text.match(koreanMarkerRegex);

                        if (koreanMatch) {
                            try {
                                let jsonStr = koreanMatch[1].trim();
                                console.log('🔥 한국어 마커로 추출된 JSON:', jsonStr.substring(0, 200) + '...');

                                // JSON 정제 - 주석 제거 및 클린업
                                jsonStr = this.cleanJsonString(jsonStr);

                                const parsed = JSON.parse(jsonStr);
                                console.log('🔥 한국어 마커 JSON 파싱 성공:', parsed);

                                // policyData가 있으면 그대로 반환, 없으면 래핑
                                if (parsed.policyData) {
                                    return parsed;
                                } else {
                                    return {
                                        policyData: parsed,
                                        roleIdToNameMap: this.createIdToNameMap('role', parsed.roleIds),
                                        permissionIdToNameMap: this.createIdToNameMap('permission', parsed.permissionIds),
                                        conditionIdToNameMap: this.createIdToNameMap('condition', Object.keys(parsed.conditions || {}))
                                    };
                                }
                            } catch (e) {
                                console.log('🔥 한국어 마커 JSON 파싱 실패:', e.message);
                            }
                        }

                        // 2. 영어 마커 방식들
                        const markerPatterns = [
                            /<<JSON_START>>([\s\S]*?)<<JSON_END>>/,
                            /<<<JSON_START>>>([\s\S]*?)<<<JSON_END>>>/,
                            /JSON_START([\s\S]*?)JSON_END/,
                            /\*\*JSON\*\*([\s\S]*?)\*\*\/JSON\*\*/,
                        ];

                        for (const pattern of markerPatterns) {
                            const match = text.match(pattern);
                            if (match) {
                                try {
                                    let jsonStr = match[1].trim();
                                    jsonStr = this.cleanJsonString(jsonStr);
                                    const parsed = JSON.parse(jsonStr);
                                    console.log('🔥 영어 마커 JSON 파싱 성공:', parsed);

                                    if (parsed.policyData) {
                                        return parsed;
                                    } else {
                                        return {
                                            policyData: parsed,
                                            roleIdToNameMap: this.createIdToNameMap('role', parsed.roleIds),
                                            permissionIdToNameMap: this.createIdToNameMap('permission', parsed.permissionIds),
                                            conditionIdToNameMap: this.createIdToNameMap('condition', Object.keys(parsed.conditions || {}))
                                        };
                                    }
                                } catch (e) {
                                    console.log('🔥 영어 마커 JSON 파싱 실패:', e.message);
                                    continue;
                                }
                            }
                        }

                        // 3. 중괄호 기반 추출 (fallback)
                        const jsonMatch = text.match(/\{[\s\S]*"policyName"[\s\S]*"effect"[\s\S]*\}/);
                        if (jsonMatch) {
                            try {
                                let jsonStr = jsonMatch[0];
                                jsonStr = this.cleanJsonString(jsonStr);
                                const parsed = JSON.parse(jsonStr);
                                console.log('🔥 중괄호 기반 JSON 파싱 성공:', parsed);

                                if (parsed.policyData) {
                                    return parsed;
                                } else {
                                    return {
                                        policyData: parsed,
                                        roleIdToNameMap: this.createIdToNameMap('role', parsed.roleIds),
                                        permissionIdToNameMap: this.createIdToNameMap('permission', parsed.permissionIds),
                                        conditionIdToNameMap: this.createIdToNameMap('condition', Object.keys(parsed.conditions || {}))
                                    };
                                }
                            } catch (e) {
                                console.log('🔥 중괄호 기반 JSON 파싱 실패:', e.message);
                            }
                        }

                        console.warn('🔥 JSON 추출 실패 - 모든 방법 시도함');
                        return null;

                    } catch (error) {
                        console.error('🔥 JSON 추출 오류:', error);
                        return null;
                    }
                }

// 🔥 JSON 문자열 정제 메서드
                cleanJsonString(jsonStr) {
                    console.log('🔥 JSON 정제 시작, 원본 길이:', jsonStr.length);

                    // 1. 마크다운 코드 블록 제거
                    let cleaned = jsonStr
                        .replace(/```json\s*/g, '')
                        .replace(/```\s*/g, '');

                    // 2. 주석 제거 (// 스타일)
                    cleaned = cleaned.split('\n').map(line => {
                        // 문자열 내부가 아닌 // 주석만 제거
                        let inString = false;
                        let result = '';
                        for (let i = 0; i < line.length; i++) {
                            if (line[i] === '"' && (i === 0 || line[i-1] !== '\\')) {
                                inString = !inString;
                            }
                            if (!inString && line[i] === '/' && line[i+1] === '/') {
                                break; // 주석 시작, 나머지 줄 무시
                            }
                            result += line[i];
                        }
                        return result.trim();
                    }).join('\n');

                    // 3. /* */ 스타일 주석 제거
                    cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, '');

                    // 4. 잘못된 쉼표 제거
                    cleaned = cleaned
                        .replace(/,\s*}/g, '}')
                        .replace(/,\s*]/g, ']')
                        .replace(/,(\s*[}\]])/g, '$1');

                    // 5. 불필요한 공백 정리
                    cleaned = cleaned
                        .replace(/\s+/g, ' ')
                        .replace(/\s*:\s*/g, ':')
                        .replace(/\s*,\s*/g, ',')
                        .replace(/\s*{\s*/g, '{')
                        .replace(/\s*}\s*/g, '}')
                        .replace(/\s*\[\s*/g, '[')
                        .replace(/\s*]\s*/g, ']');

                    // 6. conditional 필드 제거 (있는 경우)
                    if (cleaned.includes('"conditional"')) {
                        cleaned = cleaned.replace(/"conditional"\s*:\s*(true|false)\s*,?/g, '');
                    }

                    console.log('🔥 정제된 JSON 길이:', cleaned.length);
                    console.log('🔥 정제된 JSON 미리보기:', cleaned.substring(0, 200) + '...');

                    return cleaned.trim();
                }

// ID to Name 매핑 생성 헬퍼
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

// 🔥 스트리밍 데이터 표시 개선
                displayStreamingData(thoughtLog, data) {
                    try {
                        // JSON 블록은 코드 블록으로 표시
                        if (data.includes('===JSON_START===') || data.includes('===JSON_END===')) {
                            thoughtLog.innerHTML += `<div style="background: #1e1e1e; padding: 10px; border-radius: 5px; margin: 10px 0;">
                <pre style="color: #4fc3f7; font-family: monospace; margin: 0; white-space: pre-wrap;">${this.escapeHtml(data)}</pre>
            </div>`;
                        } else {
                            // 일반 텍스트는 포맷팅하여 표시
                            let displayData = this.escapeHtml(data);

                            // 키워드 하이라이팅
                            displayData = displayData
                                .replace(/분석|구성|매핑/g, '<span style="color: #28a745;">$&</span>')
                                .replace(/역할|권한|조건/g, '<span style="color: #fd7e14;">📋 $&</span>')
                                .replace(/정책/g, '<span style="color: #dc3545;">🎯 $&</span>')
                                .replace(/\*\*([^*]+)\*\*/g, '<br><strong>$1</strong><br>');

                            thoughtLog.innerHTML += displayData + ' ';
                        }

                        thoughtLog.scrollTop = thoughtLog.scrollHeight;
                    } catch (error) {
                        console.error('스트리밍 데이터 표시 오류:', error);
                        thoughtLog.innerHTML += this.escapeHtml(data) + ' ';
                    }
                }

// HTML 이스케이프 헬퍼
                escapeHtml(text) {
                    const div = document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }

                /**
                 * AI 응답을 검증하고 존재하지 않는 항목들을 필터링
                 */
                validateAndFilterAIResponse(policyData) {
                    console.log('AI 응답 검증 시작:', policyData);

                    const availableItems = this.collectAvailableItems();
                    const validatedData = { ...policyData };

                    // 사용 가능한 ID 세트 생성
                    const availableRoleIds = new Set(availableItems.roles.map(r => r.id));
                    const availablePermissionIds = new Set(availableItems.permissions.map(p => p.id));
                    const availableConditionIds = new Set(availableItems.conditions.map(c => c.id));

                    // 역할 ID 검증 및 필터링
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

                    // 권한 ID 검증 및 필터링
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

                    // 조건 ID 검증 및 필터링
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

                /**
                 * 🔥 ai-studio.js 스타일의 정책 응답 전처리 - 서버 데이터 구조 정규화
                 */
                preprocessPolicyResponse(response) {
                    console.log('🔥 [SERVER-RESPONSE] 정책 응답 전처리 시작:', response);

                    if (!response) {
                        console.error('응답이 없습니다');
                        return null;
                    }

                    // 🔥 AiApiController 응답 구조 처리
                    // Case 1: 이미 올바른 AiGeneratedPolicyDraftDto 구조인 경우 (response 레벨에 Map들)
                    if (response.policyData && response.roleIdToNameMap !== undefined) {
                        console.log('이미 올바른 AiGeneratedPolicyDraftDto 구조 (response 레벨)');
                        return {
                            policyData: response.policyData,
                            roleIdToNameMap: response.roleIdToNameMap || {},
                            permissionIdToNameMap: response.permissionIdToNameMap || {},
                            conditionIdToNameMap: response.conditionIdToNameMap || {}
                        };
                    }

                    // Case 1-2: policyData 내부에 모든 데이터가 있는 구조 (서버 실제 응답)
                    if (response.policyData && response.policyData.roleIdToNameMap !== undefined) {
                        console.log('policyData 내부 통합 구조 감지 (서버 실제 응답)');
                        return {
                            policyData: response.policyData,
                            roleIdToNameMap: response.policyData.roleIdToNameMap || {},
                            permissionIdToNameMap: response.policyData.permissionIdToNameMap || {},
                            conditionIdToNameMap: response.policyData.conditionIdToNameMap || {}
                        };
                    }

                    // Case 2: 스트리밍에서 직접 BusinessPolicyDto가 온 경우 (래핑 필요)
                    if (response.policyName && response.roleIds !== undefined) {
                        console.log('BusinessPolicyDto 구조 감지 - AiGeneratedPolicyDraftDto로 래핑');
                        return {
                            policyData: response,
                            roleIdToNameMap: this.createIdToNameMap('role', response.roleIds || []),
                            permissionIdToNameMap: this.createIdToNameMap('permission', response.permissionIds || []),
                            conditionIdToNameMap: this.createIdToNameMap('condition', Object.keys(response.conditions || {}))
                        };
                    }

                    // Case 3: 중첩된 구조 또는 예상치 못한 구조 처리
                    if (response.data && typeof response.data === 'object') {
                        console.log('중첩된 응답 구조 감지 - data 필드 추출');
                        return this.preprocessPolicyResponse(response.data);
                    }

                    // Case 4: PolicyResponse 서버 응답 구조
                    if (response.generatedPolicy || response.policyConfidenceScore !== undefined) {
                        console.log('PolicyResponse 서버 구조 감지');
                        
                        // policyData 필드가 있으면 사용
                        if (response.policyData) {
                            return {
                                policyData: response.policyData,
                                roleIdToNameMap: response.roleIdToNameMap || {},
                                permissionIdToNameMap: response.permissionIdToNameMap || {},
                                conditionIdToNameMap: response.conditionIdToNameMap || {}
                            };
                        }
                        
                        // generatedPolicy가 문자열이면 파싱 시도
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

                /**
                 * 🔥 ai-studio.js 스타일의 안전한 JSON 추출 - 중괄호 매칭 기반
                 */
                extractCompleteJsonSafe(text) {
                    console.log('🔧 안전한 JSON 추출 시작');
                    
                    if (!text || text.trim() === '') {
                        console.error('빈 텍스트입니다');
                        return '';
                    }

                    text = text.trim();
                    
                    // 첫 번째 '{' 찾기
                    const startIndex = text.indexOf('{');
                    if (startIndex === -1) {
                        console.error('JSON 시작 중괄호를 찾을 수 없습니다');
                        return '';
                    }

                    // 중괄호 매칭으로 완전한 JSON 추출
                    let braceCount = 0;
                    let endIndex = -1;
                    let inString = false;
                    let escaped = false;

                    for (let i = startIndex; i < text.length; i++) {
                        const char = text[i];
                        
                        if (escaped) {
                            escaped = false;
                            continue;
                        }
                        
                        if (char === '\\') {
                            escaped = true;
                            continue;
                        }
                        
                        if (char === '"') {
                            inString = !inString;
                            continue;
                        }
                        
                        if (!inString) {
                            if (char === '{') {
                                braceCount++;
                            } else if (char === '}') {
                                braceCount--;
                                if (braceCount === 0) {
                                    endIndex = i;
                                    break;
                                }
                            }
                        }
                    }

                    if (endIndex === -1) {
                        console.error('JSON 종료 중괄호를 찾을 수 없습니다');
                        return '';
                    }

                    const extractedJson = text.substring(startIndex, endIndex + 1);
                    console.log('안전한 JSON 추출 완료:', extractedJson.length + '자');
                    
                    return extractedJson;
                }

                populateBuilderWithAIData(draftDto) {
                    console.log('🔥 AI 데이터로 빌더 채우기:', draftDto);

                    // 🔥 ai-studio.js 스타일의 엄격한 데이터 검증
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

                    // policyData 내부 필수 필드 검증
                    const policyData = draftDto.policyData;
                    if (!policyData.policyName && !policyData.description) {
                        console.error('policyData에 필수 필드가 없습니다:', policyData);
                        this.showMessage('AI가 생성한 정책 데이터가 불완전합니다.', 'error');
                        return;
                    }

                    console.log('데이터 검증 통과 - 빌더 채우기 시작');

                    // 🎯 AI 응답 검증 및 필터링
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

                    // 기존 하이라이트 제거
                    this.clearPaletteHighlights();

                    // 상태 초기화
                    ['role', 'permission', 'condition'].forEach(type => this.state.clear(type));

                    // 기본 필드 설정
                    if (this.elements.policyNameInput) {
                        this.elements.policyNameInput.value = data.policyName || '';
                    }
                    if (this.elements.policyDescTextarea) {
                        this.elements.policyDescTextarea.value = data.description || '';
                    }
                    if (this.elements.policyEffectSelect) {
                        this.elements.policyEffectSelect.value = data.effect || 'ALLOW';
                    }

                    // 역할 추가 (하이라이트는 나중에)
                    const selectedRoleIds = [];
                    if (data.roleIds && Array.isArray(data.roleIds)) {
                        data.roleIds.forEach(id => {
                            const name = maps.roles[id] || `역할 (ID: ${id})`;
                            console.log(`🔥 역할 추가: ID=${id}, Name=${name}`);
                            this.state.add('role', String(id), { id, name });
                            selectedRoleIds.push(id);
                        });
                    }

                    // 권한 추가 (하이라이트는 나중에)
                    const selectedPermissionIds = [];
                    if (data.permissionIds && Array.isArray(data.permissionIds)) {
                        data.permissionIds.forEach(id => {
                            const name = maps.permissions[id] || `권한 (ID: ${id})`;
                            console.log(`🔥 권한 추가: ID=${id}, Name=${name}`);
                            this.state.add('permission', String(id), { id, name });
                            selectedPermissionIds.push(id);
                        });
                    }

                    // 조건 추가 (하이라이트는 나중에)
                    const selectedConditionIds = [];
                    if (data.conditions && typeof data.conditions === 'object') {
                        Object.keys(data.conditions).forEach(id => {
                            const name = maps.conditions[id] || `조건 (ID: ${id})`;
                            console.log(`🔥 조건 추가: ID=${id}, Name=${name}`);
                            this.state.add('condition', String(id), { id, name });
                            selectedConditionIds.push(id);
                        });
                    }

                    // AI 설정
                    this.state.aiRiskAssessmentEnabled = data.aiRiskAssessmentEnabled || false;
                    if (this.elements.aiEnabledCheckbox) {
                        this.elements.aiEnabledCheckbox.checked = this.state.aiRiskAssessmentEnabled;
                    }

                    this.state.requiredTrustScore = data.requiredTrustScore || 0.7;
                    if (this.elements.trustScoreSlider) {
                        this.elements.trustScoreSlider.value = this.state.requiredTrustScore * 100;
                    }
                    if (this.elements.trustScoreValueSpan) {
                        this.elements.trustScoreValueSpan.textContent = Math.round(this.state.requiredTrustScore * 100);
                    }

                    // UI 업데이트
                    this.handleAiToggle();
                    this.ui.renderAll(this.state);

                    // UI 렌더링 완료 후 하이라이트 적용 (중요!)
                    console.log('🎨 UI 렌더링 완료, 하이라이트 적용 시작...');

                    // 짧은 지연 후 하이라이트 적용 (DOM 업데이트 완료 대기)
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

                /**
                 * 팔레트 아이템을 초록색으로 하이라이트
                 */
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

                    // data-info 속성에서 ID가 일치하는 아이템 찾기
                    const paletteItems = palette.querySelectorAll('.palette-item');
                    paletteItems.forEach(item => {
                        const dataInfo = item.getAttribute('data-info');
                        if (dataInfo && dataInfo.startsWith(String(id) + ':')) {
                            // AI 선택 하이라이트 클래스 추가
                            item.classList.add('ai-selected');

                            // 아이콘을 체크 표시로 변경
                            const icon = item.querySelector('i');
                            if (icon) {
                                icon.className = 'fas fa-check-circle text-green-400';
                            }

                            // 텍스트를 초록색으로 변경
                            const span = item.querySelector('span');
                            if (span) {
                                span.classList.add('text-green-400', 'font-semibold');
                            }

                            // 배경 효과 추가
                            item.style.background = 'linear-gradient(135deg, rgba(34, 197, 94, 0.15), rgba(16, 185, 129, 0.1))';
                            item.style.borderColor = 'rgba(34, 197, 94, 0.4)';
                            item.style.boxShadow = '0 0 20px rgba(34, 197, 94, 0.3)';

                            console.log(`🟢 팔레트 하이라이트 적용: ${type} ID=${id}`);
                        }
                    });
                }

                /**
                 * 모든 팔레트 하이라이트 제거 (최강화 버전)
                 */
                clearPaletteHighlights() {
                    console.log('🧹 팔레트 하이라이트 제거 시작');
                    const palettes = ['#roles-palette', '#permissionsPalette', '#conditionsPalette'];
                    let totalCleared = 0;

                    // 1. 먼저 전체 페이지에서 ai-selected 클래스를 가진 모든 요소 찾기
                    const allHighlighted = document.querySelectorAll('.ai-selected');
                    console.log(`전체 페이지에서 ${allHighlighted.length}개 하이라이트 아이템 발견`);

                    allHighlighted.forEach(item => {
                        const dataInfo = item.getAttribute('data-info');
                        const type = item.getAttribute('data-type');
                        console.log(`🧹 전역 하이라이트 제거 중: ${dataInfo} (타입: ${type})`);

                        // 클래스 제거
                        item.classList.remove('ai-selected');

                        // 아이콘 복원 (강화된 버전)
                        const icon = item.querySelector('i');
                        if (icon && type) {
                            // 모든 기존 클래스 완전 제거
                            icon.className = '';
                            // 모든 초록색 관련 클래스 강제 제거
                            icon.classList.remove('text-green-400', 'fa-check-circle', 'fas', 'fa-user-shield', 'fa-key', 'fa-clock');

                            const iconMap = {
                                'role': 'fas fa-user-shield text-purple-400',
                                'permission': 'fas fa-key text-yellow-400',
                                'condition': 'fas fa-clock text-orange-400'
                            };
                            const originalIconClass = iconMap[type];
                            icon.className = originalIconClass;

                            // 인라인 스타일도 강제 제거
                            icon.removeAttribute('style');
                            console.log(`🎨 아이콘 완전 복원: ${originalIconClass}`);
                        }

                        // 텍스트 스타일 복원 (강화된 버전)
                        const span = item.querySelector('span');
                        if (span) {
                            span.classList.remove('text-green-400', 'font-semibold');
                            // 인라인 스타일도 강제 제거
                            span.removeAttribute('style');
                            console.log('텍스트 스타일 완전 복원');
                        }

                        // 스타일 완전 복원
                        item.style.background = '';
                        item.style.borderColor = '';
                        item.style.boxShadow = '';
                        item.style.border = '';
                        item.style.transform = '';
                        item.style.filter = '';
                        // 모든 인라인 스타일 완전 제거
                        item.removeAttribute('style');
                        console.log('🎨 모든 인라인 스타일 완전 제거');

                        totalCleared++;
                    });

                    // 2. 추가로 각 팔레트에서 개별 검색 (이중 체크)
                    palettes.forEach(paletteSelector => {
                        const palette = document.querySelector(paletteSelector);
                        if (!palette) {
                            console.log(`팔레트 찾을 수 없음: ${paletteSelector}`);
                            return;
                        }

                        // 모든 palette-item을 검사하여 초록색 스타일이 남아있는지 확인
                        const allItems = palette.querySelectorAll('.palette-item');
                        console.log(`${paletteSelector}에서 총 ${allItems.length}개 아이템 검사`);

                        allItems.forEach(item => {
                            const hasGreenIcon = item.querySelector('i.text-green-400');
                            const hasGreenText = item.querySelector('span.text-green-400');
                            const hasGreenBg = item.style.background && item.style.background.includes('rgba(34, 197, 94');
                            const isPreselected = item.classList.contains('preselected');

                            // 더 포괄적인 초록 텍스트 검사 (모든 하위 요소 포함)
                            const allGreenTexts = item.querySelectorAll('.text-green-400');
                            const hasAnyGreenText = allGreenTexts.length > 0;

                            if (hasGreenIcon || hasGreenText || hasGreenBg || hasAnyGreenText || isPreselected) {
                                const dataInfo = item.getAttribute('data-info');
                                const type = item.getAttribute('data-type');
                                console.log(`🧹 잔여 초록 스타일 제거: ${dataInfo} (초록텍스트: ${allGreenTexts.length}개, preselected: ${isPreselected})`);

                                // 강제로 모든 초록 스타일 제거 (강화된 버전)
                                const icon = item.querySelector('i');
                                if (icon) {
                                    // 모든 기존 클래스 완전 제거
                                    icon.className = '';
                                    // 모든 초록색 관련 클래스 강제 제거
                                    icon.classList.remove('text-green-400', 'fa-check-circle', 'fas', 'fa-user-shield', 'fa-key', 'fa-clock');
                                    // 인라인 스타일도 강제 제거
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

                                // 모든 하위 요소에서 초록 텍스트 제거
                                allGreenTexts.forEach(greenElement => {
                                    greenElement.classList.remove('text-green-400', 'font-semibold');
                                    console.log(`  ↳ 초록 텍스트 제거: ${greenElement.tagName}`);
                                });

                                const span = item.querySelector('span');
                                if (span) {
                                    span.classList.remove('text-green-400', 'font-semibold');
                                    // 인라인 스타일도 강제 제거
                                    span.removeAttribute('style');
                                    console.log(`  ↳ 텍스트 스타일 완전 제거`);
                                }

                                // 모든 스타일 완전 제거
                                item.style.background = '';
                                item.style.borderColor = '';
                                item.style.boxShadow = '';
                                item.style.border = '';
                                item.style.transform = '';
                                item.style.filter = '';
                                // 모든 인라인 스타일 완전 제거
                                item.removeAttribute('style');
                                item.classList.remove('ai-selected');
                                console.log(`  ↳ 모든 인라인 스타일 완전 제거`);

                                // preselected 클래스도 제거 (필요시)
                                if (isPreselected) {
                                    console.log(`  ↳ preselected 클래스 제거`);
                                    // item.classList.remove('preselected'); // 주석: 서버에서 설정한 preselected는 유지할 수도 있음
                                }

                                totalCleared++;
                            }
                        });
                    });

                    console.log(`총 ${totalCleared}개 팔레트 하이라이트 제거 완료`);

                    // 🔥 브루트 포스: 모든 하이라이트를 강제로 제거
                    this.bruteForceRemoveAllHighlights();
                }

                /**
                 * 브루트 포스 방식으로 모든 하이라이트 완전 제거
                 */
                bruteForceRemoveAllHighlights() {
                    console.log('🔥 브루트 포스 하이라이트 제거 시작');

                    // 1. 모든 ai-selected 클래스 제거
                    document.querySelectorAll('.ai-selected').forEach(element => {
                        element.classList.remove('ai-selected');
                        element.removeAttribute('style');
                        console.log('  ↳ ai-selected 제거:', element.getAttribute('data-info'));
                    });

                    // 2. 모든 text-green-400 클래스 제거
                    document.querySelectorAll('.text-green-400').forEach(element => {
                        element.classList.remove('text-green-400', 'font-semibold');
                        element.removeAttribute('style');
                        console.log('  ↳ text-green-400 제거:', element.tagName);
                    });

                    // 3. 모든 fa-check-circle 아이콘 복원
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

                    // 4. 모든 palette-item의 인라인 스타일 제거
                    document.querySelectorAll('.palette-item').forEach(item => {
                        if (item.style.background || item.style.borderColor || item.style.boxShadow) {
                            item.removeAttribute('style');
                            console.log('  ↳ palette-item 스타일 제거:', item.getAttribute('data-info'));
                        }
                    });

                    console.log('🔥 브루트 포스 하이라이트 제거 완료');
                }

                /**
                 * 특정 팔레트 아이템의 하이라이트 제거
                 */
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

                    // data-info 속성에서 ID가 일치하는 아이템 찾기
                    const paletteItems = palette.querySelectorAll('.palette-item');
                    paletteItems.forEach(item => {
                        const dataInfo = item.getAttribute('data-info');
                        if (dataInfo && dataInfo.startsWith(id + ':')) {
                            // AI 선택 하이라이트 클래스 제거
                            item.classList.remove('ai-selected');

                            // 아이콘 완전 복원
                            const icon = item.querySelector('i');
                            const itemType = item.getAttribute('data-type');
                            if (icon && itemType) {
                                // 모든 기존 클래스 완전 제거
                                icon.className = '';
                                // 모든 초록색 관련 클래스 강제 제거
                                icon.classList.remove('text-green-400', 'fa-check-circle', 'fas', 'fa-user-shield', 'fa-key', 'fa-clock');
                                // 인라인 스타일도 강제 제거
                                icon.removeAttribute('style');

                                const iconMap = {
                                    'role': 'fas fa-user-shield text-purple-400',
                                    'permission': 'fas fa-key text-yellow-400',
                                    'condition': 'fas fa-clock text-orange-400'
                                };
                                icon.className = iconMap[itemType] || icon.className;
                            }

                            // 텍스트 스타일 완전 복원
                            const span = item.querySelector('span');
                            if (span) {
                                span.classList.remove('text-green-400', 'font-semibold');
                                // 인라인 스타일도 강제 제거
                                span.removeAttribute('style');
                            }

                            // 스타일 완전 복원
                            item.style.background = '';
                            item.style.borderColor = '';
                            item.style.boxShadow = '';
                            item.style.border = '';
                            item.style.transform = '';
                            item.style.filter = '';
                            // 모든 인라인 스타일 완전 제거
                            item.removeAttribute('style');

                            console.log(`🔴 팔레트 하이라이트 제거: ${type} ID=${id}`);
                        }
                    });
                }

                handleAiToggle() {
                    if (this.elements.aiEnabledCheckbox) {
                        this.state.aiRiskAssessmentEnabled = this.elements.aiEnabledCheckbox.checked;
                    }
                    if (this.elements.trustScoreContainer) {
                        this.elements.trustScoreContainer.classList.toggle('hidden', !this.state.aiRiskAssessmentEnabled);
                    }
                    this.ui.updatePreview(this.state);
                }

                handleTrustSlider() {
                    if (this.elements.trustScoreSlider) {
                        this.state.requiredTrustScore = this.elements.trustScoreSlider.value / 100.0;
                        if (this.elements.trustScoreValueSpan) {
                            this.elements.trustScoreValueSpan.textContent = this.elements.trustScoreSlider.value;
                        }
                    }
                    this.ui.updatePreview(this.state);
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

                        // 조건 팔레트의 각 아이템을 순회하며 호환성 검사
                        this.elements.conditionsPalette.querySelectorAll('.palette-item').forEach(item => {
                            // 예시: data-required-type="Document" 와 같은 속성이 템플릿에 있다고 가정
                            const requiredType = item.dataset.requiredType;

                            if (requiredType && !availableParamTypes.has(requiredType)) {
                                item.classList.add('disabled'); // 호환되지 않으면 비활성화
                                item.title = `이 조건은 '${requiredType}' 타입의 정보가 필요하지만, 현재 리소스는 제공하지 않습니다.`;
                            }
                        });
                    }
                    if (window.preselectedPermission) {
                        const perm = window.preselectedPermission;
                        this.state.add('permission', String(perm.id), { id: perm.id, name: perm.friendlyName });
                    }
                }

                showMessage(message, type) {
                    if (typeof showToast === 'function') {
                        showToast(message, type);
                    } else {
                        // 커스텀 토스트 메시지 표시
                        this.showToast(message, type);
                    }
                }

                /**
                 * 커스텀 토스트 메시지 표시
                 */
                showToast(message, type = 'info') {
                    // 기존 토스트 제거
                    const existingToast = document.querySelector('.policy-toast');
                    if (existingToast) {
                        existingToast.remove();
                    }

                    // 토스트 요소 생성
                    const toast = document.createElement('div');
                    toast.className = `policy-toast toast-${type}`;
                    
                    // 타입별 아이콘 설정
                    const icons = {
                        success: 'fas fa-check-circle',
                        error: 'fas fa-exclamation-circle',
                        warning: 'fas fa-exclamation-triangle',
                        info: 'fas fa-info-circle'
                    };
                    
                    // 타입별 색상 설정
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

                    // 스타일 적용
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

                    // 애니메이션으로 표시
                    setTimeout(() => {
                        toast.style.opacity = '1';
                        toast.style.transform = 'translateX(0)';
                    }, 10);

                    // 3초 후 자동 제거
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

                /**
                 * 모달 닫기 핸들러 (클래스 메서드)
                 */
                handleCloseModal() {
                    console.log('🚪🚪🚪 모달 닫기 메서드 호출됨 🚪🚪🚪');
                    console.log('🚪 현재 시간:', new Date().toLocaleTimeString());

                    try {
                        // 0. 닫기 전 현재 하이라이트 상태 확인
                        console.log('📊 닫기 전 하이라이트 상태:');
                        this.checkHighlightStatus();

                        // 1. 먼저 상태 초기화 실행
                        this.resetAllStates();
                        console.log('상태 초기화 완료');

                        // 초기화 후 상태 재확인
                        console.log('📊 초기화 후 하이라이트 상태:');
                        this.checkHighlightStatus();

                        // 페이지 닫기
                        console.log('🚪 정책 빌더 페이지를 닫습니다');
                        window.close();

                        setTimeout(() => {
                            console.log('🚪 페이지 닫기 시도');
                            window.close();

                            // 3. window.close()가 작동하지 않는 경우 뒤로가기
                            setTimeout(() => {
                                if (!window.closed) {
                                    console.log('🔙 뒤로가기 실행');
                                    window.history.back();
                                }
                            }, 100);
                        }, 100);

                    } catch (error) {
                        console.error('모달 닫기 중 오류:', error);
                        // 오류가 발생해도 페이지는 닫아야 함
                        window.close();
                        if (!window.closed) window.history.back();
                    }
                }

                /**
                 * 현재 하이라이트 상태 확인 (클래스 메서드)
                 */
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

                    // 모든 초록 요소 상세 정보
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

                /**
                 * 모달 닫기 시 모든 상태 초기화
                 */
                resetAllStates() {
                    console.log('🧹 모달 닫기 - 모든 상태 초기화 시작');

                    // 1. 팔레트 하이라이트 모두 제거
                    console.log('1️⃣ 팔레트 하이라이트 제거 중...');
                    this.clearPaletteHighlights();

                    // 2. 상태 초기화
                    ['role', 'permission', 'condition'].forEach(type => this.state.clear(type));

                    // 3. 입력 필드 초기화
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

                    // 4. AI 설정 초기화
                    this.state.aiRiskAssessmentEnabled = false;
                    this.state.requiredTrustScore = 0.7;

                    if (this.elements.aiEnabledCheckbox) {
                        this.elements.aiEnabledCheckbox.checked = false;
                    }
                    if (this.elements.trustScoreSlider) {
                        this.elements.trustScoreSlider.value = 70;
                    }
                    if (this.elements.trustScoreValueSpan) {
                        this.elements.trustScoreValueSpan.textContent = '70';
                    }

                    // 5. AI 사고 과정 컨테이너 숨기기
                    const thoughtContainer = document.getElementById('ai-thought-process-container');
                    if (thoughtContainer) {
                        thoughtContainer.classList.add('hidden');
                        const thoughtLog = document.getElementById('ai-thought-process');
                        if (thoughtLog) {
                            thoughtLog.innerHTML = '';
                        }
                    }

                    // 6. UI 업데이트
                    this.handleAiToggle();
                    this.ui.renderAll(this.state);

                    console.log('모든 상태 초기화 완료');
                }

                /**
                 * 3단계: 조건 추천 관련 메서드들
                 */

                /**
                 * 개선: 권한 추가 시 스마트 매칭 조건 추천 핸들러
                 */
                async handlePermissionAdded(permissionInfo) {
                    console.log('🎯 권한 추가됨, 스마트 매칭 조건 추천 시작:', permissionInfo);

                    // 권한에서 리소스 식별자 추출
                    const resourceIdentifier = this.extractResourceFromPermission(permissionInfo);
                    const permissionName = permissionInfo.name || permissionInfo.description || `권한-${permissionInfo.id}`;

                    if (!resourceIdentifier) {
                        console.log('리소스 식별자를 추출할 수 없어 조건 추천을 생략합니다.');
                        return;
                    }

                    try {
                        // 🎯 스마트 매칭 시도 (권한명 기반)
                        console.log('🎯 스마트 매칭 시도 - 권한명:', permissionName, '리소스:', resourceIdentifier);
                        const smartResponse = await this.api.smartMatchConditions(permissionName, resourceIdentifier, "auto");

                        if (smartResponse && smartResponse.smartMatchedConditions && smartResponse.smartMatchedConditions.length > 0) {
                            console.log('스마트 매칭 성공:', smartResponse.smartMatchedConditions.length, '개 조건 매칭');
                            this.showSmartMatchModal(smartResponse, permissionName);
                            return;
                        }

                        console.log('스마트 매칭 결과 없음, 기본 추천으로 폴백');

                        // 폴백: 기본 조건 추천
                        const recommendations = await this.api.recommendConditions(resourceIdentifier, "auto");
                        if (recommendations && recommendations.totalRecommended > 0) {
                            this.showConditionRecommendModal(recommendations, `${permissionName} (기본 추천)`);
                        }
                    } catch (error) {
                        console.warn('🔥 조건 추천 실패:', error);
                    }
                }

                /**
                 * 수동 조건 추천 버튼 클릭 핸들러
                 */
                async handleManualRecommendConditions() {
                    console.log('🎯 수동 조건 추천 요청');

                    // 현재 선택된 권한들에서 리소스 식별자 추출
                    const resourceIdentifiers = this.extractResourcesFromCurrentPermissions();
                    if (resourceIdentifiers.length === 0) {
                        this.showMessage('조건을 추천하려면 먼저 권한을 선택해주세요.', 'warning');
                        return;
                    }

                    this.showLoadingModal('🎯 맞춤형 조건 추천 중...');

                    try {
                        // 첫 번째 리소스에 대한 추천 (향후 다중 리소스 지원 가능)
                        const recommendations = await this.api.recommendConditions(resourceIdentifiers[0], "manual");
                        this.hideLoadingModal();

                        if (recommendations && recommendations.totalRecommended > 0) {
                            this.showConditionRecommendModal(recommendations, '선택된 권한');
                        } else {
                            this.showMessage('현재 권한에 적용 가능한 조건이 없습니다.', 'info');
                        }
                    } catch (error) {
                        this.hideLoadingModal();
                        console.error('🔥 수동 조건 추천 실패:', error);
                        this.showMessage('조건 추천 중 오류가 발생했습니다.', 'error');
                    }
                }

                /**
                 * 권한 정보에서 리소스 식별자 추출
                 */
                extractResourceFromPermission(permissionInfo) {
                    // 권한명에서 리소스 정보 추출 로직
                    // 예: "READ_USER_PROFILE" -> "UserController.getProfile"
                    const permissionName = permissionInfo.name;

                    // 간단한 매핑 로직 (실제로는 더 정교한 매핑 필요)
                    const resourceMappings = {
                        'READ_USER': 'UserController.getUser',
                        'UPDATE_USER': 'UserController.updateUser',
                        'DELETE_USER': 'UserController.deleteUser',
                        'READ_DOCUMENT': 'DocumentController.getDocument',
                        'UPDATE_DOCUMENT': 'DocumentController.updateDocument',
                        'DELETE_DOCUMENT': 'DocumentController.deleteDocument'
                    };

                    return resourceMappings[permissionName] || null;
                }

                /**
                 * 현재 선택된 권한들에서 리소스 식별자들 추출
                 */
                extractResourcesFromCurrentPermissions() {
                    const resourceIdentifiers = [];
                    this.state.permissions.forEach((permissionInfo) => {
                        const resourceId = this.extractResourceFromPermission(permissionInfo);
                        if (resourceId && !resourceIdentifiers.includes(resourceId)) {
                            resourceIdentifiers.push(resourceId);
                        }
                    });
                    return resourceIdentifiers;
                }

                /**
                 * 개선: 스마트 매칭 모달 표시
                 */
                showSmartMatchModal(smartResponse, permissionName) {
                    console.log('🎯 스마트 매칭 모달 표시:', smartResponse);

                    // 스마트 매칭 모달 HTML 생성
                    const modalHtml = this.generateSmartMatchModalHtml(smartResponse, permissionName);

                    // 기존 모달 제거
                    const existingModal = document.getElementById('smartMatchModal');
                    if (existingModal) {
                        existingModal.remove();
                    }

                    // 새 모달 추가
                    document.body.insertAdjacentHTML('beforeend', modalHtml);

                    // 모달 표시 및 이벤트 바인딩
                    const modal = document.getElementById('smartMatchModal');
                    modal.style.display = 'flex';

                    // 조건 선택 이벤트 바인딩
                    this.bindSmartMatchModalEvents(modal, smartResponse);
                }

                /**
                 * 조건 추천 모달 표시
                 */
                showConditionRecommendModal(recommendations, contextName) {
                    console.log('🎯 조건 추천 모달 표시:', recommendations);

                    // 모달 HTML 동적 생성
                    const modalHtml = this.generateRecommendModalHtml(recommendations, contextName);

                    // 기존 모달 제거
                    const existingModal = document.getElementById('conditionRecommendModal');
                    if (existingModal) {
                        existingModal.remove();
                    }

                    // 새 모달 추가
                    document.body.insertAdjacentHTML('beforeend', modalHtml);

                    // 모달 표시 및 이벤트 바인딩
                    const modal = document.getElementById('conditionRecommendModal');
                    modal.style.display = 'flex';

                    // 조건 선택 이벤트 바인딩
                    this.bindRecommendModalEvents(modal, recommendations);
                }

                /**
                 * 개선: 스마트 매칭 모달 HTML 생성
                 */
                generateSmartMatchModalHtml(smartResponse, permissionName) {
                    const smartMatchedConditions = smartResponse.smartMatchedConditions;

                    // 매칭 점수별로 정렬 (이미 서버에서 정렬되어 있지만 확실히)
                    const sortedConditions = [...smartMatchedConditions].sort((a, b) => b.smartMatchingScore - a.smartMatchingScore);

                    // 고득점 조건 (3.0 이상)
                    const highScoreConditions = sortedConditions.filter(c => c.smartMatchingScore >= 3.0);
                    const mediumScoreConditions = sortedConditions.filter(c => c.smartMatchingScore >= 1.5 && c.smartMatchingScore < 3.0);
                    const lowScoreConditions = sortedConditions.filter(c => c.smartMatchingScore < 1.5);

                    let contentHtml = '';

                    // 고득점 조건들
                    if (highScoreConditions.length > 0) {
                        contentHtml += `
                            <div class="recommendation-group mb-4">
                                <h4 class="font-semibold text-lg mb-2 text-green-400">
                                    🎯 강력 추천 (${highScoreConditions.length}개)
                                </h4>
                                <div class="text-sm text-gray-300 mb-2">권한명과 높은 일치도를 보이는 조건들</div>
                                <div class="grid gap-2">
                        `;

                        highScoreConditions.forEach(condition => {
                            contentHtml += this.generateSmartMatchConditionHtml(condition, 'high');
                        });

                        contentHtml += '</div></div>';
                    }

                    // 중간 점수 조건들
                    if (mediumScoreConditions.length > 0) {
                        contentHtml += `
                            <div class="recommendation-group mb-4">
                                <h4 class="font-semibold text-lg mb-2 text-yellow-400">
                                    일반 추천 (${mediumScoreConditions.length}개)
                                </h4>
                                <div class="grid gap-2">
                        `;

                        mediumScoreConditions.forEach(condition => {
                            contentHtml += this.generateSmartMatchConditionHtml(condition, 'medium');
                        });

                        contentHtml += '</div></div>';
                    }

                    // 낮은 점수 조건들 (접기 가능)
                    if (lowScoreConditions.length > 0) {
                        contentHtml += `
                            <div class="recommendation-group mb-4">
                                <details class="cursor-pointer">
                                    <summary class="font-semibold text-lg mb-2 text-gray-400 hover:text-gray-200">
                                        📋 기타 호환 조건 (${lowScoreConditions.length}개)
                                    </summary>
                                    <div class="grid gap-2 mt-2">
                        `;

                        lowScoreConditions.forEach(condition => {
                            contentHtml += this.generateSmartMatchConditionHtml(condition, 'low');
                        });

                        contentHtml += '</div></details></div>';
                    }

                    return `
                        <div id="smartMatchModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" style="display: none;">
                            <div class="bg-gray-800 p-6 rounded-lg shadow-xl max-w-5xl max-h-[85vh] overflow-y-auto">
                                <div class="flex justify-between items-center mb-4">
                                    <h3 class="text-xl font-bold text-white">🎯 "${permissionName}" 권한에 대한 스마트 조건 매칭</h3>
                                    <button id="closeSmartMatchModal" class="text-gray-400 hover:text-white text-2xl">&times;</button>
                                </div>
                                <div class="text-sm text-gray-300 mb-4">
                                    권한명 기반 의미적 분석으로 총 ${smartMatchedConditions.length}개의 관련 조건을 발견했습니다.
                                    <br>📊 리소스: ${smartResponse.resourceFriendlyName || smartResponse.resourceIdentifier}
                                </div>
                                ${contentHtml}
                                <div class="flex justify-end mt-4 space-x-2">
                                    <button id="addAllHighScoreBtn" class="bg-green-600 hover:bg-green-500 text-white px-4 py-2 rounded">
                                        강력 추천 모두 추가 (${highScoreConditions.length}개)
                                    </button>
                                    <button id="closeSmartMatchModal" class="bg-gray-600 hover:bg-gray-500 text-white px-4 py-2 rounded">
                                        닫기
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                }

                /**
                 * 스마트 매치 조건 HTML 생성
                 */
                generateSmartMatchConditionHtml(condition, scoreLevel) {
                    const borderColors = {
                        'high': 'border-green-500',
                        'medium': 'border-yellow-500',
                        'low': 'border-gray-500'
                    };

                    const bgColors = {
                        'high': 'bg-green-900 bg-opacity-20',
                        'medium': 'bg-yellow-900 bg-opacity-20',
                        'low': 'bg-gray-700'
                    };

                    const riskColor = {
                        'LOW': 'text-green-400',
                        'MEDIUM': 'text-yellow-400',
                        'HIGH': 'text-red-400'
                    }[condition.riskLevel] || 'text-gray-400';

                    const classificationIcon = {
                        'UNIVERSAL': '🟢',
                        'CONTEXT_DEPENDENT': '🟡',
                        'CUSTOM_COMPLEX': '🔴'
                    }[condition.classification] || '⚪';

                    return `
                        <div class="smart-match-item p-3 border ${borderColors[scoreLevel]} ${bgColors[scoreLevel]} rounded-lg hover:bg-opacity-40 cursor-pointer"
                             data-condition-id="${condition.id}"
                             data-score-level="${scoreLevel}">
                            <div class="flex justify-between items-start">
                                <div class="flex-1">
                                    <div class="flex items-center gap-2">
                                        <span class="font-medium text-white">${condition.name}</span>
                                        <span class="text-xs">${classificationIcon}</span>
                                        <span class="text-xs px-2 py-1 bg-blue-600 text-white rounded">
                                            점수: ${condition.smartMatchingScore.toFixed(1)}
                                        </span>
                                    </div>
                                    <div class="text-sm text-gray-300 mt-1">${condition.description}</div>
                                    <div class="text-xs text-gray-400 mt-2">
                                        🎯 매칭 이유: <span class="text-blue-300">${condition.matchingReason}</span>
                                    </div>
                                    <div class="text-xs text-gray-400 mt-1">
                                        복잡도: ${condition.complexityScore} | 
                                        위험도: <span class="${riskColor}">${condition.riskLevel}</span> |
                                        호환성: ${condition.compatibilityReason}
                                    </div>
                                </div>
                                <button class="add-smart-condition-btn bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1 rounded text-sm ml-4"
                                        data-condition-id="${condition.id}">
                                    추가
                                </button>
                            </div>
                        </div>
                    `;
                }

                /**
                 * 조건 추천 모달 HTML 생성
                 */
                generateRecommendModalHtml(recommendations, contextName) {
                    const recommendedConditions = recommendations.recommendedConditions;

                    let contentHtml = '';

                    // 분류별로 조건들을 렌더링
                    Object.entries(recommendedConditions).forEach(([classification, conditions]) => {
                        if (conditions.length === 0) return;

                        const classificationNames = {
                            'UNIVERSAL': '🟢 범용 조건',
                            'CONTEXT_DEPENDENT': '🟡 컨텍스트 의존 조건',
                            'CUSTOM_COMPLEX': '🔴 복잡한 조건'
                        };

                        contentHtml += `
                            <div class="recommendation-group mb-4">
                                <h4 class="font-semibold text-lg mb-2 text-indigo-300">
                                    ${classificationNames[classification] || classification}
                                </h4>
                                <div class="grid gap-2">
                        `;

                        conditions.forEach((condition, index) => {
                            const riskColor = {
                                'LOW': 'text-green-400',
                                'MEDIUM': 'text-yellow-400',
                                'HIGH': 'text-red-400'
                            }[condition.riskLevel] || 'text-gray-400';

                            contentHtml += `
                                <div class="recommendation-item p-3 border border-gray-600 rounded-lg hover:bg-gray-700 cursor-pointer"
                                     data-condition-id="${condition.id}"
                                     data-classification="${classification}">
                                    <div class="flex justify-between items-start">
                                        <div class="flex-1">
                                            <div class="font-medium text-white">${condition.name}</div>
                                            <div class="text-sm text-gray-300 mt-1">${condition.description}</div>
                                            <div class="text-xs text-gray-400 mt-1">
                                                추천 점수: ${condition.recommendationScore.toFixed(2)} | 
                                                복잡도: ${condition.complexityScore} | 
                                                위험도: <span class="${riskColor}">${condition.riskLevel}</span>
                                            </div>
                                        </div>
                                        <button class="add-condition-btn bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1 rounded text-sm"
                                                data-condition-id="${condition.id}">
                                            추가
                                        </button>
                                    </div>
                                </div>
                            `;
                        });

                        contentHtml += `
                                </div>
                            </div>
                        `;
                    });

                    return `
                        <div id="conditionRecommendModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" style="display: none;">
                            <div class="bg-gray-800 p-6 rounded-lg shadow-xl max-w-4xl max-h-[80vh] overflow-y-auto">
                                <div class="flex justify-between items-center mb-4">
                                    <h3 class="text-xl font-bold text-white">🎯 ${contextName}에 대한 조건 추천</h3>
                                    <button id="closeRecommendModal" class="text-gray-400 hover:text-white text-2xl">&times;</button>
                                </div>
                                <div class="text-sm text-gray-300 mb-4">
                                    총 ${recommendations.totalRecommended}개의 적용 가능한 조건이 발견되었습니다.
                                </div>
                                ${contentHtml}
                                <div class="flex justify-end mt-4">
                                    <button id="closeRecommendModal" class="bg-gray-600 hover:bg-gray-500 text-white px-4 py-2 rounded">
                                        닫기
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                }

                /**
                 * 개선: 스마트 매칭 모달 이벤트 바인딩
                 */
                bindSmartMatchModalEvents(modal, smartResponse) {
                    // 개별 조건 추가 버튼들
                    const addButtons = modal.querySelectorAll('.add-smart-condition-btn');
                    addButtons.forEach(btn => {
                        btn.addEventListener('click', (e) => {
                            e.stopPropagation();
                            const conditionId = btn.getAttribute('data-condition-id');
                            this.addSmartMatchedCondition(conditionId, smartResponse);
                        });
                    });

                    // 강력 추천 모두 추가 버튼
                    const addAllBtn = modal.querySelector('#addAllHighScoreBtn');
                    if (addAllBtn) {
                        addAllBtn.addEventListener('click', () => {
                            this.addAllHighScoreConditions(smartResponse);
                        });
                    }

                    // 모달 닫기
                    const closeButtons = modal.querySelectorAll('#closeSmartMatchModal');
                    closeButtons.forEach(btn => {
                        btn.addEventListener('click', () => this.hideSmartMatchModal());
                    });

                    // 모달 외부 클릭시 닫기
                    modal.addEventListener('click', (e) => {
                        if (e.target === modal) {
                            this.hideSmartMatchModal();
                        }
                    });
                }

                /**
                 * 스마트 매칭된 조건 추가
                 */
                addSmartMatchedCondition(conditionId, smartResponse) {
                    // 스마트 매칭 목록에서 해당 조건 찾기
                    const foundCondition = smartResponse.smartMatchedConditions.find(c => c.id == conditionId);

                    if (!foundCondition) {
                        console.error('🔥 스마트 매칭 조건을 찾을 수 없습니다:', conditionId);
                        return;
                    }

                    // 상태에 조건 추가
                    this.state.add('condition', `${foundCondition.id}:smartmatch`, {
                        id: foundCondition.id,
                        name: foundCondition.name,
                        description: foundCondition.description,
                        isValidated: true,
                        isCompatible: true,
                        reason: `스마트 매칭을 통해 추가됨 (점수: ${foundCondition.smartMatchingScore.toFixed(1)})`
                    });

                    // UI 업데이트
                    this.ui.renderAll(this.state);

                    // 팔레트에서 해당 조건 하이라이트
                    this.highlightPaletteItem('condition', foundCondition.id);

                    this.showMessage(`조건 "${foundCondition.name}"이 추가되었습니다. (매칭 점수: ${foundCondition.smartMatchingScore.toFixed(1)})`, 'success');

                    console.log('스마트 매칭 조건 추가됨:', foundCondition.name, '점수:', foundCondition.smartMatchingScore);
                }

                /**
                 * 강력 추천 조건들 모두 추가
                 */
                addAllHighScoreConditions(smartResponse) {
                    const highScoreConditions = smartResponse.smartMatchedConditions.filter(c => c.smartMatchingScore >= 3.0);

                    if (highScoreConditions.length === 0) {
                        this.showMessage('강력 추천 조건이 없습니다.', 'info');
                        return;
                    }

                    let addedCount = 0;
                    highScoreConditions.forEach(condition => {
                        // 중복 확인
                        const existingKey = Array.from(this.state.conditions.keys()).find(key =>
                            key.startsWith(`${condition.id}:`));

                        if (!existingKey) {
                            this.state.add('condition', `${condition.id}:smartmatch-bulk`, {
                                id: condition.id,
                                name: condition.name,
                                description: condition.description,
                                isValidated: true,
                                isCompatible: true,
                                reason: `스마트 매칭 일괄 추가 (점수: ${condition.smartMatchingScore.toFixed(1)})`
                            });
                            addedCount++;
                        }
                    });

                    // UI 업데이트
                    this.ui.renderAll(this.state);

                    // 팔레트 하이라이트
                    highScoreConditions.forEach(condition => {
                        this.highlightPaletteItem('condition', condition.id);
                    });

                    this.showMessage(`${addedCount}개의 강력 추천 조건이 모두 추가되었습니다.`, 'success');
                    this.hideSmartMatchModal();

                    console.log('강력 추천 조건 일괄 추가 완료:', addedCount, '개');
                }

                /**
                 * 스마트 매칭 모달 숨기기
                 */
                hideSmartMatchModal() {
                    const modal = document.getElementById('smartMatchModal');
                    if (modal) {
                        modal.style.display = 'none';
                        modal.remove();
                    }
                }

                /**
                 * 조건 추천 모달 이벤트 바인딩
                 */
                bindRecommendModalEvents(modal, recommendations) {
                    // 조건 추가 버튼 이벤트
                    modal.querySelectorAll('.add-condition-btn').forEach(button => {
                        button.addEventListener('click', (e) => {
                            const conditionId = e.target.dataset.conditionId;
                            this.addRecommendedCondition(conditionId, recommendations);
                        });
                    });

                    // 닫기 버튼 이벤트
                    modal.querySelectorAll('#closeRecommendModal').forEach(button => {
                        button.addEventListener('click', () => {
                            this.hideConditionRecommendModal();
                        });
                    });
                }

                /**
                 * 추천된 조건 추가
                 */
                addRecommendedCondition(conditionId, recommendations) {
                    // 추천 목록에서 해당 조건 찾기
                    let foundCondition = null;
                    Object.values(recommendations.recommendedConditions).forEach(conditions => {
                        const condition = conditions.find(c => c.id == conditionId);
                        if (condition) foundCondition = condition;
                    });

                    if (!foundCondition) {
                        console.error('🔥 추천 조건을 찾을 수 없습니다:', conditionId);
                        return;
                    }

                    // 상태에 조건 추가
                    this.state.add('condition', `${foundCondition.id}:recommend`, {
                        id: foundCondition.id,
                        name: foundCondition.name,
                        description: foundCondition.description,
                        isValidated: true,
                        isCompatible: true,
                        reason: '추천 시스템을 통해 추가됨'
                    });

                    // UI 업데이트
                    this.ui.renderAll(this.state);

                    // 팔레트에서 해당 조건 하이라이트
                    this.highlightPaletteItem('condition', foundCondition.id);

                    this.showMessage(`조건 "${foundCondition.name}"이 추가되었습니다.`, 'success');

                    console.log('추천 조건 추가됨:', foundCondition.name);
                }

                /**
                 * 조건 추천 모달 숨기기
                 */
                hideConditionRecommendModal() {
                    const modal = document.getElementById('conditionRecommendModal');
                    if (modal) {
                        modal.style.display = 'none';
                        modal.remove();
                    }
                }

                // ============================= 
                // 🎥 AI Studio 스트리밍 메서드들 (PolicyBuilderApp 내부)
                // ============================= 

                showStreamingProgressModal(query) {
                    console.log('🎥 스트리밍 모달 표시:', query);

                    // 🔥 기존 모달 제거 (상태 플래그는 초기화하지 않음)
                    this.removeExistingStreamingModal();

                    // 모달 HTML 동적 생성
                    const modalHtml = `
                    <div id="streaming-modal" class="streaming-modal">
                        <div class="streaming-modal-content">
                            <div class="streaming-header">
                                <h3><i class="fas fa-brain mr-2"></i>AI 정책 분석 진행 중</h3>
                                <button class="streaming-close-btn" onclick="window.forceHideStreamingModal()">
                                    <i class="fas fa-times"></i>
                                </button>
                                <div class="streaming-query">
                                    <strong>질의:</strong> <span id="streaming-query-text">${this.escapeHtml(query)}</span>
                                </div>
                            </div>
                            
                            <div class="streaming-progress">
                                <div class="streaming-content" id="streaming-content">
                                    <div class="streaming-step">
                                        <i class="fas fa-cog fa-spin mr-2"></i>
                                        AI가 정책 분석을 시작합니다...
                                    </div>
                                </div>
                            </div>
                            
                            <div class="streaming-footer">
                                <div class="streaming-animation">
                                    <div class="dot"></div>
                                    <div class="dot"></div>
                                    <div class="dot"></div>
                                </div>
                                <small>AI가 정책을 분석하고 있습니다. 잠시만 기다려주세요.</small>
                            </div>
                        </div>
                    </div>
                `;

                    // body에 모달 추가
                    document.body.insertAdjacentHTML('beforeend', modalHtml);

                    // 모달 표시
                    const modal = document.getElementById('streaming-modal');
                    if (modal) {
                        // 강제로 display flex 설정
                        modal.style.display = 'flex';

                        // 애니메이션을 위한 지연
                        requestAnimationFrame(() => {
                            modal.classList.add('show');
                        });
                    }
                }

                // 🗑️ [제거됨] startStreamingProgress - 일원화된 스트리밍으로 대체됨

                addStreamingStepImmediate(text) {
                    const streamingContent = document.getElementById('streaming-content');
                    if (!streamingContent) return;

                    console.log('🌊 스트리밍 단계 추가:', text);

                    // 스트리밍 단계 생성
                    const stepDiv = document.createElement('div');
                    stepDiv.className = 'streaming-step';
                    stepDiv.style.opacity = '0';
                    stepDiv.style.transform = 'translateX(-10px)';

                    // 아이콘 결정
                    let icon = 'fas fa-arrow-right';
                    if (text.includes('분석')) icon = 'fas fa-search';
                    else if (text.includes('검토')) icon = 'fas fa-check';
                    else if (text.includes('생성')) icon = 'fas fa-cog';
                    else if (text.includes('완료')) icon = 'fas fa-check-circle text-green-400';
                    else if (text.includes('오류')) icon = 'fas fa-exclamation-triangle text-red-400';

                    stepDiv.innerHTML = `<i class="${icon} mr-2"></i>${this.escapeHtml(text)}`;

                    // DOM에 추가
                    streamingContent.appendChild(stepDiv);

                    // 강제 리플로우
                    void stepDiv.offsetHeight;

                    // 애니메이션 효과
                    requestAnimationFrame(() => {
                        stepDiv.style.transition = 'all 0.3s ease';
                        stepDiv.style.opacity = '1';
                        stepDiv.style.transform = 'translateX(0)';

                        // 스크롤을 맨 아래로
                        streamingContent.scrollTop = streamingContent.scrollHeight;
                    });
                }

                /**
                 * 🌊 스트리밍 단계 추가 (AI Studio 방식 - 서버에서 완성된 문장 수신)
                 */
                addStreamingStep(text) {
                    const streamingContent = document.getElementById('streaming-content');
                    if (!streamingContent) {
                        console.error('🌊 스트리밍 컨텐츠 요소 없음');
                        return;
                    }

                    console.log('🌊 서버에서 완성된 문장 수신:', text);

                    // 서버에서 이미 완성된 문장을 보내므로 간단한 필터링만 적용
                    if (text && text.trim().length > 0) {
                        console.log('🌊 완성된 문장 추가:', text);
                        const stepDiv = document.createElement('div');
                        stepDiv.className = 'streaming-step';
                        stepDiv.innerHTML = `<i class="fas fa-arrow-right mr-2"></i>${this.escapeHtml(text)}`;
                        
                        streamingContent.appendChild(stepDiv);
                        streamingContent.scrollTop = streamingContent.scrollHeight;
                    } else {
                        console.log('🌊 빈 텍스트로 스킵됨:', text);
                    }
                }

                /**
                 * 🌊 스트리밍 중지
                 */
                stopStreamingProgress() {
                    this.isStreaming = false;
                    
                    const streamingContent = document.getElementById('streaming-content');
                    if (streamingContent) {
                        const completedStep = document.createElement('div');
                        completedStep.className = 'streaming-step';
                        completedStep.innerHTML = '<i class="fas fa-check-circle mr-2 text-green-400"></i>AI 정책 분석이 완료되었습니다.';
                        streamingContent.appendChild(completedStep);
                        streamingContent.scrollTop = streamingContent.scrollHeight;
                    }
                    
                    // 🔥 스트리밍 완료 메시지를 충분히 보여준 후 모달 닫기
                    setTimeout(() => {
                        console.log('🛑 스트리밍 완료 - 3초 후 모달 자동 닫기');
                        this.hideStreamingProgressModal();
                    }, 3000);
                }

                /**
                 * 🧹 기존 스트리밍 모달 제거 (상태 플래그 초기화 안함)
                 */
                removeExistingStreamingModal() {
                    const modal = document.getElementById('streaming-modal');
                    if (modal) {
                        console.log('🧹 기존 스트리밍 모달 DOM 제거');
                        modal.classList.remove('show');
                        modal.style.display = 'none';
                        
                        // DOM에서 즉시 제거
                        if (modal.parentNode) {
                            modal.parentNode.removeChild(modal);
                        }
                    }
                }

                /**
                 * 🎥 스트리밍 모달 숨기기
                 */
                hideStreamingProgressModal() {
                    // 🔥 호출 스택 추적
                    console.log('hideStreamingProgressModal 호출됨 - 스트리밍 완료 처리');
                    console.log('📍 호출 스택:', new Error().stack);
                    
                    const modal = document.getElementById('streaming-modal');
                    if (modal) {
                        console.log('모달 발견 - 실제로 숨기기 진행');
                        
                        // 🔥 먼저 상태 플래그 초기화
                        this.isProcessingQuery = false;
                        this.isStreaming = false;
                        this.ui.setLoading(this.elements.generateByAiBtn, false);
                        console.log('스트리밍 모달 숨김 - 상태 플래그 초기화 완료');
                        
                        // 🔥 모달을 완전히 숨기기
                        modal.classList.remove('show');
                        modal.style.display = 'none';
                        console.log('🎥 스트리밍 모달 숨김');
                        
                        // 🔥 모달을 DOM에서 완전히 제거 (애니메이션을 위해 약간의 지연)
                        setTimeout(() => {
                            if (modal.parentNode) {
                                modal.parentNode.removeChild(modal);
                                console.log('🎥 스트리밍 모달 DOM에서 제거 완료');
                            }
                        }, 1000);
                    } else {
                        console.error('모달을 찾을 수 없음!');
                    }
                }

                /**
                 * 🔧 JSON 청크 감지
                 */
                isJsonChunk(text) {
                    const trimmed = text.trim();
                    return trimmed.startsWith('{') || trimmed.startsWith('[') || 
                           trimmed.includes('===JSON') || trimmed.includes('policyData') ||
                           trimmed.includes('"roles"') || trimmed.includes('"permissions"');
                }

                /**
                 * 🔧 유효한 분석 단계 확인
                 */
                isValidAnalysisStep(text) {
                    const analysisKeywords = ['분석', '검토', '확인', '생성', '처리', '평가', '구성'];
                    return analysisKeywords.some(keyword => text.includes(keyword));
                }

                /**
                 * 🔧 HTML 이스케이프
                 */
                escapeHtml(text) {
                    const div = document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }
            }

            const policyBuilderApp = new PolicyBuilderApp();

            // 전역 함수로 등록하여 HTML에서 호출 가능하도록 함
            window.resetPolicyBuilderStates = () => {
                // 🔥 AI 처리 상태 강제 초기화
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

            // 🎥 스트리밍 모달 강제 닫기 (모달 닫기 버튼용)
            window.forceHideStreamingModal = () => {
                console.log('🚪 스트리밍 모달 강제 닫기 요청');
                if (policyBuilderApp) {
                    policyBuilderApp.hideStreamingProgressModal();
                }
            };

            // 하이라이트 테스트 함수 (디버깅용)
            window.testHighlightClear = () => {
                console.log('🧪 하이라이트 제거 테스트 시작');
                policyBuilderApp.clearPaletteHighlights();
                console.log('🧪 하이라이트 제거 테스트 완료');
            };

            // 브루트 포스 하이라이트 제거 함수 (긴급용)
            window.bruteForceRemoveHighlights = () => {
                console.log('🔥 전역 브루트 포스 하이라이트 제거 시작');

                // 1. 모든 ai-selected 클래스 제거
                document.querySelectorAll('.ai-selected').forEach(element => {
                    element.classList.remove('ai-selected');
                    element.removeAttribute('style');
                    console.log('  ↳ ai-selected 제거:', element.getAttribute('data-info'));
                });

                // 2. 모든 text-green-400 클래스 제거 (preselected 제외)
                document.querySelectorAll('.text-green-400').forEach(element => {
                    const paletteItem = element.closest('.palette-item');
                    if (!paletteItem || !paletteItem.classList.contains('preselected')) {
                        element.classList.remove('text-green-400', 'font-semibold');
                        element.removeAttribute('style');
                        console.log('  ↳ text-green-400 제거:', element.tagName);
                    }
                });

                // 3. 모든 fa-check-circle 아이콘 복원 (preselected 제외)
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

                // 4. 모든 palette-item의 인라인 스타일 제거
                document.querySelectorAll('.palette-item').forEach(item => {
                    if (item.style.background || item.style.borderColor || item.style.boxShadow) {
                        item.removeAttribute('style');
                        console.log('  ↳ palette-item 스타일 제거:', item.getAttribute('data-info'));
                    }
                });

                console.log('🔥 전역 브루트 포스 하이라이트 제거 완료');
            };

            // 현재 하이라이트 상태 확인 함수
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

                // 모든 초록 요소 상세 정보
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

            // 🔥 스트리밍 모달 강제 숨기기 함수
            window.forceHideStreamingModal = () => {
                console.log('🔥 스트리밍 모달 강제 숨기기 시작');
                
                const modal = document.getElementById('streaming-modal');
                if (modal) {
                    // 모달 완전히 숨기기
                    modal.classList.remove('show');
                    modal.style.display = 'none';
                    
                    // DOM에서 제거
                    setTimeout(() => {
                        if (modal.parentNode) {
                            modal.parentNode.removeChild(modal);
                            console.log('🔥 스트리밍 모달 DOM에서 강제 제거 완료');
                        }
                    }, 100);
                }
                
                // 🔥 모든 상태 플래그 강제 초기화
                if (policyBuilderApp) {
                    policyBuilderApp.isProcessingQuery = false;
                    policyBuilderApp.isStreaming = false;
                    if (policyBuilderApp.ui && policyBuilderApp.elements.generateByAiBtn) {
                        policyBuilderApp.ui.setLoading(policyBuilderApp.elements.generateByAiBtn, false);
                    }
                    console.log('🔥 스트리밍 모달 강제 숨기기 - 모든 상태 플래그 초기화 완료');
                }
            };

            // 모달 닫기 핸들러 함수
            window.handleCloseModal = () => {
                console.log('🚪 모달 닫기 버튼 클릭됨');

                try {
                    // 0. 닫기 전 현재 하이라이트 상태 확인
                    console.log('📊 닫기 전 하이라이트 상태:');
                    window.checkHighlightStatus();

                    // 🔥 AI 처리 상태 강제 초기화
                    if (policyBuilderApp) {
                        policyBuilderApp.isProcessingQuery = false;
                        policyBuilderApp.isStreaming = false;
                        if (policyBuilderApp.ui && policyBuilderApp.elements.generateByAiBtn) {
                            policyBuilderApp.ui.setLoading(policyBuilderApp.elements.generateByAiBtn, false);
                        }
                        console.log('🔥 AI 처리 상태 강제 초기화 완료');
                    }

                    // 1. 먼저 상태 초기화 실행
                    if (typeof window.resetPolicyBuilderStates === 'function') {
                        window.resetPolicyBuilderStates();
                        console.log('상태 초기화 완료');

                        // 초기화 후 상태 재확인
                        console.log('📊 초기화 후 하이라이트 상태:');
                        window.checkHighlightStatus();
                    }

                    // 페이지 닫기
                    setTimeout(() => {
                        console.log('🚪 페이지 닫기 시도');
                        window.close();

                        // window.close()가 작동하지 않는 경우 뒤로가기
                        setTimeout(() => {
                            if (!window.closed) {
                                console.log('🔙 뒤로가기 실행');
                                window.history.back();
                            }
                        }, 100);
                    }, 100);

                } catch (error) {
                    console.error('모달 닫기 중 오류:', error);
                    // 오류가 발생해도 페이지는 닫아야 함
                    window.close();
                    if (!window.closed) window.history.back();
                }
            };

            // 페이지 언로드 시에도 상태 초기화 (브라우저 뒤로가기, 새로고침 등)
            window.addEventListener('beforeunload', () => {
                policyBuilderApp.resetAllStates();
            });

            // ESC 키 눌렀을 때 모달 닫기 및 초기화
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    console.log('⌨️ ESC 키 눌림');
                    
                    // 🔥 스트리밍 모달이 열려있으면 우선 닫기
                    const streamingModal = document.getElementById('streaming-modal');
                    if (streamingModal && streamingModal.style.display !== 'none') {
                        console.log('⌨️ ESC 키로 스트리밍 모달 닫기');
                        if (typeof window.forceHideStreamingModal === 'function') {
                            window.forceHideStreamingModal();
                        }
                    } else {
                        // 스트리밍 모달이 없으면 일반 모달 닫기
                        policyBuilderApp.handleCloseModal();
                    }
                }
            });

            console.log('🌟 PolicyBuilderApp 초기화 성공!');
        } catch (error) {
            console.error('PolicyBuilderApp 초기화 실패:', error);
        }
    });
})();

// ============================= 
// 🎥 스트리밍 함수들이 PolicyBuilderApp 클래스 내부로 이동됨
// ============================= 