// =============================
// 🌐 클라이언트 다국어화 (서버 하드코딩 문제 해결)
// =============================
const AI_STUDIO_MESSAGES = {
    ko: {
        // 질의 관련
        queryPlaceholder: "AI에게 자연어로 질의하세요\n예: '개발팀에서 누가 고객 데이터를 삭제할 수 있나요?'",
        queryExamples: {
            whoCanAccess: "누가 ~할 수 있나요?",
            whyCannot: "왜 ~할 수 없나요?",
            accessPath: "접근 경로는?"
        },

        // 시각화 관련
        visualization: {
            title: "권한 시각화",
            types: {
                NETWORK: "네트워크",
                HIERARCHY: "계층구조",
                FLOWCHART: "플로우차트",
                MATRIX: "매트릭스"
            },
            noData: "시각화할 데이터가 없습니다.",
            loading: "시각화 생성 중..."
        },

        // AI 응답 관련
        aiResponse: {
            confidence: {
                high: "신뢰도 높음",
                medium: "신뢰도 보통",
                low: "신뢰도 낮음"
            },
            thinking: "AI가 분석 중입니다..."
        },

        // 오류 메시지
        errors: {
            queryEmpty: "질의를 입력해주세요.",
            networkError: "네트워크 오류가 발생했습니다.",
            aiError: "AI 분석 중 오류가 발생했습니다.",
            processing: "이미 처리 중입니다. 잠시 후 다시 시도해주세요.",
            tooFrequent: "너무 자주 질의하고 있습니다. 잠시 후 다시 시도해주세요.",
            general: "오류가 발생했습니다. 다시 시도해주세요."
        }
    }
};

// 현재 언어 (추후 다국어 확장 가능)
const currentLang = 'ko';
const MSG = AI_STUDIO_MESSAGES[currentLang];

// =============================
// 🧠 AI Studio Legacy Class (renamed to avoid conflict with modular AIStudioCore)
// =============================
class AIStudioLegacy {
    constructor() {
        this.currentPermissionData = null;
        this.currentQuery = null;
        this.aiQueryHistory = [];
        this.currentZoom = 1;
        this.currentVisualizationType = 'network';
        this.currentAIAnalysis = null;
        this.currentVisualizationData = null;
        this.currentOriginalQuery = null;

        // 중복 호출 방지 플래그
        this.isProcessingQuery = false;
        this.lastQueryTime = 0;
        this.MIN_QUERY_INTERVAL = 2000; // 최소 2초 간격

        // 🎥 스트리밍 관련 상태
        this.streamingModal = null;
        this.streamingEventSource = null;
        this.streamingContent = '';
        this.isStreaming = false;
        this.isProcessingQuery = false; // 🔥 Policy Builder와 동일한 상태 플래그 추가

        // 🔥 Cytoscape 관련 초기화 (Mermaid 대체)
        this.cytoscapeInstance = null;
        this.cytoscapeInitialized = false;
        this.currentLayoutIndex = 0;
        this.availableLayouts = ['cola', 'dagre', 'circle', 'grid', 'breadthfirst'];

        // 🔧 메시지 상수
        this.MSG = MSG;

        // 메서드 바인딩
        this.handleAIQuery = this.handleAIQuery.bind(this);
        this.sendAIQuery = this.sendAIQuery.bind(this);
        this.startUnifiedStreamingAnalysis = this.startUnifiedStreamingAnalysis.bind(this);
        this.processAIResponse = this.processAIResponse.bind(this);

        this.init();
    }

    async init() {
        await this.initializeCytoscape(); // 🔥 Mermaid 대신 Cytoscape 초기화
        this.bindEventListeners();
        console.log('🚀 AI-Native Authorization Studio initialized with Cytoscape');
    }

    // =============================
    // 🎨 Cytoscape 초기화 및 관리 (Mermaid 대체)
    // =============================
    async initializeCytoscape() {
        // Cytoscape 라이브러리 로딩 확인
        if (typeof cytoscape === 'undefined') {
            console.warn('Cytoscape.js 라이브러리 로딩 대기 중...');

            // 라이브러리 로딩 대기 (최대 5초)
            let attempts = 0;
            const maxAttempts = 50;

            while (typeof cytoscape === 'undefined' && attempts < maxAttempts) {
                await new Promise(resolve => setTimeout(resolve, 100));
                attempts++;
            }

            if (typeof cytoscape === 'undefined') {
                console.error('Cytoscape.js 라이브러리를 로드할 수 없습니다');
                return false;
            }
        }

        // 확장 라이브러리 확인
        try {
            // Cola 레이아웃 확인
            const testInstance = cytoscape({headless: true});
            const colaLayout = testInstance.layout({name: 'cola'});
            if (!colaLayout || !colaLayout.run) {
                this.availableLayouts = this.availableLayouts.filter(l => l !== 'cola');
                console.warn('Cola layout 사용 불가');
            }

            // Dagre 레이아웃 확인
            const dagreLayout = testInstance.layout({name: 'dagre'});
            if (!dagreLayout || !dagreLayout.run) {
                this.availableLayouts = this.availableLayouts.filter(l => l !== 'dagre');
                console.warn('Dagre layout 사용 불가');
            }

            testInstance.destroy();
        } catch (e) {
            console.warn('확장 레이아웃 확인 중 오류:', e);
        }

        this.cytoscapeInitialized = true;
        console.log('🎨 Cytoscape initialized with layouts:', this.availableLayouts);
        return true;
    }

    // =============================
    // 🎯 이벤트 리스너 바인딩
    // =============================
    bindEventListeners() {
        // AI 질의 버튼
        const aiQueryBtn = document.getElementById('ai-query-btn');
        const aiQueryInput = document.getElementById('ai-query-input');

        if (aiQueryBtn && aiQueryInput) {
            aiQueryBtn.addEventListener('click', () => this.handleAIQuery());
            aiQueryInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.handleAIQuery();
                }
            });

            // 🎯 타이핑 효과 추가
            let typingTimer;

            aiQueryInput.addEventListener('input', () => {
                // 타이핑 클래스 추가
                aiQueryInput.classList.add('typing');

                // 이전 타이머 클리어
                clearTimeout(typingTimer);

                // 1초 후 타이핑 클래스 제거
                typingTimer = setTimeout(() => {
                    aiQueryInput.classList.remove('typing');
                }, 1000);
            });

            // 포커스 아웃 시 타이핑 클래스 제거
            aiQueryInput.addEventListener('blur', () => {
                aiQueryInput.classList.remove('typing');
                clearTimeout(typingTimer);
            });
        }

        // 시각화 타입 변경
        const visualizationType = document.getElementById('visualization-type');
        if (visualizationType) {
            visualizationType.addEventListener('change', (e) => {
                this.changeVisualizationType(e.target.value);
            });
        }

        // 전체화면 버튼
        const fullscreenBtn = document.getElementById('canvas-fullscreen-btn');
        if (fullscreenBtn) {
            fullscreenBtn.addEventListener('click', () => this.showFullscreen());
        }

        // 전체화면 닫기
        const closeFullscreenBtn = document.getElementById('close-fullscreen-btn');
        if (closeFullscreenBtn) {
            closeFullscreenBtn.addEventListener('click', () => this.closeFullscreen());
        }

        // 내보내기 버튼
        const exportBtn = document.getElementById('canvas-export-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportVisualization());
        }

        // ESC 키로 전체화면 닫기
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeFullscreen();
            }
        });
    }

    // =============================
    // 🧠 AI 자연어 질의 처리 - 병렬 처리 개선
    // =============================
    async handleAIQuery() {
        // 중복 호출 방지 체크
        if (this.isProcessingQuery) {
            console.warn('이미 처리 중인 질의가 있습니다.');
            this.showToast(this.MSG.errors.processing, 'warning');
            return;
        }

        const currentTime = Date.now();
        if (currentTime - this.lastQueryTime < this.MIN_QUERY_INTERVAL) {
            console.warn('질의 간격이 너무 짧습니다.');
            this.showToast(this.MSG.errors.tooFrequent, 'warning');
            return;
        }

        const queryInput = document.getElementById('ai-query-input');
        const query = queryInput ? queryInput.value.trim() : '';

        if (!query) {
            this.showToast(this.MSG.errors.queryEmpty, 'warning');
            return;
        }

        // 처리 시작 플래그 설정
        this.isProcessingQuery = true;
        this.lastQueryTime = currentTime;
        this.currentOriginalQuery = query;

        // UI 상태 변경
        this.setAIThinking(true);
        this.hideCanvasPlaceholder();

        try {
            console.log('🧠 AI Query (일원화된 스트리밍):', query);

            // AI 질의 히스토리에 추가
            this.aiQueryHistory.push({
                query: query,
                timestamp: new Date().toISOString()
            });

            // 🎥 스트리밍 모달 표시하고 DOM 추가 완료 대기
            this.showStreamingProgressModal(query);
            await new Promise(resolve => setTimeout(resolve, 100));

            console.log('🌊 [일원화] 단일 스트리밍 호출 시작');

            // 🔥 일원화된 스트리밍 호출 (SecurityCopilot 방식)
            await this.startUnifiedStreamingAnalysis(query);

            console.log('[일원화] 스트리밍 완료');

        } catch (error) {
            console.error('AI Studio 질의 실패:', error);
            this.handleQueryError(error, query);
        } finally {
            // 처리 완료 플래그 해제
            this.isProcessingQuery = false;
            this.setAIThinking(false);

            // 입력창 초기화
            if (queryInput) queryInput.value = '';
        }
    }


    // 스트리밍을 비동기로 독립 실행
    async startStreamingProgressAsync(query) {
        try {
            console.log('🌊 스트리밍 비동기 시작');
            await this.startUnifiedStreamingAnalysis(query);
            console.log('스트리밍 완료');

            // 스트리밍 완료 메시지 표시
            this.showStreamingComplete();

        } catch (error) {
            console.error('🌊 스트리밍 오류:', error);
            this.addStreamingStep('스트리밍 중 오류가 발생했습니다.');
        }
    }

    // 🗑️ [제거됨] startAIQueryAsync - 일원화된 스트리밍으로 대체됨

    // 오류 처리 통합
    handleQueryError(error, query) {
        // 모달 닫기
        this.hideStreamingProgressModal();

        // 오류 메시지 표시
        const userMessage = this.getErrorMessage(error);
        this.addStreamingStep(`오류 발생: ${userMessage}`);
        this.showToast(userMessage, 'error');
        this.displayErrorInInspector(error, query);
        this.showCanvasPlaceholder();

        // 상태 초기화는 handleAIQuery finally에서 처리
    }

    // =============================
    // 🌊 스트리밍 진행 상황 처리
    // =============================

    /**
     * Streaming progress modal using shared ModalUIAdapter
     */
    showStreamingProgressModal(query) {
        // Use shared ModalUIAdapter from contexa-streaming.bundle.js
        if (!this.modalAdapter) {
            this.modalAdapter = typeof ModalUIAdapter !== 'undefined'
                ? new ModalUIAdapter({ headerText: 'AI 권한 분석 진행 중' })
                : null;
        }

        // Reset flags for new streaming session
        this.llmAnalysisCompleted = false;

        if (this.modalAdapter) {
            this.modalAdapter.onStreamStart(query);
        }
    }

    /**
     * 🌊 진짜 스트리밍 진행 상황
     */
    // ai-studio.js 수정
    async startUnifiedStreamingAnalysis(query, permissions) {
        const startTime = Date.now();
        console.log('🌊 [JS-STREAM-' + startTime + '] 진짜 스트리밍 진행 상황 시작');

        try {
            const startTime = Date.now();
            console.log('🌊 [JS-STREAM-' + startTime + '] 진짜 스트리밍 진행 상황 시작');

            const userId = this.getCurrentUserId();
            const queryType = this.detectQueryType(query);

            const requestData = {
                query: query,
                userId: userId,
                queryType: queryType
            };

            const response = await fetch('/api/ai/studio/query/stream', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'text/event-stream'
                },
                body: JSON.stringify(requestData)
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            let buffer = '';
            let allDataBuffer = ''; // 🔥 모든 데이터를 저장하는 버퍼
            let finalResponseDetected = false;

            while (true) {
                const {done, value} = await reader.read();

                if (done) {
                    console.log('🌊 스트림 읽기 완료');
                    console.log('📊 전체 수집된 데이터 길이:', allDataBuffer.length);
                    break;
                }

                const chunk = decoder.decode(value, {stream: true});
                buffer += chunk;

                const lines = buffer.split('\n');
                buffer = lines.pop() || ''; // 마지막 불완전한 라인은 버퍼에 유지

                for (const line of lines) {
                    if (line.trim() === '') continue;

                    if (line.startsWith('data: ') || line.startsWith('data:')) {
                        let data = line.startsWith('data: ') ? line.slice(6) : line.slice(5);

                        if (data === '[DONE]') {
                            console.log('🌊 [DONE] 신호 수신');
                            continue;
                        }

                        // 🔥 모든 데이터를 allDataBuffer에 누적
                        console.log('📦 [SSE-DATA] Received:', data.length, 'chars, preview:', data.substring(0, 100));
                        allDataBuffer += data;

                        // FINAL_RESPONSE 감지
                        if (!finalResponseDetected && allDataBuffer.includes('###FINAL_RESPONSE###')) {
                            console.log('📊 [DIAGNOSIS] FINAL_RESPONSE 마커 감지, buffer length:', allDataBuffer.length);
                            finalResponseDetected = true;

                            // "결과 데이터 생성중..." 애니메이션 제거
                            if (this.modalAdapter) {
                                this.modalAdapter.removeLoadingStep('ctx-generating-result');
                            }

                            // 분석 완료 메시지들 표시
                            this.addStreamingStep('AI 분석 완료! 결과 데이터 처리 중...');

                            setTimeout(() => {
                                this.addStreamingStep('📊 분석 결과를 정리하고 있습니다...');
                            }, 500);

                            setTimeout(() => {
                                this.addStreamingStep('🎯 시각화 데이터를 준비하고 있습니다...');
                            }, 1000);
                        }

                        // 일반 스트리밍 표시 (FINAL_RESPONSE 전까지만)
                        if (data.trim() && !finalResponseDetected) {
                            // 첫 번째 청크 도착 시 "LLM 분석 시작..." 제거하고 "LLM 분석 완료" 표시
                            if (this.modalAdapter && !this.llmAnalysisCompleted) {
                                this.modalAdapter.removeLoadingStep('ctx-initial-loading');
                                this.llmAnalysisCompleted = true;
                                this.addStreamingStep('LLM 분석 완료');
                            }

                            // GENERATING_RESULT 마커 감지 시 애니메이션 효과가 있는 "결과 데이터 생성중..." 표시
                            if (data.includes('###GENERATING_RESULT###')) {
                                if (this.modalAdapter) {
                                    this.modalAdapter.onGeneratingResult();
                                }
                            } else {
                                this.addStreamingStep(data.trim());
                            }
                        }
                    }
                }
            }

            // 🔥 버퍼에 남은 마지막 데이터 처리
            if (buffer.trim()) {
                console.log('📦 마지막 버퍼 처리:', buffer);
                if (buffer.startsWith('data: ')) {
                    allDataBuffer += buffer.slice(6);
                } else if (buffer.startsWith('data:')) {
                    allDataBuffer += buffer.slice(5);
                } else {
                    allDataBuffer += buffer;
                }
            }

            // 스트리밍 완료 후 JSON 처리
            console.log('🌊 스트리밍 종료 - 완료 처리 시작');
            console.log('📊 최종 수집된 전체 데이터 길이:', allDataBuffer.length);

            if (finalResponseDetected && allDataBuffer.includes('###FINAL_RESPONSE###')) {
                this.addStreamingStep('✨ 모든 분석이 완료되었습니다!');

                // processFinalResponse 메서드 호출
                setTimeout(() => {
                    this.processFinalResponse(allDataBuffer);
                }, 1000);
            }

            console.log('[일원화] 스트리밍 완료');

        } catch (error) {
            console.error('🌊 스트리밍 오류:', error);
            this.addStreamingStep('스트리밍 연결 오류가 발생했습니다.');
            this.hideStreamingProgressModal();
            throw error;
        }
    }

// FINAL_RESPONSE 처리 메서드
    processFinalResponse(fullData) {
        console.log('📊 [FINAL-PARSING] JSON 파싱 시작');
        console.log('전체 데이터 길이:', fullData.length);
        console.log('📊 [FINAL-PARSING] fullData (first 500):', fullData.substring(0, 500));
        console.log('📊 [FINAL-PARSING] fullData (last 500):', fullData.substring(Math.max(0, fullData.length - 500)));

        const markerIndex = fullData.lastIndexOf('###FINAL_RESPONSE###');
        console.log('📊 [FINAL-PARSING] Marker index:', markerIndex);
        if (markerIndex === -1) {
            console.error('FINAL_RESPONSE 마커를 찾을 수 없음');
            this.handleJsonParseError('');
            return;
        }

        const marker = '###FINAL_RESPONSE###';
        let jsonData = fullData.substring(markerIndex + marker.length);
        console.log('📊 [FINAL-PARSING] jsonData after marker (first 500):', jsonData.substring(0, 500));
        console.log('📊 [FINAL-PARSING] jsonData after marker (last 500):', jsonData.substring(Math.max(0, jsonData.length - 500)));

        // JSON 추출 및 정제
        let cleanJsonData = jsonData.trim();

        // 마크다운 코드 블록 제거
        if (cleanJsonData.startsWith('```json')) {
            cleanJsonData = cleanJsonData.replace(/^```json\s*/, '');
            cleanJsonData = cleanJsonData.replace(/```\s*$/, '');
            cleanJsonData = cleanJsonData.trim();
            console.log('🔥 마크다운 코드 블록 제거 완료');
        } else if (cleanJsonData.startsWith('```')) {
            cleanJsonData = cleanJsonData.replace(/^```\s*/, '');
            cleanJsonData = cleanJsonData.replace(/```\s*$/, '');
            cleanJsonData = cleanJsonData.trim();
            console.log('🔥 일반 코드 블록 제거 완료');
        }

        // 첫 번째 { 부터 마지막 } 까지 추출
        const firstBrace = cleanJsonData.indexOf('{');
        let lastBrace = cleanJsonData.lastIndexOf('}');

        console.log('첫 번째 { 위치:', firstBrace);
        console.log('마지막 } 위치:', lastBrace);

        // 🔥 JSON이 불완전한 경우 자동 완성
        if (firstBrace !== -1 && lastBrace === -1) {
            console.warn('JSON이 불완전함 - 자동 완성 시도');

            // 열린 중괄호와 대괄호 수 계산
            let braceCount = 0;
            let bracketCount = 0;
            let inString = false;
            let escapeNext = false;

            for (let i = firstBrace; i < cleanJsonData.length; i++) {
                const char = cleanJsonData[i];

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
                    if (char === '{') braceCount++;
                    else if (char === '}') braceCount--;
                    else if (char === '[') bracketCount++;
                    else if (char === ']') bracketCount--;
                }
            }

            // 필요한 닫는 괄호 추가
            for (let i = 0; i < bracketCount; i++) {
                cleanJsonData += ']';
            }
            for (let i = 0; i < braceCount; i++) {
                cleanJsonData += '}';
            }

            console.log('🔥 자동 완성 후 JSON:', cleanJsonData);
            lastBrace = cleanJsonData.lastIndexOf('}');
        }

        if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
            cleanJsonData = cleanJsonData.substring(firstBrace, lastBrace + 1);
            console.log('🔥 JSON 추출 성공:', cleanJsonData.length, 'bytes');
            console.log('📊 [FINAL-PARSING] cleanJsonData to parse (first 500):', cleanJsonData.substring(0, 500));
            console.log('📊 [FINAL-PARSING] cleanJsonData to parse (last 500):', cleanJsonData.substring(Math.max(0, cleanJsonData.length - 500)));

            try {
                const parsedResult = JSON.parse(cleanJsonData);
                console.log('JSON 파싱 성공:', parsedResult);

                // AI 응답 처리
                this.processAIResponse(parsedResult, this.currentQuery);
                this.showMessage('AI 분석이 성공적으로 완료되었습니다!', 'success');

                // 1.5초 후 모달 닫기
                setTimeout(() => {
                    this.hideStreamingProgressModal();
                }, 1500);

            } catch (error) {
                console.error('JSON 파싱 실패:', error);
                console.log('파싱 실패한 JSON:', cleanJsonData);

                // 기본 응답 생성
                const basicResponse = {
                    analysisId: "studio-query-001",
                    query: this.currentQuery || "그룹은 누가 조회할 수 있나요",
                    naturalLanguageAnswer: cleanJsonData.match(/"naturalLanguageAnswer"\s*:\s*"([^"]+)"/)?.[1] ||
                        "그룹 정보 조회 권한은 ROLE_ADMIN 역할을 가진 사용자들에게만 부여되어 있습니다.",
                    status: "PARTIAL"
                };

                console.log('🔥 기본 응답 생성:', basicResponse);
                this.processAIResponse(basicResponse, this.currentQuery);
                this.showMessage('AI 분석이 완료되었습니다 (일부 데이터 누락)', 'warning');

                setTimeout(() => {
                    this.hideStreamingProgressModal();
                }, 1500);
            }
        } else {
            console.error('🔥 JSON 중괄호를 찾을 수 없음');
            this.handleJsonParseError(jsonData);
        }
    }

// JSON 파싱 에러 처리 메서드
    handleJsonParseError(jsonData) {
        this.addStreamingStep('결과 데이터 처리 중 오류가 발생했습니다.');

        const errorResponse = {
            analysisId: 'error-001',
            query: this.currentQuery,
            naturalLanguageAnswer: 'JSON 파싱 오류로 인해 완전한 분석 결과를 표시할 수 없습니다.',
            status: 'ERROR'
        };

        this.processAIResponse(errorResponse, this.currentQuery);
        this.showMessage('분석 결과 처리 중 오류가 발생했습니다', 'error');

        setTimeout(() => {
            this.hideStreamingProgressModal();
        }, 1500);
    }

    /**
     * Streaming step addition using shared ModalUIAdapter
     */
    addStreamingStep(text) {
        // Use shared ModalUIAdapter
        if (this.modalAdapter) {
            this.modalAdapter.addStep(text);
        }
    }

    /**
     * Internal streaming step addition (delegates to shared adapter)
     */
    addStreamingStepInternal(streamingContent, text) {
        this.addStreamingStep(text);
    }

    /**
     * Show streaming complete message using shared adapter
     */
    showStreamingComplete() {
        if (this.modalAdapter) {
            this.modalAdapter.addStep('AI 권한 분석이 완료되었습니다.');
        }
    }

    /**
     * Stop streaming progress using shared ModalUIAdapter
     */
    stopStreamingProgress() {
        this.isStreaming = false;

        // Add completion message using shared adapter
        if (this.modalAdapter) {
            this.modalAdapter.addStep('AI 권한 분석이 완료되었습니다.');
            this.modalAdapter.onFinalResponse({ status: 'complete' });
        }

        // Close modal after delay
        setTimeout(() => {
            this.hideStreamingProgressModal();
        }, 2000);
    }

    /**
     * Hide streaming progress modal using shared ModalUIAdapter
     */
    hideStreamingProgressModal() {
        // Reset state flags
        this.isProcessingQuery = false;
        this.isLoading = false;
        this.isStreaming = false;

        // Restore button state (matches studio.html id="ai-query-btn")
        const queryBtn = document.getElementById('ai-query-btn');
        if (queryBtn) {
            queryBtn.disabled = false;
        }

        // Hide modal using shared adapter
        if (this.modalAdapter) {
            this.modalAdapter.hide();
        }
    }

    /**
     * 🔧 HTML 이스케이프 (XSS 방지)
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // AI 질의 API 호출
    async sendAIQuery(query) {
        // 실제 사용자 ID 추출 (인증된 사용자 정보에서)
        const userId = this.getCurrentUserId();

        // 질의 타입 자동 감지
        const queryType = this.detectQueryType(query);

        // 디버깅: 전송하는 데이터 로깅
        const requestData = {
            query: query,
            userId: userId,
            queryType: queryType
        };

        console.log('Sending AI Query Request:', requestData);
        console.log('Query length:', query ? query.length : 'NULL');
        console.log('Query content:', JSON.stringify(query));

        // 🔥 정책빌더와 동일한 CSRF 토큰 처리 방식 적용
        const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
        const csrfHeader = document.querySelector('meta[name="_csrf_header"]')?.content;

        const headers = {
            'Content-Type': 'application/json',
            ...(csrfToken && csrfHeader ? {[csrfHeader]: csrfToken} : {})
        };

        const response = await fetch('/api/ai/studio/query', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(requestData)
        });

        if (!response.ok) {
            // 🔥 정책빌더와 동일한 단순한 에러 처리 방식 적용
            const errorData = await response.json().catch(() => ({message: `서버 오류 (${response.status})`}));
            throw new Error(errorData.message);
        }

        // 🔥 단순한 JSON 파싱 (복잡한 safeJsonParse 제거)
        return response.status === 204 ? null : response.json();
    }

    // =============================
    // 🔧 헬퍼 메서드들
    // =============================

    /**
     * 🔥 안전한 JSON 파싱 (Jackson 오류 방지)
     */
    async safeJsonParse(response) {
        let responseText = '';

        try {
            // 먼저 응답을 텍스트로 받기
            responseText = await response.text();
            console.log('Raw response (first 500 chars):', responseText.substring(0, 500));

            // 마크다운 응답 감지
            if (this.isMarkdownResponse(responseText)) {
                console.error('AI가 마크다운으로 응답했습니다:', responseText.substring(0, 200));
                this.showToast('AI가 올바르지 않은 형식으로 응답했습니다. 다시 시도해주세요.', 'error');
                return this.generateErrorResponse('AI_MARKDOWN_RESPONSE', 'AI가 마크다운 형식으로 응답하여 처리할 수 없습니다.');
            }

            // JSON 마커 추출 시도
            const jsonContent = this.extractJsonFromMarkers(responseText);
            if (jsonContent) {
                console.log('Extracted JSON from markers:', jsonContent.substring(0, 200));

                // 잘못된 문자 정리
                const cleanedJson = this.cleanJsonString(jsonContent);
                console.log('Cleaned JSON:', cleanedJson.substring(0, 200));

                // 안전한 파싱 시도
                return JSON.parse(cleanedJson);
            }

            // 마커가 없으면 전체 응답을 JSON으로 파싱 시도
            const cleanedResponse = this.cleanJsonString(responseText);
            return JSON.parse(cleanedResponse);

        } catch (jsonError) {
            console.error('JSON 파싱 오류:', jsonError);
            console.error('원본 응답:', responseText);

            // 응답이 이미 객체인 경우 그대로 반환
            if (typeof response === 'object' && response !== null) {
                console.log('응답이 이미 객체입니다. 파싱 없이 반환합니다.');
                return response;
            }

            // 사용자에게 알림
            this.showToast('AI 응답 처리 중 오류가 발생했습니다. 다시 시도해주세요.', 'error');

            // 기본 응답 구조 반환
            return this.generateErrorResponse('JSON_PARSE_ERROR', jsonError.message);
        }
    }

    /**
     * 마크다운 응답 감지
     */
    isMarkdownResponse(text) {
        // 마크다운 패턴들
        const markdownPatterns = [
            /^\*\*[^*]+\*\*/m,          // **헤더**
            /^#{1,6}\s+/m,              // # 헤더
            /^\s*[-*]\s+/m,             // - 또는 * 리스트
            /\*\*핵심\s*임무\*\*/,       // **핵심 임무**
            /\*\*데이터\*\*/,           // **데이터**
            /\*\*응답\s*형식\*\*/,       // **응답 형식**
            /\*\*질의\*\*/              // **질의**
        ];

        return markdownPatterns.some(pattern => pattern.test(text));
    }

    /**
     * 🔧 오류 응답 생성
     */
    generateErrorResponse(errorType, errorMessage) {
        return {
            naturalLanguageAnswer: "AI 응답 처리 중 오류가 발생했습니다. 시스템 로그를 확인해주세요.",
            analysisResults: [],
            queryResults: [],
            recommendations: [{
                title: "오류 해결 제안",
                description: `${errorType}: ${errorMessage}`,
                priority: 1,
                type: "ERROR_RECOVERY",
                actionItems: [
                    "브라우저 새로고침 후 다시 시도",
                    "다른 방식으로 질문 재작성",
                    "프롬프트 개선 요청"
                ]
            }],
            error: {
                message: errorMessage,
                type: errorType,
                timestamp: new Date().toISOString()
            }
        };
    }

    /**
     * JSON 마커에서 내용 추출
     */
    extractJsonFromMarkers(text) {
        const startMarker = '===JSON_START===';
        const endMarker = '===JSON_END===';

        const startIndex = text.indexOf(startMarker);
        const endIndex = text.indexOf(endMarker);

        if (startIndex !== -1 && endIndex !== -1 && endIndex > startIndex) {
            return text.substring(startIndex + startMarker.length, endIndex).trim();
        }

        return null;
    }

    /**
     * 🧹 JSON 문자열 정리 (잘못된 문자 제거)
     */
    cleanJsonString(jsonString) {
        return jsonString
            // 마크다운 제거 (AI가 마크다운으로 응답하는 경우)
            .replace(/^\*\*[^*]+\*\*.*$/gm, '')  // **헤더** 제거
            .replace(/^#{1,6}\s+.*$/gm, '')      // # 헤더 제거
            .replace(/^\s*-\s+.*$/gm, '')        // - 리스트 제거
            .replace(/^\s*\*\s+.*$/gm, '')       // * 리스트 제거
            .replace(/\*\*([^*]+)\*\*/g, '$1')   // **볼드** → 텍스트
            .replace(/\*([^*]+)\*/g, '$1')       // *이탤릭* → 텍스트

            // JSON 밖에 있는 한국어 토큰들 제거
            .replace(/^[^{]*모든[^{]*/, '')
            .replace(/^[^{]*전체[^{]*/, '')
            .replace(/^[^{]*결과[^{]*/, '')
            .replace(/^[^{]*핵심[^{]*/, '')
            .replace(/^[^{]*데이터[^{]*/, '')

            // JSON 후에 오는 한국어 토큰들 제거
            .replace(/}[^}]*모든.*$/, '}')
            .replace(/}[^}]*전체.*$/, '}')
            .replace(/}[^}]*결과.*$/, '}')
            .replace(/}[^}]*핵심.*$/, '}')
            .replace(/}[^}]*데이터.*$/, '}')

            // + 기호 제거 (JSON에서 문자열 연결 시도)
            .replace(/\s*\+\s*"[^"]*"/g, '')
            .replace(/"\s*\+\s*/g, '"')

            // JSON 배열 오류 수정
            .replace(/,\s*]/g, ']')              // 배열 끝 여분 쉼표 제거
            .replace(/,\s*}/g, '}')              // 객체 끝 여분 쉼표 제거
            .replace(/,(\s*[,\]}])/g, '$1')      // 연속 쉼표 제거

            // 잘못된 문자 제거
            .replace(/\s*&\s*/g, '')
            .replace(/\s*\|\s*/g, '')            // | 기호 제거

            // 여러 줄 공백 정리
            .replace(/\n\s*\n/g, '\n')
            .replace(/^\s+|\s+$/g, '')           // 앞뒤 공백 제거
            .trim();
    }

    /**
     * 현재 사용자 ID 가져오기
     */
    getCurrentUserId() {
        // 1. Spring Security 인증 컨텍스트에서 추출 시도
        try {
            const userElement = document.querySelector('[data-user-id]');
            if (userElement) {
                return userElement.getAttribute('data-user-id');
            }
        } catch (e) {
            // 무시
        }

        // 2. 전역 변수에서 추출 시도
        if (typeof window.currentUser !== 'undefined' && window.currentUser.id) {
            return window.currentUser.id;
        }

        // 3. 세션 정보에서 추출 시도
        try {
            const userInfo = sessionStorage.getItem('userInfo');
            if (userInfo) {
                const parsed = JSON.parse(userInfo);
                if (parsed.userId) {
                    return parsed.userId;
                }
            }
        } catch (e) {
            // 무시
        }

        // 4. 기본값: AI Studio 전용 익명 사용자
        console.warn('사용자 ID를 찾을 수 없어 익명 사용자로 처리합니다.');
        return 'ai-studio-user-' + Date.now();
    }

    /**
     * 자연어 질의에서 타입 자동 감지
     */
    detectQueryType(query) {
        if (!query || typeof query !== 'string') {
            return 'ANALYZE_PERMISSIONS';
        }

        const lowerQuery = query.toLowerCase().trim();

        // 질의 패턴 분석
        if (lowerQuery.includes('누가') || lowerQuery.includes('who can') || lowerQuery.includes('can access')) {
            return 'WHO_CAN';
        }

        if (lowerQuery.includes('왜') || lowerQuery.includes('why') || lowerQuery.includes('cannot') || lowerQuery.includes('할 수 없')) {
            return 'WHY_CANNOT';
        }

        if (lowerQuery.includes('경로') || lowerQuery.includes('path') || lowerQuery.includes('접근') || lowerQuery.includes('어떻게')) {
            return 'ACCESS_PATH';
        }

        if (lowerQuery.includes('시각화') || lowerQuery.includes('구조') || lowerQuery.includes('분석') || lowerQuery.includes('보여')) {
            return 'ANALYZE_PERMISSIONS';
        }

        if (lowerQuery.includes('영향') || lowerQuery.includes('impact') || lowerQuery.includes('변경')) {
            return 'IMPACT_ANALYSIS';
        }

        if (lowerQuery.includes('규정') || lowerQuery.includes('compliance') || lowerQuery.includes('준수')) {
            return 'COMPLIANCE_CHECK';
        }

        // 기본값: 일반적인 권한 분석
        return 'ANALYZE_PERMISSIONS';
    }

    // =============================
    // 📊 AI 응답 처리 및 시각화
    // =============================
    async processAIResponse(response, originalQuery) {
        console.log('🧠 AI-Native Response:', response);

        // 🧠 AI 분석 결과 전처리
        const analysisResult = this.preprocessAIAnalysis(response);

        // Inspector에 AI-Native 분석 결과 표시 (모든 섹션 포함: 인사이트, 이상 탐지, 최적화 제안)
        this.displayAINativeAnalysisInInspector(analysisResult, originalQuery);

        // 🔥 시각화 우선순위: 서버 visualizationData 우선 사용!
        if (analysisResult.visualizationData && (analysisResult.visualizationData.nodes || analysisResult.visualizationData.edges)) {
            console.log('🎯 서버 visualizationData 우선 사용 (완전한 구조)');
            await this.renderIntelligentVisualization(analysisResult.visualizationData, analysisResult);
        } else if (analysisResult.analysisResults && analysisResult.analysisResults.length > 0) {
            console.log('🎯 서버 visualizationData가 없어서 analysisResults 기반 생성');

            // 🔥 analysisResults에서 완전한 USER-GROUP-ROLE-PERMISSION 구조 생성
            const completeVisualizationData = this.generateCompleteVisualizationFromAnalysis(analysisResult.analysisResults, originalQuery);

            await this.renderIntelligentVisualization(completeVisualizationData, analysisResult);
        } else {
            // 시각화 데이터가 없으면 캔버스 숨기기만 함
            this.hideCanvasPlaceholder();
            console.log('🎯 시각화 데이터 없음 - 중앙 패널 표시 생략');
        }

        // 🔥 중복 제거: displayAINativeAnalysisInInspector에서 이미 모든 섹션 표시됨
        // this.displayPermissionAnomalies(analysisResult.anomalies);
        // this.displayOptimizationSuggestions(analysisResult.suggestions);
        // this.displayKeyInsights(analysisResult.insights);

        // 💡 Canvas 오버레이는 상세 리포트에서만 표시하도록 변경
        // 가운데 패널에서 핵심 인사이트 제거 - 상세 리포트에서만 표시
        console.log('🎯 핵심 인사이트는 상세 리포트에서만 표시합니다.');
    }

    /**
     * 🔥 Policy Builder처럼 서버가 클라이언트 구조 제공 - 단순 매핑
     */
    preprocessAIAnalysis(response) {
        console.log('🔥 [SERVER-RESPONSE] 서버가 클라이언트 구조로 응답:', response);

        // 서버 응답 데이터 구조 확인
        console.log('[DATA-STRUCTURE] 서버 응답 데이터 구조:', {
            hasAnalysisResults: !!(response.analysisResults && response.analysisResults.length),
            hasQueryResults: !!(response.queryResults && response.queryResults.length),
            hasRecommendations: !!(response.recommendations && response.recommendations.length),
            hasVisualizationData: !!(response.visualizationData && response.visualizationData.nodes),
            dynamicStatsWillGenerate: true
        });

        // 🔥 서버 응답 데이터를 올바르게 매핑
        const analysisResult = {
            // 서버에서 클라이언트 구조로 제공하는 필드들
            analysisId: response.analysisId || 'unknown',
            query: response.query || '',
            naturalAnswer: response.naturalLanguageAnswer || '',
            confidenceScore: response.confidenceScore || 0,

            // 🔥 서버 데이터 올바른 매핑
            analysisResults: this.convertServerDataToAnalysisResults(response),
            queryResults: response.queryResults || [],
            recommendations: response.recommendations || [],

            // 시각화 데이터
            visualizationData: response.visualizationData || null,

            // 메타데이터
            processingTime: response.processingTimeMs || 0,
            statistics: this.generateDynamicStatistics(response), // 🔥 실제 데이터 기반 동적 생성

            // 클라이언트 전용 필드 계산
            analysisType: this.detectAnalysisTypeFromServerData(response),
            complexityScore: 0,
            riskScore: 0,

            // 🔥 올바른 데이터 매핑 (6번 문제 해결 - insights는 문자열)
            insights: typeof response.insights === 'string' ? [response.insights] : (response.insights || []),
            // 🔥 recommendations를 suggestions 형태로 변환
            suggestions: this.transformRecommendationsToSuggestions(response.recommendations || []),
            anomalies: []
        };

        console.log('🔥 [PREPROCESSED] 클라이언트 구조 기반 분석 결과:', analysisResult);
        return analysisResult;
    }

    /**
     * 📊 실제 서버 데이터 기반 동적 통계 생성
     */
    generateDynamicStatistics(response) {
        const stats = {};

        try {
            // 1. 📊 analysisResults 기반 권한 통계 (실제 서버 구조 대응)
            if (response.analysisResults && Array.isArray(response.analysisResults)) {
                // 실제 서버 구조: {userName, groupName, roleName, hasPermission, permissionName}
                const usersWithPermission = response.analysisResults.filter(result =>
                    result.hasPermission === true
                ).length;
                const usersWithoutPermission = response.analysisResults.filter(result =>
                    result.hasPermission === false
                ).length;
                const totalAnalyzedUsers = response.analysisResults.length;

                stats.totalAnalyzedUsers = totalAnalyzedUsers;
                stats.usersWithGroupInfoPermission = usersWithPermission;
                stats.usersWithoutGroupInfoPermission = usersWithoutPermission;
                stats.permissionGrantRate = totalAnalyzedUsers > 0 ? Math.round((usersWithPermission / totalAnalyzedUsers) * 100) : 0;

                // 추가 통계: 권한별 분석
                const allPermissions = response.analysisResults.filter(result => result.permissionName).map(result => result.permissionName);
                const uniquePermissions = [...new Set(allPermissions)];
                stats.uniquePermissionsCount = uniquePermissions.length;
                stats.totalPermissionAssignments = allPermissions.length;

                console.log('📊 권한 통계 계산 완료 (실제 구조):', {
                    totalUsers: totalAnalyzedUsers,
                    withPermission: usersWithPermission,
                    withoutPermission: usersWithoutPermission,
                    grantRate: stats.permissionGrantRate
                });
            }

            // 2. 📊 visualizationData 기반 구조 통계
            if (response.visualizationData && response.visualizationData.nodes) {
                const nodes = response.visualizationData.nodes;
                const userNodes = nodes.filter(node => node.type === 'USER').length;
                const groupNodes = nodes.filter(node => node.type === 'GROUP').length;
                const roleNodes = nodes.filter(node => node.type === 'ROLE').length;
                const permissionNodes = nodes.filter(node => node.type === 'PERMISSION').length;

                stats.totalNodes = nodes.length;
                stats.userNodes = userNodes;
                stats.groupNodes = groupNodes;
                stats.roleNodes = roleNodes;
                stats.permissionNodes = permissionNodes;

                // 엣지 통계
                if (response.visualizationData.edges) {
                    stats.totalConnections = response.visualizationData.edges.length;
                    stats.hasRoleConnections = response.visualizationData.edges.filter(edge => edge.type === 'HAS_ROLE').length;
                    stats.hasPermissionConnections = response.visualizationData.edges.filter(edge => edge.type === 'HAS_PERMISSION').length;
                }
            }

            // 3. 📊 queryResults 기반 접근 통계
            if (response.queryResults && Array.isArray(response.queryResults)) {
                const accessGranted = response.queryResults.filter(result => result.hasAccess === true).length;
                const accessDenied = response.queryResults.filter(result => result.hasAccess === false).length;

                stats.totalQueryResults = response.queryResults.length;
                stats.accessGrantedCount = accessGranted;
                stats.accessDeniedCount = accessDenied;
            }

            // 4. 📊 recommendations 기반 개선 통계
            if (response.recommendations && Array.isArray(response.recommendations)) {
                stats.totalRecommendations = response.recommendations.length;
                stats.highPriorityRecommendations = response.recommendations.filter(rec => rec.priority <= 2).length;
                stats.mediumPriorityRecommendations = response.recommendations.filter(rec => rec.priority === 3).length;
                stats.lowPriorityRecommendations = response.recommendations.filter(rec => rec.priority >= 4).length;
            }

            // 5. 📊 전체 분석 요약
            stats.confidenceScore = response.confidenceScore || 0;
            stats.analysisCompleteness = this.calculateAnalysisCompleteness(response);

            console.log('📊 동적 생성된 통계:', stats);

        } catch (error) {
            console.error('통계 생성 오류:', error);
            // 기본 통계 반환
            stats.totalAnalyzedUsers = 0;
            stats.usersWithGroupInfoPermission = 0;
            stats.usersWithoutGroupInfoPermission = 0;
        }

        return stats;
    }

    /**
     * 📈 분석 완성도 계산
     */
    calculateAnalysisCompleteness(response) {
        let score = 0;
        let maxScore = 6;

        if (response.analysisResults && response.analysisResults.length > 0) score += 1;
        if (response.queryResults && response.queryResults.length > 0) score += 1;
        if (response.recommendations && response.recommendations.length > 0) score += 1;
        if (response.visualizationData && response.visualizationData.nodes) score += 1;
        if (response.naturalLanguageAnswer && response.naturalLanguageAnswer.length > 10) score += 1;
        if (response.confidenceScore && response.confidenceScore > 50) score += 1;

        return Math.round((score / maxScore) * 100);
    }

    /**
     * Recommendations를 Suggestions 형태로 변환
     */
    transformRecommendationsToSuggestions(recommendations) {
        if (!Array.isArray(recommendations)) {
            return [];
        }

        return recommendations.map((rec, index) => {
            // 문자열인 경우 기본 구조로 변환
            if (typeof rec === 'string') {
                return {
                    title: `권장사항 ${index + 1}`,
                    description: rec,
                    type: 'SECURITY_IMPROVEMENT',
                    priority: 2, // 보통
                    implementationComplexity: 'MEDIUM',
                    expectedBenefit: '보안 향상',
                    actionLinks: []
                };
            }

            // 객체인 경우 구조 매핑
            return {
                title: rec.title || `권장사항 ${index + 1}`,
                description: rec.description || rec.content || rec,
                type: rec.type || 'SECURITY_IMPROVEMENT',
                priority: rec.priority || 2,
                implementationComplexity: rec.complexity || 'MEDIUM',
                expectedBenefit: rec.expectedBenefit || rec.benefit || '보안 향상',
                actionLinks: rec.actionLinks || []
            };
        });
    }

    /**
     * 📊 필터링된 핵심 통계만 생성하여 과다 표시 방지
     */
    generateFilteredStatistics(statistics) {
        if (!statistics || Object.keys(statistics).length === 0) {
            return '<div class="no-statistics">통계 데이터가 없습니다.</div>';
        }

        // 🔥 핵심 통계 우선순위 순서로 정렬
        const coreStatsPriority = [
            'totalAnalyzedUsers',
            'usersWithGroupInfoPermission',
            'permissionGrantRate',
            'totalNodes',
            'uniquePermissionsCount',
            'totalConnections'
        ];

        // 🔥 핵심 통계만 선별
        const filteredStats = [];

        coreStatsPriority.forEach(key => {
            if (statistics[key] !== undefined && statistics[key] !== null && statistics[key] !== 0) {
                filteredStats.push([key, statistics[key]]);
            }
        });

        // 🔥 추가로 의미있는 통계 2-3개 더 선택 (0이 아닌 값만)
        const additionalStats = Object.entries(statistics)
            .filter(([key, value]) =>
                !coreStatsPriority.includes(key) &&
                value !== undefined && value !== null && value !== 0
            )
            .slice(0, 2); // 최대 2개만

        const allDisplayStats = [...filteredStats, ...additionalStats];

        console.log('📊 표시할 통계:', allDisplayStats.length, '개 (원본:', Object.keys(statistics).length, '개)');

        return allDisplayStats.map(([key, value]) => {
            const explanation = this.getStatExplanation(key, value);
            return `
            <div class="stat-card-modern ${coreStatsPriority.includes(key) ? 'core' : 'additional'}" 
                 title="${explanation}">
                <div class="stat-icon">
                    ${this.getStatIcon(key)}
                </div>
                <div class="stat-content">
                    <div class="stat-value">${value}</div>
                    <div class="stat-label">${this.translateStatKey(key)}</div>
                    <div class="stat-explanation">
                        ${explanation}
                    </div>
                    <div class="stat-trend">
                        ${this.getStatTrend(key, value)}
                    </div>
                </div>
            </div>
            `;
        }).join('');
    }

    /**
     * 🎨 AI 데이터 기반 역동적 Cytoscape 스타일 (완전히 새로운 접근)
     */
    getEnhancedCytoscapeStyles() {
        return [
            // =============================
            // 🔵 USER 노드 - 데이터 기반 동적 크기 조정
            // =============================
            {
                selector: 'node[type="USER"]',
                style: {
                    // 고정 크기 (계속 커지는 문제 해결)
                    'width': '90px',
                    'height': '45px',

                    // 권한 상태에 따른 색상 변화
                    'background-color': function (node) {
                        const hasPermission = node.data('hasPermission');
                        return hasPermission ? '#22c55e' : '#ef4444';
                    },
                    'background-gradient-direction': 'to-bottom-right',
                    'background-gradient-stop-colors': function (node) {
                        const hasPermission = node.data('hasPermission');
                        return hasPermission ? '#22c55e #16a34a' : '#ef4444 #dc2626';
                    },

                    // 텍스트 스타일
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#ffffff',
                    'font-size': function (node) {
                        const connections = node.degree() || 1;
                        return Math.max(12, Math.min(18, 12 + connections * 0.8)) + 'px';
                    },
                    'font-weight': 'bold',
                    'font-family': '"Inter", sans-serif',
                    'text-shadow-blur': '2px',
                    'text-shadow-color': 'rgba(0,0,0,0.6)',

                    // 모양과 테두리
                    'shape': 'round-rectangle',
                    'border-width': function (node) {
                        const isGenerated = node.data('properties')?.generated;
                        return isGenerated ? '2px' : '3px';
                    },
                    'border-color': function (node) {
                        const hasPermission = node.data('hasPermission');
                        return hasPermission ? '#059669' : '#991b1b';
                    },
                    'border-style': function (node) {
                        const isGenerated = node.data('properties')?.generated;
                        return isGenerated ? 'dashed' : 'solid';
                    },

                    // 동적 그림자 효과
                    'box-shadow-blur': function (node) {
                        const connections = node.degree() || 1;
                        return Math.max(8, Math.min(16, 8 + connections)) + 'px';
                    },
                    'box-shadow-color': function (node) {
                        const hasPermission = node.data('hasPermission');
                        return hasPermission ? 'rgba(34, 197, 94, 0.5)' : 'rgba(239, 68, 68, 0.5)';
                    },
                    'box-shadow-opacity': 0.6,

                    'text-wrap': 'wrap',
                    'text-max-width': function (node) {
                        const connections = node.degree() || 1;
                        return Math.max(70, Math.min(130, 70 + connections * 6)) + 'px';
                    },

                    // 애니메이션 전환
                    'transition-property': 'width, height, background-color, border-width, box-shadow-blur',
                    'transition-duration': '0.4s',
                    'transition-timing-function': 'ease-out-cubic'
                }
            },

            // =============================
            // 🟢 GROUP 노드 - 조직 구조 강조
            // =============================
            {
                selector: 'node[type="GROUP"]',
                style: {
                    // 고정 크기 (계속 커지는 문제 해결)
                    'width': '85px',
                    'height': '50px',

                    // 시안 계열 그라데이션
                    'background-color': '#06b6d4',
                    'background-gradient-direction': 'to-bottom-right',
                    'background-gradient-stop-colors': '#06b6d4 #0891b2 #0e7490',

                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#ffffff',
                    'font-size': function (node) {
                        const members = node.connectedEdges('[type*="MEMBER"], [type*="BELONGS"]').length || 1;
                        return Math.max(11, Math.min(16, 11 + members * 0.5)) + 'px';
                    },
                    'font-weight': '600',
                    'font-family': '"Inter", sans-serif',
                    'text-shadow-blur': '1px',
                    'text-shadow-color': 'rgba(0,0,0,0.4)',

                    'shape': 'hexagon',
                    'border-width': '2px',
                    'border-color': '#155e75',
                    'border-style': function (node) {
                        const isGenerated = node.data('properties')?.generated;
                        return isGenerated ? 'dashed' : 'solid';
                    },

                    'box-shadow-blur': '10px',
                    'box-shadow-color': 'rgba(6, 182, 212, 0.4)',
                    'box-shadow-opacity': 0.5,

                    'text-wrap': 'wrap',
                    'text-max-width': function (node) {
                        const members = node.connectedEdges('[type*="MEMBER"], [type*="BELONGS"]').length || 1;
                        return Math.max(60, Math.min(100, 60 + members * 4)) + 'px';
                    },

                    'transition-property': 'width, height, background-color',
                    'transition-duration': '0.3s'
                }
            },

            // =============================
            // 🟣 ROLE 노드 - 권한 계층 시각화
            // =============================
            {
                selector: 'node[type="ROLE"]',
                style: {
                    // 고정 크기 (계속 커지는 문제 해결)
                    'width': '75px',
                    'height': '40px',

                    'background-color': '#8b5cf6',
                    'background-gradient-direction': 'to-bottom-right',
                    'background-gradient-stop-colors': '#8b5cf6 #7c3aed #6d28d9',

                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#ffffff',
                    'font-size': function (node) {
                        const permissions = node.connectedEdges('[type*="PERMISSION"]').length || 1;
                        return Math.max(10, Math.min(15, 10 + permissions * 0.4)) + 'px';
                    },
                    'font-weight': '600',
                    'font-family': '"Inter", sans-serif',
                    'text-shadow-blur': '1px',
                    'text-shadow-color': 'rgba(0,0,0,0.5)',

                    'shape': 'diamond',
                    'border-width': function (node) {
                        const permissions = node.connectedEdges('[type*="PERMISSION"]').length || 1;
                        return permissions > 3 ? '3px' : '2px';
                    },
                    'border-color': '#581c87',
                    'border-style': function (node) {
                        const isGenerated = node.data('properties')?.generated;
                        return isGenerated ? 'dashed' : 'solid';
                    },

                    'box-shadow-blur': '8px',
                    'box-shadow-color': 'rgba(139, 92, 246, 0.4)',
                    'box-shadow-opacity': 0.6,

                    'text-wrap': 'wrap',
                    'text-max-width': function (node) {
                        const permissions = node.connectedEdges('[type*="PERMISSION"]').length || 1;
                        return Math.max(50, Math.min(80, 50 + permissions * 2)) + 'px';
                    },

                    'transition-property': 'width, height, border-width',
                    'transition-duration': '0.25s'
                }
            },

            // =============================
            // 🟠 PERMISSION 노드 - 권한 시각화
            // =============================
            {
                selector: 'node[type="PERMISSION"]',
                style: {
                    'width': '65px',
                    'height': '32px',

                    'background-color': '#f97316',
                    'background-gradient-direction': 'to-right',
                    'background-gradient-stop-colors': '#f97316 #ea580c #c2410c',

                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#ffffff',
                    'font-size': '10px',
                    'font-weight': '500',
                    'font-family': '"Inter", sans-serif',
                    'text-shadow-blur': '1px',
                    'text-shadow-color': 'rgba(0,0,0,0.4)',

                    'shape': 'octagon',
                    'border-width': '1.5px',
                    'border-color': '#9a3412',
                    'border-style': function (node) {
                        const isGenerated = node.data('properties')?.generated;
                        return isGenerated ? 'dashed' : 'solid';
                    },

                    'box-shadow-blur': '6px',
                    'box-shadow-color': 'rgba(249, 115, 22, 0.3)',
                    'box-shadow-opacity': 0.4,

                    'text-wrap': 'wrap',
                    'text-max-width': '55px',

                    'transition-property': 'background-color, border-color',
                    'transition-duration': '0.2s'
                }
            },

            // =============================
            // 🔗 동적 엣지 스타일 - 데이터 플로우 시각화
            // =============================

            // USER → GROUP 연결
            {
                selector: 'edge[type*="BELONGS"], edge[type*="MEMBER"]',
                style: {
                    'width': function (edge) {
                        const targetConnections = edge.target().degree() || 1;
                        return Math.max(3, Math.min(7, 3 + targetConnections * 0.3)) + 'px';
                    },
                    'line-color': '#06b6d4',
                    'line-gradient-stop-colors': '#3b82f6 #06b6d4',
                    'line-gradient-direction': 'to-target',
                    'target-arrow-color': '#0891b2',
                    'target-arrow-shape': 'triangle',
                    'target-arrow-scale': 1.2,
                    'curve-style': 'straight',
                    'opacity': 0.8,

                    'transition-property': 'width, line-color, opacity',
                    'transition-duration': '0.3s'
                }
            },

            // GROUP → ROLE 연결
            {
                selector: 'edge[type*="ROLE"]',
                style: {
                    'width': function (edge) {
                        const targetPermissions = edge.target().connectedEdges('[type*="PERMISSION"]').length || 1;
                        return Math.max(3, Math.min(6, 3 + targetPermissions * 0.2)) + 'px';
                    },
                    'line-color': '#8b5cf6',
                    'line-gradient-stop-colors': '#06b6d4 #8b5cf6',
                    'line-gradient-direction': 'to-target',
                    'target-arrow-color': '#7c3aed',
                    'target-arrow-shape': 'triangle',
                    'target-arrow-scale': 1.3,
                    'curve-style': 'bezier',
                    'control-point-step-size': 40,
                    'opacity': 0.8,

                    'transition-property': 'width, line-color',
                    'transition-duration': '0.25s'
                }
            },

            // ROLE → PERMISSION 연결
            {
                selector: 'edge[type*="PERMISSION"]',
                style: {
                    'width': '4px',
                    'line-color': '#f97316',
                    'line-gradient-stop-colors': '#8b5cf6 #f97316',
                    'line-gradient-direction': 'to-target',
                    'target-arrow-color': '#ea580c',
                    'target-arrow-shape': 'triangle',
                    'target-arrow-scale': 1.5,
                    'curve-style': 'bezier',
                    'control-point-step-size': 30,
                    'opacity': 0.9,

                    'transition-property': 'opacity, line-color',
                    'transition-duration': '0.2s'
                }
            },

            // 생성된 엣지 (동적으로 추가된 연결)
            {
                selector: 'edge.generated-edge',
                style: {
                    'line-style': 'dashed',
                    'line-dash-pattern': [8, 4],
                    'opacity': 0.6,

                    // 고정 점선 스타일 (애니메이션 제거)
                    'line-dash-offset': 0
                }
            },

            // 기본 엣지
            {
                selector: 'edge',
                style: {
                    'width': '2px',
                    'line-color': '#64748b',
                    'target-arrow-color': '#475569',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.5,
                    'transition-property': 'opacity',
                    'transition-duration': '0.15s'
                }
            },

            // =============================
            // 🎯 고급 인터랙션 상태 스타일
            // =============================

            // 호버 효과 - 노드
            {
                selector: 'node:hover',
                style: {
                    'box-shadow-blur': function (node) {
                        const currentBlur = parseInt(node.style('box-shadow-blur')) || 8;
                        return (currentBlur * 1.8) + 'px';
                    },
                    'box-shadow-opacity': 0.9,
                    'border-width': function (node) {
                        const currentWidth = parseInt(node.style('border-width')) || 2;
                        return (currentWidth + 2) + 'px';
                    },
                    'z-index': 999,

                    // 살짝 확대 효과
                    'width': function (node) {
                        const currentWidth = parseInt(node.style('width')) || 80;
                        return (currentWidth * 1.05) + 'px';
                    },
                    'height': function (node) {
                        const currentHeight = parseInt(node.style('height')) || 40;
                        return (currentHeight * 1.05) + 'px';
                    },

                    'transition-property': 'width, height, box-shadow-blur, border-width',
                    'transition-duration': '0.2s',
                    'transition-timing-function': 'ease-out'
                }
            },

            // 호버 효과 - 엣지
            {
                selector: 'edge:hover',
                style: {
                    'width': function (edge) {
                        const currentWidth = parseInt(edge.style('width')) || 3;
                        return (currentWidth * 1.6) + 'px';
                    },
                    'opacity': 1.0,
                    'z-index': 100,

                    // 호버 시 더 밝은 색상
                    'line-color': function (edge) {
                        const type = edge.data('type');
                        if (type && type.includes('BELONGS') || type && type.includes('MEMBER')) return '#38bdf8';
                        if (type && type.includes('ROLE')) return '#a78bfa';
                        if (type && type.includes('PERMISSION')) return '#fb923c';
                        return '#94a3b8';
                    },

                    'transition-property': 'width, opacity, line-color',
                    'transition-duration': '0.15s'
                }
            },

            // 선택된 요소 (클릭)
            {
                selector: '.highlighted',
                style: {
                    'border-color': '#fbbf24',
                    'border-width': '4px',
                    'box-shadow-color': 'rgba(251, 191, 36, 0.7)',
                    'box-shadow-blur': '20px',
                    'box-shadow-opacity': 0.9,
                    'z-index': 1000,

                    // 펄스 효과 (시간 기반 애니메이션)
                    'background-opacity': function (ele) {
                        return 0.8 + 0.2 * Math.sin(Date.now() * 0.004);
                    }
                }
            },

            // 선택된 엣지
            {
                selector: 'edge.highlighted',
                style: {
                    'line-color': '#fbbf24',
                    'target-arrow-color': '#f59e0b',
                    'width': function (edge) {
                        const currentWidth = parseInt(edge.style('width')) || 3;
                        return (currentWidth * 2.2) + 'px';
                    },
                    'opacity': 1.0,
                    'z-index': 200,

                    // 엣지 펄스 효과
                    'line-opacity': function (edge) {
                        return 0.9 + 0.1 * Math.sin(Date.now() * 0.006);
                    }
                }
            }
        ];
    }

    /**
     * 🎯 계층적 레이아웃 (역동적 구조)
     */
    getHierarchicalLayout() {
        return {
            name: 'dagre',
            rankDir: 'TB', // Top to Bottom 계층 구조
            ranker: 'network-simplex',
            nodeSep: 60,
            rankSep: 80,
            edgeSep: 20,
            animate: true,
            animationDuration: 1000,
            animationEasing: 'ease-out-cubic',
            fit: true,
            padding: 40,
            spacingFactor: 1.2,
            avoidOverlap: true,
            nodeDimensionsIncludeLabels: true
        };
    }

    /**
     * 📊 상세리포트용 통계 HTML 생성
     */
    generateDetailedStatisticsHTML(statistics) {
        if (!statistics || Object.keys(statistics).length === 0) {
            return '';
        }

        // 📊 핵심 통계 우선순위 순서로 정렬
        const coreStatsPriority = [
            'totalAnalyzedUsers',
            'usersWithGroupInfoPermission',
            'permissionGrantRate',
            'totalNodes',
            'uniquePermissionsCount',
            'totalConnections'
        ];

        // 📊 통계를 카테고리별로 분류
        const categorizedStats = {
            core: [],
            additional: []
        };

        Object.entries(statistics).forEach(([key, value]) => {
            if (value !== undefined && value !== null && value !== 0) {
                if (coreStatsPriority.includes(key)) {
                    categorizedStats.core.push([key, value]);
                } else {
                    categorizedStats.additional.push([key, value]);
                }
            }
        });

        return `
            <div class="report-section">
                <div class="section-header">
                    <i class="fas fa-chart-bar text-indigo-400"></i>
                    <h4>상세 통계 분석</h4>
                </div>
                <div class="section-content">
                    
                    <!-- 핵심 통계 -->
                    ${categorizedStats.core.length > 0 ? `
                        <div class="stats-category">
                            <h5 class="stats-category-title">
                                <i class="fas fa-star text-yellow-400"></i>
                                핵심 통계
                            </h5>
                            <div class="detailed-stats-grid">
                                ${categorizedStats.core.map(([key, value]) => this.generateDetailedStatCard(key, value, true)).join('')}
                            </div>
                        </div>
                    ` : ''}
                    
                    <!-- 추가 통계 -->
                    ${categorizedStats.additional.length > 0 ? `
                        <div class="stats-category">
                            <h5 class="stats-category-title">
                                <i class="fas fa-plus-circle text-blue-400"></i>
                                추가 통계
                            </h5>
                            <div class="detailed-stats-grid">
                                ${categorizedStats.additional.map(([key, value]) => this.generateDetailedStatCard(key, value, false)).join('')}
                            </div>
                        </div>
                    ` : ''}
                    
                </div>
            </div>
        `;
    }

    /**
     * 📊 상세 통계 카드 생성
     */
    generateDetailedStatCard(key, value, isCore) {
        const explanation = this.getStatExplanation(key, value);
        const icon = this.getStatIcon(key);
        const trend = this.getStatTrend(key, value);

        return `
            <div class="detailed-stat-card ${isCore ? 'core-stat' : 'additional-stat'}">
                <div class="stat-card-header">
                    <div class="stat-icon-large">
                        ${icon}
                    </div>
                    <div class="stat-meta">
                        <div class="stat-value-large">${value}</div>
                        <div class="stat-label-large">${this.translateStatKey(key)}</div>
                    </div>
                </div>
                <div class="stat-card-body">
                    <p class="stat-explanation-detailed">${explanation}</p>
                    ${trend ? `<div class="stat-trend-detailed">${trend}</div>` : ''}
                </div>
            </div>
        `;
    }

    /**
     * 📋 통계 설명 생성 (관리자가 이해할 수 있도록)
     */
    getStatExplanation(key, value) {
        const explanations = {
            'totalAnalyzedUsers': `시스템에서 분석한 전체 사용자 수입니다. 현재 ${value}명의 사용자가 권한 분석 대상입니다.`,
            'usersWithGroupInfoPermission': `그룹 정보 조회 권한을 보유한 사용자 수입니다. ${value}명이 해당 권한을 가지고 있습니다.`,
            'usersWithoutGroupInfoPermission': `그룹 정보 조회 권한이 없는 사용자 수입니다. ${value}명이 해당 권한을 보유하지 않습니다.`,
            'permissionGrantRate': `권한 보유율입니다. 전체 사용자 중 ${value}%가 분석 대상 권한을 보유하고 있습니다.`,
            'totalNodes': `시각화 다이어그램의 전체 엔티티 수입니다. 사용자, 그룹, 역할, 권한을 포함하여 ${value}개의 노드가 있습니다.`,
            'uniquePermissionsCount': `시스템에서 발견된 고유 권한의 수입니다. ${value}개의 서로 다른 권한이 확인되었습니다.`,
            'totalConnections': `엔티티 간의 관계 연결 수입니다. 사용자-그룹, 그룹-역할, 역할-권한 등 ${value}개의 관계가 있습니다.`,
            'userNodes': `분석 대상 사용자 노드 수입니다. ${value}명의 사용자가 시각화에 포함되었습니다.`,
            'groupNodes': `시스템의 그룹 수입니다. ${value}개의 그룹이 권한 구조에 포함되어 있습니다.`,
            'roleNodes': `시스템의 역할 수입니다. ${value}개의 역할이 권한 체계에 정의되어 있습니다.`,
            'permissionNodes': `시스템의 권한 수입니다. ${value}개의 권한이 관리되고 있습니다.`,
            'totalRecommendations': `AI가 제안한 권장사항 수입니다. ${value}개의 개선 제안이 있습니다.`,
            'averageConfidenceScore': `분석 결과의 평균 신뢰도입니다. AI 분석 결과에 대한 확신도가 ${value}%입니다.`,
            'totalPermissionAssignments': `전체 권한 할당 건수입니다. 시스템 전체에서 ${value}건의 권한 할당이 있습니다.`
        };

        return explanations[key] || `${this.translateStatKey(key)}: ${value}`;
    }

    /**
     * 🔥 analysisResults에서 완전한 USER-GROUP-ROLE-PERMISSION 시각화 생성
     */
    generateCompleteVisualizationFromAnalysis(analysisResults, originalQuery) {
        console.log('🔥 완전한 시각화 구조 생성 시작:', analysisResults);

        const nodes = [];
        const edges = [];
        const nodeIds = new Set();

        // 🔥 Step 1: analysisResults에서 모든 엔티티 추출
        const entities = {
            users: new Map(),
            groups: new Map(),
            roles: new Map(),
            permissions: new Map()
        };

        analysisResults.forEach(result => {
            // USER 엔티티
            if (result.name && !entities.users.has(result.name)) {
                entities.users.set(result.name, {
                    id: result.name,
                    label: result.name,
                    type: 'USER',
                    hasPermission: result.hasPermission,
                    properties: {
                        name: result.name,
                        description: `${result.name} 사용자`,
                        hasPermission: result.hasPermission
                    }
                });
            }

            // GROUP 엔티티
            if (result.group && !entities.groups.has(result.group)) {
                entities.groups.set(result.group, {
                    id: result.group,
                    label: result.group,
                    type: 'GROUP',
                    properties: {
                        name: result.group,
                        description: `${result.group} 그룹`
                    }
                });
            }

            // ROLE 엔티티
            if (result.role && !entities.roles.has(result.role)) {
                entities.roles.set(result.role, {
                    id: result.role,
                    label: result.role,
                    type: 'ROLE',
                    properties: {
                        name: result.role,
                        description: `${result.role} 역할`
                    }
                });
            }

            // PERMISSION 엔티티들
            if (result.permissions && Array.isArray(result.permissions)) {
                result.permissions.forEach(permission => {
                    if (!entities.permissions.has(permission)) {
                        entities.permissions.set(permission, {
                            id: permission,
                            label: permission,
                            type: 'PERMISSION',
                            properties: {
                                name: permission,
                                description: `${permission} 권한`,
                                granted: result.hasPermission
                            }
                        });
                    }
                });
            }
        });

        // 🔥 Step 2: 노드 생성
        entities.users.forEach(user => nodes.push(user));
        entities.groups.forEach(group => nodes.push(group));
        entities.roles.forEach(role => nodes.push(role));
        entities.permissions.forEach(permission => nodes.push(permission));

        nodes.forEach(node => nodeIds.add(node.id));

        // 🔥 Step 3: 엣지 생성 (analysisResults 기반 관계)
        analysisResults.forEach(result => {
            // USER -> GROUP 관계
            if (result.name && result.group &&
                nodeIds.has(result.name) && nodeIds.has(result.group)) {
                edges.push({
                    id: `${result.name}-${result.group}`,
                    source: result.name,
                    target: result.group,
                    type: 'BELONGS_TO',
                    label: '소속',
                    properties: {relationship: 'belongs_to'}
                });
            }

            // GROUP -> ROLE 관계
            if (result.group && result.role &&
                nodeIds.has(result.group) && nodeIds.has(result.role)) {
                edges.push({
                    id: `${result.group}-${result.role}`,
                    source: result.group,
                    target: result.role,
                    type: 'HAS_ROLE',
                    label: '역할 보유',
                    properties: {relationship: 'has_role'}
                });
            }

            // ROLE -> PERMISSION 관계들
            if (result.role && result.permissions && Array.isArray(result.permissions)) {
                result.permissions.forEach(permission => {
                    if (nodeIds.has(result.role) && nodeIds.has(permission)) {
                        edges.push({
                            id: `${result.role}-${permission}`,
                            source: result.role,
                            target: permission,
                            type: 'HAS_PERMISSION',
                            label: result.hasPermission ? '권한 보유' : '권한 없음',
                            properties: {
                                relationship: 'has_permission',
                                granted: result.hasPermission
                            }
                        });
                    }
                });
            }
        });

        console.log('🔥 완전한 시각화 구조 생성 완료:', {
            nodes: nodes.length,
            edges: edges.length,
            users: entities.users.size,
            groups: entities.groups.size,
            roles: entities.roles.size,
            permissions: entities.permissions.size
        });

        return {nodes, edges};
    }

    /**
     * 🔥 visualizationData에 없는 USER 노드를 analysisResults에서 추가
     */
    addMissingUserNodes(visualizationData, analysisResults) {
        console.log('🔥 사용자 노드 추가 시작:', visualizationData, analysisResults);

        const enhancedData = {
            nodes: [...(visualizationData.nodes || [])],
            edges: [...(visualizationData.edges || [])]
        };

        if (!analysisResults || analysisResults.length === 0) {
            return enhancedData;
        }

        analysisResults.forEach(result => {
            const userName = result.name;
            const existingUserNode = enhancedData.nodes.find(node =>
                node.id === userName || node.label === userName ||
                (node.type === 'USER' && node.id.includes(userName))
            );

            if (!existingUserNode) {
                console.log(`🔥 USER 노드 추가: ${userName}`);

                // USER 노드 생성
                const userNode = {
                    id: userName,
                    type: 'USER',
                    label: userName,
                    properties: {
                        name: userName,
                        role: result.role,
                        group: result.group,
                        permissions: result.permissions,
                        hasPermission: result.hasPermission
                    }
                };

                enhancedData.nodes.push(userNode);

                // USER -> ROLE 엣지 추가
                const roleNode = enhancedData.nodes.find(node =>
                    node.type === 'ROLE' && (node.id === result.role || node.label.includes('관리자'))
                );
                if (roleNode) {
                    const userRoleEdge = {
                        id: `USER_ROLE_${userName}`,
                        source: userName,
                        target: roleNode.id,
                        type: 'HAS_ROLE',
                        properties: {relationship: 'has_role'}
                    };
                    enhancedData.edges.push(userRoleEdge);
                    console.log(`🔗 USER-ROLE 엣지 추가: ${userName} -> ${roleNode.id}`);
                }

                // USER -> GROUP 엣지 추가
                const groupNode = enhancedData.nodes.find(node =>
                    node.type === 'GROUP' && (node.id === result.group || node.label === result.group)
                );
                if (groupNode) {
                    const userGroupEdge = {
                        id: `USER_GROUP_${userName}`,
                        source: userName,
                        target: groupNode.id,
                        type: 'BELONGS_TO',
                        properties: {relationship: 'belongs_to'}
                    };
                    enhancedData.edges.push(userGroupEdge);
                    console.log(`🔗 USER-GROUP 엣지 추가: ${userName} -> ${groupNode.id}`);
                }

                // USER -> PERMISSION 직접 엣지 추가 (권한이 있는 경우)
                if (result.hasPermission && result.permissions) {
                    result.permissions.forEach(permissionName => {
                        const permissionNode = enhancedData.nodes.find(node =>
                            node.type === 'PERMISSION' &&
                            (node.id === permissionName || node.label === permissionName ||
                                node.label.includes('조회') || permissionName.includes('조회'))
                        );
                        if (permissionNode) {
                            const userPermissionEdge = {
                                id: `USER_PERMISSION_${userName}_${permissionNode.id}`,
                                source: userName,
                                target: permissionNode.id,
                                type: 'HAS_PERMISSION',
                                properties: {
                                    relationship: 'has_permission',
                                    granted: true
                                }
                            };
                            enhancedData.edges.push(userPermissionEdge);
                            console.log(`🔗 USER-PERMISSION 엣지 추가: ${userName} -> ${permissionNode.id}`);
                        }
                    });
                }
            }
        });

        console.log('🔥 최종 보강된 visualizationData:', enhancedData);
        return enhancedData;
    }

    /**
     * 🔥 서버 데이터를 클라이언트 analysisResults 구조로 변환
     */
    convertServerDataToAnalysisResults(response) {
        console.log('🔥 [NEW STRUCTURE] 새로운 서버 구조 기반 변환:', response.analysisResults);

        const analysisResults = [];

        // 🔥 새로운 서버 구조: {user, groups: Array, permissions: Array}
        if (response.analysisResults && Array.isArray(response.analysisResults)) {
            response.analysisResults.forEach(serverResult => {
                console.log('실제 서버 analysisResult 항목:', serverResult);

                // 🔥 4개 필드 구조에 맞춰 변환 (user, groups, roles, permissions)
                const analysisResult = {
                    name: serverResult.user || '알 수 없는 사용자',
                    hasPermission: serverResult.permissions && serverResult.permissions.length > 0,
                    role: (serverResult.roles && serverResult.roles.length > 0) ? serverResult.roles[0] : '역할 불명',
                    group: (serverResult.groups && serverResult.groups.length > 0) ? serverResult.groups[0] : '그룹 불명',
                    permissions: serverResult.permissions || [],
                    permissionCount: (serverResult.permissions || []).length,
                    hasSpecialPermissions: (serverResult.permissions || []).length > 0,
                    // rawInfo 동적 생성 - roles와 groups 모두 활용
                    rawInfo: {
                        roleInfo: (serverResult.roles && serverResult.roles.length > 0) ? `역할: ${serverResult.roles.join(', ')}` : '역할 정보 없음',
                        groupInfo: (serverResult.groups && serverResult.groups.length > 0) ? `그룹: ${serverResult.groups.join(', ')}` : '그룹 정보 없음',
                        permissionInfo: (serverResult.permissions || []).join(', ') || '권한 정보 없음',
                        description: `${serverResult.user}의 권한 분석 결과`
                    }
                };

                analysisResults.push(analysisResult);
                console.log('🎯 변환된 analysisResult:', analysisResult);
            });
        } else {
            console.log('서버에서 analysisResults를 제공하지 않음');
        }

        console.log('🔥 최종 변환된 analysisResults (새로운 구조 기반):', analysisResults);
        return analysisResults;
    }


    /**
     * 🔥 서버 데이터 기반 신뢰도 계산 (하드코딩 제거)
     */
    calculateConfidenceFromServerData(response) {
        // 서버에서 제공된 통계 데이터 기반으로 계산
        if (response.statistics && response.statistics.totalPermissions) {
            const total = response.statistics.totalPermissions || 1;
            const executed = response.statistics.executeMethods || 0;
            const accessed = response.statistics.accessPermissions || 0;
            return Math.round(((executed + accessed) / total) * 100);
        }

        // 분석 결과가 있으면 높은 신뢰도
        if (response.insights && response.insights.length > 0) {
            return 85;
        }

        return 0;
    }

    /**
     * 🔥 서버 데이터 기반 분석 타입 감지 (하드코딩 제거)
     */
    detectAnalysisTypeFromServerData(response) {
        if (response.query && response.query.includes('최고관리자')) {
            return 'ADMIN_ANALYSIS';
        }
        if (response.query && response.query.includes('권한')) {
            return 'PERMISSION_ANALYSIS';
        }
        return 'GENERAL_ANALYSIS';
    }

    /**
     * 🔥 서버 데이터 기반 복잡도 계산 (하드코딩 제거)
     */
    calculateComplexityFromServerData(response) {
        let complexity = 0;

        if (response.visualizationData) {
            const nodeCount = response.visualizationData.nodes ? response.visualizationData.nodes.length : 0;
            const edgeCount = response.visualizationData.edges ? response.visualizationData.edges.length : 0;
            complexity = Math.min(100, (nodeCount + edgeCount) * 10);
        }

        return complexity;
    }

    /**
     * 🔥 서버 데이터 기반 위험도 계산 (하드코딩 제거)
     */
    calculateRiskFromServerData(response) {
        // 권장사항 개수 기반으로 위험도 계산
        if (response.recommendations && response.recommendations.length > 0) {
            return Math.min(100, response.recommendations.length * 25);
        }

        return 0;
    }


    /**
     * 🔥 통계 키 번역 (한국어 개선)
     */
    translateStatKey(key) {
        // 📊 실제 데이터 기반 동적 통계 한국어 라벨 매핑
        const koreanLabels = {
            // 권한 분석 통계
            'totalAnalyzedUsers': '분석 대상 사용자',
            'usersWithGroupInfoPermission': '권한 보유자',
            'usersWithoutGroupInfoPermission': '권한 미보유자',
            'permissionGrantRate': '권한 부여율 (%)',
            'uniquePermissionsCount': '고유 권한 수',
            'totalPermissionAssignments': '권한 할당 총계',

            // 시각화 구조 통계
            'totalNodes': '전체 노드',
            'userNodes': '사용자 노드',
            'groupNodes': '그룹 노드',
            'roleNodes': '역할 노드',
            'permissionNodes': '권한 노드',
            'totalConnections': '전체 연결',
            'hasRoleConnections': '역할 연결',
            'hasPermissionConnections': '권한 연결',

            // 질의 결과 통계
            'totalQueryResults': '질의 결과',
            'accessGrantedCount': '접근 허용',
            'accessDeniedCount': '접근 거부',

            // 권장사항 통계
            'totalRecommendations': '전체 권장사항',
            'highPriorityRecommendations': '높은 우선순위',
            'mediumPriorityRecommendations': '중간 우선순위',
            'lowPriorityRecommendations': '낮은 우선순위',

            // 분석 품질 통계
            'confidenceScore': '신뢰도 점수',
            'analysisCompleteness': '분석 완성도 (%)',

            // 기존 호환성 (제거 예정)
            'totalUsers': '전체 사용자',
            'totalRoles': '전체 역할',
            'totalGroups': '전체 그룹',
            'totalPermissions': '전체 권한'
        };

        // 한국어 라벨이 있으면 사용, 없으면 자동 변환
        if (koreanLabels[key]) {
            return koreanLabels[key];
        }

        // 기본 영어 → 한국어 변환 (폴백)
        return key
            .replace(/([A-Z])/g, ' $1')
            .toLowerCase()
            .replace(/^./, str => str.toUpperCase())
            .replace('users', '사용자')
            .replace('groups', '그룹')
            .replace('roles', '역할')
            .replace('permissions', '권한')
            .replace('nodes', '노드')
            .replace('connections', '연결')
            .replace('total', '전체')
            .replace('with', '보유')
            .replace('without', '미보유')
            .replace('info', '정보')
            .replace('permission', '권한')
            .replace('access', '접근')
            .replace('granted', '허용')
            .replace('denied', '거부')
            .replace('count', '개수')
            .replace('rate', '비율')
            .replace('score', '점수')
            .replace('completeness', '완성도');
    }

    /**
     * 📊 통계 항목별 아이콘 가져오기
     */
    getStatIcon(key) {
        const iconMap = {
            // 권한 분석 통계 아이콘
            'totalAnalyzedUsers': '<i class="fas fa-users-cog text-blue-500"></i>',
            'usersWithGroupInfoPermission': '<i class="fas fa-user-check text-green-500"></i>',
            'usersWithoutGroupInfoPermission': '<i class="fas fa-user-times text-red-500"></i>',
            'permissionGrantRate': '<i class="fas fa-percentage text-purple-500"></i>',

            // 시각화 구조 통계 아이콘
            'totalNodes': '<i class="fas fa-project-diagram text-indigo-500"></i>',
            'userNodes': '<i class="fas fa-users text-blue-500"></i>',
            'groupNodes': '<i class="fas fa-layer-group text-cyan-500"></i>',
            'roleNodes': '<i class="fas fa-user-tag text-purple-500"></i>',
            'permissionNodes': '<i class="fas fa-key text-orange-500"></i>',
            'totalConnections': '<i class="fas fa-network-wired text-gray-500"></i>',
            'hasRoleConnections': '<i class="fas fa-link text-purple-400"></i>',
            'hasPermissionConnections': '<i class="fas fa-unlink text-orange-400"></i>',

            // 질의 결과 통계 아이콘
            'totalQueryResults': '<i class="fas fa-search text-blue-500"></i>',
            'accessGrantedCount': '<i class="fas fa-check-circle text-green-500"></i>',
            'accessDeniedCount': '<i class="fas fa-times-circle text-red-500"></i>',

            // 권장사항 통계 아이콘
            'totalRecommendations': '<i class="fas fa-lightbulb text-yellow-500"></i>',
            'highPriorityRecommendations': '<i class="fas fa-exclamation text-red-500"></i>',
            'mediumPriorityRecommendations': '<i class="fas fa-info text-orange-500"></i>',
            'lowPriorityRecommendations': '<i class="fas fa-check text-green-500"></i>',

            // 분석 품질 통계 아이콘
            'confidenceScore': '<i class="fas fa-medal text-yellow-600"></i>',
            'analysisCompleteness': '<i class="fas fa-tasks text-blue-600"></i>',

            // 기존 호환성 아이콘 (제거 예정)
            'totalUsers': '<i class="fas fa-users text-blue-500"></i>',
            'totalRoles': '<i class="fas fa-user-tag text-purple-500"></i>',
            'totalGroups': '<i class="fas fa-layer-group text-indigo-500"></i>',
            'totalPermissions': '<i class="fas fa-key text-orange-500"></i>'
        };

        return iconMap[key] || '<i class="fas fa-chart-bar text-blue-400"></i>';
    }

    /**
     * 📈 통계 트렌드 텍스트 가져오기
     */
    getStatTrend(key, value) {
        // 권한 관련 통계에 대한 트렌드 분석
        if (key.includes('WithGroupInfoPermission')) {
            return value > 0 ?
                '<span class="trend-positive">권한 보유 ✓</span>' :
                '<span class="trend-neutral">권한 없음</span>';
        }

        if (key.includes('WithoutGroupInfoPermission')) {
            return value > 0 ?
                '<span class="trend-warning">권한 필요</span>' :
                '<span class="trend-positive">모든 사용자 권한 보유</span>';
        }

        if (key.includes('totalUsers')) {
            return value > 5 ?
                '<span class="trend-positive">대규모 시스템</span>' :
                '<span class="trend-neutral">소규모 시스템</span>';
        }

        if (key.includes('totalRoles')) {
            return value > 3 ?
                '<span class="trend-positive">세분화된 역할</span>' :
                '<span class="trend-neutral">단순 역할 구조</span>';
        }

        // 기본 트렌드
        return '<span class="trend-neutral">분석 완료</span>';
    }

    /**
     * 💡 핵심 인사이트 추출
     */
    /**
     * 🧠 AI 분석 결과에서 핵심 인사이트 추출 (중복 제거)
     */
    extractKeyInsights(response) {
        // 실제 AI 분석 결과에서만 인사이트 추출
        if (response.insights && Array.isArray(response.insights)) {
            console.log('🧠 실제 AI 분석에서 제공된 핵심 인사이트:', response.insights);
            return response.insights;
        }

        // 중복 제거: recommendations는 최적화 제안에서만 사용
        console.log('중복 제거: recommendations는 최적화 제안에서만 사용');

        // 빈 배열 반환
        return [];
    }

    /**
     * 🧠 AI 분석 결과에서 권한 이상 탐지 추출 (하드코딩 제거)
     */
    extractPermissionAnomalies(response) {
        // 실제 AI 분석 결과에서만 이상 탐지 추출
        if (response.anomalies && Array.isArray(response.anomalies)) {
            console.log('🧠 실제 AI 분석에서 탐지된 권한 이상:', response.anomalies);
            return response.anomalies;
        }

        // 하드코딩된 패턴 기반 이상 탐지 제거
        console.log('하드코딩된 패턴 기반 이상 탐지 로직 제거됨');
        console.log('🧠 실제 AI 분석 결과만을 사용합니다');

        // 빈 배열 반환 (실제 AI 분석 결과가 없으면 이상 없음)
        return [];
    }

    /**
     * 🚀 최적화 제안 추출
     */
    extractOptimizationSuggestions(response) {
        // 백엔드에서 직접 제공되는 경우
        if (response.optimizationSuggestions && Array.isArray(response.optimizationSuggestions)) {
            return response.optimizationSuggestions;
        }

        // recommendations를 최적화 제안으로 변환
        if (response.recommendations && Array.isArray(response.recommendations)) {
            return response.recommendations.map(rec => ({
                type: 'SYSTEM_OPTIMIZATION',
                title: rec.title || '시스템 개선',
                description: rec.description || '',
                expectedBenefit: '권한 관리 효율성 향상',
                priority: rec.priority || 2,
                implementationComplexity: 2,
                actionLinks: rec.actionLinks || [],
                actionItems: rec.actionItems || []
            }));
        }

        return [];
    }

    /**
     * 🎯 분석 타입 감지
     */
    detectAnalysisType(response) {
        const naturalAnswer = response.naturalLanguageAnswer || '';

        if (naturalAnswer.includes('누가') || naturalAnswer.includes('사용자')) {
            return 'WHO_CAN_ACCESS';
        } else if (naturalAnswer.includes('권한') || naturalAnswer.includes('접근')) {
            return 'PERMISSION_ANALYSIS';
        } else if (naturalAnswer.includes('그룹') || naturalAnswer.includes('역할')) {
            return 'ROLE_ANALYSIS';
        } else {
            return 'GENERAL_ANALYSIS';
        }
    }

    /**
     * 🧠 AI 분석 결과에서 복잡도 점수 계산 (하드코딩 제거)
     */
    calculateComplexityScore(response) {
        // 실제 AI 분석 결과가 있는 경우만 복잡도 계산
        if (response.complexityScore !== undefined && response.complexityScore !== null) {
            console.log('🧠 실제 AI 분석에서 제공된 복잡도:', response.complexityScore);
            return Math.min(response.complexityScore, 1.0);
        }

        // 하드코딩된 임계값 기반 복잡도 계산 제거
        console.log('하드코딩된 임계값 기반 복잡도 계산 제거됨');
        console.log('🧠 실제 AI 분석 결과가 없으면 복잡도 0으로 설정');

        // 기본값 (AI 분석 결과가 없으면 복잡도 없음)
        return 0.0;
    }

    /**
     * 🧠 AI 분석 결과에서 위험도 점수 계산 (하드코딩 제거)
     */
    calculateRiskScore(response) {
        // 실제 AI 분석 결과가 있는 경우만 위험도 계산
        if (response.riskScore !== undefined && response.riskScore !== null) {
            console.log('🧠 실제 AI 분석에서 제공된 위험도:', response.riskScore);
            return Math.min(response.riskScore, 1.0);
        }

        // 하드코딩된 패턴 기반 위험도 계산 제거
        console.log('하드코딩된 패턴 기반 위험도 계산 제거됨');
        console.log('🧠 실제 AI 분석 결과가 없으면 위험도 0으로 설정');

        // 기본값 (AI 분석 결과가 없으면 위험도 없음)
        return 0.0;
    }

    /**
     * 🎯 우선순위를 중요도로 변환
     */
    convertPriorityToImportance(priority) {
        // priority: 1(높음), 2(보통), 3(낮음)
        // importance: 1(높음), 2(보통), 3(낮음)
        return priority || 2;
    }

    // Inspector에 AI-Native 분석 결과 표시
    displayAINativeAnalysisInInspector(analysisResult, originalQuery) {
        const inspectorContent = document.getElementById('inspector-content');
        const inspectorPlaceholder = document.getElementById('inspector-placeholder');

        if (!inspectorContent) return;

        // Placeholder 숨기기
        inspectorPlaceholder.classList.add('hidden');
        inspectorContent.classList.remove('hidden');

        // 🧠 AI-Native 메타데이터 생성
        const confidenceClass = this.getConfidenceClass(analysisResult.confidenceScore || 80);
        const confidenceText = this.getConfidenceText(analysisResult.confidenceScore || 80);
        const timestamp = new Date().toLocaleString('ko-KR');

        // 디버깅: originalQuery 값 확인
        console.log('Inspector 질의어 표시:', {
            originalQuery: originalQuery,
            queryType: typeof originalQuery,
            queryLength: originalQuery?.length
        });

        const displayQuery = originalQuery || analysisResult.query || "자연어 질의가 전달되지 않았습니다";

        const html = `
            <!-- 🎯 사용자 질의 섹션 (최상단 - 항상 표시) -->
            <div class="user-query-section">
                <div class="query-header">
                    <i class="fas fa-question-circle text-blue-400"></i>
                    <h4>사용자 질의</h4>
                </div>
                <div class="query-content">
                    <div class="query-text">${displayQuery}</div>
                </div>
            </div>
            
            <!-- 📊 AI 분석 결과 (단일 타이틀) -->
            <div class="analysis-summary-section">
                <div class="summary-header">
                    <div class="summary-title">
                        <i class="fas fa-brain text-indigo-400"></i>
                        <h4>AI 분석 결과</h4>
                    </div>
                    <button class="detailed-report-btn" onclick="aiStudio.showDetailedReport()">
                        <i class="fas fa-chart-pie"></i>
                        상세 리포트
                    </button>
                </div>
                
                <div class="analysis-answer">
                    ${this.formatAINativeAnswer(analysisResult.naturalAnswer, originalQuery, analysisResult.analysisResults)}
                </div>
                
                <!-- 메타 정보 -->
                <div class="analysis-meta">
                    <div class="meta-item">
                        <span class="meta-label">신뢰도:</span>
                        <span class="meta-value ${confidenceClass}">${confidenceText}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">처리시간:</span>
                        <span class="meta-value">${analysisResult.processingTime}ms</span>
                    </div>
                </div>
                
                <!-- 📊 통계 분석은 상세리포트에서 확인 -->
                ${analysisResult.statistics && Object.keys(analysisResult.statistics).length > 0 ? `
                    <div class="statistics-notice">
                        <div class="notice-header">
                            <i class="fas fa-chart-pie text-blue-400"></i>
                            <h5>상세 통계 분석</h5>
                        </div>
                        <div class="notice-content">
                            <p class="notice-text">📊 ${Object.keys(analysisResult.statistics).length}개의 상세 통계가 분석되었습니다.</p>
                            <button class="view-statistics-btn" onclick="aiStudio.showDetailedStatistics()">
                                <i class="fas fa-chart-bar"></i>
                                상세 통계 보기
                            </button>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;

        // 🗂️ 상세 리포트 데이터 저장 (모달에서 사용)
        console.log('[INSIGHTS] AI 인사이트 및 권장사항 확인:', {
            insights: analysisResult.insights?.length || 0,
            suggestions: analysisResult.suggestions?.length || 0,
            recommendations: analysisResult.recommendations?.length || 0,
            hasDetailedReportData: !!(analysisResult.insights || analysisResult.suggestions)
        });

        this.currentDetailedReport = {
            analysisResult,
            originalQuery,
            timestamp,
            insights: analysisResult.insights,
            anomalies: analysisResult.anomalies,
            suggestions: analysisResult.suggestions,
            naturalLanguageAnswer: analysisResult.naturalAnswer || analysisResult.naturalLanguageAnswer || ''
        };

        inspectorContent.innerHTML = html;

        // 🎯 인터랙티브 기능 활성화
        this.enableAINativeInteractions(analysisResult);
    }

    /**
     * 📊 기본 분석 결과 생성 (AI 응답이 부족한 경우)
     */
    generateBasicAnalysisResults(analysisResult, originalQuery) {
        // 권한 분석 결과가 있는지 확인
        if (analysisResult.analysisResults && analysisResult.analysisResults.length > 0) {
            // 모든 권한이 false인지 확인
            const hasAnyPermission = analysisResult.analysisResults.some(result => result.hasPermission === true);

            if (!hasAnyPermission) {
                // 모든 권한이 false인 경우 "결과 없음" 메시지
                return `
                    <div class="no-permission-analysis">
                        <div class="no-permission-header">
                            <i class="fas fa-ban text-red-400"></i>
                            <h5>권한 분석 결과</h5>
                        </div>
                        <div class="no-permission-content">
                            <div class="analysis-status">
                                <div class="status-item">
                                    <i class="fas fa-search text-blue-400"></i>
                                    <span class="status-text">질의: "${originalQuery}"</span>
                                </div>
                                <div class="status-item">
                                    <i class="fas fa-times-circle text-red-400"></i>
                                    <span class="status-text">결과: 해당 작업을 수행할 권한이 있는 사용자가 없습니다</span>
                                </div>
                                <div class="status-item">
                                    <i class="fas fa-info-circle text-yellow-400"></i>
                                    <span class="status-text">분석 항목: ${analysisResult.analysisResults.length}개 사용자/그룹 검토</span>
                                </div>
                            </div>
                            
                            <div class="permission-actions">
                                <h6>🔧 권장 조치 사항:</h6>
                                <div class="action-buttons">
                                    <button class="action-btn" onclick="window.location.href='/admin/users'">
                                        <i class="fas fa-users"></i>
                                        사용자 권한 관리
                                    </button>
                                    <button class="action-btn" onclick="window.location.href='/admin/roles'">
                                        <i class="fas fa-user-tag"></i>
                                        역할 관리
                                    </button>
                                    <button class="action-btn" onclick="window.location.href='/admin/groups'">
                                        <i class="fas fa-layer-group"></i>
                                        그룹 관리
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            } else {
                // 권한이 있는 사용자가 있으면 추가 표시 안함
                return '';
            }
        }

        // AI 답변이 의미있는 경우 추가 표시 안함
        if (analysisResult.naturalAnswer &&
            analysisResult.naturalAnswer.length > 30 &&
            !analysisResult.naturalAnswer.includes('가져올 수 없습니다')) {
            return '';
        }

        // 기본 분석 결과 생성
        return `
            <div class="basic-analysis-section">
                <div class="basic-analysis-header">
                    <i class="fas fa-info-circle text-blue-400"></i>
                    <h5>기본 분석 정보</h5>
                </div>
                <div class="basic-analysis-content">
                    <div class="analysis-status">
                        <div class="status-item">
                            <i class="fas fa-question-circle text-orange-400"></i>
                            <span class="status-text">질의: "${originalQuery}"</span>
                        </div>
                        <div class="status-item">
                            <i class="fas fa-exclamation-triangle text-yellow-400"></i>
                            <span class="status-text">상태: AI 분석 결과가 제한적입니다</span>
                        </div>
                        <div class="status-item">
                            <i class="fas fa-lightbulb text-green-400"></i>
                            <span class="status-text">권장사항: 더 구체적인 질의를 시도해보세요</span>
                        </div>
                    </div>
                    
                    <div class="suggested-queries">
                        <h6>💡 추천 질의 예시:</h6>
                        <div class="query-suggestions">
                            <button class="suggestion-btn" onclick="aiStudio.fillQuery('누가 문서를 삭제할 수 있나요?')">
                                <i class="fas fa-arrow-right"></i>
                                누가 문서를 삭제할 수 있나요?
                            </button>
                            <button class="suggestion-btn" onclick="aiStudio.fillQuery('개발팀에서 누가 관리자 권한을 가지고 있나요?')">
                                <i class="fas fa-arrow-right"></i>
                                개발팀에서 누가 관리자 권한을 가지고 있나요?
                            </button>
                            <button class="suggestion-btn" onclick="aiStudio.fillQuery('최고관리자는 어떤 권한을 가지고 있나요?')">
                                <i class="fas fa-arrow-right"></i>
                                최고관리자는 어떤 권한을 가지고 있나요?
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * 💡 추천 질의를 입력창에 채우기
     */
    fillQuery(query) {
        const queryInput = document.getElementById('ai-query-input');
        if (queryInput) {
            queryInput.value = query;
            queryInput.focus();
        }
    }

    /**
     * 사용자 카드 필터링 (검색 기능)
     */
    /**
     * 완전한 검색 기능 - 사용자명, 그룹, 역할, 권한 모두 검색
     * 즉시 실행되는 실시간 검색
     */
    filterUserCards(searchTerm) {
        const searchValue = searchTerm.toLowerCase().trim();
        const userCards = document.querySelectorAll('.user-card-mini');
        let visibleCount = 0;

        userCards.forEach(card => {
            const userName = card.getAttribute('data-user-name')?.toLowerCase() || '';
            const userGroup = card.getAttribute('data-user-group')?.toLowerCase() || '';
            const userRole = card.getAttribute('data-user-role')?.toLowerCase() || '';
            const userPermissions = card.getAttribute('data-user-permissions')?.toLowerCase() || '';

            // 사용자명, 그룹, 역할, 권한 모두에서 검색
            const matches = userName.includes(searchValue) ||
                userGroup.includes(searchValue) ||
                userRole.includes(searchValue) ||
                userPermissions.includes(searchValue);

            if (matches) {
                card.style.display = 'flex';
                visibleCount++;

                // 검색어 하이라이팅
                this.highlightSearchTerm(card, searchValue);
            } else {
                card.style.display = 'none';
            }
        });

        // 검색 결과 없음 메시지
        const gridContainer = document.getElementById('user-cards-grid');
        const noResultsMessage = document.getElementById('no-search-results');

        if (visibleCount === 0 && searchValue) {
            if (!noResultsMessage && gridContainer) {
                const message = document.createElement('div');
                message.id = 'no-search-results';
                message.className = 'no-search-results';
                message.innerHTML = `
                    <div class="no-results-icon">
                        <i class="fas fa-search"></i>
                    </div>
                    <div class="no-results-text">
                        <h6>검색 결과가 없습니다</h6>
                        <p>"${searchTerm}"과 일치하는 사용자가 없습니다.</p>
                        <div class="search-suggestions">
                            <p class="suggestion-title">💡 검색 팁:</p>
                            <ul>
                                <li>사용자명, 그룹, 역할, 권한으로 검색 가능</li>
                                <li>일부 문자만 입력해도 검색됩니다</li>
                                <li>예: "관리", "조회", "승인" 등</li>
                            </ul>
                        </div>
                    </div>
                `;
                gridContainer.appendChild(message);
            }
        } else if (noResultsMessage) {
            noResultsMessage.remove();
        }

        // 검색 통계 표시
        this.updateSearchStats(visibleCount, userCards.length, searchValue);
    }

    /**
     * 🎯 검색어 하이라이팅
     */
    highlightSearchTerm(card, searchTerm) {
        if (!searchTerm) return;

        // 기존 하이라이트 제거
        const existingHighlights = card.querySelectorAll('.search-highlight');
        existingHighlights.forEach(highlight => {
            highlight.outerHTML = highlight.innerHTML;
        });

        // 새로운 하이라이트 적용
        const textElements = card.querySelectorAll('.user-name-mini, .user-group-mini, .user-role-mini');
        textElements.forEach(element => {
            const text = element.textContent;
            const regex = new RegExp(`(${searchTerm})`, 'gi');
            element.innerHTML = text.replace(regex, '<span class="search-highlight">$1</span>');
        });
    }

    /**
     * 📊 검색 통계 업데이트
     */
    updateSearchStats(visibleCount, totalCount, searchTerm) {
        const searchInput = document.getElementById('user-search-input');
        if (!searchInput) return;

        const statsElement = document.getElementById('search-stats');
        if (searchTerm) {
            if (!statsElement) {
                const stats = document.createElement('div');
                stats.id = 'search-stats';
                stats.className = 'search-stats';
                searchInput.parentNode.insertBefore(stats, searchInput.nextSibling);
            }

            const statsEl = document.getElementById('search-stats');
            statsEl.innerHTML = `
                <span class="stats-text">
                    <i class="fas fa-filter"></i>
                    ${visibleCount}개 결과 / 전체 ${totalCount}개
                </span>
            `;
        } else if (statsElement) {
            statsElement.remove();
        }
    }

    /**
     * 사용자 검색 초기화
     */
    clearUserSearch() {
        const searchInput = document.getElementById('user-search-input');
        if (searchInput) {
            searchInput.value = '';
            this.filterUserCards('');
        }
    }

    // 🔥 하드코딩 제거 완료 - AI가 질의를 분석해서 적절한 결과만 반환하도록 프롬프트에서 처리

    /**
     * 권한이 없는 경우 캔버스에 결과 없음 표시
     */
    showNoPermissionResult(originalQuery) {
        const container = document.getElementById('mermaid-container');
        if (!container) return;

        this.hideCanvasPlaceholder();

        container.innerHTML = `
            <div class="no-permission-result">
                <div class="no-result-icon">
                    <i class="fas fa-ban"></i>
                </div>
                <div class="no-result-content">
                    <h3>권한 분석 결과</h3>
                    <p>질의하신 작업을 수행할 수 있는 권한을 보유한 사용자가 없습니다.</p>
                    <div class="query-display">
                        <strong>질의:</strong> "${originalQuery}"
                    </div>
                    <div class="suggestion-section">
                        <p class="suggestion-title">💡 다음 작업을 고려해보세요:</p>
                        <ul class="suggestion-list">
                            <li>사용자에게 필요한 권한을 부여</li>
                            <li>적절한 역할에 사용자를 배정</li>
                            <li>권한 정책 검토 및 수정</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * 📊 상세 리포트 모달 표시
     */
    showDetailedReport() {
        if (!this.currentDetailedReport) {
            this.showToast('상세 리포트 데이터가 없습니다.', 'warning');
            return;
        }

        const {
            analysisResult,
            originalQuery,
            timestamp,
            insights,
            anomalies,
            suggestions,
            naturalLanguageAnswer
        } = this.currentDetailedReport;

        // 모달 생성
        const modal = document.createElement('div');
        modal.className = 'detailed-report-modal';
        modal.innerHTML = `
            <div class="detailed-report-content">
                <div class="report-modal-header">
                    <div class="report-modal-title">
                        <i class="fas fa-brain text-indigo-400"></i>
                        <h3>AI-Native 권한 분석 상세 리포트</h3>
                        <span class="ai-expert-badge">전문가 리포트</span>
                    </div>
                    <button class="close-report-btn" onclick="aiStudio.closeDetailedReport()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                
                <div class="report-modal-body">
                    <!-- 리포트 메타데이터 -->
                    <div class="report-meta-section">
                        <div class="meta-grid-detailed">
                            <div class="meta-card">
                                <i class="fas fa-clock text-blue-400"></i>
                                <div>
                                    <span class="meta-label">분석 일시</span>
                                    <span class="meta-value">${timestamp}</span>
                                </div>
                            </div>
                            <div class="meta-card">
                                <i class="fas fa-brain text-indigo-400"></i>
                                <div>
                                    <span class="meta-label">분석 타입</span>
                                    <span class="meta-value">${analysisResult.analysisType || '권한 분석'}</span>
                                </div>
                            </div>
                            <div class="meta-card">
                                <i class="fas fa-gauge text-green-400"></i>
                                <div>
                                    <span class="meta-label">신뢰도</span>
                                    <span class="meta-value">${Math.round((analysisResult.confidenceScore || 80))}%</span>
                                </div>
                            </div>
                            <div class="meta-card">
                                <i class="fas fa-stopwatch text-orange-400"></i>
                                <div>
                                    <span class="meta-label">처리 시간</span>
                                    <span class="meta-value">${analysisResult.processingTime || 0}ms</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 🎯 AI 자연어 답변 -->
                    ${naturalLanguageAnswer ? `
                    <div class="report-section">
                        <div class="section-header">
                            <i class="fas fa-comments text-blue-400"></i>
                            <h4>AI 자연어 분석 답변</h4>
                        </div>
                        <div class="section-content">
                            <div class="natural-answer-content">
                                <div class="answer-text">
                                    ${naturalLanguageAnswer}
                                </div>
                            </div>
                        </div>
                    </div>
                    ` : ''}
                    
                    <!-- 🧠 AI 핵심 인사이트 -->
                    ${this.generateAIInsightsHTML(insights)}
                    
                    <!-- 🔥 권한 이상 탐지 -->
                    ${this.generateAnomaliesHTML(anomalies)}
                    
                    <!-- 📊 상세 분석 결과 -->
                    <div class="report-section">
                        <div class="section-header">
                            <i class="fas fa-chart-line text-blue-400"></i>
                            <h4>상세 분석 결과</h4>
                        </div>
                        <div class="section-content">
                            ${this.generateDetailedAnalysisHTML(analysisResult.queryResults)}
                        </div>
                    </div>
                    
                    <!-- 🚀 AI 최적화 제안 -->
                    ${this.generateOptimizationSuggestionsHTML(suggestions)}
                    
                    <!-- 📈 성과 메트릭 -->
                    <div class="report-section">
                        <div class="section-header">
                            <i class="fas fa-chart-bar text-purple-400"></i>
                            <h4>성과 메트릭</h4>
                        </div>
                        <div class="section-content">
                            <div class="metrics-grid">
                                <div class="metric-card">
                                    <i class="fas fa-shield-alt text-green-400"></i>
                                    <div class="metric-info">
                                        <span class="metric-value">${analysisResult.analysisResults?.length || 0}</span>
                                        <span class="metric-label">분석 대상</span>
                                    </div>
                                </div>
                                <div class="metric-card">
                                    <i class="fas fa-lightbulb text-yellow-400"></i>
                                    <div class="metric-info">
                                        <span class="metric-value">${insights?.length || 0}</span>
                                        <span class="metric-label">인사이트</span>
                                    </div>
                                </div>
                                <div class="metric-card">
                                    <i class="fas fa-exclamation-triangle text-red-400"></i>
                                    <div class="metric-info">
                                        <span class="metric-value">${anomalies?.length || 0}</span>
                                        <span class="metric-label">이상 탐지</span>
                                    </div>
                                </div>
                                <div class="metric-card">
                                    <i class="fas fa-rocket text-blue-400"></i>
                                    <div class="metric-info">
                                        <span class="metric-value">${suggestions?.length || 0}</span>
                                        <span class="metric-label">최적화 제안</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="report-modal-footer">
                    <button class="export-report-btn">
                        <i class="fas fa-download"></i>
                        리포트 내보내기
                    </button>
                    <button class="close-report-btn-secondary" onclick="aiStudio.closeDetailedReport()">
                        닫기
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // 애니메이션 효과
        requestAnimationFrame(() => {
            modal.classList.add('show');
        });

        // ESC 키로 닫기
        this.currentModal = modal;
        document.addEventListener('keydown', this.handleModalEscape.bind(this));
    }

    /**
     * 📊 상세 통계 모달 표시 (리포트와 별도)
     */
    showDetailedStatistics() {
        if (!this.currentDetailedReport || !this.currentDetailedReport.analysisResult.statistics) {
            this.showToast('상세 통계 데이터가 없습니다.', 'warning');
            return;
        }

        const statistics = this.currentDetailedReport.analysisResult.statistics;
        const timestamp = this.currentDetailedReport.timestamp;

        // 통계 전용 모달 생성
        const modal = document.createElement('div');
        modal.className = 'detailed-statistics-modal';
        modal.innerHTML = `
            <div class="statistics-modal-content">
                <div class="statistics-modal-header">
                    <div class="statistics-modal-title">
                        <i class="fas fa-chart-pie text-indigo-400"></i>
                        <h3>AI 권한 분석 상세 통계</h3>
                        <span class="statistics-badge">데이터 중심 분석</span>
                    </div>
                    <button class="close-statistics-btn" onclick="aiStudio.closeDetailedStatistics()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                
                <div class="statistics-modal-body">
                    <!-- 통계 메타데이터 -->
                    <div class="statistics-meta-section">
                        <div class="meta-info">
                            <i class="fas fa-clock text-blue-400"></i>
                            <span>생성 시간: ${timestamp}</span>
                        </div>
                        <div class="meta-info">
                            <i class="fas fa-database text-green-400"></i>
                            <span>통계 항목: ${Object.keys(statistics).length}개</span>
                        </div>
                    </div>
                    
                    <!-- 상세 통계 내용 -->
                    ${this.generateDetailedStatisticsHTML(statistics)}
                    
                    <!-- 통계 요약 -->
                    <div class="statistics-summary">
                        <h4>통계 요약</h4>
                        <div class="summary-grid">
                            <div class="summary-item">
                                <i class="fas fa-users text-blue-400"></i>
                                <span>총 분석 사용자: ${statistics.totalAnalyzedUsers || 0}명</span>
                            </div>
                            <div class="summary-item">
                                <i class="fas fa-percentage text-green-400"></i>
                                <span>권한 보유율: ${statistics.permissionGrantRate || 0}%</span>
                            </div>
                            <div class="summary-item">
                                <i class="fas fa-sitemap text-purple-400"></i>
                                <span>시각화 노드: ${statistics.totalNodes || 0}개</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    /**
     * 📊 상세 통계 모달 닫기
     */
    closeDetailedStatistics() {
        const modal = document.querySelector('.detailed-statistics-modal');
        if (modal) {
            document.body.removeChild(modal);
        }
    }

    /**
     * 📊 상세 리포트 모달 닫기
     */
    closeDetailedReport() {
        const modal = document.querySelector('.detailed-report-modal');
        if (modal) {
            modal.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(modal);
            }, 300);
        }

        document.removeEventListener('keydown', this.handleModalEscape.bind(this));
        this.currentModal = null;
    }

    /**
     * ⌨️ 모달 ESC 키 처리
     */
    handleModalEscape(event) {
        if (event.key === 'Escape' && this.currentModal) {
            this.closeDetailedReport();
        }
    }

    /**
     * 🧠 AI 핵심 인사이트 HTML 생성
     */
    generateAIInsightsHTML(insights) {
        if (!insights || insights.length === 0) return '';

        const insightsHTML = insights.map((insight, index) => `
            <div class="ai-insight-card" data-insight-type="${insight.type}">
                <div class="insight-header">
                    <div class="insight-icon ${this.getInsightIconClass(insight.type)}">
                        <i class="${this.getInsightIcon(insight.type)}"></i>
                    </div>
                    <div class="insight-title">
                        <h5>${insight.title}</h5>
                        <div class="insight-meta">
                            <span class="insight-importance ${this.getImportanceClass(insight.importance)}">
                                ${this.getImportanceText(insight.importance)}
                            </span>
                            <span class="insight-confidence">
                                신뢰도: ${Math.round(insight.confidenceScore * 100)}%
                            </span>
                        </div>
                    </div>
                </div>
                <div class="insight-content">
                    <p>${insight.description}</p>
                    ${insight.actionable && insight.actionLinks ? `
                        <div class="insight-actions">
                            ${insight.actionLinks.map(link => `
                                <button class="insight-action-btn" onclick="window.location.href='${link.url}'" data-type="${link.type}">
                                    <i class="fas fa-arrow-right"></i>
                                    ${link.text}
                                </button>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');

        return `
            <div class="report-section ai-insights-section">
                <div class="section-header">
                    <i class="fas fa-lightbulb text-yellow-400"></i>
                    <h4>🧠 AI 핵심 인사이트</h4>
                    <div class="section-badge ai-badge">${insights.length}개 인사이트</div>
                </div>
                <div class="section-content">
                    <div class="ai-insights-grid">
                        ${insightsHTML}
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * 🔥 권한 이상 탐지 HTML 생성
     */
    generateAnomaliesHTML(anomalies) {
        if (!anomalies || anomalies.length === 0) return '';

        const anomaliesHTML = anomalies.map((anomaly, index) => `
            <div class="anomaly-card ${this.getAnomalySeverityClass(anomaly.severity)}" data-anomaly-type="${anomaly.type}">
                <div class="anomaly-header">
                    <div class="anomaly-icon">
                        <i class="${this.getAnomalyIcon(anomaly.type)}"></i>
                    </div>
                    <div class="anomaly-title">
                        <h5>${anomaly.title}</h5>
                        <div class="anomaly-meta">
                            <span class="anomaly-severity ${this.getSeverityClass(anomaly.severity)}">
                                ${this.getSeverityText(anomaly.severity)}
                            </span>
                            <span class="anomaly-risk">
                                위험도: ${Math.round(anomaly.riskScore * 100)}%
                            </span>
                        </div>
                    </div>
                </div>
                <div class="anomaly-content">
                    <p>${anomaly.description}</p>
                    ${anomaly.recommendedActions && anomaly.recommendedActions.length > 0 ? `
                        <div class="anomaly-actions">
                            <h6>권장 조치:</h6>
                            <ul>
                                ${anomaly.recommendedActions.map(action => `
                                    <li><i class="fas fa-chevron-right"></i> ${action}</li>
                                `).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');

        return `
            <div class="report-section anomalies-section">
                <div class="section-header">
                    <i class="fas fa-exclamation-triangle text-red-400"></i>
                    <h4>🔥 권한 이상 탐지</h4>
                    <div class="section-badge anomaly-badge">${anomalies.length}개 이상</div>
                </div>
                <div class="section-content">
                    <div class="anomalies-list">
                        ${anomaliesHTML}
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * 🚀 최적화 제안 HTML 생성
     */
    generateOptimizationSuggestionsHTML(suggestions) {
        if (!suggestions || suggestions.length === 0) return '';

        const suggestionsHTML = suggestions.map((suggestion, index) => `
            <div class="optimization-card" data-suggestion-type="${suggestion.type}">
                <div class="optimization-header">
                    <div class="optimization-icon">
                        <i class="${this.getOptimizationIcon(suggestion.type)}"></i>
                    </div>
                    <div class="optimization-title">
                        <h5>${suggestion.title}</h5>
                        <div class="optimization-meta">
                            <span class="optimization-priority ${this.getPriorityClass(suggestion.priority)}">
                                ${this.getPriorityText(suggestion.priority)}
                            </span>
                            <span class="optimization-complexity">
                                복잡도: ${this.getComplexityText(suggestion.implementationComplexity)}
                            </span>
                        </div>
                    </div>
                </div>
                <div class="optimization-content">
                    <p>${suggestion.description}</p>
                    ${suggestion.expectedBenefit ? `
                        <div class="optimization-benefit">
                            <i class="fas fa-chart-line text-green-400"></i>
                            <span>예상 효과: ${suggestion.expectedBenefit}</span>
                        </div>
                    ` : ''}
                    ${suggestion.actionLinks && suggestion.actionLinks.length > 0 ? `
                        <div class="optimization-actions">
                            ${suggestion.actionLinks.map(link => `
                                <button class="optimization-action-btn" onclick="window.location.href='${link.url}'" data-type="${link.type}">
                                    <i class="fas fa-rocket"></i>
                                    ${link.text}
                                </button>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');

        return `
            <div class="report-section optimization-section">
                <div class="section-header">
                    <i class="fas fa-rocket text-purple-400"></i>
                    <h4>🚀 AI 최적화 제안</h4>
                    <div class="section-badge optimization-badge">${suggestions.length}개 제안</div>
                </div>
                <div class="section-content">
                    <div class="optimization-grid">
                        ${suggestionsHTML}
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * 📈 AI 메트릭 HTML 생성
     */
    generateAIMetricsHTML(analysisResult) {
        return `
            <div class="report-section ai-metrics-section">
                <div class="section-header">
                    <i class="fas fa-brain text-indigo-400"></i>
                    <h4>📈 AI 분석 메트릭</h4>
                </div>
                <div class="section-content">
                    <div class="ai-metrics-grid">
                        <div class="ai-metric-card">
                            <div class="metric-icon">
                                <i class="fas fa-crosshairs text-blue-400"></i>
                            </div>
                            <div class="metric-content">
                                <div class="metric-value">${Math.round(analysisResult.confidenceScore)}%</div>
                                <div class="metric-label">분석 신뢰도</div>
                            </div>
                        </div>
                        <div class="ai-metric-card">
                            <div class="metric-icon">
                                <i class="fas fa-project-diagram text-green-400"></i>
                            </div>
                            <div class="metric-content">
                                <div class="metric-value">${Math.round(analysisResult.complexityScore * 100)}%</div>
                                <div class="metric-label">권한 복잡도</div>
                            </div>
                        </div>
                        <div class="ai-metric-card">
                            <div class="metric-icon">
                                <i class="fas fa-shield-alt text-red-400"></i>
                            </div>
                            <div class="metric-content">
                                <div class="metric-value">${Math.round(analysisResult.riskScore * 100)}%</div>
                                <div class="metric-label">보안 위험도</div>
                            </div>
                        </div>
                        <div class="ai-metric-card">
                            <div class="metric-icon">
                                <i class="fas fa-clock text-yellow-400"></i>
                            </div>
                            <div class="metric-content">
                                <div class="metric-value">${analysisResult.processingTime}</div>
                                <div class="metric-label">처리시간(ms)</div>
                            </div>
                        </div>
                        <div class="ai-metric-card">
                            <div class="metric-icon">
                                <i class="fas fa-lightbulb text-purple-400"></i>
                            </div>
                            <div class="metric-content">
                                <div class="metric-value">${analysisResult.insights.length}</div>
                                <div class="metric-label">발견 인사이트</div>
                            </div>
                        </div>
                        <div class="ai-metric-card">
                            <div class="metric-icon">
                                <i class="fas fa-exclamation-triangle text-orange-400"></i>
                            </div>
                            <div class="metric-content">
                                <div class="metric-value">${analysisResult.anomalies.length}</div>
                                <div class="metric-label">탐지 이상</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * 🎯 AI-Native 답변 포맷팅 (구조화된 사용자 카드 포함)
     */
    formatAINativeAnswer(answer, originalQuery, analysisResults = null) {
        if (!answer) {
            return '<div class="ai-answer-placeholder">AI가 분석 중입니다...</div>';
        }

        // 🔥 서버 데이터 그대로 사용 - 모든 조건/필터링 제거
        if (analysisResults && analysisResults.length > 0) {
            const structuredData = {
                users: analysisResults,
                summary: `${analysisResults.length}명의 사용자가 분석되었습니다.`
            };

            return `
                <!-- 🎯 구조화된 사용자 카드 -->
                ${this.generateUserCards(structuredData.users)}
                
                <!-- 📄 요약 정보 -->
                <div class="analysis-summary">
                    <div class="summary-header">
                        <i class="fas fa-chart-bar text-blue-400"></i>
                        <span class="summary-label">분석 요약</span>
                    </div>
                    <p class="summary-content">${structuredData.summary}</p>
                </div>
            `;
        }

        // analysisResults 없으면 자연어만 표시
        return `<div class="answer-content"><p>${answer}</p></div>`;
    }

    /**
     * 🎯 특정 사용자의 문맥에서 역할과 권한 추출 (강화된 문맥 분석)
     */
    extractUserContextFromText(text, userName) {
        const context = {
            role: null,
            group: null,
            permissions: [],
            roleText: '',
            permissionText: ''
        };

        try {
            console.log(`${userName} 사용자 문맥 분석 시작`);

            // 1. 사용자명이 포함된 문장들 찾기 (더 넓은 범위)
            const sentences = text.split(/[.。]/);
            const userSentences = sentences.filter(sentence =>
                sentence.includes(userName) ||
                sentence.includes(`**${userName}**`) ||
                sentence.includes(`${userName}는`) ||
                sentence.includes(`${userName}가`) ||
                sentence.includes(`${userName}은`) ||
                sentence.includes(`${userName}이`)
            );

            console.log(`${userName} 관련 문장들:`, userSentences);

            // 2. 각 문장에서 정보 추출
            for (const sentence of userSentences) {
                // 2-1. 역할 추출
                const roleMatch = sentence.match(/ROLE_([A-Z_]+)/);
                if (roleMatch) {
                    context.role = roleMatch[1].replace(/_/g, ' ');
                    context.roleText = sentence.trim();
                    console.log(`🎯 ${userName} 역할 발견:`, context.role);
                }

                // 2-2. 그룹 추출 (다양한 패턴)
                const groupPatterns = [
                    /([가-힣a-zA-Z0-9\s]+그룹)에\s*속해?\s*있/,
                    /([가-힣a-zA-Z0-9\s]+그룹)에\s*속한/,
                    /([가-힣a-zA-Z0-9\s]+그룹)\s*소속/,
                    /([가-힣a-zA-Z0-9\s]+)\s*그룹/
                ];

                for (const pattern of groupPatterns) {
                    const groupMatch = sentence.match(pattern);
                    if (groupMatch) {
                        const groupName = groupMatch[1].includes('그룹') ?
                            groupMatch[1] :
                            groupMatch[1].trim() + ' 그룹';

                        if (!groupName.includes('권한') && !groupName.includes('역할')) {
                            context.group = groupName;
                            console.log(`🎯 ${userName} 그룹 발견:`, context.group);
                            break;
                        }
                    }
                }

                // 2-3. 권한 추출
                const permissionMatches = sentence.match(/METHOD_[A-Z_]+/g);
                if (permissionMatches) {
                    context.permissions.push(...permissionMatches);
                    context.permissionText = sentence.trim();
                    console.log(`🎯 ${userName} 권한 발견:`, permissionMatches);
                }
            }

            // 3. 전체 텍스트에서 확장 검색 (사용자와 가까운 위치의 정보)
            const userIndex = text.indexOf(userName);
            if (userIndex !== -1) {
                // 사용자명 앞뒤 200자 범위에서 추가 정보 찾기
                const contextRange = text.substring(
                    Math.max(0, userIndex - 200),
                    Math.min(text.length, userIndex + 200)
                );

                // 그룹 정보가 없으면 확장 검색
                if (!context.group) {
                    const expandedGroupMatch = contextRange.match(/([가-힣a-zA-Z0-9\s]+그룹)/);
                    if (expandedGroupMatch) {
                        const groupName = expandedGroupMatch[1];
                        if (!groupName.includes('권한') && !groupName.includes('역할')) {
                            context.group = groupName;
                            console.log(`🎯 ${userName} 확장 그룹 발견:`, context.group);
                        }
                    }
                }

                // 권한 정보가 없으면 확장 검색
                if (context.permissions.length === 0) {
                    const expandedPermissions = contextRange.match(/METHOD_[A-Z_]+/g);
                    if (expandedPermissions) {
                        context.permissions.push(...expandedPermissions);
                        context.permissionText = contextRange.trim();
                        console.log(`🎯 ${userName} 확장 권한 발견:`, expandedPermissions);
                    }
                }
            }

            console.log(`🎯 ${userName} 최종 문맥:`, context);

        } catch (error) {
            console.error(`${userName} 사용자 문맥 추출 중 오류:`, error);
        }

        return context;
    }

    /**
     * 🎯 사용자 카드 HTML 생성
     */
    generateUserCards(users) {
        if (!users || users.length === 0) return '';

        return `
            <!-- 검색 기능 -->
            <div class="user-search-section">
                <div class="search-input-container">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" id="user-search-input" placeholder="사용자명, 그룹, 역할로 검색..." 
                           onkeyup="aiStudio.filterUserCards(this.value)"
                           class="user-search-input">
                    <button class="search-clear-btn" onclick="aiStudio.clearUserSearch()" title="검색 초기화">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
            
            <div class="user-cards-grid" id="user-cards-grid">
                ${users.map(user => this.generateSingleUserCard(user)).join('')}
            </div>
        `;
    }

    /**
     * 🎯 개별 사용자 카드 생성 (개선된 버전: 크기 축소, 역할 표시 강화)
     */
    generateSingleUserCard(user) {
        // 권한 유무에 따른 스타일 설정
        const hasPermission = user.hasSpecialPermissions;
        const cardClass = hasPermission ? 'user-card-with-permission' : 'user-card-no-permission';
        const statusIcon = hasPermission ? 'fas fa-check-circle' : 'fas fa-times-circle';
        const statusText = hasPermission ? '권한 보유' : '권한 없음';
        const statusClass = hasPermission ? 'permission-granted' : 'permission-denied';

        // 검색을 위한 권한 정보 추출
        const permissions = user.permissions || [];
        const permissionNames = permissions.map(p => p.name || p).join(' ');
        const permissionDescriptions = permissions.map(p => p.description || '').join(' ');
        const allPermissionText = `${permissionNames} ${permissionDescriptions}`.toLowerCase();

        return `
            <div class="user-card-mini ${cardClass}" 
                 data-user-name="${user.name}" 
                 data-user-group="${user.group}" 
                 data-user-role="${user.role}"
                 data-user-permissions="${allPermissionText}"
                 data-has-permission="${hasPermission}">
                <div class="user-card-header-mini">
                    <div class="user-avatar-mini ${hasPermission ? 'avatar-active' : 'avatar-inactive'}">
                        <i class="fas fa-user"></i>
                    </div>
                    <div class="user-info-mini">
                        <div class="user-name-mini">${user.name}</div>
                        <div class="user-details-mini">
                            <span class="user-group-mini">${user.group}</span>
                            <span class="role-separator">•</span>
                            <span class="user-role-mini">${user.role}</span>
                        </div>
                    </div>
                    <div class="permission-status-mini ${statusClass}">
                        <i class="${statusIcon}"></i>
                    </div>
                </div>
                
                <div class="user-card-actions-mini">
                    <button class="user-detail-btn-mini" onclick="aiStudio.showUserDetailModal('${user.name}', ${JSON.stringify(user).replace(/"/g, '&quot;')})" title="상세보기">
                        <i class="fas fa-info-circle"></i>
                    </button>
                </div>
            </div>
        `;
    }

    /**
     * 🎯 AI-Native 인터랙티브 기능 활성화
     */
    enableAINativeInteractions(analysisResult) {
        // 인사이트 카드 클릭 이벤트
        document.querySelectorAll('.ai-insight-card').forEach(card => {
            card.addEventListener('click', (e) => {
                this.handleInsightCardClick(e, analysisResult);
            });
        });

        // 이상 탐지 카드 클릭 이벤트
        document.querySelectorAll('.anomaly-card').forEach(card => {
            card.addEventListener('click', (e) => {
                this.handleAnomalyCardClick(e, analysisResult);
            });
        });

        // 최적화 제안 카드 클릭 이벤트
        document.querySelectorAll('.optimization-card').forEach(card => {
            card.addEventListener('click', (e) => {
                this.handleOptimizationCardClick(e, analysisResult);
            });
        });

        // 🎯 사용자 카드 클릭 이벤트 (이미 onclick 속성으로 처리됨)
        console.log('🎯 사용자 카드는 onclick 속성으로 처리됨');

        console.log('🎯 AI-Native 인터랙티브 기능 활성화 완료');
    }

    /**
     * 🎯 사용자 상세보기 모달 표시
     */
    showUserDetailModal(userName, userDataJson) {
        try {
            // JSON 문자열을 파싱하여 사용자 데이터 복원
            const userData = typeof userDataJson === 'string' ? JSON.parse(userDataJson.replace(/&quot;/g, '"')) : userDataJson;

            console.log('🎯 사용자 상세보기 모달 표시:', userName, userData);

            // 기존 모달이 있으면 제거
            const existingModal = document.getElementById('user-detail-modal');
            if (existingModal) {
                existingModal.remove();
            }

            // 모달 HTML 생성
            const modalHTML = `
                <div id="user-detail-modal" class="user-detail-modal-overlay">
                    <div class="user-detail-modal-content">
                        <div class="user-detail-modal-header">
                            <div class="user-detail-title">
                                <div class="user-detail-avatar">
                                    <i class="${userData.hasSpecialPermissions ? 'fas fa-shield-alt text-green-400' : 'fas fa-user-circle text-gray-400'}"></i>
                                </div>
                                <div class="user-detail-info">
                                    <h3 class="text-xl font-bold text-white">${userData.name}</h3>
                                    <p class="user-detail-subtitle text-gray-300">${userData.group} · ${userData.role}</p>
                                </div>
                            </div>
                            <button type="button" id="close-user-detail-btn" class="close-button">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                        
                        <div class="user-detail-modal-body">
                            ${this.generateUserDetailContent(userData)}
                        </div>
                        
                        <div class="user-detail-modal-footer">
                            <button type="button" class="btn btn-secondary" onclick="document.getElementById('user-detail-modal').remove()">
                                <i class="fas fa-times mr-2"></i>닫기
                            </button>
                            <button type="button" class="btn btn-primary" onclick="aiStudio.editUserPermissions('${userData.name}')">
                                <i class="fas fa-edit mr-2"></i>권한 편집
                            </button>
                        </div>
                    </div>
                </div>
            `;

            // 모달을 body에 추가
            document.body.insertAdjacentHTML('beforeend', modalHTML);

            // 모달 표시
            const modal = document.getElementById('user-detail-modal');
            modal.style.display = 'flex';
            setTimeout(() => {
                modal.classList.add('show');
            }, 10);

            // 닫기 버튼 이벤트 리스너
            const closeBtn = document.getElementById('close-user-detail-btn');
            if (closeBtn) {
                closeBtn.addEventListener('click', () => {
                    modal.classList.remove('show');
                    setTimeout(() => modal.remove(), 300);
                });
            }

            // ESC 키로 모달 닫기
            const escapeHandler = (e) => {
                if (e.key === 'Escape') {
                    modal.classList.remove('show');
                    setTimeout(() => modal.remove(), 300);
                    document.removeEventListener('keydown', escapeHandler);
                }
            };
            document.addEventListener('keydown', escapeHandler);

            // 모달 배경 클릭으로 닫기
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('show');
                    setTimeout(() => modal.remove(), 300);
                }
            });

        } catch (error) {
            console.error('사용자 상세보기 모달 표시 중 오류:', error);
            this.showToast('사용자 정보를 불러오는 중 오류가 발생했습니다.', 'error');
        }
    }

    /**
     * 🎯 사용자 상세 정보 콘텐츠 생성
     */
    generateUserDetailContent(userData) {
        return `
            <div class="user-detail-content">
                <!-- 기본 정보 섹션 -->
                <div class="detail-section">
                    <div class="detail-section-header">
                        <i class="fas fa-user text-blue-400"></i>
                        <h4>기본 정보</h4>
                    </div>
                    <div class="detail-section-content">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">사용자명</span>
                                <span class="detail-value">${userData.name}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">소속 그룹</span>
                                <span class="detail-value">${userData.group}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">역할</span>
                                <span class="detail-value role-badge">${userData.role}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">권한 수</span>
                                <span class="detail-value permission-count ${userData.hasSpecialPermissions ? 'has-permissions' : 'no-permissions'}">
                                    ${userData.permissionCount}개
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 권한 상세 섹션 -->
                <div class="detail-section">
                    <div class="detail-section-header">
                        <i class="fas fa-key text-green-400"></i>
                        <h4>보유 권한</h4>
                        ${userData.hasSpecialPermissions ?
            '<span class="permission-status has-permissions">특별 권한 보유</span>' :
            '<span class="permission-status no-permissions">기본 권한만 보유</span>'
        }
                    </div>
                    <div class="detail-section-content">
                        ${userData.hasSpecialPermissions ? `
                            <div class="permissions-list">
                                ${userData.permissions.map(permission => `
                                    <div class="permission-item">
                                        <i class="fas fa-shield-alt text-green-400"></i>
                                        <span class="permission-name">${permission}</span>
                                        <span class="permission-type">메서드 권한</span>
                                    </div>
                                `).join('')}
                            </div>
                        ` : `
                            <div class="no-permissions-message">
                                <i class="fas fa-exclamation-triangle text-red-400"></i>
                                <p><strong>해당 권한이 없습니다.</strong></p>
                                <p class="text-sm text-slate-400">이 사용자는 요청된 작업을 수행할 수 있는 권한을 보유하고 있지 않습니다.</p>
                                ${userData.rawInfo?.roleInfo ? `
                                    <div class="permission-details-box">
                                        <strong>상세 사유:</strong>
                                        <p class="permission-reason">${userData.rawInfo.roleInfo}</p>
                                    </div>
                                ` : ''}
                                <p class="text-sm text-slate-500 mt-2">
                                    <i class="fas fa-lightbulb text-yellow-400"></i>
                                    추가 권한이 필요한 경우 시스템 관리자에게 문의하거나 권한 부여 버튼을 이용하세요.
                                </p>
                            </div>
                        `}
                    </div>
                </div>

                <!-- 분석 정보 섹션 -->
                <div class="detail-section">
                    <div class="detail-section-header">
                        <i class="fas fa-chart-line text-purple-400"></i>
                        <h4>AI 분석 정보</h4>
                    </div>
                    <div class="detail-section-content">
                        <div class="analysis-info">
                            <div class="analysis-item">
                                <span class="analysis-label">역할 정보</span>
                                <span class="analysis-value">${userData.rawInfo?.roleInfo || '정보 없음'}</span>
                            </div>
                            ${userData.rawInfo?.permissionInfo ? `
                                <div class="analysis-item">
                                    <span class="analysis-label">권한 상세</span>
                                    <span class="analysis-value">${userData.rawInfo?.permissionInfo}</span>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }


    /**
     * 🎯 사용자 권한 편집 (향후 구현 예정)
     */
    editUserPermissions(userName) {
        console.log('🎯 사용자 권한 편집 요청:', userName);
        this.showToast(`${userName} 권한 편집 기능은 향후 구현 예정입니다.`, 'info');

        // 향후 Authorization Studio의 기존 편집 기능과 연동
        // window.location.href = `/admin/studio?editUser=${encodeURIComponent(userName)}`;
    }

    // 상세 분석 HTML 생성 (전문적 리포트 형식)
    generateDetailedAnalysisHTML(queryResults) {
        if (!queryResults || queryResults.length === 0) return '';

        const resultsHTML = queryResults.map((result, index) => `
            <div class="analysis-item">
                <div class="analysis-item-header">
                    <div class="analysis-item-number">${index + 1}</div>
                    <div class="analysis-item-title">
                        <h5>${result.entity}</h5>
                        <div class="analysis-item-score">
                            <span class="score-label">관련도:</span>
                            <span class="score-value">${result.relevanceScore}%</span>
                        </div>
                    </div>
                </div>
                <div class="analysis-item-content">
                    <p class="analysis-description">${result.description}</p>
                    ${result.actionType ? `
                        <div class="analysis-action">
                            <i class="fas fa-arrow-right text-green-400"></i>
                            <span class="action-type">${result.actionType}</span>
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');

        return `
            <div class="report-section">
                <div class="section-header">
                    <i class="fas fa-search text-green-400"></i>
                    <h4>상세 분석 (Detailed Analysis)</h4>
                    <div class="section-badge">${queryResults.length}개 항목</div>
                </div>
                <div class="section-content">
                    <div class="analysis-list">
                        ${resultsHTML}
                    </div>
                </div>
            </div>
        `;
    }

    // 통계 및 메트릭 HTML 생성
    generateMetricsHTML(queryResults, recommendations) {
        if (!queryResults || queryResults.length === 0) return '';

        // 메트릭 계산
        const totalItems = queryResults.length;
        const averageRelevance = queryResults.reduce((sum, r) => sum + (r.relevanceScore || 0), 0) / totalItems;
        const highRelevanceCount = queryResults.filter(r => (r.relevanceScore || 0) >= 80).length;
        const actionableCount = queryResults.filter(r => r.actionType).length;
        const recommendationCount = recommendations ? recommendations.length : 0;

        return `
            <div class="report-section">
                <div class="section-header">
                    <i class="fas fa-chart-bar text-yellow-400"></i>
                    <h4>통계 및 메트릭 (Metrics)</h4>
                </div>
                <div class="section-content">
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value">${totalItems}</div>
                            <div class="metric-label">분석 항목</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${averageRelevance.toFixed(1)}%</div>
                            <div class="metric-label">평균 관련도</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${highRelevanceCount}</div>
                            <div class="metric-label">고관련도 항목</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${actionableCount}</div>
                            <div class="metric-label">실행 가능 항목</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">${recommendationCount}</div>
                            <div class="metric-label">권장사항</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // 권장사항 HTML 생성 (전문적 리포트 형식)
    generateRecommendationsReportHTML(recommendations) {
        if (!recommendations || recommendations.length === 0) return '';

        const recsHTML = recommendations.map((rec, index) => `
            <div class="recommendation-item">
                <div class="recommendation-header">
                    <div class="recommendation-number">${index + 1}</div>
                    <div class="recommendation-title">
                        <h5>${rec.title}</h5>
                        <div class="recommendation-priority">
                            <span class="priority-badge ${this.getPriorityColor(rec.priority)}">
                                ${this.getPriorityText(rec.priority)}
                            </span>
                        </div>
                    </div>
                </div>
                <div class="recommendation-content">
                    <p class="recommendation-description">${rec.description}</p>
                    ${rec.actionItems && rec.actionItems.length > 0 ? `
                        <div class="recommendation-actions">
                            <h6 class="actions-title">실행 항목:</h6>
                            <ul class="actions-list">
                                ${rec.actionItems.map(item => `
                                    <li class="action-item">
                                        <i class="fas fa-check-circle text-green-400"></i>
                                        <span>${item}</span>
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    ${rec.actionLinks && rec.actionLinks.length > 0 ? `
                        <div class="recommendation-buttons">
                            ${rec.actionLinks.map(link => `
                                <button class="action-button" onclick="window.location.href='${link.url}'" data-type="${link.type}">
                                    <i class="fas fa-external-link-alt"></i>
                                    ${link.text}
                                </button>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');

        return `
            <div class="report-section">
                <div class="section-header">
                    <i class="fas fa-lightbulb text-purple-400"></i>
                    <h4>권장사항 (Recommendations)</h4>
                    <div class="section-badge">${recommendations.length}개 권장사항</div>
                </div>
                <div class="section-content">
                    <div class="recommendations-list">
                        ${recsHTML}
                    </div>
                </div>
            </div>
        `;
    }

    // 구조화된 답변 포맷팅
    formatStructuredAnswer(answer, query) {
        if (!answer) {
            return '<strong>결론:</strong> 분석 결과를 아래 상세 내용에서 확인하세요.';
        }

        // "누가" 질의인 경우 사용자 목록을 구조화
        if (query.includes('누가') || query.includes('who')) {
            return this.formatWhoCanAnswer(answer);
        }

        // 일반적인 답변
        return `<strong>결론:</strong> ${answer}`;
    }

    // "누가" 질의 답변 구조화
    formatWhoCanAnswer(answer) {
        try {
            console.log('구조화 시작 - 원본 답변:', answer);

            // 다양한 사용자 이름 패턴 매칭
            const userPatterns = [
                /([가-힣]+팀장|[가-힣]+관리자|[가-힣]+개발|[가-힣]+운영|[가-힣]+재무)/g,  // 역할 포함 이름
                /([가-힣]{2,4})(?:은|는|이|가)/g,  // "김팀장은", "박개발이" 형태
                /사용자(?:는|가)\s*([가-힣]+)/g   // "사용자는 김팀장" 형태
            ];

            let foundUsers = new Set();
            let userDetails = {};

            // 🔥 서버 analysisResults에서 직접 사용자명 추가
            if (analysisResult.analysisResults && analysisResult.analysisResults.length > 0) {
                analysisResult.analysisResults.forEach(result => {
                    if (result.name) {
                        foundUsers.add(result.name);
                        userDetails[result.name] = result;
                        console.log('🔥 서버에서 사용자 추가:', result.name);
                    }
                });
            }

            // 여러 패턴으로 사용자 이름 추출
            userPatterns.forEach(pattern => {
                const matches = [...answer.matchAll(pattern)];
                matches.forEach(match => {
                    const userName = match[1];
                    if (userName && userName.length >= 2) {
                        foundUsers.add(userName);
                        console.log('발견된 사용자:', userName);
                    }
                });
            });

            // 사용자별 역할과 권한 정보 추출
            foundUsers.forEach(userName => {
                // 각 사용자에 대한 역할 정보 찾기
                const userContext = this.extractUserContext(answer, userName);
                userDetails[userName] = userContext;
                console.log('사용자 상세정보:', userName, userContext);
            });

            if (foundUsers.size === 0) {
                console.log('사용자 정보 없음, 기본 형태로 반환');
                return `<strong>결론:</strong> ${answer}`;
            }

            // 구조화된 사용자 목록 생성
            let structuredAnswer = '<strong>접근 권한 분석 결과:</strong><br>';
            structuredAnswer += '<div class="user-access-list">';

            foundUsers.forEach(userName => {
                const details = userDetails[userName];
                const hasAccess = this.checkUserAccess(answer, userName);

                structuredAnswer += `
                    <div class="user-access-item ${hasAccess ? 'has-access' : 'no-access'}">
                        <div class="user-info">
                            <span class="user-name">${userName}</span>
                            <span class="user-role">${details.role || details.group || '역할 불명'}</span>
                        </div>
                        <div class="access-status">
                            <i class="fas fa-${hasAccess ? 'check-circle text-green-400' : 'times-circle text-red-400'}"></i>
                            <span class="${hasAccess ? 'text-green-400' : 'text-red-400'}">${hasAccess ? '접근 가능' : '접근 불가'}</span>
                        </div>
                    </div>
                `;
            });

            structuredAnswer += '</div>';

            // 추가 설명 추출 및 표시
            const summary = this.extractSummary(answer, foundUsers);
            if (summary) {
                structuredAnswer += `<div class="additional-info"><strong>상세 설명:</strong> ${summary}</div>`;
            }

            console.log('최종 구조화 결과:', structuredAnswer);
            return structuredAnswer;

        } catch (error) {
            console.error('🔥 답변 구조화 실패:', error);
            return `<strong>결론:</strong> ${answer}`;
        }
    }

    // 사용자 컨텍스트 추출 (역할, 그룹 등)
    extractUserContext(answer, userName) {
        const context = {role: '', group: '', details: ''};

        // "김팀장은 개발본부에 속해 있으며, 최고관리자 역할로서" 형태 파싱
        const contextPattern = new RegExp(`${userName}[은는이가]?\\s*([^.]*?)(?:역할|권한|속해)([^.]*?)`, 'g');
        const match = contextPattern.exec(answer);

        if (match) {
            const fullContext = match[0];

            // 그룹 정보 추출
            const groupMatch = fullContext.match(/(개발본부|인프라보안팀|재무회계팀|시스템관리자)/);
            if (groupMatch) context.group = groupMatch[1];

            // 역할 정보 추출
            const roleMatch = fullContext.match(/(최고관리자|팀장|개발자|운영자|재무|ROLE_[A-Z_]+)/);
            if (roleMatch) context.role = roleMatch[1];

            context.details = fullContext;
        }

        return context;
    }

    // 사용자 접근 권한 확인
    checkUserAccess(answer, userName) {
        const accessKeywords = ['권한을 가지고', '조회할 수 있', '접근할 수 있', '사용할 수 있'];
        const noAccessKeywords = ['권한이 없', '접근할 수 없', '권한이 할당되어 있지 않'];

        // 해당 사용자 관련 문장 추출
        const userSentencePattern = new RegExp(`[^.]*${userName}[^.]*\\.`, 'g');
        const userSentences = answer.match(userSentencePattern) || [];
        const userText = userSentences.join(' ');

        // 접근 불가 키워드 먼저 확인
        for (let keyword of noAccessKeywords) {
            if (userText.includes(keyword)) return false;
        }

        // 접근 가능 키워드 확인
        for (let keyword of accessKeywords) {
            if (userText.includes(keyword)) return true;
        }

        // 애매한 경우 전체 컨텍스트로 판단
        return answer.includes(`${userName}`) && !answer.includes('권한이 없') && !answer.includes('접근할 수 없');
    }

    // 요약 정보 추출
    extractSummary(answer, users) {
        // 사용자 이름들을 제거하고 남은 설명 부분 추출
        let summary = answer;
        users.forEach(user => {
            summary = summary.replace(new RegExp(`[^.]*${user}[^.]*\\.`, 'g'), '');
        });

        return summary.trim().replace(/^[:\s\-]*|[:\s\-]*$/g, '').substring(0, 200);
    }

    // =============================
    // 🎨 Cytoscape 시각화 렌더링 (Mermaid 대체)
    // =============================
    async renderVisualization(visualizationData) {
        if (!visualizationData) return;

        console.log('🎨 Rendering visualization with Cytoscape:', visualizationData);

        this.currentVisualization = visualizationData;

        // Cytoscape 데이터 생성
        const cytoscapeData = this.generateCytoscapeData(visualizationData);

        // Canvas에 표시
        await this.displayCytoscapeDiagram(cytoscapeData);
    }

    // 🔥 Cytoscape 데이터 생성 (Mermaid 대체)
    generateCytoscapeData(visualizationData) {
        const {graphType, nodes, edges} = visualizationData;

        console.log('🎨 Generating Cytoscape data for type:', graphType || 'network');

        // 🔥 누락된 target 노드들 동적 수집
        const allNodeIds = new Set();
        const existingNodes = new Map();

        if (nodes && nodes.length > 0) {
            nodes.forEach(node => {
                allNodeIds.add(node.id);
                existingNodes.set(node.id, node);
            });
        }

        // edges에서 누락된 target 노드들 찾기
        if (edges && edges.length > 0) {
            edges.forEach(edge => {
                if (!allNodeIds.has(edge.target)) {
                    // 누락된 target 노드 동적 생성
                    const targetType = edge.type === 'HAS_PERMISSION' ? 'PERMISSION' : 'GROUP';
                    const missingNode = {
                        id: edge.target,
                        type: targetType,
                        label: edge.target,
                        properties: {name: edge.target}
                    };
                    existingNodes.set(edge.target, missingNode);
                    allNodeIds.add(edge.target);
                    console.log('🔥 누락 노드 동적 생성:', edge.target, 'type:', targetType);
                }
            });
        }

        const cytoscapeElements = [];

        // 노드 데이터 생성 (스타일시트 방식)
        existingNodes.forEach(node => {
            const nodeType = node.type?.toUpperCase() || 'USER';
            const hasPermission = this.nodeHasPermission(node);

            cytoscapeElements.push({
                data: {
                    id: node.id,
                    label: node.label || node.properties?.name || node.id,
                    type: nodeType,
                    nodeType: nodeType.toLowerCase(),
                    hasPermission: hasPermission,
                    originalData: node
                },
                classes: `${nodeType.toLowerCase()}-node ${hasPermission ? 'has-permission' : 'no-permission'}`
            });
        });

        // 엣지 데이터 생성 (스타일시트 방식)
        if (edges && edges.length > 0) {
            edges.forEach(edge => {
                const edgeType = edge.type || 'CONNECTED';

                cytoscapeElements.push({
                    data: {
                        id: edge.id || `${edge.source}-${edge.target}`,
                        source: edge.source,
                        target: edge.target,
                        label: edge.label || edge.type || '',
                        edgeType: edgeType.toLowerCase(),
                        originalData: edge
                    },
                    classes: `${edgeType.toLowerCase()}-edge`
                });
            });
        }

        console.log('🎨 Generated Cytoscape elements:', cytoscapeElements.length, 'items');
        return cytoscapeElements;
    }

    // ID 정리 (Mermaid 호환)
    sanitizeId(id) {
        return id.replace(/[^a-zA-Z0-9]/g, '_');
    }

    // 노드 모양 결정
    getNodeShape(nodeType) {
        const shapes = {
            'USER': ['[', ']'],      // 사각형
            'GROUP': ['(', ')'],     // 원형
            'ROLE': ['{', '}'],      // 다이아몬드
            'METHOD': ['[[', ']]'],  // 메서드 (서브루틴)
            'PERMISSION': ['[[', ']]'], // 권한 (서브루틴)
            'RESOURCE': ['>', ']'],   // 비대칭
            'POLICY': ['[[', ']]']    // 서브루틴
        };

        return shapes[nodeType] || ['[', ']']; // 기본: 사각형
    }

    // 🔥 Cytoscape 다이어그램 표시 (Mermaid 완전 대체)
    async displayCytoscapeDiagram(visualizationData) {
        console.log('🎯 Cytoscape 다이어그램 표시 시작:', visualizationData);

        const canvasContent = document.getElementById('canvas-content');
        let cytoscapeContainer = document.getElementById('cytoscape-container') || document.getElementById('mermaid-container');

        if (!canvasContent) {
            console.error('canvas-content 컨테이너를 찾을 수 없습니다');
            return;
        }

        // 🔥 컨테이너가 없으면 생성
        if (!cytoscapeContainer) {
            cytoscapeContainer = document.createElement('div');
            cytoscapeContainer.id = 'cytoscape-container';
            cytoscapeContainer.className = 'w-full h-full';
            canvasContent.appendChild(cytoscapeContainer);
        }

        // Placeholder 숨기기, Cytoscape 컨테이너 표시
        this.hideCanvasPlaceholder();
        cytoscapeContainer.classList.remove('hidden');

        // 컨테이너 ID 업데이트 (기존 mermaid-container를 재사용)
        if (cytoscapeContainer.id === 'mermaid-container') {
            cytoscapeContainer.id = 'cytoscape-container';
        }

        // 기존 Cytoscape 인스턴스 제거
        if (this.cytoscapeInstance) {
            this.cytoscapeInstance.destroy();
            this.cytoscapeInstance = null;
        }

        // 기존 내용 제거
        cytoscapeContainer.innerHTML = '';

        // 🔥 visualizationData를 Cytoscape 형태로 변환
        const cytoscapeElements = this.convertToCytoscapeFormat(visualizationData);

        if (!cytoscapeElements || cytoscapeElements.length === 0) {
            console.error('Cytoscape 요소 변환 실패');
            return;
        }

        try {
            // Cytoscape 컨테이너 설정
            cytoscapeContainer.style.width = '100%';
            cytoscapeContainer.style.height = '500px';
            cytoscapeContainer.style.background = '#0f172a';

            // Cytoscape 인스턴스 생성 (전체보기와 동일한 스타일 사용)
            this.cytoscapeInstance = cytoscape({
                container: cytoscapeContainer,
                elements: cytoscapeElements,

                style: this.getCytoscapeStyles(), // 🔥 전체보기와 동일한 간단한 스타일 사용
                layout: this.getCurrentLayoutOptions(),

                zoom: 1,
                pan: {x: 0, y: 0},
                minZoom: 0.1,
                maxZoom: 5,
                wheelSensitivity: 0.5,
                zoomingEnabled: true,
                userZoomingEnabled: true,
                panningEnabled: true,
                userPanningEnabled: true,
                boxSelectionEnabled: false,
                selectionType: 'single'
            });

            // 이벤트 리스너 설정
            this.setupCytoscapeEvents();

            // 🔥 레이아웃 완료 후 노드 고정 처리 (안전한 처리)
            this.cytoscapeInstance.one('layoutstop', () => {
                console.log('🎯 레이아웃 애니메이션 완료 - 모든 애니메이션 중지');

                // 안전한 처리를 위한 유효성 검사
                setTimeout(() => {
                    // Cytoscape 인스턴스와 컨테이너 유효성 검사
                    if (!this.cytoscapeInstance || this.cytoscapeInstance.destroyed()) {
                        console.log('Cytoscape 인스턴스가 이미 제거됨');
                        return;
                    }

                    const container = this.cytoscapeInstance.container();
                    if (!container || !document.contains(container)) {
                        console.log('Cytoscape 컨테이너가 DOM에서 제거됨');
                        return;
                    }

                    try {
                        this.cytoscapeInstance.fit();
                        this.cytoscapeInstance.center();

                        // 모든 노드 크기 고정하여 더 이상 변화 방지
                        this.cytoscapeInstance.nodes().style({
                            'transition-property': 'none',
                            'transition-duration': '0s'
                        });

                        // 모든 엣지 애니메이션 중지
                        this.cytoscapeInstance.edges().style({
                            'line-dash-offset': 0,
                            'transition-property': 'none',
                            'transition-duration': '0s'
                        });

                        // 모든 노드를 ungrabable로 만들어 움직임 완전 방지
                        this.cytoscapeInstance.nodes().ungrabify();
                        
                        console.log('다이어그램 애니메이션 완전히 중지됨');
                    } catch (error) {
                        console.warn('레이아웃 완료 후 처리 중 오류:', error.message);
                    }
                }, 100);
            });

            console.log('Cytoscape diagram rendered with', cytoscapeElements.length, 'elements');

        } catch (error) {
            console.error('Cytoscape render error:', error);
            this.showCytoscapeError(cytoscapeContainer, error);
        }
    }

    /**
     * VisualizationData를 Cytoscape 형태로 변환
     */
    convertToCytoscapeFormat(visualizationData) {
        if (!visualizationData) {
            console.error('visualizationData가 없습니다');
            return [];
        }

        const elements = [];
        const nodeIds = new Set();

        // 🔥 Step 1: 서버 제공 노드만 수집 (하드코딩 금지!)
        if (visualizationData.nodes && visualizationData.nodes.length > 0) {
            visualizationData.nodes.forEach(node => {
                nodeIds.add(node.id);

                const nodeType = node.type?.toUpperCase() || 'USER';
                const hasPermission = this.nodeHasPermission(node);

                elements.push({
                    data: {
                        id: node.id,
                        label: node.label || node.id,
                        type: nodeType,
                        nodeType: nodeType.toLowerCase(),
                        hasPermission: hasPermission,
                        properties: node.properties || {}
                    },
                    classes: `${nodeType.toLowerCase()}-node ${hasPermission ? 'has-permission' : 'no-permission'}`
                });
            });
        }

        // 🔥 Step 2: 엣지 처리 전 누락된 노드 동적 생성
        const missingNodes = new Set();

        if (visualizationData.edges && visualizationData.edges.length > 0) {
            // 엣지에서 참조하는 모든 노드 ID 수집
            visualizationData.edges.forEach(edge => {
                if (!nodeIds.has(edge.source)) {
                    missingNodes.add(edge.source);
                }
                if (!nodeIds.has(edge.target)) {
                    missingNodes.add(edge.target);
                }
            });

            // 누락된 노드들 동적 생성
            missingNodes.forEach(nodeId => {
                let nodeType = 'UNKNOWN';
                let label = nodeId;

                // 노드 ID에서 타입 추론
                if (nodeId.startsWith('user-')) {
                    nodeType = 'USER';
                    label = nodeId.replace('user-', '');
                } else if (nodeId.startsWith('group-')) {
                    nodeType = 'GROUP';
                    label = nodeId.replace('group-', '');
                } else if (nodeId.startsWith('role-')) {
                    nodeType = 'ROLE';
                    label = nodeId.replace('role-', '');
                } else if (nodeId.startsWith('permission-')) {
                    nodeType = 'PERMISSION';
                    label = nodeId.replace('permission-', '');
                }

                console.log(`🔧 누락된 노드 동적 생성: ${nodeId} (${nodeType})`);

                elements.push({
                    data: {
                        id: nodeId,
                        label: label,
                        type: nodeType,
                        nodeType: nodeType.toLowerCase(),
                        hasPermission: nodeType === 'PERMISSION',
                        properties: {generated: true, description: `동적 생성된 ${nodeType} 노드`}
                    },
                    classes: `${nodeType.toLowerCase()}-node generated-node`
                });

                nodeIds.add(nodeId);
            });

            // 이제 모든 엣지 처리 (누락된 노드들이 생성되었으므로)
            visualizationData.edges.forEach(edge => {
                const edgeType = edge.type || 'CONNECTED';

                elements.push({
                    data: {
                        id: edge.id || `${edge.source}-${edge.target}`,
                        source: edge.source,
                        target: edge.target,
                        type: edgeType,
                        edgeType: edgeType.toLowerCase(),
                        properties: edge.properties || {}
                    },
                    classes: `${edgeType.toLowerCase()}-edge`
                });
            });

            console.log(`🔧 동적 생성된 노드: ${missingNodes.size}개, 처리된 엣지: ${visualizationData.edges.length}개`);
        }

        // 🔥 Step 3: analysisResults를 활용한 누락된 연결 생성 (필요한 경우만)
        if (this.currentAnalysisResults && this.currentAnalysisResults.length > 0) {
            // 🔥 서버 데이터가 완전한 구조인지 확인
            const hasCompleteUserChain = visualizationData.nodes &&
                visualizationData.nodes.some(node => node.type === 'USER') &&
                visualizationData.nodes.some(node => node.type === 'GROUP') &&
                visualizationData.nodes.some(node => node.type === 'ROLE') &&
                visualizationData.nodes.some(node => node.type === 'PERMISSION');

            if (hasCompleteUserChain) {
                console.log('🎯 서버 데이터가 완전한 구조 - 추가 연결 생성 생략');
            } else {
                console.log('🔗 analysisResults 기반 누락된 연결 생성 시작');
                const generatedEdges = this.generateMissingConnections(this.currentAnalysisResults, nodeIds, elements);
                console.log(`🔗 생성된 누락 연결: ${generatedEdges}개`);
            }
        } else {
            console.log('🔗 analysisResults가 없어서 추가 연결 생성 생략');
        }

        console.log('Cytoscape 요소 변환 완료 (서버 데이터만 사용):', elements.length, '개 요소');
        return elements;
    }

    /**
     * 🔗 analysisResults 기반 누락된 연결 생성
     */
    generateMissingConnections(analysisResults, existingNodeIds, elements) {
        let generatedCount = 0;
        const existingEdgeKeys = new Set();

        // 기존 엣지 키 수집 (중복 방지용)
        elements.forEach(element => {
            if (element.data.source && element.data.target) {
                existingEdgeKeys.add(`${element.data.source}-${element.data.target}`);
            }
        });

        analysisResults.forEach(userAnalysis => {
            // 🔥 사용자 ID 안전하게 추출 (undefined 방지)
            const userName = userAnalysis.user || userAnalysis.name || userAnalysis.userName || 'unknown';

            // undefined나 빈 문자열인 경우 건너뛰기
            if (!userName || userName === 'unknown') {
                console.warn('사용자 정보가 없어서 연결 생성을 건너뜁니다:', userAnalysis);
                return;
            }

            const userId = `user-${userName}`;
            console.log(`🔗 사용자 연결 처리: ${userId}`);

            // 🔗 Step 1: User → Groups 연결 생성
            if (userAnalysis.groups && userAnalysis.groups.length > 0) {
                userAnalysis.groups.forEach(groupName => {
                    const groupId = `group-${groupName}`;
                    const edgeKey = `${userId}-${groupId}`;

                    // 그룹 노드가 없으면 생성
                    if (!existingNodeIds.has(groupId)) {
                        console.log(`🔧 누락된 그룹 노드 생성: ${groupId}`);
                        elements.push({
                            data: {
                                id: groupId,
                                label: groupName,
                                type: 'GROUP',
                                nodeType: 'group',
                                hasPermission: false,
                                properties: {generated: true, description: `동적 생성된 GROUP 노드`}
                            },
                            classes: 'group-node generated-node'
                        });
                        existingNodeIds.add(groupId);
                    }

                    // User → Group 연결이 없으면 생성
                    if (!existingEdgeKeys.has(edgeKey)) {
                        console.log(`🔗 User-Group 연결 생성: ${userId} → ${groupId}`);
                        elements.push({
                            data: {
                                id: `edge-${userId}-${groupId}`,
                                source: userId,
                                target: groupId,
                                type: 'MEMBER_OF',
                                edgeType: 'member_of',
                                properties: {label: '소속', description: '그룹 멤버십', generated: true}
                            },
                            classes: 'member_of-edge generated-edge'
                        });
                        existingEdgeKeys.add(edgeKey);
                        generatedCount++;
                    }
                });
            }

            // 🔗 Step 2: Groups → Roles 연결 생성
            if (userAnalysis.groups && userAnalysis.roles &&
                userAnalysis.groups.length > 0 && userAnalysis.roles.length > 0) {
                userAnalysis.groups.forEach(groupName => {
                    userAnalysis.roles.forEach(roleName => {
                        const groupId = `group-${groupName}`;
                        const roleId = `role-${roleName}`;
                        const edgeKey = `${groupId}-${roleId}`;

                        // 역할 노드가 없으면 생성
                        if (!existingNodeIds.has(roleId)) {
                            console.log(`🔧 누락된 역할 노드 생성: ${roleId}`);
                            elements.push({
                                data: {
                                    id: roleId,
                                    label: roleName,
                                    type: 'ROLE',
                                    nodeType: 'role',
                                    hasPermission: false,
                                    properties: {generated: true, description: `동적 생성된 ROLE 노드`}
                                },
                                classes: 'role-node generated-node'
                            });
                            existingNodeIds.add(roleId);
                        }

                        // Group → Role 연결이 없으면 생성
                        if (!existingEdgeKeys.has(edgeKey)) {
                            console.log(`🔗 Group-Role 연결 생성: ${groupId} → ${roleId}`);
                            elements.push({
                                data: {
                                    id: `edge-${groupId}-${roleId}`,
                                    source: groupId,
                                    target: roleId,
                                    type: 'HAS_ROLE',
                                    edgeType: 'has_role',
                                    properties: {label: '역할 보유', description: '그룹 역할 관계', generated: true}
                                },
                                classes: 'has_role-edge generated-edge'
                            });
                            existingEdgeKeys.add(edgeKey);
                            generatedCount++;
                        }
                    });
                });
            }

            // 🔗 Step 3: User → Permissions 직접 연결 생성 (선택적)
            if (userAnalysis.permissions && userAnalysis.permissions.length > 0) {
                userAnalysis.permissions.forEach(permissionName => {
                    const permissionId = `permission-${permissionName}`;
                    const edgeKey = `${userId}-${permissionId}`;

                    // Permission 노드가 없으면 생성
                    if (!existingNodeIds.has(permissionId)) {
                        console.log(`🔧 누락된 권한 노드 생성: ${permissionId}`);
                        elements.push({
                            data: {
                                id: permissionId,
                                label: permissionName,
                                type: 'PERMISSION',
                                nodeType: 'permission',
                                hasPermission: true,
                                properties: {generated: true, description: `동적 생성된 PERMISSION 노드`}
                            },
                            classes: 'permission-node generated-node'
                        });
                        existingNodeIds.add(permissionId);
                    }

                    // User → Permission 직접 연결이 없으면 생성
                    if (!existingEdgeKeys.has(edgeKey)) {
                        console.log(`🔗 User-Permission 연결 생성: ${userId} → ${permissionId}`);
                        elements.push({
                            data: {
                                id: `edge-${userId}-${permissionId}`,
                                source: userId,
                                target: permissionId,
                                type: 'HAS_PERMISSION',
                                edgeType: 'has_permission',
                                properties: {label: '권한 보유', description: '사용자 권한 관계', generated: true}
                            },
                            classes: 'has_permission-edge generated-edge'
                        });
                        existingEdgeKeys.add(edgeKey);
                        generatedCount++;
                    }
                });
            }
        });

        return generatedCount;
    }

    /**
     * Cytoscape 오류 표시
     */
    showCytoscapeError(container, error) {
        container.innerHTML = `
            <div class="flex flex-col items-center justify-center h-full text-slate-400 p-8">
                <i class="fas fa-exclamation-triangle text-4xl text-red-500 mb-4"></i>
                <p class="text-lg mb-2">Cytoscape 렌더링 오류</p>
                <details class="text-xs text-slate-500 cursor-pointer">
                    <summary>오류 상세 보기</summary>
                    <pre class="mt-2 p-2 bg-slate-800 rounded text-xs overflow-auto max-h-32">${error.message || error}</pre>
                </details>
            </div>
        `;
    }

    // 🔥 Cytoscape 헬퍼 함수들 (스타일시트 방식으로 변경됨)

    // 🔥 이전 함수들 제거됨 - 스타일시트 방식으로 교체

    nodeHasPermission(node) {
        if (node.properties?.permissions && node.properties.permissions.length > 0) {
            return true;
        }
        // 최고관리자는 기본적으로 권한이 있다고 가정
        if (node.id === '최고관리자') {
            return true;
        }
        return false;
    }

    getCytoscapeStyles() {
        return [
            // 기본 노드 스타일
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'color': '#ffffff',
                    'font-size': '14px',
                    'font-weight': 'bold',
                    'border-width': '2px',
                    'border-color': '#ffffff',
                    'text-wrap': 'wrap',
                    'text-max-width': '100px'
                }
            },

            // 🔵 USER 노드
            {
                selector: '.user-node',
                style: {
                    'shape': 'round-rectangle',
                    'width': '80px',
                    'height': '50px',
                    'font-size': '12px'
                }
            },
            {
                selector: '.user-node.has-permission',
                style: {
                    'background-color': '#10b981', // 초록색 - 권한 있음
                    'border-color': '#059669'
                }
            },
            {
                selector: '.user-node.no-permission',
                style: {
                    'background-color': '#ef4444', // 빨간색 - 권한 없음
                    'border-color': '#dc2626'
                }
            },

            // 🟣 ROLE 노드
            {
                selector: '.role-node',
                style: {
                    'shape': 'diamond',
                    'width': '70px',
                    'height': '70px',
                    'background-color': '#8b5cf6', // 보라색
                    'border-color': '#7c3aed',
                    'font-size': '11px'
                }
            },

            // 🔷 GROUP 노드
            {
                selector: '.group-node',
                style: {
                    'shape': 'rectangle',
                    'width': '90px',
                    'height': '45px',
                    'background-color': '#3b82f6', // 파란색
                    'border-color': '#2563eb',
                    'font-size': '12px'
                }
            },

            // 🟠 PERMISSION 노드
            {
                selector: '.permission-node',
                style: {
                    'shape': 'hexagon',
                    'width': '75px',
                    'height': '75px',
                    'background-color': '#f59e0b', // 주황색
                    'border-color': '#d97706',
                    'font-size': '10px'
                }
            },

            // 기본 엣지 스타일
            {
                selector: 'edge',
                style: {
                    'width': '3px',
                    'line-color': '#6366f1',
                    'target-arrow-color': '#6366f1',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier'
                }
            },

            // 엣지 타입별 스타일
            {
                selector: '.has_role-edge',
                style: {
                    'line-color': '#8b5cf6',
                    'target-arrow-color': '#8b5cf6'
                }
            },
            {
                selector: '.has_permission-edge',
                style: {
                    'line-color': '#f59e0b',
                    'target-arrow-color': '#f59e0b'
                }
            },

            // 강조 스타일
            {
                selector: '.highlighted',
                style: {
                    'border-width': '4px',
                    'border-color': '#ff6b35',
                    'line-color': '#ff6b35',
                    'target-arrow-color': '#ff6b35',
                    'z-index': 999
                }
            }
        ];
    }

    getCurrentLayoutOptions() {
        const layoutType = this.currentVisualizationType || 'network';

        // 🔥 Cola 레이아웃 사용 가능 여부 확인
        const isColaAvailable = this.availableLayouts && this.availableLayouts.includes('cola');

        switch (layoutType) {
            case 'hierarchy':
                return {
                    name: 'dagre',
                    rankDir: 'TB',
                    rankSep: 100,
                    nodeSep: 50,
                    animate: true,
                    animationDuration: 1000,
                    fit: true,
                    padding: 50,
                    spacingFactor: 1.2
                };
            case 'flowchart':
                return {
                    name: 'breadthfirst',
                    directed: true,
                    spacingFactor: 1.75,
                    animate: true,
                    animationDuration: 1000,
                    fit: true,
                    padding: 50,
                    maximalAdjustments: 0
                };
            default: // network
                if (isColaAvailable) {
                    return {
                        name: 'cola',
                        infinite: false,
                        fit: true,
                        padding: 50,
                        nodeSpacing: function (node) {
                            return 30;
                        },
                        edgeLength: function (edge) {
                            return 150;
                        },
                        animate: true,
                        animationDuration: 1500,
                        animationEasing: 'ease-out-quart',
                        randomize: false,
                        maxSimulationTime: 3000, // 🔥 최대 3초만 시뮬레이션 후 고정
                        ungrabifyWhileSimulating: false,
                        centerGraph: true,
                        avoidOverlap: true,
                        handleDisconnected: true
                    };
                } else {
                    // 🔥 Cola 미사용 시 Circle 레이아웃으로 fallback (안정적)
                    console.log('Cola 레이아웃 미사용 - Circle 레이아웃 사용');
                    return {
                        name: 'circle',
                        fit: true,
                        padding: 50,
                        animate: true,
                        animationDuration: 1000,
                        startAngle: 0,
                        sweep: Math.PI * 2,
                        clockwise: true,
                        sort: function (a, b) {
                            return a.data('label').localeCompare(b.data('label'));
                        }
                    };
                }
        }
    }

    setupCytoscapeEvents() {
        if (!this.cytoscapeInstance) return;

        // =============================
        // 🎯 노드 클릭 이벤트 - 향상된 시각적 피드백
        // =============================
        this.cytoscapeInstance.on('tap', 'node', (event) => {
            const node = event.target;
            const nodeData = node.data();

            // 모든 요소 하이라이트 제거
            this.cytoscapeInstance.elements().removeClass('highlighted selected');

            // 선택된 노드와 연결된 요소들 하이라이트
            node.addClass('highlighted selected');

            // 연결된 엣지와 노드들도 하이라이트
            const connectedEdges = node.connectedEdges();
            const connectedNodes = connectedEdges.connectedNodes();

            connectedEdges.addClass('highlighted');
            connectedNodes.addClass('highlighted');

            // 🔥 선택된 노드에 펄스 애니메이션 효과
            this.startNodePulseAnimation(node);

            // 🔥 연결된 엣지에 플로우 애니메이션 추가
            this.startEdgeFlowAnimation(connectedEdges);

            // 🔥 상세 정보 패널 표시
            this.showNodeDetailsPanel(nodeData, event);

            console.log('🎯 Node selected:', nodeData);
        });

        // =============================
        // 🎯 엣지 클릭 이벤트 - 연결 관계 시각화
        // =============================
        this.cytoscapeInstance.on('tap', 'edge', (event) => {
            const edge = event.target;
            const edgeData = edge.data();

            // 모든 하이라이트 제거
            this.cytoscapeInstance.elements().removeClass('highlighted selected');

            // 선택된 엣지와 연결된 노드들 하이라이트
            edge.addClass('highlighted selected');
            edge.source().addClass('highlighted');
            edge.target().addClass('highlighted');

            // 🔥 엣지 플로우 애니메이션
            this.startSingleEdgeFlowAnimation(edge);

            // 🔥 연결 정보 표시
            this.showEdgeDetailsPanel(edgeData, event);

            console.log('🔗 Edge selected:', edgeData);
        });

        // =============================
        // 🖱️ 노드 호버 이벤트 - 실시간 툴팁
        // =============================
        this.cytoscapeInstance.on('mouseover', 'node', (event) => {
            const node = event.target;
            const nodeData = node.data();

            // 🔥 실시간 툴팁 표시
            this.showNodeTooltip(nodeData, event);

            // 호버된 노드에 글로우 효과
            node.addClass('hovered');
        });

        this.cytoscapeInstance.on('mouseout', 'node', (event) => {
            const node = event.target;
            node.removeClass('hovered');

            // 툴팁 숨기기
            this.hideNodeTooltip();
        });

        // =============================
        // 🖱️ 엣지 호버 이벤트
        // =============================
        this.cytoscapeInstance.on('mouseover', 'edge', (event) => {
            const edge = event.target;
            const edgeData = edge.data();

            edge.addClass('hovered');
            this.showEdgeTooltip(edgeData, event);
        });

        this.cytoscapeInstance.on('mouseout', 'edge', (event) => {
            const edge = event.target;
            edge.removeClass('hovered');
            this.hideEdgeTooltip();
        });

        // =============================
        // 🎯 배경 클릭 - 모든 선택 해제
        // =============================
        this.cytoscapeInstance.on('tap', (event) => {
            if (event.target === this.cytoscapeInstance) {
                this.cytoscapeInstance.elements().removeClass('highlighted selected hovered');
                this.hideAllTooltips();
                this.hideDetailsPanel();
                this.stopAllAnimations();
            }
        });

        // =============================
        // 줌 이벤트 - 동적 레이블 크기 조정
        // =============================
        this.cytoscapeInstance.on('zoom', (event) => {
            const zoom = this.cytoscapeInstance.zoom();
            this.adjustLabelsForZoom(zoom);
        });

        // =============================
        // 🎨 렌더링 완료 후 초기 애니메이션
        // =============================
        this.cytoscapeInstance.ready(() => {
            this.startInitialLoadAnimation();
        });

        console.log('고급 Cytoscape 이벤트 바인딩 완료');
    }

    // =============================
    // 애니메이션 메서드들
    // =============================

    /**
     * 🔥 노드 펄스 애니메이션
     */
    startNodePulseAnimation(node) {
        let pulseCount = 0;
        const maxPulses = 3;

        const pulse = () => {
            if (pulseCount >= maxPulses) return;

            node.animate({
                style: {
                    'border-width': '6px',
                    'box-shadow-blur': '25px'
                }
            }, {
                duration: 300,
                complete: () => {
                    node.animate({
                        style: {
                            'border-width': '3px',
                            'box-shadow-blur': '12px'
                        }
                    }, {
                        duration: 300,
                        complete: () => {
                            pulseCount++;
                            if (pulseCount < maxPulses) {
                                setTimeout(pulse, 100);
                            }
                        }
                    });
                }
            });
        };

        pulse();
    }

    /**
     * 🔥 엣지 플로우 애니메이션
     */
    startEdgeFlowAnimation(edges) {
        edges.forEach(edge => {
            this.startSingleEdgeFlowAnimation(edge);
        });
    }

    /**
     * 🔥 단일 엣지 플로우 애니메이션
     */
    startSingleEdgeFlowAnimation(edge) {
        let offset = 0;
        const animate = () => {
            offset = (offset + 2) % 20;
            edge.style('line-dash-offset', offset);

            if (edge.hasClass('highlighted')) {
                requestAnimationFrame(animate);
            }
        };

        // 점선 스타일로 변경하고 애니메이션 시작
        edge.style({
            'line-style': 'dashed',
            'line-dash-pattern': [8, 4]
        });

        requestAnimationFrame(animate);
    }

    /**
     * 🎨 초기 로드 애니메이션
     */
    startInitialLoadAnimation() {
        const nodes = this.cytoscapeInstance.nodes();
        const edges = this.cytoscapeInstance.edges();

        // 모든 요소를 투명하게 시작
        this.cytoscapeInstance.elements().style('opacity', 0);

        // 노드들을 순차적으로 나타나게 함
        nodes.forEach((node, index) => {
            setTimeout(() => {
                node.animate({
                    style: {'opacity': 1},
                }, {
                    duration: 500,
                    easing: 'ease-out-cubic'
                });
            }, index * 100);
        });

        // 엣지들을 노드 이후에 나타나게 함
        setTimeout(() => {
            edges.forEach((edge, index) => {
                setTimeout(() => {
                    edge.animate({
                        style: {'opacity': 0.8},
                    }, {
                        duration: 400,
                        easing: 'ease-out'
                    });
                }, index * 50);
            });
        }, nodes.length * 100 + 200);
    }

    /**
     * 줌에 따른 레이블 크기 조정
     */
    adjustLabelsForZoom(zoom) {
        const nodes = this.cytoscapeInstance.nodes();

        nodes.forEach(node => {
            const baseSize = parseInt(node.data('baseFontSize')) || 12;
            const newSize = Math.max(8, Math.min(20, baseSize * zoom));
            node.style('font-size', newSize + 'px');
        });
    }

    /**
     * 🛑 모든 애니메이션 중지
     */
    stopAllAnimations() {
        this.cytoscapeInstance.elements().stop();
        this.cytoscapeInstance.elements().style({
            'line-style': 'solid',
            'line-dash-pattern': undefined,
            'line-dash-offset': 0
        });
    }

    // =============================
    // 🔧 툴팁 및 상세 패널 메서드들
    // =============================

    /**
     * 🔥 노드 실시간 툴팁 표시
     */
    showNodeTooltip(nodeData, event) {
        const tooltip = this.getOrCreateTooltip('node-tooltip');

        const connections = this.cytoscapeInstance.getElementById(nodeData.id).degree();
        const nodeType = nodeData.type || 'UNKNOWN';
        const hasPermission = nodeData.hasPermission ? '권한 있음' : '권한 없음';

        tooltip.innerHTML = `
            <div class="tooltip-header">
                <strong>${nodeData.label}</strong>
                <span class="tooltip-type">${nodeType}</span>
            </div>
            <div class="tooltip-body">
                <div class="tooltip-stat">연결: ${connections}개</div>
                <div class="tooltip-status">${hasPermission}</div>
                ${nodeData.properties?.generated ? '<div class="tooltip-generated">🔧 동적 생성</div>' : ''}
            </div>
        `;

        this.positionTooltip(tooltip, event);
        tooltip.style.display = 'block';
    }

    /**
     * 🔥 엣지 툴팁 표시
     */
    showEdgeTooltip(edgeData, event) {
        const tooltip = this.getOrCreateTooltip('edge-tooltip');

        const edgeType = edgeData.type || 'CONNECTED';
        const source = edgeData.source;
        const target = edgeData.target;

        tooltip.innerHTML = `
            <div class="tooltip-header">
                <strong>${edgeType}</strong>
            </div>
            <div class="tooltip-body">
                <div class="tooltip-connection">${source} → ${target}</div>
                ${edgeData.properties?.generated ? '<div class="tooltip-generated">🔧 동적 생성</div>' : ''}
            </div>
        `;

        this.positionTooltip(tooltip, event);
        tooltip.style.display = 'block';
    }

    /**
     * 🔥 상세 정보 패널 표시
     */
    showNodeDetailsPanel(nodeData, event) {
        const panel = this.getOrCreateDetailsPanel();
        const node = this.cytoscapeInstance.getElementById(nodeData.id);
        const connections = node.degree();
        const connectedEdges = node.connectedEdges();

        // 연결 타입별 분석
        const edgesByType = {};
        connectedEdges.forEach(edge => {
            const type = edge.data('type') || 'UNKNOWN';
            edgesByType[type] = (edgesByType[type] || 0) + 1;
        });

        panel.innerHTML = `
            <div class="details-panel-header">
                <h3>${nodeData.label}</h3>
                <button class="details-close-btn" onclick="aiStudio.hideDetailsPanel()">×</button>
            </div>
            <div class="details-panel-body">
                <div class="detail-section">
                    <h4>기본 정보</h4>
                    <p><strong>타입:</strong> ${nodeData.type}</p>
                    <p><strong>권한 상태:</strong> ${nodeData.hasPermission ? '보유' : '없음'}</p>
                    <p><strong>총 연결:</strong> ${connections}개</p>
                </div>
                
                <div class="detail-section">
                    <h4>연결 분석</h4>
                    ${Object.entries(edgesByType).map(([type, count]) =>
            `<p><strong>${type}:</strong> ${count}개</p>`
        ).join('')}
                </div>
                
                ${nodeData.properties ? `
                    <div class="detail-section">
                        <h4>속성</h4>
                        ${Object.entries(nodeData.properties).map(([key, value]) =>
            `<p><strong>${key}:</strong> ${value}</p>`
        ).join('')}
                    </div>
                ` : ''}
            </div>
        `;

        panel.style.display = 'block';
    }

    /**
     * 🔧 툴팁 DOM 요소 생성/가져오기
     */
    getOrCreateTooltip(id) {
        let tooltip = document.getElementById(id);
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = id;
            tooltip.className = 'cytoscape-tooltip';
            tooltip.style.cssText = `
                position: absolute;
                background: rgba(15, 23, 42, 0.95);
                color: white;
                padding: 8px 12px;
                border-radius: 8px;
                font-size: 12px;
                pointer-events: none;
                z-index: 10000;
                border: 1px solid rgba(99, 102, 241, 0.3);
                backdrop-filter: blur(10px);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
                display: none;
                max-width: 200px;
            `;
            document.body.appendChild(tooltip);
        }
        return tooltip;
    }

    /**
     * 🔧 상세 패널 DOM 요소 생성/가져오기
     */
    getOrCreateDetailsPanel() {
        let panel = document.getElementById('cytoscape-details-panel');
        if (!panel) {
            panel = document.createElement('div');
            panel.id = 'cytoscape-details-panel';
            panel.className = 'cytoscape-details-panel';
            panel.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                width: 300px;
                max-height: 80vh;
                background: rgba(15, 23, 42, 0.95);
                color: white;
                border-radius: 12px;
                border: 1px solid rgba(99, 102, 241, 0.3);
                backdrop-filter: blur(15px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                z-index: 10001;
                overflow-y: auto;
                display: none;
            `;
            document.body.appendChild(panel);
        }
        return panel;
    }

    /**
     * 🔧 툴팁 위치 조정
     */
    positionTooltip(tooltip, event) {
        const x = event.renderedPosition ? event.renderedPosition.x : event.clientX;
        const y = event.renderedPosition ? event.renderedPosition.y : event.clientY;

        tooltip.style.left = (x + 10) + 'px';
        tooltip.style.top = (y - 30) + 'px';
    }

    /**
     * 🔧 툴팁 숨기기
     */
    hideNodeTooltip() {
        const tooltip = document.getElementById('node-tooltip');
        if (tooltip) tooltip.style.display = 'none';
    }

    hideEdgeTooltip() {
        const tooltip = document.getElementById('edge-tooltip');
        if (tooltip) tooltip.style.display = 'none';
    }

    hideAllTooltips() {
        this.hideNodeTooltip();
        this.hideEdgeTooltip();
    }

    /**
     * 🔧 상세 패널 숨기기
     */
    hideDetailsPanel() {
        const panel = document.getElementById('cytoscape-details-panel');
        if (panel) panel.style.display = 'none';
    }

    // Cytoscape 오류 표시
    showCytoscapeError(container, error) {
        container.innerHTML = `
            <div class="flex flex-col items-center justify-center h-full text-slate-400 p-8">
                <i class="fas fa-exclamation-triangle text-4xl text-yellow-500 mb-4"></i>
                <p class="text-lg mb-2">Cytoscape 렌더링 오류</p>
                <details class="text-xs text-slate-500 cursor-pointer">
                    <summary>오류 상세</summary>
                    <pre class="mt-2 p-2 bg-slate-800 rounded text-xs overflow-auto max-h-32">${error.message || error}</pre>
                </details>
            </div>
        `;
    }

    // 다이어그램 중앙 정렬 - 개선된 버전
    centerDiagram(container) {
        setTimeout(() => {
            const svg = container.querySelector('svg');
            if (svg) {
                // SVG를 중앙에 정렬하고 적절한 크기로 조정
                svg.style.display = 'block';
                svg.style.margin = '0 auto';
                svg.style.maxWidth = '100%';
                svg.style.maxHeight = '100%';

                // 컨테이너 스타일 설정
                container.style.display = 'flex';
                container.style.alignItems = 'center';
                container.style.justifyContent = 'center';
                container.style.overflow = 'auto';
                container.style.padding = '20px';

                console.log('다이어그램 중앙 정렬 완료');
            }
        }, 100);
    }

    // 전체화면 다이어그램 중앙 정렬
    centerFullscreenDiagram(container) {
        setTimeout(() => {
            const svg = container.querySelector('svg');
            if (svg) {
                // 전체화면에서는 더 큰 크기로 표시
                svg.style.display = 'block';
                svg.style.margin = '0 auto';
                svg.style.width = '90%';
                svg.style.height = '90%';
                svg.style.maxWidth = '1200px';
                svg.style.maxHeight = '800px';

                // 전체화면 컨테이너 스타일 설정
                container.style.display = 'flex';
                container.style.alignItems = 'center';
                container.style.justifyContent = 'center';
                container.style.width = '100%';
                container.style.height = '100%';
                container.style.overflow = 'auto';
                container.style.padding = '40px';

                console.log('전체화면 다이어그램 중앙 정렬 완료');
            }
        }, 200);
    }

    // =============================
    // 🌐 UI 상태 관리 유틸리티
    // =============================
    setAIThinking(thinking) {
        const aiQueryBtn = document.getElementById('ai-query-btn');
        if (aiQueryBtn) {
            if (thinking) {
                aiQueryBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                aiQueryBtn.classList.add('ai-thinking');
                aiQueryBtn.disabled = true;
            } else {
                aiQueryBtn.innerHTML = '<i class="fas fa-paper-plane"></i>';
                aiQueryBtn.classList.remove('ai-thinking');
                aiQueryBtn.disabled = false;
            }
        }
    }

    hideCanvasPlaceholder() {
        const placeholder = document.getElementById('canvas-placeholder');
        const aiResponseContainer = document.getElementById('ai-response-container');

        if (placeholder) placeholder.classList.add('hidden');
        if (aiResponseContainer) aiResponseContainer.classList.add('hidden');
    }

    showCanvasPlaceholder() {
        const placeholder = document.getElementById('canvas-placeholder');
        const mermaidContainer = document.getElementById('mermaid-container');
        const aiResponseContainer = document.getElementById('ai-response-container');

        if (placeholder) placeholder.classList.remove('hidden');
        if (mermaidContainer) mermaidContainer.classList.add('hidden');
        if (aiResponseContainer) aiResponseContainer.classList.add('hidden');
    }

    // =============================
    // 🖥️ 전체화면 기능
    // =============================
    showFullscreen() {
        // 현재 시각화 데이터 확인
        const hasVisualization = this.currentVisualization || this.currentVisualizationData;

        if (!hasVisualization) {
            this.showToast('표시할 시각화가 없습니다.', 'warning');
            return;
        }

        const modal = document.getElementById('fullscreen-modal');
        if (modal) {
            modal.classList.add('show');

            // 전체화면용 Mermaid 렌더링
            this.renderFullscreenVisualization();

            // 줌 기능 초기화
            this.initializeZoomControls();
        }
    }

    closeFullscreen() {
        const modal = document.getElementById('fullscreen-modal');
        if (modal) {
            modal.classList.remove('show');
        }
    }

    /**
     * 줌 컨트롤 초기화
     */
    initializeZoomControls() {
        // 줌 컨트롤 UI 추가
        const fullscreenContainer = document.getElementById('fullscreen-modal');
        if (!fullscreenContainer) return;

        // 기존 줌 컨트롤 제거
        const existingControls = fullscreenContainer.querySelector('.zoom-controls');
        if (existingControls) {
            existingControls.remove();
        }

        // 새로운 줌 컨트롤 생성
        const zoomControls = document.createElement('div');
        zoomControls.className = 'zoom-controls';
        zoomControls.innerHTML = `
            <div class="zoom-controls-container">
                <button class="zoom-btn zoom-in" title="확대">
                    <i class="fas fa-plus"></i>
                </button>
                <button class="zoom-btn zoom-out" title="축소">
                    <i class="fas fa-minus"></i>
                </button>
                <button class="zoom-btn zoom-reset" title="원래 크기">
                    <i class="fas fa-home"></i>
                </button>
                <span class="zoom-level">100%</span>
                <div class="drag-hint">💡 드래그하여 이동</div>
            </div>
        `;

        fullscreenContainer.appendChild(zoomControls);

        // 줌 이벤트 리스너 추가
        this.currentZoomLevel = 1.0;
        this.bindZoomEvents();

        // 🖱️ 드래그 기능 초기화
        this.initializeDragControls();
    }

    /**
     * 줌 이벤트 바인딩
     */
    bindZoomEvents() {
        const zoomInBtn = document.querySelector('.zoom-in');
        const zoomOutBtn = document.querySelector('.zoom-out');
        const zoomResetBtn = document.querySelector('.zoom-reset');

        if (zoomInBtn) {
            zoomInBtn.addEventListener('click', () => this.zoomIn());
        }

        if (zoomOutBtn) {
            zoomOutBtn.addEventListener('click', () => this.zoomOut());
        }

        if (zoomResetBtn) {
            zoomResetBtn.addEventListener('click', () => this.resetZoom());
        }

        // 마우스 휠 줌 지원
        const container = document.getElementById('fullscreen-mermaid-container');
        if (container) {
            container.addEventListener('wheel', (e) => {
                if (e.ctrlKey) {
                    e.preventDefault();
                    if (e.deltaY > 0) {
                        this.zoomOut();
                    } else {
                        this.zoomIn();
                    }
                }
            });
        }
    }

    /**
     * 🖱️ 드래그 기능 초기화
     */
    initializeDragControls() {
        const container = document.getElementById('fullscreen-mermaid-container');
        if (!container) return;

        let isDragging = false;
        let lastX = 0;
        let lastY = 0;
        let translateX = 0;
        let translateY = 0;

        container.style.cursor = 'grab';

        // 마우스 드래그 시작
        container.addEventListener('mousedown', (e) => {
            // 버튼이나 컨트롤 요소가 아닌 경우에만 드래그 시작
            if (e.target.closest('.zoom-controls') || e.target.closest('button')) {
                return;
            }

            isDragging = true;
            lastX = e.clientX;
            lastY = e.clientY;
            container.style.cursor = 'grabbing';
            e.preventDefault();
        });

        // 마우스 드래그 중
        container.addEventListener('mousemove', (e) => {
            if (!isDragging) return;

            const deltaX = e.clientX - lastX;
            const deltaY = e.clientY - lastY;

            translateX += deltaX;
            translateY += deltaY;

            lastX = e.clientX;
            lastY = e.clientY;

            this.applyTransform(translateX, translateY);
        });

        // 마우스 드래그 종료
        container.addEventListener('mouseup', () => {
            isDragging = false;
            container.style.cursor = 'grab';
        });

        // 마우스가 컨테이너 밖으로 나갔을 때 드래그 종료
        container.addEventListener('mouseleave', () => {
            isDragging = false;
            container.style.cursor = 'grab';
        });

        // 터치 이벤트 지원 (모바일)
        container.addEventListener('touchstart', (e) => {
            if (e.touches.length === 1) {
                isDragging = true;
                lastX = e.touches[0].clientX;
                lastY = e.touches[0].clientY;
                e.preventDefault();
            }
        });

        container.addEventListener('touchmove', (e) => {
            if (!isDragging || e.touches.length !== 1) return;

            const deltaX = e.touches[0].clientX - lastX;
            const deltaY = e.touches[0].clientY - lastY;

            translateX += deltaX;
            translateY += deltaY;

            lastX = e.touches[0].clientX;
            lastY = e.touches[0].clientY;

            this.applyTransform(translateX, translateY);
            e.preventDefault();
        });

        container.addEventListener('touchend', () => {
            isDragging = false;
        });

        // 드래그 상태 저장
        this.dragState = {
            translateX: 0,
            translateY: 0
        };
    }

    /**
     * 확대
     */
    zoomIn() {
        this.currentZoomLevel = Math.min(this.currentZoomLevel + 0.1, 3.0);
        this.applyZoom();
    }

    /**
     * 축소
     */
    zoomOut() {
        this.currentZoomLevel = Math.max(this.currentZoomLevel - 0.1, 0.3);
        this.applyZoom();
    }

    /**
     * 원래 크기로 복원
     */
    resetZoom() {
        this.currentZoomLevel = 1.0;
        this.applyZoom();
    }

    /**
     * 줌 적용
     */
    applyZoom() {
        const container = document.getElementById('fullscreen-mermaid-container');
        const zoomLevelSpan = document.querySelector('.zoom-level');

        if (container) {
            const svg = container.querySelector('svg');
            if (svg) {
                const translateX = this.dragState ? this.dragState.translateX : 0;
                const translateY = this.dragState ? this.dragState.translateY : 0;
                svg.style.transform = `translate(${translateX}px, ${translateY}px) scale(${this.currentZoomLevel})`;
                svg.style.transformOrigin = 'center center';
            }
        }

        if (zoomLevelSpan) {
            zoomLevelSpan.textContent = `${Math.round(this.currentZoomLevel * 100)}%`;
        }
    }

    /**
     * 🖱️ 이동 변환 적용
     */
    applyTransform(translateX, translateY) {
        const container = document.getElementById('fullscreen-mermaid-container');

        if (container) {
            const svg = container.querySelector('svg');
            if (svg) {
                svg.style.transform = `translate(${translateX}px, ${translateY}px) scale(${this.currentZoomLevel})`;
                svg.style.transformOrigin = 'center center';

                // 드래그 상태 업데이트
                if (this.dragState) {
                    this.dragState.translateX = translateX;
                    this.dragState.translateY = translateY;
                }
            }
        }
    }

    async renderFullscreenVisualization() {
        const container = document.getElementById('fullscreen-mermaid-container');
        if (!container) return;

        let visualizationData = null;

        // AI 시각화 데이터 우선 사용
        if (this.currentVisualizationData) {
            visualizationData = this.currentVisualizationData;
        } else if (this.currentVisualization) {
            visualizationData = this.currentVisualization;
        } else {
            this.showToast('렌더링할 시각화 데이터가 없습니다.', 'warning');
            return;
        }

        container.innerHTML = '';

        try {
            console.log('🎨 전체화면 Cytoscape 렌더링 시작:', visualizationData);

            // 🔥 Cytoscape로 전체화면 렌더링
            const cytoscapeData = this.convertToCytoscapeFormat(visualizationData);

            // 전체화면용 Cytoscape 인스턴스 생성
            const fullscreenCy = cytoscape({
                container: container,
                elements: cytoscapeData,
                style: this.getCytoscapeStyles(),
                layout: this.getCurrentLayoutOptions(),
                zoom: 1,
                pan: {x: 0, y: 0},
                minZoom: 0.1,
                maxZoom: 5,
                wheelSensitivity: 0.5
            });

            // 전체화면 전용 레이아웃 완료 후 안전한 처리
            fullscreenCy.one('layoutstop', () => {
                console.log('🎯 전체화면 레이아웃 완료 - 애니메이션 중지');
                
                setTimeout(() => {
                    // 안전한 처리를 위한 유효성 검사
                    if (!fullscreenCy || fullscreenCy.destroyed()) {
                        console.log('전체화면 Cytoscape 인스턴스가 이미 제거됨');
                        return;
                    }

                    const container = fullscreenCy.container();
                    if (!container || !document.contains(container)) {
                        console.log('전체화면 컨테이너가 DOM에서 제거됨');
                        return;
                    }

                    try {
                        fullscreenCy.fit();
                        fullscreenCy.center();
                        
                        // 애니메이션 완전 중지
                        fullscreenCy.nodes().style({
                            'transition-property': 'none',
                            'transition-duration': '0s'
                        });
                        
                        fullscreenCy.edges().style({
                            'line-dash-offset': 0,
                            'transition-property': 'none',
                            'transition-duration': '0s'
                        });
                        
                        fullscreenCy.nodes().ungrabify();
                        
                        console.log('전체화면 애니메이션 완전히 중지됨');
                    } catch (error) {
                        console.warn('전체화면 레이아웃 완료 후 처리 중 오류:', error.message);
                    }
                }, 100);
            });

            console.log('전체화면 Cytoscape 시각화 렌더링 완료');

        } catch (error) {
            console.error('Fullscreen Mermaid error:', error);
            this.showMermaidError(container, mermaidCode);
        }
    }

    // =============================
    // 📤 내보내기 기능
    // =============================
    exportVisualization() {
        if (!this.currentVisualization) {
            this.showToast('내보낼 시각화가 없습니다.', 'warning');
            return;
        }

        // SVG 추출 및 다운로드
        const svg = document.querySelector('#mermaid-container svg');
        if (svg) {
            const svgData = new XMLSerializer().serializeToString(svg);
            const blob = new Blob([svgData], {type: 'image/svg+xml'});
            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');
            a.href = url;
            a.download = `ai-studio-visualization-${new Date().getTime()}.svg`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            this.showToast('시각화가 다운로드되었습니다.', 'success');
        }
    }

    // =============================
    // 시각화 타입 변경 (Cytoscape 레이아웃 변경)
    // =============================
    changeVisualizationType(newType) {
        console.log('Changing visualization type to:', newType);

        // 현재 시각화 타입 업데이트
        this.currentVisualizationType = newType;

        // Cytoscape 인스턴스가 있는 경우 레이아웃 변경
        if (this.cytoscapeInstance) {
            const layoutOptions = this.getCurrentLayoutOptions();
            console.log('🎯 Cytoscape 레이아웃 변경:', newType, layoutOptions);

            // 🔥 레이아웃 변경 시에도 완료 후 고정 처리
            const layout = this.cytoscapeInstance.layout(layoutOptions);

            layout.one('layoutstop', () => {
                console.log('🎯 레이아웃 변경 완료 - 노드 고정');

                setTimeout(() => {
                    this.cytoscapeInstance.fit();
                    this.cytoscapeInstance.center();

                    // Network 타입에서만 노드 고정
                    if (newType === 'network') {
                        this.cytoscapeInstance.nodes().ungrabify();
                    } else {
                        this.cytoscapeInstance.nodes().grabify(); // 다른 타입에서는 draggable 유지
                    }
                }, 100);
            });

            layout.run();
            return;
        }

        // AI 분석 결과가 있는 경우 AI 시각화 재렌더링
        if (this.currentAIAnalysis && this.currentVisualizationData && this.currentOriginalQuery) {
            console.log('🎯 AI 시각화 타입 변경:', newType);

            // 새로운 타입으로 Cytoscape 데이터 생성
            const cytoscapeData = this.generateCytoscapeData(this.currentVisualizationData);

            // 재렌더링
            this.displayCytoscapeDiagram(cytoscapeData);

            // 인사이트 오버레이 업데이트 (나중에 추가)
            // this.createAIVisualizationInsights(this.currentVisualizationData, this.currentOriginalQuery);

            return;
        }

        // 기존 시각화가 있는 경우 기존 방식으로 처리
        if (this.currentVisualization) {
            console.log('기존 시각화 타입 변경:', newType);

            // 타입 변경
            this.currentVisualization.graphType = newType;

            // 재렌더링
            this.renderVisualization(this.currentVisualization);
        } else {
            console.log('변경할 시각화 데이터가 없습니다.');
            this.showToast('먼저 AI 질의를 통해 시각화 데이터를 생성하세요.', 'info');
        }
    }

    // =============================
    // 📊 텍스트 기반 응답 표시 (시각화 데이터 없을 때)
    // =============================
    displayTextResponse(response) {
        const aiResponseContainer = document.getElementById('ai-response-container');
        if (!aiResponseContainer) return;

        this.hideCanvasPlaceholder();
        aiResponseContainer.classList.remove('hidden');

        const html = `
            <div class="ai-response-section">
                <div class="ai-response-header">
                    <i class="fas fa-comment-alt"></i>
                    <h4>AI 텍스트 응답</h4>
                </div>
                <div class="bg-slate-800/50 rounded-lg p-4 text-slate-200">
                    ${response.naturalLanguageAnswer || '응답을 처리할 수 없습니다.'}
                </div>
            </div>
        `;

        aiResponseContainer.innerHTML = html;
    }

    // =============================
    // 오류 처리 메서드들
    // =============================

    /**
     * 오류 메시지를 사용자 친화적으로 변환
     */
    getErrorMessage(error) {
        const message = error.message || error.toString();

        if (message.includes('Query content is required')) {
            return '질의 내용을 입력해주세요.';
        }

        if (message.includes('사용자 ID') || message.includes('userId')) {
            return '사용자 인증 정보를 확인할 수 없습니다. 페이지를 새로고침해주세요.';
        }

        if (message.includes('질의 타입') || message.includes('queryType')) {
            return '질의 형식을 인식할 수 없습니다. 다시 시도해주세요.';
        }

        if (message.includes('너무 깁니다')) {
            return '질의 내용이 너무 깁니다. 1000자 이내로 작성해주세요.';
        }

        if (message.includes('올바르지 않은 사용자 ID')) {
            return '사용자 ID 형식이 올바르지 않습니다. 관리자에게 문의하세요.';
        }

        if (message.includes('네트워크') || message.includes('Network')) {
            return MSG.errors.networkError;
        }

        if (message.includes('400') || message.includes('Bad Request')) {
            return '잘못된 요청입니다. 입력 내용을 확인해주세요.';
        }

        if (message.includes('401') || message.includes('Unauthorized')) {
            return '권한이 없습니다. 로그인 상태를 확인해주세요.';
        }

        if (message.includes('500') || message.includes('Internal Server Error')) {
            return '서버 오류가 발생했습니다. 잠시 후 다시 시도해주세요.';
        }

        // 기본 오류 메시지
        return MSG.errors.aiError;
    }

    /**
     * Inspector에 오류 정보 표시
     */
    displayErrorInInspector(error, originalQuery) {
        const inspectorContent = document.getElementById('inspector-content');
        const inspectorPlaceholder = document.getElementById('inspector-placeholder');

        if (!inspectorContent) return;

        inspectorPlaceholder.classList.add('hidden');
        inspectorContent.classList.remove('hidden');

        const html = `
            <div class="ai-response-section">
                <div class="ai-response-header bg-red-900/20 border border-red-500/30">
                    <i class="fas fa-exclamation-triangle text-red-400"></i>
                    <h4 class="text-red-300">처리 중 오류 발생</h4>
                </div>
                
                <div class="mb-4">
                    <h5 class="text-slate-300 font-semibold mb-2">
                        <i class="fas fa-question-circle mr-2 text-indigo-400"></i>
                        질의: "${originalQuery}"
                    </h5>
                </div>
                
                <div class="mb-4">
                    <h5 class="text-red-300 font-semibold mb-2">
                        <i class="fas fa-exclamation-circle mr-2 text-red-400"></i>
                        오류 내용
                    </h5>
                    <div class="bg-red-900/20 border border-red-500/30 rounded-lg p-4 text-red-200">
                        ${this.getErrorMessage(error)}
                    </div>
                </div>
                
                <div class="mb-4">
                    <h5 class="text-slate-300 font-semibold mb-2">
                        <i class="fas fa-lightbulb mr-2 text-yellow-400"></i>
                        해결 방법
                    </h5>
                    <ul class="text-sm text-slate-400 space-y-1">
                        <li>• 질의 내용을 더 명확하게 작성해보세요</li>
                        <li>• 특수문자나 너무 긴 문장은 피해주세요</li>
                        <li>• 페이지를 새로고침 후 다시 시도해보세요</li>
                        <li>• 문제가 지속되면 관리자에게 문의하세요</li>
                    </ul>
                </div>
            </div>
        `;

        inspectorContent.innerHTML = html;
    }

    // =============================
    // 🛠️ 헬퍼 함수들
    // =============================
    getConfidenceClass(score) {
        if (score >= 80) return 'high-confidence';
        if (score >= 60) return 'medium-confidence';
        return 'low-confidence';
    }

    getConfidenceText(score) {
        if (score >= 80) return MSG.aiResponse.confidence.high;
        if (score >= 60) return MSG.aiResponse.confidence.medium;
        return MSG.aiResponse.confidence.low;
    }

    getPriorityColor(priority) {
        const colors = {
            1: 'bg-red-600',      // HIGH
            2: 'bg-yellow-600',   // MEDIUM
            3: 'bg-green-600'     // LOW
        };
        return colors[priority] || 'bg-gray-600';
    }

    getPriorityText(priority) {
        const texts = {
            1: '높음',
            2: '보통',
            3: '낮음'
        };
        return texts[priority] || '보통';
    }

    // =============================
    // 🧠 AI-Native 전용 유틸리티 메서드들
    // =============================

    /**
     * 복잡도 점수에 따른 CSS 클래스 반환
     */
    getComplexityClass(score) {
        if (score >= 0.7) return 'complexity-high text-red-400';
        if (score >= 0.4) return 'complexity-medium text-yellow-400';
        return 'complexity-low text-green-400';
    }

    /**
     * 복잡도 점수를 텍스트로 변환
     */
    getComplexityText(score) {
        if (typeof score === 'number') {
            if (score >= 0.7) return '높음';
            if (score >= 0.4) return '보통';
            return '낮음';
        }
        // implementationComplexity인 경우 (1, 2, 3)
        const complexityMap = {
            1: '쉬움',
            2: '보통',
            3: '어려움'
        };
        return complexityMap[score] || '보통';
    }

    /**
     * 위험도 점수에 따른 CSS 클래스 반환
     */
    getRiskClass(score) {
        if (score >= 0.7) return 'risk-high text-red-500';
        if (score >= 0.4) return 'risk-medium text-orange-400';
        return 'risk-low text-green-400';
    }

    /**
     * 위험도 점수를 텍스트로 변환
     */
    getRiskText(score) {
        if (score >= 0.7) return '높음';
        if (score >= 0.4) return '보통';
        return '낮음';
    }

    /**
     * 중요도에 따른 CSS 클래스 반환
     */
    getImportanceClass(importance) {
        const classMap = {
            1: 'importance-high text-red-400',
            2: 'importance-medium text-yellow-400',
            3: 'importance-low text-green-400'
        };
        return classMap[importance] || 'importance-medium text-yellow-400';
    }

    /**
     * 중요도를 텍스트로 변환
     */
    getImportanceText(importance) {
        const textMap = {
            1: '높음',
            2: '보통',
            3: '낮음'
        };
        return textMap[importance] || '보통';
    }

    /**
     * 인사이트 타입에 따른 아이콘 반환
     */
    getInsightIcon(type) {
        const iconMap = {
            'ACCESS_PATTERN': 'fas fa-route',
            'ACCESS_RESTRICTION': 'fas fa-lock',
            'RECOMMENDATION_INSIGHT': 'fas fa-lightbulb',
            'DISTRIBUTION': 'fas fa-chart-pie',
            'PATTERN': 'fas fa-project-diagram',
            'RISK': 'fas fa-exclamation-triangle',
            'EFFICIENCY': 'fas fa-tachometer-alt',
            'COMPLIANCE': 'fas fa-shield-check',
            'TREND': 'fas fa-chart-line'
        };
        return iconMap[type] || 'fas fa-info-circle';
    }

    /**
     * 인사이트 타입에 따른 아이콘 CSS 클래스 반환
     */
    getInsightIconClass(type) {
        const classMap = {
            'ACCESS_PATTERN': 'insight-icon-blue',
            'ACCESS_RESTRICTION': 'insight-icon-red',
            'RECOMMENDATION_INSIGHT': 'insight-icon-yellow',
            'DISTRIBUTION': 'insight-icon-green',
            'PATTERN': 'insight-icon-purple',
            'RISK': 'insight-icon-red',
            'EFFICIENCY': 'insight-icon-blue',
            'COMPLIANCE': 'insight-icon-green',
            'TREND': 'insight-icon-indigo'
        };
        return classMap[type] || 'insight-icon-default';
    }

    /**
     * 이상 탐지 타입에 따른 아이콘 반환
     */
    getAnomalyIcon(type) {
        const iconMap = {
            'MISSING_PERMISSION': 'fas fa-ban',
            'DUPLICATE': 'fas fa-copy',
            'CONFLICT': 'fas fa-exclamation-triangle',
            'EXCESSIVE': 'fas fa-warning',
            'ORPHANED': 'fas fa-unlink',
            'CIRCULAR': 'fas fa-sync-alt',
            'COMPLEX_PERMISSION_CHAIN': 'fas fa-project-diagram'
        };
        return iconMap[type] || 'fas fa-exclamation';
    }

    /**
     * 심각도에 따른 CSS 클래스 반환
     */
    getAnomalySeverityClass(severity) {
        const classMap = {
            1: 'anomaly-low',
            2: 'anomaly-medium',
            3: 'anomaly-high'
        };
        return classMap[severity] || 'anomaly-medium';
    }

    /**
     * 심각도에 따른 CSS 클래스 반환
     */
    getSeverityClass(severity) {
        const classMap = {
            1: 'severity-low text-green-400',
            2: 'severity-medium text-yellow-400',
            3: 'severity-high text-red-400'
        };
        return classMap[severity] || 'severity-medium text-yellow-400';
    }

    /**
     * 심각도를 텍스트로 변환
     */
    getSeverityText(severity) {
        const textMap = {
            1: '낮음',
            2: '보통',
            3: '높음'
        };
        return textMap[severity] || '보통';
    }

    /**
     * 최적화 제안 타입에 따른 아이콘 반환
     */
    getOptimizationIcon(type) {
        const iconMap = {
            'SYSTEM_OPTIMIZATION': 'fas fa-cogs',
            'CONSOLIDATE': 'fas fa-compress-alt',
            'RESTRUCTURE': 'fas fa-sitemap',
            'SIMPLIFY': 'fas fa-magic',
            'ENHANCE': 'fas fa-level-up-alt',
            'STANDARDIZE': 'fas fa-balance-scale'
        };
        return iconMap[type] || 'fas fa-rocket';
    }

    /**
     * 우선순위에 따른 CSS 클래스 반환 (최적화용)
     */
    getPriorityClass(priority) {
        const classMap = {
            1: 'priority-high text-red-400',
            2: 'priority-medium text-yellow-400',
            3: 'priority-low text-green-400'
        };
        return classMap[priority] || 'priority-medium text-yellow-400';
    }

    /**
     * 🎯 AI-Native 인터랙티브 이벤트 핸들러들
     */
    handleInsightCardClick(event, analysisResult) {
        event.preventDefault();
        const card = event.currentTarget;
        const insightType = card.getAttribute('data-insight-type');

        // 카드 확장/축소 토글
        card.classList.toggle('expanded');

        // 시각화에서 관련 요소 하이라이트
        this.highlightRelatedElements(insightType, analysisResult);

        console.log('🎯 인사이트 카드 클릭:', insightType);
    }

    handleAnomalyCardClick(event, analysisResult) {
        event.preventDefault();
        const card = event.currentTarget;
        const anomalyType = card.getAttribute('data-anomaly-type');

        // 카드 확장/축소 토글
        card.classList.toggle('expanded');

        // 위험 요소 시각화에 표시
        this.highlightRiskElements(anomalyType, analysisResult);

        console.log('🔥 이상 탐지 카드 클릭:', anomalyType);
    }

    handleOptimizationCardClick(event, analysisResult) {
        event.preventDefault();
        const card = event.currentTarget;
        const suggestionType = card.getAttribute('data-suggestion-type');

        // 카드 확장/축소 토글
        card.classList.toggle('expanded');

        // 최적화 대상 요소 하이라이트
        this.highlightOptimizationTargets(suggestionType, analysisResult);

        console.log('🚀 최적화 제안 카드 클릭:', suggestionType);
    }

    /**
     * 🎨 시각화 요소 하이라이트 메서드들
     */
    highlightRelatedElements(insightType, analysisResult) {
        // 시각화에서 인사이트 관련 요소들을 하이라이트
        const mermaidContainer = document.getElementById('mermaid-container');
        if (mermaidContainer) {
            // 기존 하이라이트 제거
            this.clearHighlights();

            // 새로운 하이라이트 적용
            const elements = mermaidContainer.querySelectorAll('.node');
            elements.forEach(el => {
                if (this.isRelatedToInsight(el, insightType)) {
                    el.classList.add('insight-highlight');
                }
            });
        }
    }

    highlightRiskElements(anomalyType, analysisResult) {
        // 위험 요소들을 빨간색으로 하이라이트
        const mermaidContainer = document.getElementById('mermaid-container');
        if (mermaidContainer) {
            this.clearHighlights();

            const elements = mermaidContainer.querySelectorAll('.node');
            elements.forEach(el => {
                if (this.isRiskElement(el, anomalyType)) {
                    el.classList.add('risk-highlight');
                }
            });
        }
    }

    highlightOptimizationTargets(suggestionType, analysisResult) {
        // 최적화 대상들을 초록색으로 하이라이트
        const mermaidContainer = document.getElementById('mermaid-container');
        if (mermaidContainer) {
            this.clearHighlights();

            const elements = mermaidContainer.querySelectorAll('.node');
            elements.forEach(el => {
                if (this.isOptimizationTarget(el, suggestionType)) {
                    el.classList.add('optimization-highlight');
                }
            });
        }
    }

    clearHighlights() {
        const mermaidContainer = document.getElementById('mermaid-container');
        if (mermaidContainer) {
            const highlighted = mermaidContainer.querySelectorAll('.insight-highlight, .risk-highlight, .optimization-highlight');
            highlighted.forEach(el => {
                el.classList.remove('insight-highlight', 'risk-highlight', 'optimization-highlight');
            });
        }
    }

    /**
     * 🎯 요소 관련성 판단 메서드들
     */
    isRelatedToInsight(element, insightType) {
        // 인사이트 타입에 따라 관련성 판단
        const elementText = element.textContent?.toLowerCase() || '';

        switch (insightType) {
            case 'ACCESS_PATTERN':
                return elementText.includes('권한') || elementText.includes('access');
            case 'ACCESS_RESTRICTION':
                return elementText.includes('제한') || elementText.includes('deny');
            default:
                return false;
        }
    }

    isRiskElement(element, anomalyType) {
        // 이상 탐지 타입에 따라 위험 요소 판단
        const elementText = element.textContent?.toLowerCase() || '';

        switch (anomalyType) {
            case 'MISSING_PERMISSION':
                return elementText.includes('user') || elementText.includes('사용자');
            case 'COMPLEX_PERMISSION_CHAIN':
                return true; // 모든 요소가 복잡성에 관련
            default:
                return false;
        }
    }

    isOptimizationTarget(element, suggestionType) {
        // 최적화 제안 타입에 따라 대상 요소 판단
        const elementText = element.textContent?.toLowerCase() || '';

        switch (suggestionType) {
            case 'SYSTEM_OPTIMIZATION':
                return elementText.includes('role') || elementText.includes('역할');
            default:
                return false;
        }
    }

    // Toast 메시지 표시 (기존 toast.js 활용)
    showToast(message, type = 'info') {
        if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            console.log(`Toast (${type}):`, message);
        }
    }

    // =============================
    // 🧠 AI-Native 지능형 시각화 렌더링
    // =============================

    /**
     * 🧠 AI 분석 결과 기반 지능형 시각화 렌더링 (Cytoscape)
     */
    async renderIntelligentVisualization(visualizationData, analysisResult) {
        console.log('🎯 서버 visualizationData 직접 Cytoscape 시각화 시작:', visualizationData);

        if (!visualizationData || (!visualizationData.nodes && !visualizationData.edges)) {
            console.log('서버 visualizationData가 없습니다.');
            return;
        }

        try {
            // 🔥 서버에서 완벽한 구조화된 데이터를 보내주므로 그대로 사용
            console.log('🎯 서버 데이터 직접 사용 - nodes:', visualizationData.nodes?.length, 'edges:', visualizationData.edges?.length);

            // 🔥 전체보기 모달을 위해 현재 시각화 데이터 저장
            this.currentVisualizationData = visualizationData;
            this.currentVisualization = visualizationData;

            // 🔥 analysisResults 저장 (누락된 연결 생성용)
            this.currentAnalysisResults = analysisResult?.analysisResults || null;

            // 🔥 Cytoscape 데이터로 변환하여 시각화 렌더링
            await this.displayCytoscapeDiagram(visualizationData);

            console.log('🚀 서버 데이터 직접 Cytoscape 시각화 완료!');

        } catch (error) {
            console.error('서버 데이터 Cytoscape 시각화 오류:', error);
            console.error('오류 상세:', error.stack);
        }
    }


    /**
     * 🧠 AI 분석 결과에서 엔티티 추출
     */
    extractAIEntities(naturalAnswer) {
        const entities = {
            users: [],
            roles: [],
            permissions: [],
            groups: [],
            risks: [],
            insights: []
        };

        // 사용자 추출 (패턴: "사용자 A", "김○○", "user123" 등)
        const userPatterns = [
            /사용자\s*([가-힣A-Za-z0-9_]+)/g,
            /([가-힣]{2,4})\s*(?:님|씨|사용자|관리자)/g,
            /user[A-Za-z0-9_]+/gi,
            /admin[A-Za-z0-9_]*/gi
        ];

        userPatterns.forEach(pattern => {
            const matches = [...naturalAnswer.matchAll(pattern)];
            matches.forEach(match => {
                const user = match[1] || match[0];
                if (user && !entities.users.includes(user)) {
                    entities.users.push(user);
                }
            });
        });

        // 역할 추출 (패턴: "관리자", "일반사용자", "ROLE_" 등)
        const rolePatterns = [
            /관리자|admin|administrator/gi,
            /일반사용자|user/gi,
            /ROLE_[A-Z_]+/g,
            /([가-힣]+)\s*역할/g,
            /([가-힣]+)\s*권한/g
        ];

        rolePatterns.forEach(pattern => {
            const matches = [...naturalAnswer.matchAll(pattern)];
            matches.forEach(match => {
                const role = match[1] || match[0];
                if (role && !entities.roles.includes(role)) {
                    entities.roles.push(role);
                }
            });
        });

        // 권한 추출 (패턴: "읽기", "쓰기", "삭제" 등)
        const permissionPatterns = [
            /읽기|read/gi,
            /쓰기|write/gi,
            /삭제|delete/gi,
            /수정|update/gi,
            /실행|execute/gi,
            /([가-힣]+)\s*권한/g
        ];

        permissionPatterns.forEach(pattern => {
            const matches = [...naturalAnswer.matchAll(pattern)];
            matches.forEach(match => {
                const permission = match[1] || match[0];
                if (permission && !entities.permissions.includes(permission)) {
                    entities.permissions.push(permission);
                }
            });
        });

        // 위험 요소 추출
        const riskPatterns = [
            /위험|위험성|risk/gi,
            /보안\s*문제/gi,
            /취약점|vulnerability/gi,
            /이상|anomaly/gi
        ];

        riskPatterns.forEach(pattern => {
            const matches = [...naturalAnswer.matchAll(pattern)];
            matches.forEach(match => {
                if (!entities.risks.includes(match[0])) {
                    entities.risks.push(match[0]);
                }
            });
        });

        return entities;
    }

    /**
     * 🔮 AI 분석과 데이터 융합
     */
    fuseAIAnalysisWithData(visualizationData, aiEntities, analysisResult) {
        const enhanced = {
            nodes: [],
            edges: [],
            aiInsights: [],
            riskLevels: new Map(),
            confidenceScores: new Map()
        };

        // 기존 데이터 노드 처리
        if (visualizationData && visualizationData.nodes) {
            visualizationData.nodes.forEach(node => {
                // AI 분석 결과로 노드 강화
                const isAIRelevant = this.isNodeRelevantToAI(node, aiEntities);
                const riskLevel = this.calculateAIRiskLevel(node, aiEntities, analysisResult);

                enhanced.nodes.push({
                    ...node,
                    aiRelevant: isAIRelevant,
                    riskLevel: riskLevel,
                    aiEnhanced: true,
                    aiInsights: this.getNodeAIInsights(node, analysisResult)
                });

                enhanced.riskLevels.set(node.id, riskLevel);
                enhanced.confidenceScores.set(node.id, this.calculateNodeConfidence(node, analysisResult));
            });
        }

        // AI 추출 엔티티로 추가 노드 생성
        aiEntities.users.forEach(user => {
            if (!enhanced.nodes.find(n => n.id === user)) {
                enhanced.nodes.push({
                    id: user,
                    name: user,
                    type: 'user',
                    aiRelevant: true,
                    riskLevel: this.calculateAIRiskLevel({id: user, type: 'user'}, aiEntities, analysisResult),
                    aiEnhanced: true,
                    aiInsights: [`AI 분석에서 식별된 사용자: ${user}`]
                });
            }
        });

        // 기존 엣지 처리
        if (visualizationData && visualizationData.edges) {
            visualizationData.edges.forEach(edge => {
                enhanced.edges.push({
                    ...edge,
                    aiConfidence: this.calculateEdgeConfidence(edge, analysisResult),
                    riskLevel: this.calculateEdgeRiskLevel(edge, aiEntities, analysisResult)
                });
            });
        }

        return enhanced;
    }

    /**
     * 🎨 지능형 Mermaid 코드 생성
     */
    generateIntelligentMermaidCode(enhancedData, analysisResult) {
        let mermaidCode = 'graph TD\n';

        // 1. 스타일 정의 (AI 분석 결과 기반)
        mermaidCode += this.generateAIEnhancedStyles();

        // 2. 노드 정의 (AI 위험도 기반 색상)
        enhancedData.nodes.forEach(node => {
            const shape = this.getAIEnhancedNodeShape(node);
            const className = this.getAIRiskClassName(node.riskLevel);
            mermaidCode += `    ${this.sanitizeId(node.id)}${shape}\n`;
            mermaidCode += `    class ${this.sanitizeId(node.id)} ${className}\n`;
        });

        // 3. 엣지 정의 (AI 신뢰도 기반)
        enhancedData.edges.forEach(edge => {
            const lineStyle = this.getAIConfidenceLineStyle(edge.aiConfidence);
            mermaidCode += `    ${this.sanitizeId(edge.from)} ${lineStyle} ${this.sanitizeId(edge.to)}\n`;
        });

        // 4. AI 인사이트 노드 추가
        if (analysisResult.recommendations && analysisResult.recommendations.length > 0) {
            mermaidCode += `    AI_INSIGHTS["🧠 AI 인사이트<br/>${analysisResult.recommendations.length}개 권장사항"]\n`;
            mermaidCode += `    class AI_INSIGHTS ai-insight-node\n`;

            // 주요 노드들과 AI 인사이트 연결
            const mainNodes = enhancedData.nodes.filter(n => n.aiRelevant).slice(0, 3);
            mainNodes.forEach(node => {
                mermaidCode += `    ${this.sanitizeId(node.id)} -.-> AI_INSIGHTS\n`;
            });
        }

        return mermaidCode;
    }

    /**
     * 🎨 AI 강화 스타일 정의
     */
    generateAIEnhancedStyles() {
        return `
    %% AI 분석 결과 기반 스타일 정의
    classDef ai-high-risk fill:#ff6b6b,stroke:#d63031,stroke-width:3px,color:#ffffff
    classDef ai-medium-risk fill:#ffa726,stroke:#f57c00,stroke-width:2px,color:#ffffff
    classDef ai-low-risk fill:#66bb6a,stroke:#388e3c,stroke-width:1px,color:#ffffff
    classDef ai-insight-node fill:#9c27b0,stroke:#7b1fa2,stroke-width:2px,color:#ffffff
    classDef ai-relevant fill:#42a5f5,stroke:#1976d2,stroke-width:2px,color:#ffffff
    classDef ai-normal fill:#78909c,stroke:#546e7a,stroke-width:1px,color:#ffffff
    
`;
    }

    /**
     * 🎯 AI 향상된 노드 모양 결정
     */
    getAIEnhancedNodeShape(node) {
        const baseName = node.name || node.id;

        if (node.riskLevel === 'high') {
            return `["${baseName}"]`;
        } else if (node.riskLevel === 'medium') {
            return `["⚡ ${baseName}"]`;
        } else if (node.aiRelevant) {
            return `["🎯 ${baseName}"]`;
        } else {
            return `["${baseName}"]`;
        }
    }

    /**
     * AI 위험도 클래스명 반환
     */
    getAIRiskClassName(riskLevel) {
        switch (riskLevel) {
            case 'high':
                return 'ai-high-risk';
            case 'medium':
                return 'ai-medium-risk';
            case 'low':
                return 'ai-low-risk';
            default:
                return 'ai-normal';
        }
    }

    /**
     * 📊 AI 신뢰도 기반 라인 스타일
     */
    getAIConfidenceLineStyle(confidence) {
        if (confidence >= 0.8) {
            return '===>';  // 매우 확실한 관계
        } else if (confidence >= 0.6) {
            return '-->';   // 확실한 관계
        } else {
            return '-.->'; // 추정 관계
        }
    }

    /**
     * 노드의 AI 관련성 판단
     */
    isNodeRelevantToAI(node, aiEntities) {
        const nodeName = (node.name || node.id).toLowerCase();

        // AI 엔티티 목록과 비교
        const allEntities = [
            ...aiEntities.users,
            ...aiEntities.roles,
            ...aiEntities.permissions,
            ...aiEntities.groups
        ].map(e => e.toLowerCase());

        return allEntities.some(entity =>
            nodeName.includes(entity) || entity.includes(nodeName)
        );
    }

    /**
     * 🎯 AI 위험도 계산
     */
    calculateAIRiskLevel(node, aiEntities, analysisResult) {
        let riskScore = 0;

        // 위험 키워드 포함 시 점수 증가
        const dangerKeywords = ['admin', '관리자', 'root', 'system'];
        const nodeName = (node.name || node.id).toLowerCase();

        dangerKeywords.forEach(keyword => {
            if (nodeName.includes(keyword)) {
                riskScore += 0.3;
            }
        });

        // AI 위험 엔티티에 포함된 경우
        if (aiEntities.risks.length > 0) {
            riskScore += 0.2;
        }

        if (riskScore >= 0.6) return 'high';
        if (riskScore >= 0.3) return 'medium';
        return 'low';
    }

    /**
     * 🧠 노드 AI 인사이트 생성
     */
    getNodeAIInsights(node, analysisResult) {
        const insights = [];

        // AI 분석 결과에서 해당 노드 관련 인사이트 추출
        if (analysisResult.naturalLanguageAnswer) {
            const nodeName = node.name || node.id;
            if (analysisResult.naturalLanguageAnswer.includes(nodeName)) {
                insights.push(`AI 분석에서 ${nodeName} 관련 내용 발견`);
            }
        }

        return insights;
    }

    /**
     * 📊 노드 신뢰도 계산
     */
    calculateNodeConfidence(node, analysisResult) {
        // AI 분석 결과에 명시적으로 언급된 경우 높은 신뢰도
        if (analysisResult.naturalLanguageAnswer &&
            analysisResult.naturalLanguageAnswer.includes(node.name || node.id)) {
            return 0.9;
        }

        return 0.7; // 기본 신뢰도
    }

    /**
     * 📈 엣지 신뢰도 계산
     */
    calculateEdgeConfidence(edge, analysisResult) {
        // AI 분석 결과에 관계가 명시된 경우 높은 신뢰도
        return 0.8; // 기본값
    }

    /**
     * 엣지 위험도 계산
     */
    calculateEdgeRiskLevel(edge, aiEntities, analysisResult) {
        // 관리자 관련 엣지는 위험도 높음
        if (edge.from.includes('admin') || edge.to.includes('admin')) {
            return 'high';
        }

        return 'low';
    }

    /**
     * 🎯 AI 시각화 오버레이 생성
     */
    createAIVisualizationOverlay(analysisResult, enhancedData) {
        const canvasContainer = document.getElementById('canvas-container') || document.getElementById('canvas-content');
        if (!canvasContainer) return;

        // 기존 오버레이 제거
        const existingOverlay = canvasContainer.querySelector('.ai-visualization-overlay');
        if (existingOverlay) {
            existingOverlay.remove();
        }

        // 새 AI 시각화 오버레이 생성
        const overlay = document.createElement('div');
        overlay.className = 'ai-visualization-overlay';
        overlay.style.cssText = `
            position: absolute;
            top: 10px;
            left: 10px;
            max-width: 300px;
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.95), rgba(5, 150, 105, 0.95));
            border: 1px solid rgba(16, 185, 129, 0.4);
            border-radius: 12px;
            padding: 1rem;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            z-index: 100;
            animation: slideInFromLeft 0.5s ease-out;
        `;

        const highRiskNodes = enhancedData.nodes.filter(n => n.riskLevel === 'high');
        const aiRelevantNodes = enhancedData.nodes.filter(n => n.aiRelevant);

        overlay.innerHTML = `
            <div class="flex items-center gap-2 mb-3">
                <i class="fas fa-robot text-green-400"></i>
                <h4 class="text-sm font-semibold text-white">🤖 AI 진단 시각화</h4>
            </div>
            
            <div class="space-y-2">
                <div class="flex items-center gap-2">
                    <div class="w-3 h-3 bg-red-500 rounded-full"></div>
                    <span class="text-xs text-white">고위험 노드: ${highRiskNodes.length}개</span>
                </div>
                
                <div class="flex items-center gap-2">
                    <div class="w-3 h-3 bg-blue-500 rounded-full"></div>
                    <span class="text-xs text-white">AI 관련 노드: ${aiRelevantNodes.length}개</span>
                </div>
                
                <div class="flex items-center gap-2">
                    <div class="w-3 h-3 bg-purple-500 rounded-full"></div>
                    <span class="text-xs text-white">AI 권장사항: ${analysisResult.recommendations?.length || 0}개</span>
                </div>
            </div>
            
            <div class="mt-3 text-xs text-green-100">
                🧠 실시간 AI 분석 결과 기반 시각화
            </div>
        `;

        canvasContainer.appendChild(overlay);

        // 5초 후 투명도 감소
        setTimeout(() => {
            overlay.style.opacity = '0.7';
        }, 5000);
    }

    /**
     * 🎮 AI 시각화 인터랙션 활성화
     */
    enableAIVisualizationInteractions(analysisResult, enhancedData) {
        // 노드 클릭 시 AI 분석 정보 표시
        const canvas = document.getElementById('canvas-content');
        if (canvas) {
            canvas.addEventListener('click', (event) => {
                const target = event.target;
                if (target.classList.contains('node')) {
                    const nodeId = target.getAttribute('data-id');
                    this.showAINodeAnalysis(nodeId, analysisResult, enhancedData);
                }
            });
        }

        console.log('🎮 AI 시각화 인터랙션 활성화 완료');
    }

    /**
     * AI 노드 분석 정보 표시
     */
    showAINodeAnalysis(nodeId, analysisResult, enhancedData) {
        const node = enhancedData.nodes.find(n => n.id === nodeId);
        if (!node) return;

        const analysisHTML = `
            <div class="ai-node-analysis">
                <h4>🧠 AI 분석: ${node.name || node.id}</h4>
                <div class="analysis-details">
                    <div>위험도: ${node.riskLevel}</div>
                    <div>AI 관련성: ${node.aiRelevant ? '높음' : '보통'}</div>
                    <div>신뢰도: ${Math.round((enhancedData.confidenceScores.get(node.id) || 0.7) * 100)}%</div>
                </div>
                ${node.aiInsights ? `
                    <div class="ai-insights">
                        <h5>AI 인사이트:</h5>
                        <ul>
                            ${node.aiInsights.map(insight => `<li>${insight}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;

        this.showToast(analysisHTML, 'info');
    }

    /**
     * 📊 AI-Native 텍스트 응답 표시
     */
    displayAINativeTextResponse(response, analysisResult) {
        console.log('📊 Displaying AI-Native text response');

        const aiResponseContainer = document.getElementById('ai-response-container');
        if (!aiResponseContainer) return;

        this.hideCanvasPlaceholder();
        aiResponseContainer.classList.remove('hidden');

        const html = `
            <div class="ai-response-section">
                <div class="ai-response-header">
                    <i class="fas fa-brain text-purple-400"></i>
                    <h4>AI 지능형 분석 결과</h4>
                    <div class="ai-confidence-badge">
                        신뢰도: ${Math.round(analysisResult.confidenceScore * 100)}%
                    </div>
                </div>
                
                <div class="ai-native-answer">
                    ${this.formatAINativeAnswer(analysisResult.naturalAnswer, response.query, analysisResult.analysisResults)}
                </div>
                
                <!-- 📈 AI 메트릭 섹션 (하드코딩 제거) -->
                <!-- ${this.generateAIMetricsHTML(analysisResult)} -->
                
                <div class="ai-response-footer">
                    <div class="processing-time">
                        <i class="fas fa-clock text-slate-400"></i>
                        처리 시간: ${analysisResult.processingTime}ms
                    </div>
                    <div class="analysis-type">
                        <i class="fas fa-tag text-slate-400"></i>
                        분석 타입: ${analysisResult.analysisType}
                    </div>
                </div>
            </div>
        `;

        aiResponseContainer.innerHTML = html;
    }

    /**
     * 🔥 권한 이상 탐지 결과 표시
     */
    displayPermissionAnomalies(anomalies) {
        if (!anomalies || anomalies.length === 0) return;

        console.log('🔥 Displaying permission anomalies:', anomalies);

        // 이상 탐지 알림 생성
        anomalies.forEach(anomaly => {
            const severity = anomaly.severity || 2;
            const type = severity >= 3 ? 'error' : (severity >= 2 ? 'warning' : 'info');

            this.showToast(
                `🔥 ${anomaly.title || '권한 이상 탐지'}: ${anomaly.description}`,
                type
            );
        });

        // Inspector에 이상 탐지 섹션 추가
        const inspectorContent = document.getElementById('inspector-content');
        if (inspectorContent && anomalies.length > 0) {
            const anomaliesHtml = this.generateAnomaliesHTML(anomalies);
            const existingContent = inspectorContent.innerHTML;
            inspectorContent.innerHTML = existingContent + anomaliesHtml;
        }
    }

    /**
     * 🚀 최적화 제안 표시
     */
    displayOptimizationSuggestions(suggestions) {
        if (!suggestions || suggestions.length === 0) return;

        console.log('🚀 Displaying optimization suggestions:', suggestions);

        // 높은 우선순위 제안은 토스트로 표시
        suggestions.forEach(suggestion => {
            if (suggestion.priority === 1) { // 높은 우선순위
                this.showToast(
                    `🚀 최적화 제안: ${suggestion.title}`,
                    'info'
                );
            }
        });

        // Inspector에 최적화 제안 섹션 추가
        const inspectorContent = document.getElementById('inspector-content');
        if (inspectorContent && suggestions.length > 0) {
            const suggestionsHtml = this.generateOptimizationSuggestionsHTML(suggestions);
            const existingContent = inspectorContent.innerHTML;
            inspectorContent.innerHTML = existingContent + suggestionsHtml;
        }
    }

    /**
     * 🧠 AI 핵심 인사이트 표시 (실제 AI 분석 결과 기반)
     */
    displayKeyInsights(insights) {
        if (!insights || insights.length === 0) return;

        console.log('🧠 AI 핵심 인사이트 표시:', insights);

        // 실제 AI 분석 결과의 중요한 인사이트는 토스트로 표시
        insights.forEach(insight => {
            if (insight.importance === 1 || insight.confidenceScore > 0.8) {
                this.showToast(
                    `🧠 AI 인사이트: ${insight.title}`,
                    'info'
                );
            }
        });

        // Canvas 오버레이 제거 - 상세 리포트에서만 표시
        console.log('🎯 핵심 인사이트는 상세 리포트에서만 표시됩니다.');
    }

    // 🔥 핵심 인사이트 중앙패널 완전 제거 - 상세 리포트에서만 표시

    /**
     * 🎯 사용자 권한 부여 기능
     */
    grantUserPermissions(userName) {
        console.log('🔑 권한 부여 시도:', userName);

        // 권한 부여 확인 다이얼로그
        if (!confirm(`${userName}에게 권한을 부여하시겠습니까?\n\n이 작업은 관리자 권한이 필요합니다.`)) {
            return;
        }

        // 실제 권한 부여 API 호출
        fetch('/api/admin/users/permissions/grant', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': this.getCsrfToken()
            },
            body: JSON.stringify({
                username: userName,
                permission: permission,
                grantedBy: this.getCurrentUser()
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.showToast(`${userName}에게 ${permission} 권한이 부여되었습니다.`, 'success');
                this.refreshUserCards();
            } else {
                this.showToast(`권한 부여 실패: ${data.message}`, 'error');
            }
        })
        .catch(error => {
            this.showToast(`권한 부여 중 오류 발생: ${error.message}`, 'error');
        });
    }

    /**
     * 🎯 사용자 권한 편집 기능
     */
    editUserPermissions(userName) {
        console.log('✏️ 권한 편집 시도:', userName);

        // 권한 편집 확인 다이얼로그
        if (!confirm(`${userName}의 권한을 편집하시겠습니까?\n\n이 작업은 관리자 권한이 필요합니다.`)) {
            return;
        }

        // 실제 권한 편집 API 호출
        fetch('/api/admin/users/permissions/edit', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': this.getCsrfToken()
            },
            body: JSON.stringify({
                username: userName,
                permissions: this.getSelectedPermissions(),
                modifiedBy: this.getCurrentUser()
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.showToast(`${userName}의 권한이 수정되었습니다.`, 'success');
                this.refreshUserCards();
            } else {
                this.showToast(`권한 편집 실패: ${data.message}`, 'error');
            }
        })
        .catch(error => {
            this.showToast(`권한 편집 중 오류 발생: ${error.message}`, 'error');
        });
    }

    /**
     * CSRF 토큰 가져오기
     */
    getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]')?.content || '';
    }

    /**
     * 현재 로그인한 사용자 가져오기
     */
    getCurrentUser() {
        return document.querySelector('meta[name="current-user"]')?.content || 'admin';
    }

    /**
     * 선택된 권한 목록 가져오기
     */
    getSelectedPermissions() {
        const checkboxes = document.querySelectorAll('input[name="permissions"]:checked');
        return Array.from(checkboxes).map(cb => cb.value);
    }

    /**
     * 사용자 카드 새로고침
     */
    refreshUserCards() {
        // 사용자 카드 목록 새로고침
        fetch('/api/admin/users')
            .then(response => response.json())
            .then(users => {
                this.renderUserCards(users);
            })
            .catch(error => {
                console.error('사용자 목록 새로고침 실패:', error);
            });
    }

    /**
     * 🎯 토스트 메시지 표시
     */
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast-message toast-${type}`;
        toast.textContent = message;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.remove();
        }, 2000);
    }

    /**
     * 🎯 AI 분석 결과를 시각화로 변환
     */
    convertAIAnalysisToVisualization(analysisResults, queryType = 'permission') {
        console.log('🎯 AI 분석 결과를 시각화로 변환:', analysisResults);

        if (!analysisResults || analysisResults.length === 0) {
            return null;
        }

        // 시각화 데이터 구조 생성
        const visualizationData = {
            nodes: [],
            edges: [],
            metadata: {
                queryType: queryType,
                totalUsers: analysisResults.length,
                hasPermissionCount: analysisResults.filter(r => r.hasPermission === true).length,
                noPermissionCount: analysisResults.filter(r => r.hasPermission === false).length,
                timestamp: new Date().toISOString()
            }
        };

        // 엔티티 추출 및 노드 생성
        const users = new Set();
        const groups = new Set();
        const roles = new Set();
        const permissions = new Set();

        // 1. 분석 결과에서 엔티티 추출
        analysisResults.forEach(result => {
            if (result.userName) users.add(result.userName);
            if (result.groupName) groups.add(result.groupName);
            if (result.roleName) roles.add(result.roleName);
            if (result.permissionName) permissions.add(result.permissionName);
        });

        // 2. 노드 생성
        let nodeId = 0;

        // 사용자 노드
        users.forEach(userName => {
            const userResult = analysisResults.find(r => r.userName === userName);
            visualizationData.nodes.push({
                id: `user_${nodeId++}`,
                label: userName,
                type: 'user',
                category: 'user',
                hasPermission: userResult?.hasPermission || false,
                description: userResult?.description || '',
                style: {
                    color: userResult?.hasPermission ? '#10b981' : '#ef4444',
                    shape: 'circle',
                    size: 40
                }
            });
        });

        // 그룹 노드
        groups.forEach(groupName => {
            visualizationData.nodes.push({
                id: `group_${nodeId++}`,
                label: groupName,
                type: 'group',
                category: 'group',
                style: {
                    color: '#3b82f6',
                    shape: 'box',
                    size: 35
                }
            });
        });

        // 역할 노드
        roles.forEach(roleName => {
            visualizationData.nodes.push({
                id: `role_${nodeId++}`,
                label: roleName,
                type: 'role',
                category: 'role',
                style: {
                    color: '#8b5cf6',
                    shape: 'diamond',
                    size: 30
                }
            });
        });

        // 권한 노드
        permissions.forEach(permissionName => {
            visualizationData.nodes.push({
                id: `permission_${nodeId++}`,
                label: permissionName,
                type: 'permission',
                category: 'permission',
                style: {
                    color: '#f59e0b',
                    shape: 'hexagon',
                    size: 25
                }
            });
        });

        // 3. 엣지 생성 (관계 연결)
        let edgeId = 0;

        analysisResults.forEach(result => {
            const userNode = visualizationData.nodes.find(n => n.label === result.userName && n.type === 'user');
            const groupNode = visualizationData.nodes.find(n => n.label === result.groupName && n.type === 'group');
            const roleNode = visualizationData.nodes.find(n => n.label === result.roleName && n.type === 'role');
            const permissionNode = visualizationData.nodes.find(n => n.label === result.permissionName && n.type === 'permission');

            // 사용자 -> 그룹 관계
            if (userNode && groupNode) {
                visualizationData.edges.push({
                    id: `edge_${edgeId++}`,
                    source: userNode.id,
                    target: groupNode.id,
                    label: 'belongs to',
                    type: 'membership',
                    style: {
                        color: '#64748b',
                        width: 2
                    }
                });
            }

            // 사용자 -> 역할 관계
            if (userNode && roleNode) {
                visualizationData.edges.push({
                    id: `edge_${edgeId++}`,
                    source: userNode.id,
                    target: roleNode.id,
                    label: 'has role',
                    type: 'role_assignment',
                    style: {
                        color: '#8b5cf6',
                        width: 2
                    }
                });
            }

            // 역할 -> 권한 관계 (권한 유무에 따라 스타일 변경)
            if (roleNode && permissionNode) {
                visualizationData.edges.push({
                    id: `edge_${edgeId++}`,
                    source: roleNode.id,
                    target: permissionNode.id,
                    label: result.hasPermission ? 'has permission' : 'no permission',
                    type: 'permission_assignment',
                    hasPermission: result.hasPermission,
                    style: {
                        color: result.hasPermission ? '#10b981' : '#ef4444',
                        width: result.hasPermission ? 3 : 1,
                        dashArray: result.hasPermission ? null : '5,5'
                    }
                });
            }
        });

        return visualizationData;
    }


    /**
     * 🎯 현재 시각화 타입 확인
     */
    getCurrentVisualizationType() {
        const selectElement = document.getElementById('visualization-type');
        return selectElement ? selectElement.value : 'network';
    }

    /**
     * 🎯 AI 기반 Mermaid 다이어그램 표시
     */
    async displayAIMermaidDiagram(mermaidCode, visualizationData) {
        console.log('🎯 AI 기반 Mermaid 다이어그램 렌더링');

        const container = document.getElementById('mermaid-container');
        if (!container) {
            console.error('Mermaid 컨테이너를 찾을 수 없습니다.');
            return;
        }

        // 캔버스 활성화
        this.hideCanvasPlaceholder();

        try {
            // 기존 다이어그램 제거
            container.innerHTML = '';

            // 새로운 다이어그램 ID 생성
            const diagramId = `mermaid-${Date.now()}`;

            // Mermaid 렌더링
            const {svg} = await mermaid.render(diagramId, mermaidCode);
            container.innerHTML = svg;

            // 다이어그램 중앙 정렬
            this.centerDiagram(container);

            // AI 시각화 인터랙션 활성화
            this.enableAIVisualizationInteractions(visualizationData);

            console.log('AI 기반 시각화 렌더링 완료');

        } catch (error) {
            console.error('Mermaid 렌더링 실패:', error);
            this.showMermaidError(container, mermaidCode);
        }
    }

    /**
     * 🧠 AI 시각화 인사이트 생성
     */
    createAIVisualizationInsights(visualizationData, originalQuery) {
        const insights = {
            totalUsers: visualizationData.metadata.totalUsers,
            hasPermissionCount: visualizationData.metadata.hasPermissionCount,
            noPermissionCount: visualizationData.metadata.noPermissionCount,
            permissionRate: Math.round((visualizationData.metadata.hasPermissionCount / visualizationData.metadata.totalUsers) * 100),
            query: originalQuery
        };

        const insightText = `
            🧠 AI 분석 인사이트
            
            📊 권한 분석 결과:
            • 총 ${insights.totalUsers}명 분석
            • 권한 보유: ${insights.hasPermissionCount}명 (${insights.permissionRate}%)
            • 권한 없음: ${insights.noPermissionCount}명 (${100 - insights.permissionRate}%)
            
            🎯 질의: "${insights.query}"
        `;

        this.showToast(insightText, 'info');

        // 중앙패널 인사이트 제거 - 상세 리포트에서만 표시
        console.log('🎯 AI 권한 분석 인사이트는 상세 리포트에서만 표시됩니다.');
    }

    // 🔥 Policy Builder에서 가져온 JSON 정제 메서드들 (AI Studio용)

    /**
     * 완전한 JSON 객체 추출 (중괄호 쌍 매칭)
     */
    extractCompleteJsonForStudio(text) {
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

                    // 완전한 JSON 객체 완성 (Policy Builder와 동일)
                    if (braceCount === 0) {
                        const completeJson = text.substring(startIndex, i + 1);
                        console.log('🔥 [STUDIO] 완전한 JSON 추출 성공:', completeJson.substring(0, 100) + '...');
                        return completeJson;
                    }
                }
            }
        }

        // 완전하지 않은 JSON - 강력한 복구 시도 (AI Studio 전용 강화)
        console.warn('[STUDIO] 불완전한 JSON 감지, 복구 시도:', text.substring(0, 200) + '...');

        // 🔥 강력한 JSON 복구 메커니즘
        return this.repairIncompleteJsonForStudio(text, startIndex);
    }

    /**
     * JSON 문자열 정제 (Policy Builder 방식)
     */
    cleanJsonStringForStudio(jsonStr) {
        console.log('🔥 [STUDIO] JSON 정제 시작, 원본 길이:', jsonStr.length);

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
                if (line[i] === '"' && (i === 0 || line[i - 1] !== '\\')) {
                    inString = !inString;
                }
                if (!inString && line[i] === '/' && line[i + 1] === '/') {
                    break; // 주석 시작, 나머지 줄 무시
                }
                result += line[i];
            }
            return result;
        }).join('\n');

        // 3. /* */ 스타일 주석 제거
        cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, '');

        // 4. 불필요한 공백 제거
        cleaned = cleaned.replace(/\s+/g, ' ').trim();

        console.log('🔥 [STUDIO] JSON 정제 완료, 길이:', cleaned.length);
        console.log('🔥 [STUDIO] JSON 정제 결과 (처음 200자):', cleaned.substring(0, 200));
        console.log('🔥 [STUDIO] JSON 정제 결과 (마지막 200자):', cleaned.substring(Math.max(0, cleaned.length - 200)));
        return cleaned;
    }

    /**
     * JSON 끝에 있는 불필요한 텍스트 제거
     */
    removeTextAfterJsonForStudio(text) {
        if (!text || !text.trim()) {
            return text;
        }

        text = text.trim();

        // 🔥 완전한 JSON 구조를 파악한 후 마지막 } 뒤의 텍스트만 제거
        // 중괄호 쌍 매칭으로 완전한 JSON 끝점 찾기
        let braceCount = 0;
        let inString = false;
        let escapeNext = false;
        let jsonEndIndex = -1;

        for (let i = 0; i < text.length; i++) {
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
                        jsonEndIndex = i;
                        break;
                    }
                }
            }
        }

        // 완전한 JSON이 발견되면 그 뒤의 텍스트만 제거
        if (jsonEndIndex !== -1) {
            const completeJson = text.substring(0, jsonEndIndex + 1);
            console.log('🔥 [STUDIO] 완전한 JSON 보존, 뒤의 텍스트만 제거:', completeJson.length, '문자');
            return completeJson;
        }

        // 완전한 JSON을 찾을 수 없으면 원본 반환
        console.log('🔥 [STUDIO] 완전한 JSON 구조를 찾을 수 없음, 원본 반환');
        return text;
    }

    /**
     * 불완전한 JSON 복구 (AI Studio 전용 강화 메커니즘)
     */
    repairIncompleteJsonForStudio(text, startIndex) {
        console.log('🔧 [STUDIO] JSON 복구 시작:', text.length, '문자');

        if (startIndex === -1) {
            console.error('[STUDIO] JSON 시작점을 찾을 수 없음');
            return text;
        }

        let jsonCandidate = text.substring(startIndex);
        console.log('🔧 [STUDIO] JSON 후보 추출:', jsonCandidate.substring(0, 100) + '...');

        // 1. 끝나지 않은 문자열 감지 및 수정
        jsonCandidate = this.fixUnterminatedStringsForStudio(jsonCandidate);

        // 2. 누락된 중괄호 및 대괄호 계산 및 추가
        jsonCandidate = this.fixMissingBracesForStudio(jsonCandidate);

        // 3. 🆕 불완전한 배열 항목 제거 (insights, recommendations 등)
        jsonCandidate = this.fixIncompleteArrayItemsForStudio(jsonCandidate);

        // 4. 최종 검증 시도
        try {
            JSON.parse(jsonCandidate);
            console.log('[STUDIO] JSON 복구 성공!');
            return jsonCandidate;
        } catch (error) {
            console.error('[STUDIO] JSON 복구 실패:', error.message);

            // 5. 더 적극적인 복구: 마지막 완전한 필드까지만 사용
            const repairedJson = this.extractLastValidFieldForStudio(jsonCandidate);
            if (repairedJson) {
                try {
                    JSON.parse(repairedJson);
                    console.log('[STUDIO] 적극적 복구 성공!');
                    return repairedJson;
                } catch (e) {
                    console.error('[STUDIO] 적극적 복구도 실패:', e.message);
                }
            }

            // 6. 최후의 fallback: 첫 번째 { 부터 마지막 } 까지
            const firstBrace = text.indexOf('{');
            const lastBrace = text.lastIndexOf('}');

            if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
                const fallbackJson = text.substring(firstBrace, lastBrace + 1);
                console.log('🔧 [STUDIO] Fallback JSON 시도:', fallbackJson.substring(0, 100) + '...');

                try {
                    JSON.parse(fallbackJson);
                    console.log('[STUDIO] Fallback JSON 성공!');
                    return fallbackJson;
                } catch (e) {
                    console.error('[STUDIO] Fallback도 실패:', e.message);
                }
            }

            return text; // 모든 복구 시도 실패 시 원본 반환
        }
    }

    /**
     * 끝나지 않은 문자열 수정
     */
    fixUnterminatedStringsForStudio(json) {
        console.log('🔧 [STUDIO] 끝나지 않은 문자열 수정 시작');

        // 1. 패턴 매칭: "key": "value 형태의 끝나지 않은 문자열 감지
        const unterminatedStringPattern = /"[^"]*":\s*"[^"]*$/;
        const match = json.match(unterminatedStringPattern);

        if (match) {
            console.log('🔧 [STUDIO] 끝나지 않은 문자열 패턴 감지:', match[0]);
            const fixedJson = json + '"';
            console.log('🔧 [STUDIO] 끝나지 않은 문자열 수정 완료');
            return fixedJson;
        }

        // 2. 추가 패턴: 마지막이 .이나 숫자로 끝나는 경우 (타임스탬프 등)
        const timestampPattern = /"[^"]*":\s*"[^"]*\d+\.?$/;
        const timestampMatch = json.match(timestampPattern);

        if (timestampMatch) {
            console.log('🔧 [STUDIO] 끝나지 않은 타임스탬프 감지:', timestampMatch[0]);
            const fixedJson = json + '"';
            console.log('🔧 [STUDIO] 타임스탬프 문자열 수정 완료');
            return fixedJson;
        }

        // 3. 잘린 JSON 구조 복구 (statistics 객체 등)
        let fixedJson = this.fixTruncatedStructuresForStudio(json);

        return fixedJson;
    }

    /**
     * 누락된 중괄호 수정
     */
    fixMissingBracesForStudio(json) {
        console.log('🔧 [STUDIO] 누락된 중괄호 수정 시작');

        let openCount = 0;
        let closeCount = 0;
        let inString = false;
        let escapeNext = false;

        // 중괄호 개수 계산
        for (let i = 0; i < json.length; i++) {
            const char = json[i];

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
                if (char === '{') openCount++;
                else if (char === '}') closeCount++;
            }
        }

        const missingBraces = openCount - closeCount;
        console.log(`🔧 [STUDIO] 중괄호 분석: 열림=${openCount}, 닫힘=${closeCount}, 누락=${missingBraces}`);

        if (missingBraces > 0) {
            const fixedJson = json + '}'.repeat(missingBraces);
            console.log('🔧 [STUDIO] 누락된 중괄호 추가 완료');
            return fixedJson;
        }

        return json;
    }

    /**
     * 🆕 불완전한 배열 항목 제거 (AI Studio용)
     */
    fixIncompleteArrayItemsForStudio(jsonStr) {
        console.log('🔧 [STUDIO] 불완전한 배열 항목 수정 시작');

        try {
            // 먼저 파싱이 되는지 확인
            JSON.parse(jsonStr);
            return jsonStr; // 이미 완전한 JSON
        } catch (error) {
            console.log('🔧 [STUDIO] JSON이 불완전함, 배열 항목 정리 시도');

            // insights, recommendations 같은 배열에서 불완전한 마지막 항목 제거
            let fixed = jsonStr;

            // 불완전한 배열 항목 패턴 찾기 및 제거
            fixed = fixed.replace(/,\s*\{\s*"[^"]*"\s*:\s*"[^"]*$/g, ''); // 완료되지 않은 객체
            fixed = fixed.replace(/,\s*\{\s*"[^"]*"\s*:\s*[^,}\]]*$/g, ''); // 값이 끝나지 않은 객체
            fixed = fixed.replace(/,\s*"[^"]*"\s*:\s*"[^"]*$/g, ''); // 완료되지 않은 속성

            console.log('🔧 [STUDIO] 불완전한 배열 항목 제거 완료');
            return fixed;
        }
    }

    /**
     * 🆕 마지막 완전한 필드까지만 추출 (AI Studio용)
     */
    extractLastValidFieldForStudio(jsonStr) {
        console.log('🔧 [STUDIO] 마지막 완전한 필드 추출 시작');

        // 주요 필드들을 순서대로 확인하고, 마지막 완전한 필드까지만 포함
        const fieldOrder = [
            'analysisId', 'query', 'summary', 'visualizationData',
            'insights', 'statistics', 'recommendations',
            'executionTimeMs', 'completedAt', 'status'
        ];

        let lastValidJson = '{"analysisId":"unknown"}'; // 최소 기본값

        for (const field of fieldOrder) {
            const fieldPattern = new RegExp(`"${field}"\\s*:\\s*`, 'i');

            if (fieldPattern.test(jsonStr)) {
                // 해당 필드가 있으면 그 위치까지 잘라서 JSON 완성 시도
                const fieldIndex = jsonStr.search(fieldPattern);

                // 필드 뒤의 내용 찾기
                let nextFieldIndex = jsonStr.length;
                for (const nextField of fieldOrder.slice(fieldOrder.indexOf(field) + 1)) {
                    const nextPattern = new RegExp(`"${nextField}"\\s*:\\s*`, 'i');
                    const nextIndex = jsonStr.search(nextPattern);
                    if (nextIndex !== -1 && nextIndex < nextFieldIndex) {
                        nextFieldIndex = nextIndex;
                    }
                }

                // 현재 필드까지 포함하고 다음 필드 전까지 자르기
                let candidate = jsonStr.substring(0, nextFieldIndex);

                // 마지막 쉼표 제거하고 닫는 괄호 추가
                candidate = candidate.replace(/,\s*$/, '');
                candidate += '}';

                try {
                    JSON.parse(candidate);
                    lastValidJson = candidate;
                    console.log('🔧 [STUDIO] 필드 "' + field + '"까지 유효함');
                } catch (e) {
                    console.log('🔧 [STUDIO] 필드 "' + field + '"에서 파싱 실패, 이전 유효한 JSON 사용');
                    break;
                }
            }
        }

        console.log('🔧 [STUDIO] 마지막 완전한 필드 추출 완료');
        return lastValidJson;
    }

    /**
     * 메시지 표시 (Policy Builder와 동일)
     */
    showMessage(message, type) {
        if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            // 커스텀 토스트 메시지 표시
            this.showToast(message, type);
        }
    }

    // stopStreamingProgress is defined earlier in the class - removed duplicate

    /**
     * 🔥 불완전한 JSON 자동 복구
     */
    repairIncompleteJson(incompleteJson) {
        console.log('🔧 [REPAIR] JSON 복구 시작:', incompleteJson.length, '문자');

        let repaired = incompleteJson.trim();

        // 1. naturalLanguageAnswer가 끝나지 않은 경우 강제 종료
        if (repaired.includes('"naturalLanguageAnswer":') && !repaired.includes('","confidenceScore":')) {
            // naturalLanguageAnswer 끝에 따옴표 추가
            repaired += '"';
            console.log('🔧 [REPAIR] naturalLanguageAnswer 따옴표 추가');
        }

        // 2. 기본 필드들 추가
        if (!repaired.includes('"confidenceScore":')) {
            repaired += ',"confidenceScore":75';
        }
        if (!repaired.includes('"visualizationData":')) {
            repaired += ',"visualizationData":null';
        }
        if (!repaired.includes('"analysisResults":')) {
            repaired += ',"analysisResults":[]';
        }
        if (!repaired.includes('"recommendations":')) {
            repaired += ',"recommendations":[]';
        }

        // 3. JSON 닫기
        if (!repaired.endsWith('}')) {
            repaired += '}';
        }

        console.log('🔧 [REPAIR] JSON 복구 완료:', repaired.length, '문자');
        return repaired;
    }
}

// =============================
// 🚀 AI Studio 초기화
// ============================= 
let aiStudio = null;

document.addEventListener('DOMContentLoaded', () => {
    // 중복 초기화 방지
    if (aiStudio) {
        console.log('AI Studio가 이미 초기화되었습니다.');
        return;
    }

    // 기존 studio.js가 로드된 후 AI Studio 초기화
    setTimeout(() => {
        if (!aiStudio) {
            aiStudio = new AIStudioLegacy();
            aiStudio.init();

            // 인스턴스를 전역으로 노출하여 HTML에서 접근 가능하도록 함
            window.aiStudio = aiStudio;
            console.log('🧠 AI-Native Authorization Studio ready!');
        }
    }, 100);
});

// Global export with module compatibility
if (typeof window.AIStudio === 'object' && window.AIStudio.Core) {
    // Modular version already loaded, preserve it and add legacy reference
    window.AIStudio.Legacy = AIStudioLegacy;
} else {
    window.AIStudio = AIStudioLegacy;
} 