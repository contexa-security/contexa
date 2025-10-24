/**
 * SOAR Approval Handler
 * 
 * WebSocket 메시지와 승인 모달을 연결하는 핵심 핸들러
 * 이벤트 기반 아키텍처로 승인 플로우를 완벽하게 처리
 */
class SoarApprovalHandler {
    constructor() {
        this.approvalModal = null;
        this.websocketClient = null;
        this.pendingApprovals = new Map();
        this.approvalHistory = [];
        this.initialized = false;
        this.eventListeners = new Map();
        this.approvalTimeout = 300000; // 5분
        this.retryAttempts = 3;
        this.retryDelay = 2000;
    }

    /**
     * 핸들러 초기화
     * @param {EnhancedWebSocketClient} websocketClient - WebSocket 클라이언트
     * @param {SoarApprovalModal} approvalModal - 승인 모달
     */
    initialize(websocketClient, approvalModal) {
        if (this.initialized) {
            console.warn('SoarApprovalHandler already initialized');
            return true;
        }

        console.log('🔐 ===========================================');
        console.log('🔐 INITIALIZING SOAR APPROVAL HANDLER');
        console.log('🔐 WebSocket client provided:', !!websocketClient);
        console.log('🔐 Approval modal provided:', !!approvalModal);
        
        if (!websocketClient) {
            console.error('WebSocket client is required');
            return false;
        }
        
        if (!approvalModal) {
            console.error('Approval modal is required');
            return false;
        }

        this.websocketClient = websocketClient;
        this.approvalModal = approvalModal;

        // WebSocket 연결 상태 확인
        const isConnected = websocketClient.isConnected ? websocketClient.isConnected() : false;
        console.log('🔐 WebSocket connection status:', isConnected);
        
        if (isConnected) {
            // 즉시 리스너 등록
            console.log('🔐 WebSocket is connected, registering listeners immediately');
            this.registerWebSocketListeners();
        } else {
            // 연결 대기 후 리스너 등록
            console.log('⏳ WebSocket not yet connected, waiting for connection...');
            if (websocketClient.on) {
                websocketClient.on('connected', () => {
                    console.log('🔐 WebSocket connected event received, registering listeners');
                    this.registerWebSocketListeners();
                });
            } else {
                console.warn('WebSocket client does not support event listeners');
                // 폴백: 즉시 등록 시도
                this.registerWebSocketListeners();
            }
        }
        
        // 타임아웃 모니터링 시작
        this.startTimeoutMonitoring();
        
        this.initialized = true;
        console.log('SoarApprovalHandler initialization complete');
        console.log('📊 Status:', {
            initialized: this.initialized,
            modal: !!this.approvalModal,
            websocket: !!this.websocketClient,
            connected: isConnected
        });
        console.log('🔐 ===========================================');
        return true;
    }

    /**
     * WebSocket 이벤트 리스너 등록
     */
    registerWebSocketListeners() {
        if (!this.websocketClient) {
            console.error('WebSocket client not available');
            return;
        }

        // 승인 요청 메시지 처리
        this.websocketClient.on('approvals', (data) => {
            console.log('🎯 ===========================================');
            console.log('🎯 APPROVAL EVENT RECEIVED IN HANDLER');
            console.log('🎯 Message type:', data.type);
            console.log('🎯 Approval ID:', data.approvalId || data.requestId || 'N/A');
            console.log('🎯 Tool Name:', data.toolName || 'N/A');
            console.log('🎯 Full message data:', JSON.stringify(data, null, 2));
            console.log('🎯 ===========================================');
            
            // 메시지 타입별 처리
            if (data.type === 'APPROVAL_REQUEST') {
                console.log('🔐 APPROVAL_REQUEST type matched! Processing...');
                console.log('🔐 Approval modal available:', this.approvalModal !== null);
                console.log('🔐 Calling handleApprovalRequest with data:', data);
                this.handleApprovalRequest(data);
            } else if (data.type === 'APPROVAL_TIMEOUT') {
                console.log('⏱️ Processing APPROVAL_TIMEOUT message');
                this.handleServerApprovalTimeout(data);
            } else if (data.type === 'APPROVAL_PROCESSED') {
                console.log('Processing APPROVAL_PROCESSED message');
                this.handleApprovalProcessed(data);
            } else {
                // 기타 메시지도 처리 - 타입이 없는 경우 기본 승인 요청으로 처리
                console.log('📨 Unknown message type, processing as default approval request');
                console.log('📨 Type was:', data.type || 'undefined');
                this.handleApprovalRequest(data);
            }
        });

        // 승인 처리 결과 메시지
        this.websocketClient.on('approvalProcessed', (data) => {
            console.log('Approval processed:', data);
            this.handleApprovalProcessed(data);
        });

        // 도구 실행 알림
        this.websocketClient.on('tools', (data) => {
            console.log('🔧 Tool execution update:', data);
            this.handleToolUpdate(data);
        });

        // 오류 처리
        this.websocketClient.on('error', (error) => {
            console.error('WebSocket error:', error);
            this.handleError(error);
        });

        // 연결 상태 변경
        this.websocketClient.on('connected', () => {
            console.log('🔌 WebSocket connected');
            this.onWebSocketConnected();
        });

        this.websocketClient.on('disconnected', () => {
            console.warn('🔌 WebSocket disconnected');
            this.onWebSocketDisconnected();
        });
    }

    /**
     * SSE 이벤트 리스너 등록 (deprecated - WebSocket 사용)
     */
    registerSSEListeners() {
        // SSE는 더 이상 사용하지 않음 - WebSocket이 주 통신 채널
        console.log('SSE is deprecated, using WebSocket instead');
        return;
    }

    /**
     * 승인 요청 처리
     * @param {Object} data - 승인 요청 데이터
     */
    async handleApprovalRequest(data) {
        console.log('🔐 Processing approval request:', data);
        console.log('🔐 Approval modal exists?', !!this.approvalModal);
        console.log('🔐 Approval modal show method exists?', this.approvalModal && typeof this.approvalModal.show === 'function');

        // 승인 요청 데이터 정규화
        const approvalRequest = this.normalizeApprovalRequest(data);
        console.log('🔐 Normalized approval request:', approvalRequest);
        
        // 중복 체크
        if (this.pendingApprovals.has(approvalRequest.approvalId)) {
            console.warn('Duplicate approval request:', approvalRequest.approvalId);
            return;
        }

        // 승인 요청 저장
        this.pendingApprovals.set(approvalRequest.approvalId, {
            request: approvalRequest,
            timestamp: Date.now(),
            status: 'PENDING'
        });
        console.log('🔐 Pending approvals count:', this.pendingApprovals.size);

        // UI 업데이트
        this.updateApprovalBadge();
        
        // 알림 표시
        console.log('🔔 Showing notification...');
        this.showNotification('새로운 승인 요청', {
            body: `도구: ${approvalRequest.toolName}\n위험도: ${approvalRequest.riskLevel}`,
            icon: '/icons/warning.png',
            requireInteraction: true
        });

        // 모달 표시
        console.log('🔐 ===========================================');
        console.log('🔐 ATTEMPTING TO SHOW MODAL');
        console.log('🔐 Modal instance available:', this.approvalModal !== null);
        console.log('🔐 ===========================================');
        
        try {
            if (!this.approvalModal) {
                console.error('Approval modal is not initialized!');
                this.showFallbackApproval(approvalRequest);
                return;
            }
            
            console.log('🔐 Modal is available, calling show() method...');
            console.log('🔐 Request data for modal:', JSON.stringify(approvalRequest, null, 2));
            const result = await this.approvalModal.show(approvalRequest);
            console.log('🔐 Modal.show() completed with result:', result);
            console.log('User decision:', result);
            
            // 승인 결과 전송
            await this.sendApprovalDecision(approvalRequest.approvalId, result);
            
        } catch (error) {
            console.error('Failed to show approval modal:', error);
            // 폴백: 기본 confirm 다이얼로그
            this.showFallbackApproval(approvalRequest);
        }
    }

    /**
     * 승인 요청 데이터 정규화
     */
    normalizeApprovalRequest(data) {
        return {
            approvalId: data.approvalId || data.requestId || data.id,
            toolName: data.toolName || data.tool || 'Unknown Tool',
            description: data.description || data.actionDescription || data.toolDescription || '',
            riskLevel: data.riskLevel || 'MEDIUM',
            sessionId: data.sessionId || window.currentSessionId,
            parameters: data.parameters || {},
            requestedBy: data.requestedBy || data.requester || 'System',
            timestamp: data.timestamp || new Date().toISOString()
        };
    }

    /**
     * 승인 결정 전송
     */
    async sendApprovalDecision(approvalId, decision) {
        const payload = {
            requestId: approvalId,
            sessionId: window.currentSessionId,
            approved: decision.approved,
            approverId: this.getCurrentUserId(),
            reason: decision.reason || '',
            comment: decision.reason || ''  // 서버가 comment 필드도 사용하므로 추가
        };

        console.log('📤 ========================================');
        console.log('📤 Sending approval decision');
        console.log('📤 ApprovalId:', approvalId);
        console.log('📤 Approved:', decision.approved);
        console.log('📤 Full payload:', JSON.stringify(payload, null, 2));
        console.log('📤 ========================================');

        // WebSocket으로 전송 시도
        if (this.websocketClient && this.websocketClient.isConnected()) {
            // approvalId를 경로 파라미터로 포함 (서버의 @MessageMapping("/soar/approve/{approvalId}")와 일치)
            const sent = this.websocketClient.send(`/app/soar/approve/${approvalId}`, payload);
            if (sent) {
                console.log('Approval decision sent via WebSocket');
                this.markApprovalProcessed(approvalId, decision.approved);
                return;
            }
        }

        // WebSocket 실패 시 HTTP 폴백
        try {
            const response = await fetch('/api/soar/approval/process', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-Id': window.currentSessionId || ''
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                console.log('Approval decision sent via HTTP');
                this.markApprovalProcessed(approvalId, decision.approved);
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Failed to send approval decision:', error);
            this.handleApprovalError(approvalId, error);
        }
    }

    /**
     * 승인 처리 완료 표시
     */
    markApprovalProcessed(approvalId, approved) {
        const pending = this.pendingApprovals.get(approvalId);
        if (pending) {
            pending.status = approved ? 'APPROVED' : 'REJECTED';
            pending.processedAt = Date.now();
            
            // 히스토리에 추가
            this.approvalHistory.push({
                ...pending,
                processingTime: pending.processedAt - pending.timestamp
            });
            
            // 대기 목록에서 제거
            this.pendingApprovals.delete(approvalId);
            
            // UI 업데이트
            this.updateApprovalBadge();
            this.updateApprovalHistory();
        }
    }

    /**
     * 승인 처리 결과 수신
     */
    handleApprovalProcessed(data) {
        console.log('📨 Approval processed notification:', data);
        
        const approvalId = data.approvalId || data.requestId;
        const approved = data.approved || data.status === 'APPROVED';
        
        // UI 업데이트
        this.markApprovalProcessed(approvalId, approved);
        
        // 알림 표시
        this.showNotification('승인 처리 완료', {
            body: `${approved ? '승인됨' : '거부됨'}: ${data.toolName || 'Tool'}`,
            icon: approved ? '/icons/success.png' : '/icons/error.png'
        });
    }

    /**
     * 도구 실행 업데이트 처리
     */
    handleToolUpdate(data) {
        console.log('🔧 Tool update:', data);
        
        // 도구 실행 로그 업데이트
        this.updateToolLog(data);
        
        // 파이프라인 진행 상황 업데이트
        if (data.stage) {
            this.updatePipelineStage(data.stage, data.progress);
        }
    }

    /**
     * 폴백 승인 다이얼로그
     */
    showFallbackApproval(approvalRequest) {
        const message = `
보안 도구 실행 승인 요청

도구: ${approvalRequest.toolName}
위험도: ${approvalRequest.riskLevel}
설명: ${approvalRequest.description}

이 작업을 승인하시겠습니까?
        `.trim();

        const approved = confirm(message);
        
        const decision = {
            approved,
            reason: approved ? 'User approved via fallback dialog' : 'User rejected via fallback dialog'
        };
        
        this.sendApprovalDecision(approvalRequest.approvalId, decision);
    }

    /**
     * 타임아웃 모니터링
     */
    startTimeoutMonitoring() {
        setInterval(() => {
            const now = Date.now();
            
            this.pendingApprovals.forEach((pending, approvalId) => {
                if (pending.status === 'PENDING') {
                    const elapsed = now - pending.timestamp;
                    
                    if (elapsed > this.approvalTimeout) {
                        console.warn(`⏱️ Approval timeout: ${approvalId}`);
                        this.handleApprovalTimeout(approvalId);
                    } else if (elapsed > this.approvalTimeout * 0.8) {
                        // 80% 시간 경과 시 경고
                        this.showTimeoutWarning(approvalId, this.approvalTimeout - elapsed);
                    }
                }
            });
        }, 5000); // 5초마다 체크
    }

    /**
     * 서버에서 보낸 타임아웃 메시지 처리
     */
    handleServerApprovalTimeout(data) {
        console.log('⏱️ Server approval timeout received:', data);
        
        const approvalId = data.approvalId || data.requestId;
        const timeoutSeconds = data.timeoutSeconds || 0;
        
        // 대기 중인 승인 요청 확인
        const pending = this.pendingApprovals.get(approvalId);
        if (pending) {
            pending.status = 'TIMEOUT';
            this.pendingApprovals.delete(approvalId);
            this.updateApprovalBadge();
        }
        
        // 모달이 열려있으면 닫기
        if (this.approvalModal && this.approvalModal.isOpen()) {
            const currentApprovalId = this.approvalModal.getCurrentApprovalId();
            if (currentApprovalId === approvalId) {
                this.approvalModal.close();
            }
        }
        
        // 타임아웃 알림 표시
        this.showTimeoutNotification(approvalId, timeoutSeconds);
        
        // 타임아웃 모달 표시
        this.showTimeoutModal(data);
    }
    
    /**
     * 타임아웃 알림 표시
     */
    showTimeoutNotification(approvalId, timeoutSeconds) {
        const message = timeoutSeconds > 0 
            ? `승인 요청이 ${timeoutSeconds}초 후 타임아웃됩니다.`
            : `승인 요청이 타임아웃되어 자동으로 거부되었습니다.`;
            
        // 브라우저 알림
        this.showNotification('⏱️ 승인 타임아웃', {
            body: message,
            icon: '/icons/timeout.png',
            requireInteraction: true
        });
        
        // 토스트 알림
        if (window.showToast) {
            window.showToast('승인 타임아웃', message, 'warning');
        }
    }
    
    /**
     * 타임아웃 모달 표시
     */
    showTimeoutModal(data) {
        // 커스텀 모달 생성
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50';
        modal.innerHTML = `
            <div class="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 border border-yellow-500">
                <div class="flex items-center mb-4">
                    <i class="fas fa-clock text-yellow-500 text-2xl mr-3"></i>
                    <h3 class="text-xl font-bold text-white">승인 타임아웃</h3>
                </div>
                <div class="text-gray-300 mb-4">
                    <p>승인 요청이 타임아웃되었습니다.</p>
                    <p class="mt-2">승인 ID: <span class="font-mono text-sm">${data.approvalId || 'N/A'}</span></p>
                    ${data.toolName ? `<p class="mt-1">도구: ${data.toolName}</p>` : ''}
                </div>
                <div class="flex justify-end">
                    <button onclick="this.closest('.fixed').remove()" 
                            class="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded">
                        확인
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // 5초 후 자동 제거
        setTimeout(() => {
            if (modal.parentNode) {
                modal.remove();
            }
        }, 5000);
    }

    /**
     * 클라이언트 측 타임아웃 처리 (기존 메서드)
     */
    handleApprovalTimeout(approvalId) {
        const pending = this.pendingApprovals.get(approvalId);
        if (pending) {
            pending.status = 'TIMEOUT';
            
            // 자동 거부 처리
            this.sendApprovalDecision(approvalId, {
                approved: false,
                reason: 'Approval timeout - automatically rejected'
            });
            
            // 알림
            this.showNotification('승인 타임아웃', {
                body: `승인 요청이 타임아웃되어 자동으로 거부되었습니다.`,
                icon: '/icons/timeout.png'
            });
        }
    }

    /**
     * 타임아웃 경고 표시
     */
    showTimeoutWarning(approvalId, remainingTime) {
        const minutes = Math.floor(remainingTime / 60000);
        const seconds = Math.floor((remainingTime % 60000) / 1000);
        
        console.warn(`⏱️ Approval will timeout in ${minutes}:${seconds.toString().padStart(2, '0')}`);
        
        // UI에 경고 표시
        const warningEl = document.getElementById('timeout-warning');
        if (warningEl) {
            warningEl.textContent = `승인 타임아웃까지 ${minutes}분 ${seconds}초`;
            warningEl.style.display = 'block';
        }
    }

    /**
     * 오류 처리
     */
    handleError(error) {
        console.error('Approval handler error:', error);
        
        // 오류 로깅
        if (window.soarErrorHandler) {
            window.soarErrorHandler.handleError(error, {
                component: 'SoarApprovalHandler',
                severity: 'warning'
            });
        }
        
        // 사용자에게 알림
        this.showNotification('오류 발생', {
            body: '승인 처리 중 오류가 발생했습니다.',
            icon: '/icons/error.png'
        });
    }

    /**
     * 승인 오류 처리
     */
    handleApprovalError(approvalId, error) {
        console.error(`Approval error for ${approvalId}:`, error);
        
        // 재시도 로직
        const pending = this.pendingApprovals.get(approvalId);
        if (pending && pending.retryCount < this.retryAttempts) {
            pending.retryCount = (pending.retryCount || 0) + 1;
            
            console.log(`Retrying approval (${pending.retryCount}/${this.retryAttempts})...`);
            
            setTimeout(() => {
                this.handleApprovalRequest(pending.request);
            }, this.retryDelay * pending.retryCount);
        } else {
            // 최대 재시도 횟수 초과
            this.markApprovalProcessed(approvalId, false);
            this.showNotification('승인 처리 실패', {
                body: '승인 요청 처리에 실패했습니다.',
                icon: '/icons/error.png'
            });
        }
    }

    /**
     * WebSocket 연결 성공
     */
    onWebSocketConnected() {
        // 대기 중인 승인 요청 재처리
        this.pendingApprovals.forEach((pending, approvalId) => {
            if (pending.status === 'PENDING') {
                console.log(`Reprocessing pending approval: ${approvalId}`);
                // 재처리 로직
            }
        });
        
        // UI 상태 업데이트
        this.updateConnectionStatus('connected');
    }

    /**
     * WebSocket 연결 끊김
     */
    onWebSocketDisconnected() {
        // UI 상태 업데이트
        this.updateConnectionStatus('disconnected');
        
        // WebSocket 재연결은 EnhancedWebSocketClient가 자동으로 처리
        console.log('WebSocket disconnected, auto-reconnect will be attempted');
    }

    /**
     * UI 업데이트 메서드들
     */
    updateApprovalBadge() {
        const badge = document.getElementById('approvalBadge');
        if (badge) {
            const count = this.pendingApprovals.size;
            badge.textContent = count;
            badge.style.display = count > 0 ? 'inline-block' : 'none';
        }
    }

    updateToolLog(data) {
        const logEl = document.getElementById('toolLogEntries');
        if (logEl) {
            const entry = document.createElement('div');
            entry.className = `tool-entry ${data.status || 'pending'}`;
            entry.innerHTML = `
                <div class="flex justify-between items-center">
                    <span class="font-semibold">${data.toolName || 'Unknown Tool'}</span>
                    <span class="text-xs text-gray-400">${new Date().toLocaleTimeString()}</span>
                </div>
                <div class="text-sm text-gray-300 mt-1">${data.message || ''}</div>
            `;
            logEl.insertBefore(entry, logEl.firstChild);
            
            // 최대 100개 항목 유지
            while (logEl.children.length > 100) {
                logEl.removeChild(logEl.lastChild);
            }
        }
    }

    updatePipelineStage(stage, progress) {
        const stageEl = document.querySelector(`[data-stage="${stage}"]`);
        if (stageEl) {
            stageEl.classList.add('active');
            const progressBar = stageEl.querySelector('.stage-progress');
            if (progressBar) {
                progressBar.style.width = `${progress}%`;
            }
            
            if (progress >= 100) {
                setTimeout(() => {
                    stageEl.classList.remove('active');
                    stageEl.classList.add('completed');
                }, 500);
            }
        }
    }

    updateApprovalHistory() {
        const historyEl = document.getElementById('approvalHistory');
        if (historyEl && this.approvalHistory.length > 0) {
            const latest = this.approvalHistory[this.approvalHistory.length - 1];
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';
            historyItem.innerHTML = `
                <div class="flex justify-between">
                    <span>${latest.request.toolName}</span>
                    <span class="${latest.status === 'APPROVED' ? 'text-green-400' : 'text-red-400'}">
                        ${latest.status}
                    </span>
                </div>
                <div class="text-xs text-gray-500">
                    처리 시간: ${latest.processingTime}ms
                </div>
            `;
            historyEl.insertBefore(historyItem, historyEl.firstChild);
        }
    }

    updateConnectionStatus(status) {
        const wsIndicator = document.getElementById('wsIndicator');
        const wsState = document.getElementById('wsState');
        
        if (wsIndicator && wsState) {
            if (status === 'connected') {
                wsIndicator.className = 'fas fa-circle text-green-400 text-xs';
                wsState.textContent = '연결됨';
            } else {
                wsIndicator.className = 'fas fa-circle text-red-400 text-xs';
                wsState.textContent = '연결 끊김';
            }
        }
    }

    /**
     * 알림 표시
     */
    showNotification(title, options = {}) {
        // 브라우저 알림 권한 확인
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, options);
        } else if ('Notification' in window && Notification.permission !== 'denied') {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    new Notification(title, options);
                }
            });
        }
        
        // 토스트 알림 (폴백)
        if (window.showToast) {
            window.showToast(title, options.body || '', 'info');
        }
    }

    /**
     * 현재 사용자 ID 가져오기
     */
    getCurrentUserId() {
        return window.currentUserId || 'anonymous';
    }

    /**
     * 리소스 정리
     */
    destroy() {
        // WebSocket 리스너 제거
        if (this.websocketClient) {
            // EnhancedWebSocketClient가 자체적으로 정리
            console.log('🔌 Cleaning up WebSocket listeners');
        }
        
        // 타이머 정리
        this.pendingApprovals.clear();
        
        console.log('🔚 SoarApprovalHandler destroyed');
    }
}

// 전역 사용 가능하도록 등록
if (typeof window !== 'undefined') {
    window.SoarApprovalHandler = SoarApprovalHandler;
}

// 모듈 내보내기
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SoarApprovalHandler;
}