/**
 * SOAR Analysis Enhanced Integration
 * 
 * Complete integration of all enhanced components into the SOAR simulation system
 * Replaces basic functionality with advanced features
 */

class SoarAnalysisEnhanced {
    constructor() {
        // Core components
        this.websocket = null;
        this.stateManager = null;
        this.errorHandler = null;
        this.approvalModal = null;
        this.pipelineVisual = null;
        this.monitoring = null;
        
        // Configuration
        this.config = {
            websocketUrl: '/ws-soar',  // WebSocketConfig 엔드포인트 사용
            autoReconnect: true,
            enableMonitoring: true,
            enableApprovalModal: true,
            enableEnhancedPipeline: true,
            circuitBreakerEnabled: true
        };
        
        // Session data
        this.sessionId = null;
        this.conversationId = null;
        
        // WebSocket 재연결 설정
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.isAnalyzing = false;
        
        // Initialize all components automatically
        // Note: Do NOT call this.initialize() here - it will be called after DOM is ready
    }

    /**
     * Initialize all enhanced components
     */
    async initialize() {
        console.log('🚀 Initializing SOAR Enhanced Analysis System...');
        
        try {
            // 1. Initialize Error Handler first (for resilience)
            this.initializeErrorHandler();
            
            // 2. Initialize State Manager
            this.initializeStateManager();
            
            // 3. Initialize WebSocket with enhanced features
            await this.initializeWebSocket();
            
            // 4. Initialize Approval Modal (WebSocket 연결 완료 후)
            // WebSocket이 완전히 연결된 후에만 Approval 시스템 초기화
            if (this.websocket && this.websocket.isConnected()) {
                this.initializeApprovalModal();
            } else {
                console.warn('WebSocket not connected, deferring Approval Modal initialization');
                // WebSocket 연결 이벤트 대기
                if (this.websocket) {
                    this.websocket.on('connected', () => {
                        console.log('WebSocket connected, initializing Approval Modal...');
                        this.initializeApprovalModal();
                    });
                }
            }
            
            // 6. Initialize Monitoring Dashboard
            this.initializeMonitoring();
            
            // 7. Setup UI event handlers
            this.setupUIHandlers();
            
            // 8. Setup state observers
            this.setupStateObservers();
            
            console.log('SOAR Enhanced Analysis System initialized successfully');
            this.showNotification('시스템 초기화 완료', 'success');
            
        } catch (error) {
            console.error('Failed to initialize SOAR Enhanced System:', error);
            this.showNotification('시스템 초기화 실패', 'error');
        }
    }

    /**
     * Initialize Error Handler
     */
    initializeErrorHandler() {
        this.errorHandler = new SoarErrorHandler();
        
        // Configure circuit breakers for critical services
        this.errorHandler.getCircuitBreaker('soar-api', {
            failureThreshold: 3,
            successThreshold: 2,
            timeout: 30000
        });
        
        this.errorHandler.getCircuitBreaker('websocket', {
            failureThreshold: 5,
            successThreshold: 3,
            timeout: 60000
        });
        
        console.log('Error Handler initialized');
    }

    /**
     * Initialize State Manager
     */
    initializeStateManager() {
        this.stateManager = new SessionStateManager();
        
        // Subscribe to critical state changes
        this.stateManager.subscribe('session.status', (status) => {
            console.log('📊 Session status changed:', status);
            this.updateSessionUI(status);
        });
        
        this.stateManager.subscribe('errors', (errors) => {
            if (errors.count > 0) {
                this.handleStateError(errors.lastError);
            }
        });
        
        console.log('State Manager initialized');
    }

    /**
     * Initialize Enhanced WebSocket
     */
    async initializeWebSocket() {
        console.log('🚀 Starting WebSocket initialization...');
        console.log('📍 WebSocket endpoint:', this.config.websocketUrl);
        
        // Use the enhanced WebSocket client
        // WebSocket 초기화 (중앙 매니저 사용)
        if (window.soarManager) {
            console.log('🎯 Using SoarManager for WebSocket Client');
            this.websocket = window.soarManager.getComponent('WebSocketClient', EnhancedWebSocketClient, this.config.websocketUrl);
        } else {
            console.warn('SoarManager not found, creating local WebSocket instance');
            this.websocket = new EnhancedWebSocketClient(this.config.websocketUrl);
        }
        
        // Configure WebSocket with error handler integration
        this.websocket.setErrorHandler(this.errorHandler);
        
        // Set up connection event handlers
        this.websocket.onConnect = () => {
            console.log('🔌 WebSocket connected successfully');
            console.log('📊 Connection state:', this.websocket.getConnectionState());
            console.log('📡 Active subscriptions:', this.websocket.subscriptions.size);
            
            this.stateManager.setValueAtPath('mcpServers.websocket', true);
            this.showNotification('WebSocket 연결됨', 'success');
            this.updateWebSocketStatus('connected');
            
            // 연결 성공 후 서버에 세션 등록 메시지 전송
            this.websocket.send('/app/register', {
                sessionId: this.sessionId || 'session-' + Date.now(),
                timestamp: new Date().toISOString()
            });
            console.log('📤 Session registration sent to server');
        };
        
        this.websocket.onDisconnect = () => {
            console.log('🔌 WebSocket disconnected');
            this.stateManager.setValueAtPath('mcpServers.websocket', false);
            this.showNotification('WebSocket 연결 끊김', 'warning');
            this.updateWebSocketStatus('disconnected');
            
            // 재연결 시도
            this.handleWebSocketDisconnect();
        };
        
        // WebSocket 에러 핸들러 추가
        this.websocket.onWebSocketError = (error) => {
            console.error('WebSocket error:', error);
            this.showNotification('WebSocket 에러 발생', 'error');
            this.handleWebSocketDisconnect();
        };
        
        // Connect with circuit breaker protection
        console.log('Attempting WebSocket connection...');
        try {
            await this.errorHandler.executeWithResilience(
                'websocket',
                () => this.websocket.connect(),
                {
                    fallback: () => {
                        console.warn('Using fallback WebSocket connection');
                        return this.websocket.connect({ timeout: 10000 });
                    }
                }
            );
            
            // WebSocket 연결 완료 후 잠시 대기
            console.log('⏳ Waiting for connection stabilization...');
            await new Promise(resolve => setTimeout(resolve, 500));
            
            // Subscribe to all necessary topics
            console.log('📡 Subscribing to WebSocket topics...');
            this.subscribeToAllTopics();
            
            // 연결 상태 최종 확인
            const isConnected = this.websocket.isConnected();
            console.log('WebSocket initialization complete. Connected:', isConnected);
            console.log('📊 Final connection state:', {
                state: this.websocket.getConnectionState(),
                subscriptions: this.websocket.subscriptions.size,
                queueSize: this.websocket.getQueueSize()
            });
            
        } catch (error) {
            console.error('WebSocket connection failed:', error);
            this.showNotification('WebSocket 연결 실패', 'error');
            throw error;
        }
    }

    /**
     * Subscribe to all WebSocket topics
     */
    subscribeToAllTopics() {
        console.log('📡 Subscribing to all SOAR topics...');
        
        // 승인 토픽 구독 - 이벤트만 발생 (중복 제거)
        this.websocket.subscribe('/topic/soar/approvals', (message) => {
            console.log('🎯 ===========================================');
            console.log('🎯 APPROVAL MESSAGE RECEIVED');
            console.log('🎯 Message:', message);
            console.log('🎯 Type:', message.type);
            console.log('🎯 ApprovalId:', message.approvalId || message.requestId);
            console.log('🎯 ===========================================');
            
            // 'approvals' 이벤트만 발생 (SoarApprovalHandler가 처리)
            console.log('🔔 Emitting approvals event for handler...');
            this.websocket.emit('approvals', message);
            
            // 직접 처리 제거 - SoarApprovalHandler가 처리하므로 중복 제거
            // this.handleApprovalRequest(message); // 제거!
        });
        
        // Session management topics (backend: /topic/soar/events)
        this.websocket.subscribe('/topic/soar/events', (message) => {
            this.handleSessionStatus(message);
        });

        // Pipeline progress topics (backend: /topic/soar/pipeline)
        this.websocket.subscribe('/topic/soar/pipeline', (message) => {
            this.handlePipelineProgress(message);
        });

        // Tool execution topics (backend: /topic/soar/tools)
        this.websocket.subscribe('/topic/soar/tools', (message) => {
            this.handleToolExecution(message);
        });

        // Tool result topics (backend: /topic/soar/complete)
        this.websocket.subscribe('/topic/soar/complete', (message) => {
            this.handleToolResult(message);
        });
        
        // Approval topics - 비활성화 (soar-approval-handler.js에서 처리)
        // 중복 방지를 위해 이벤트 리스너 제거
        /*
        this.websocket.on('approvals', (message) => {
            console.log('🔔 ===========================================');
            console.log('🔔 APPROVAL EVENT RECEIVED IN SOAR-ANALYSIS-ENHANCED');
            console.log('🔔 Message:', JSON.stringify(message, null, 2));
            console.log('🔔 Approval Modal exists?', !!this.approvalModal);
            console.log('🔔 ===========================================');
            this.handleApprovalRequest(message);
        });
        */
        
        this.websocket.on('approvalProcessed', (message) => {
            console.log('Received approval processed event:', message);
            this.handleApprovalProcessed(message);
        });
        
        // Complete 이벤트 리스너 추가
        this.websocket.on('complete', (message) => {
            console.log('🏁 Received complete event:', message);
            this.handleComplete(message);
        });
        
        // Complete 토픽 구독 추가 - STOMP 메시지 body 파싱 수정
        this.websocket.subscribe('/topic/soar/complete', (message) => {
            console.log('🏁 Analysis complete message received:', message);
            // STOMP 메시지의 body를 파싱하여 전달
            try {
                const data = message.body ? JSON.parse(message.body) : message;
                this.handleAnalysisComplete(data);
            } catch (error) {
                console.error('Failed to parse complete message:', error);
                this.handleAnalysisComplete(message);
            }
        });
        
        // Events 이벤트 리스너 추가
        this.websocket.on('events', (message) => {
            console.log('📢 Received events:', message);
            this.handleEvents(message);
        });
        
        // approval-processed는 이미 subscribeToAllTopics()에서 구독됨
        // 이벤트로 처리하므로 중복 구독 제거
        
        // 특정 승인 요청 결과 구독 - 와일드카드 제거
        // SimpleBroker는 와일드카드를 지원하지 않으므로 필요시 개별 approvalId로 구독해야 함
        // 예: this.subscribeToApprovalResult(approvalId);
        // this.websocket.subscribe(`/topic/soar/approval-results/${approvalId}`, callback);
        
        // Session management topics
        this.websocket.subscribe('/topic/soar/sessions', (message) => {
            console.log('📋 세션 업데이트 수신:', message);
            this.handleSessionUpdate(message);
        });
        
        // MCP server topics
        this.websocket.subscribe('/topic/mcp/status', (message) => {
            this.handleMcpStatus(message);
        });
        
        this.websocket.subscribe('/topic/mcp/update', (message) => {
            this.handleMcpUpdate(message);
        });
        
        // Error topics
        this.websocket.subscribe('/topic/error', (message) => {
            this.handleWebSocketError(message);
        });
        
        // Monitoring topics
        this.websocket.subscribe('/topic/monitoring/metrics', (message) => {
            this.handleMonitoringMetrics(message);
        });
        
        // Approval completion topics - 서버와 일치하도록 수정
        // 서버는 /topic/soar/approvals로 승인 결과도 전송함
        // approvalProcessed 이벤트로 처리하거나 별도 구독 필요
        
        // approval-processed 이벤트는 WebSocket on 이벤트로 처리됨
        // this.websocket.on('approvalProcessed', ...) 에서 처리
        
        // 승인 결과를 /topic/soar/approvals에서도 받을 수 있도록 처리
        // handleApprovalRequest 메서드에서 type을 확인하여 처리
    }

    /**
     * Handle real-time approval processed (푸시 방식)
     */
    handleApprovalProcessed(data) {
        const { approvalId, approved, reviewer, comment, timestamp } = data;
        
        console.log(`승인 처리 완료 (실시간 푸시): ${approvalId}`);
        console.log(`   - 결과: ${approved ? '승인' : '거부'}`);
        console.log(`   - 검토자: ${reviewer}`);
        console.log(`   - 시간: ${timestamp}`);
        
        // UI 업데이트
        this.updateApprovalStatus(approvalId, approved ? 'APPROVED' : 'REJECTED');
        
        // 알림 표시
        this.showNotification(
            `승인 요청 ${approvalId}가 ${approved ? '승인' : '거부'}되었습니다.`,
            approved ? 'success' : 'warning'
        );
        
        // 대기 중인 콜백 실행
        if (this.pendingApprovals && this.pendingApprovals[approvalId]) {
            const callback = this.pendingApprovals[approvalId];
            callback(approved);
            delete this.pendingApprovals[approvalId];
        }
    }
    
    /**
     * Handle individual approval result (개별 푸시)
     */
    /**
     * 특정 승인 요청 결과 구독
     * @param {string} approvalId - 구독할 승인 ID
     */
    subscribeToApprovalResult(approvalId) {
        if (!approvalId) return;
        
        const topic = `/topic/soar/approval-results/${approvalId}`;
        this.websocket.subscribe(topic, (message) => {
            console.log(`📨 승인 결과 수신 [${approvalId}]:`, message);
            this.handleIndividualApprovalResult(message);
        });
        console.log(`📡 승인 결과 토픽 구독: ${topic}`);
    }
    
    handleIndividualApprovalResult(data) {
        const { requestId, approved, approverId, timestamp } = data;
        
        console.log(`📬 개별 승인 결과 수신: ${requestId} -> ${approved ? '승인' : '거부'}`);
        
        // 특정 승인에 대한 처리
        this.updateSpecificApproval(requestId, approved);
    }
    
    /**
     * Handle approval granted notification
     */
    handleApprovalGranted(data) {
        const { approvalId, toolName, reviewer, timestamp } = data;
        
        console.log('도구 실행 승인됨:', {
            approvalId,
            toolName,
            reviewer,
            timestamp
        });
        
        // 승인 상태 업데이트
        this.updateApprovalStatus(approvalId, 'APPROVED');
        
        // 더 명확한 승인 완료 알림 표시
        this.showNotification(`${toolName} 도구 실행이 승인되었습니다`, 'success');
        
        // 승인 모달 닫기 (열려있는 경우)
        if (this.approvalModal && this.approvalModal.isOpen()) {
            this.approvalModal.close();
        }
        
        // 버튼 텍스트 업데이트: "도구 실행 중..."으로 변경
        const btnText = document.getElementById('btnText');
        if (btnText) {
            btnText.innerHTML = '<span class="loading-spinner"></span> 도구 실행 중...';
        }
        
        // AI 파이프라인 진행 표시 자동 숨김 (10초 후)
        this.schedulePipelineHide();
    }
    
    /**
     * Handle approval denied notification  
     */
    handleApprovalDenied(data) {
        const { approvalId, toolName, reviewer, reason, timestamp } = data;
        
        console.log('도구 실행 거부됨:', {
            approvalId,
            toolName,
            reviewer,
            reason,
            timestamp
        });
        
        // 승인 상태 업데이트
        this.updateApprovalStatus(approvalId, 'REJECTED');
        
        // 알림 표시
        this.showNotification(`${toolName} 도구 실행이 거부되었습니다: ${reason || '사유 없음'}`, 'warning');
        
        // 승인 모달 닫기 (열려있는 경우)
        if (this.approvalModal && this.approvalModal.isOpen()) {
            this.approvalModal.close();
        }
        
        // AI 파이프라인 진행 표시 즉시 숨김
        this.hidePipelineProgress();
    }
    
    /**
     * Schedule pipeline progress hide after delay
     */
    schedulePipelineHide() {
        // 기존 타이머 취소
        if (this.pipelineHideTimer) {
            clearTimeout(this.pipelineHideTimer);
        }
        
        // 10초 후 숨김 (승인 완료 알람이 충분히 표시되도록)
        this.pipelineHideTimer = setTimeout(() => {
            this.hidePipelineProgress();
        }, 10000);
    }
    
    /**
     * Hide pipeline progress display
     */
    hidePipelineProgress() {
        console.log('AI 파이프라인 진행 표시 숨김');
        
        // 파이프라인 진행 표시 숨김
        const pipelineProgress = document.getElementById('pipelineProgress');
        if (pipelineProgress) {
            pipelineProgress.classList.add('hidden');
        }
        
        // 파이프라인 상태 텍스트 업데이트
        const pipelineStatus = document.getElementById('pipelineStatus');
        if (pipelineStatus) {
            pipelineStatus.textContent = '완료';
            pipelineStatus.className = 'text-green-400';
        }
        
        // 시각화 컴포넌트 리셋
        if (this.pipelineVisual) {
            this.pipelineVisual.complete();
        }
        
        // 타이머 정리
        if (this.pipelineHideTimer) {
            clearTimeout(this.pipelineHideTimer);
            this.pipelineHideTimer = null;
        }
    }
    
    /**
     * Update WebSocket connection status in UI
     */
    updateWebSocketStatus(status) {
        const wsIndicator = document.getElementById('wsIndicator');
        const wsState = document.getElementById('wsState');
        
        if (wsIndicator && wsState) {
            switch(status) {
                case 'connected':
                    wsIndicator.className = 'fas fa-circle text-green-400 text-xs';
                    wsState.textContent = '연결됨';
                    wsState.className = 'text-green-400';
                    break;
                case 'disconnected':
                    wsIndicator.className = 'fas fa-circle text-red-400 text-xs';
                    wsState.textContent = '연결 끊김';
                    wsState.className = 'text-red-400';
                    break;
                case 'connecting':
                    wsIndicator.className = 'fas fa-circle text-yellow-400 text-xs animate-pulse';
                    wsState.textContent = '연결 중...';
                    wsState.className = 'text-yellow-400';
                    break;
            }
        }
    }
    
    /**
     * Handle session update from server
     */
    handleSessionUpdate(data) {
        console.log('📋 세션 업데이트:', data);
        
        // Update session information
        if (data.sessionId) {
            this.sessionId = data.sessionId;
            this.stateManager.setValueAtPath('session.sessionId', data.sessionId);
            
            // Update session ID display
            const sessionIdEl = document.getElementById('currentSessionId');
            if (sessionIdEl) {
                sessionIdEl.textContent = data.sessionId.substring(0, 8) + '...';
                sessionIdEl.title = data.sessionId; // Show full ID on hover
            }
        }
        
        if (data.status) {
            this.stateManager.setValueAtPath('session.status', data.status);
            
            // Update UI based on status
            const sessionStatusEl = document.getElementById('sessionStatus');
            if (sessionStatusEl) {
                sessionStatusEl.textContent = data.status;
                sessionStatusEl.className = `ml-2 font-semibold text-${this.getStatusColor(data.status)}-400`;
            }
        }
        
        // Show notification
        if (data.message) {
            this.showNotification(data.message, 'info');
        }
        
        // Handle specific session events
        if (data.event === 'SESSION_CREATED') {
            console.log('새 세션 생성됨:', data.sessionId);
            this.onSessionCreated(data);
        } else if (data.event === 'SESSION_CLOSED') {
            console.log('🔒 세션 종료됨:', data.sessionId);
            this.onSessionClosed(data);
        }
    }
    
    /**
     * Handle session created event
     */
    onSessionCreated(data) {
        // Enable UI controls
        const stopBtn = document.getElementById('stopSimulation');
        if (stopBtn) stopBtn.disabled = false;
        
        // Show control panel
        const controlPanel = document.getElementById('enhancedControlPanel');
        if (controlPanel) controlPanel.classList.remove('hidden');
        
        // Initialize pipeline visualization
        if (this.pipelineVisual) {
            this.pipelineVisual.reset();
        }
    }
    
    /**
     * Handle session closed event
     */
    onSessionClosed(data) {
        // Disable UI controls
        const stopBtn = document.getElementById('stopSimulation');
        if (stopBtn) stopBtn.disabled = true;
        
        // Reset state
        this.sessionId = null;
        this.conversationId = null;
    }
    
    /**
     * Get status color for UI
     */
    getStatusColor(status) {
        const colors = {
            'ACTIVE': 'green',
            'RUNNING': 'green',
            'PAUSED': 'yellow',
            'WAITING': 'orange',
            'COMPLETED': 'blue',
            'ERROR': 'red',
            'CLOSED': 'gray'
        };
        return colors[status] || 'gray';
    }
    
    /**
     * Initialize Approval Modal
     */
    initializeApprovalModal() {
        if (!this.config.enableApprovalModal) {
            console.log('Approval Modal disabled in config');
            return;
        }
        
        // 이미 초기화되었는지 확인
        if (this.approvalModal && this.approvalHandler) {
            console.log('Approval system already initialized');
            return;
        }
        
        // WebSocket 연결 상태 확인
        if (!this.websocket || !this.websocket.isConnected()) {
            console.error('Cannot initialize Approval Modal: WebSocket not connected');
            return;
        }
        
        console.log('🔐 ===========================================');
        console.log('🔐 INITIALIZING APPROVAL SYSTEM');
        console.log('🔐 WebSocket connected:', this.websocket.isConnected());
        console.log('🔐 WebSocket state:', this.websocket.getConnectionState());
        console.log('🔐 ===========================================');
        
        // 승인 모달 초기화 (중앙 매니저 사용, 중복 방지)
        if (window.soarManager) {
            console.log('🎯 Using SoarManager for Approval Modal');
            // getComponent는 이미 존재하면 기존 인스턴스를 반환함
            this.approvalModal = window.soarManager.getComponent('ApprovalModal', SoarApprovalModal);
        } else if (!window.soarApprovalModalInstance) {
            console.warn('SoarManager not found, creating global instance');
            window.soarApprovalModalInstance = new SoarApprovalModal();
            this.approvalModal = window.soarApprovalModalInstance;
        } else {
            console.log('Using existing global Approval Modal instance');
            this.approvalModal = window.soarApprovalModalInstance;
        }
        console.log('Approval Modal initialized');
        
        // 승인 핸들러 초기화 및 WebSocket 연결 (중앙 매니저 사용, 중복 방지)
        if (window.SoarApprovalHandler) {
            if (window.soarManager) {
                console.log('🎯 Using SoarManager for Approval Handler');
                this.approvalHandler = window.soarManager.getComponent('ApprovalHandler', SoarApprovalHandler);
            } else if (!window.soarApprovalHandlerInstance) {
                console.warn('SoarManager not found, creating global instance');
                window.soarApprovalHandlerInstance = new SoarApprovalHandler();
                this.approvalHandler = window.soarApprovalHandlerInstance;
            } else {
                console.log('Using existing global Approval Handler instance');
                this.approvalHandler = window.soarApprovalHandlerInstance;
            }
            
            // WebSocket과 승인 모달을 핸들러에 연결
            this.approvalHandler.initialize(this.websocket, this.approvalModal);
            
            console.log('Approval Handler initialized and connected');
            console.log('📊 Approval system ready:', {
                modal: !!this.approvalModal,
                handler: !!this.approvalHandler,
                websocket: this.websocket.isConnected()
            });
            console.log('📡 Ready to receive approval requests via WebSocket');
        } else {
            console.warn('Could not initialize Approval Handler:', {
                hasHandler: !!window.SoarApprovalHandler,
                hasWebSocket: !!this.websocket,
                hasModal: !!this.approvalModal
            });
        }
    }

    /**
     * Initialize Monitoring Dashboard
     */
    initializeMonitoring() {
        if (!this.config.enableMonitoring) return;
        
        // MonitoringDashboard is auto-initialized as window.soarMonitoring
        this.monitoring = window.soarMonitoring;
        
        // Update MCP status in monitoring
        this.stateManager.subscribe('mcpServers', (status) => {
            if (this.monitoring) {
                this.monitoring.updateMcpStatus(status);
            }
        });
        
        console.log('Monitoring Dashboard initialized');
    }

    /**
     * Setup UI event handlers
     */
    setupUIHandlers() {
        // Main analyze button - the primary entry point for users
        const analyzeBtn = document.getElementById('analyzeSoarBtn');
        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', () => {
                this.analyzeIncident();
            });
        }
        
        // Stop simulation button
        const stopBtn = document.getElementById('stopSimulation');
        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                this.stopSimulation();
            });
        }
        
        // Clear logs button
        const clearBtn = document.getElementById('clearLogs');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.clearLogs();
            });
        }
        
        // Toggle monitoring button
        const monitoringBtn = document.getElementById('toggleMonitoring');
        if (monitoringBtn) {
            monitoringBtn.addEventListener('click', () => {
                if (this.monitoring) {
                    this.monitoring.toggle();
                }
            });
        }
        
        // Input field for commands
        const inputField = document.getElementById('soarInput');
        if (inputField) {
            inputField.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendCommand(inputField.value);
                    inputField.value = '';
                }
            });
        }
    }

    /**
     * Setup state observers
     */
    setupStateObservers() {
        // Pipeline progress observer
        this.stateManager.subscribe('pipeline.progress', (progress) => {
            this.updateProgressBar(progress);
        });
        
        // Tool execution observer
        this.stateManager.subscribe('tools.executed', (tools) => {
            this.updateToolLog(tools);
        });
        
        // Error observer
        this.stateManager.subscribe('errors.lastError', (error) => {
            if (error) {
                this.displayError(error);
            }
        });
        
        // Approval queue observer
        this.stateManager.subscribe('approvals.pending', (pending) => {
            this.updateApprovalBadge(pending.length);
        });
    }

    /**
     * Analyze incident from form data
     */
    async analyzeIncident() {
        console.log('Analyzing incident from form data...');
        
        // Collect form data
        const incidentData = {
            incidentId: document.getElementById('incidentIdInput')?.value || `INC-${Date.now()}`,
            threatType: document.getElementById('threatTypeInput')?.value || 'Unknown Threat',
            description: document.getElementById('descriptionInput')?.value,
            affectedAssets: document.getElementById('affectedAssetsInput')?.value.split(',').map(s => s.trim()).filter(s => s),
            detectedSource: document.getElementById('detectedSourceInput')?.value || 'Manual',
            severity: document.getElementById('severityInput')?.value || 'MEDIUM',
            organizationId: document.getElementById('organizationIdInput')?.value || 'org_default',
            userQuery: document.getElementById('userQueryInput')?.value,
            metadata: {
                timestamp: new Date().toISOString(),
                source: 'Enhanced Web UI'
            }
        };
        
        // Validate required fields
        if (!incidentData.description) {
            this.showNotification('상세 설명은 필수입니다.', 'error');
            return;
        }
        
        // Show enhanced control panel
        const controlPanel = document.getElementById('enhancedControlPanel');
        if (controlPanel) {
            controlPanel.classList.remove('hidden');
        }
        
        // Hide form sections to make room for real-time panels
        const resultSection = document.getElementById('resultsSection');
        const approvalSection = document.getElementById('soarActionApprovalSection');
        if (resultSection) resultSection.classList.add('hidden');
        if (approvalSection) approvalSection.classList.add('hidden');
        
        // Show and reset panels
        if (this.pipelineVisual) {
            this.pipelineVisual.reset();
            const pipelinePanel = document.getElementById('pipelinePanel');
            if (pipelinePanel) pipelinePanel.classList.remove('hidden');
        }
        
        const toolLogPanel = document.getElementById('toolLogPanel');
        if (toolLogPanel) {
            toolLogPanel.classList.remove('hidden');
            const toolLogContent = document.getElementById('toolLogContent');
            if (toolLogContent) toolLogContent.innerHTML = '';
        }
        
        // Start the simulation with collected data
        // 버튼 상태는 startSimulation 내부에서 관리됨
        await this.startSimulation(incidentData);
    }
    
    /**
     * Start SOAR simulation
     */
    async startSimulation(incidentData = null) {
        console.log('🚀 Starting SOAR simulation...');
        
        try {
            // Reset state
            this.stateManager.reset();
            if (this.pipelineVisual) {
                this.pipelineVisual.reset();
            }
            
            // Use provided incident data or create default request
            const requestData = incidentData || {
                incidentId: `INC-${Date.now()}`,
                threatType: 'Unknown',
                description: 'Default simulation request',
                affectedAssets: [],
                detectedSource: 'Manual',
                severity: 'MEDIUM',
                organizationId: 'org_default',
                userQuery: '',
                metadata: {
                    timestamp: new Date().toISOString(),
                    source: 'Enhanced Web UI'
                }
            };
            
            // 즉시 시뮬레이션 시작 팝업 표시 (타이밍 문제 해결)
            this.showNotification('시뮬레이션이 시작되었습니다', 'success');
            
            // 분석 진행 상태 플래그 설정 (버튼 상태 변경 전에 설정)
            this.isAnalyzing = true;
            
            // 버튼을 비활성화만 하고 텍스트는 아직 변경하지 않음
            const analyzeBtn = document.getElementById('analyzeSoarBtn');
            if (analyzeBtn) {
                analyzeBtn.disabled = true;
                analyzeBtn.classList.add('disabled', 'opacity-50', 'cursor-not-allowed');
                console.log('🔒 버튼 비활성화 - disabled:', analyzeBtn.disabled);
            }
            
            // Log the request for debugging
            console.log('📤 Sending simulation request:', requestData);
            
            // Start simulation via API with circuit breaker
            const response = await this.errorHandler.executeWithResilience(
                'soar-api',
                async () => {
                    const res = await fetch('/api/soar/simulation/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(requestData)
                    });
                    
                    if (!res.ok) {
                        // Try to get error details from response body
                        let errorMessage = `Failed to start simulation: ${res.statusText}`;
                        try {
                            const errorBody = await res.text();
                            console.error('Server error response:', errorBody);
                            if (errorBody) {
                                errorMessage += ` - ${errorBody}`;
                            }
                        } catch (e) {
                            console.error('Could not read error response body');
                        }
                        throw new Error(errorMessage);
                    }
                    
                    return res.json();
                },
                {
                    maxRetries: 3,
                    fallback: () => {
                        console.warn('Using mock simulation data');
                        return this.createMockSimulation();
                    }
                }
            );
            
            // Update state with session info - sessionId 저장 강화
            this.sessionId = response.sessionId;
            this.conversationId = response.conversationId;
            console.log('Session ID 저장:', this.sessionId);
            console.log('💬 Conversation ID 저장:', this.conversationId);
            this.stateManager.startSession(this.sessionId, this.conversationId);
            
            // finalResponse가 이미 있으면 바로 표시 (동기 응답 처리)
            if (response.finalResponse) {
                console.log('📊 즉시 최종 응답 표시 (동기 응답)');
                this.displayAnalysisResult(response.finalResponse);
                this.isAnalyzing = false;
                this.enableAnalyzeButton();
                // 동기 응답의 경우 showSimulationStarted를 호출하지 않음
                console.log('Simulation completed with final response');
            } else {
                // 비동기 처리의 경우에만 버튼 텍스트 변경
                console.log('🚀 Starting async simulation processing');
                
                // 버튼 텍스트를 "AI 파이프라인 실행 중..."으로 변경 (비동기 처리 시에만)
                const analyzeBtn = document.getElementById('analyzeSoarBtn');
                if (analyzeBtn) {
                    const btnText = document.getElementById('btnText');
                    if (btnText) {
                        btnText.innerHTML = '<i class="fas fa-spinner fa-spin"></i> AI 파이프라인 실행 중...';
                    } else {
                        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span id="btnText">AI 파이프라인 실행 중...</span>';
                    }
                }
                
                // Start pipeline visualization only if async processing
                if (this.pipelineVisual) {
                    this.pipelineVisual.startPipeline();
                }
                
                // 시뮬레이션 성공 응답 수신
                console.log('Simulation response:', response);
                
                // 결과 화면 표시 (시작 상태) - 비동기 처리 시에만
                this.showSimulationStarted(response);
            }
            
        } catch (error) {
            const result = await this.errorHandler.handleError(error, {
                operation: 'startSimulation'
            });
            
            this.showNotification(result.message, 'error');
            console.error('Failed to start simulation:', error);
            
            // 분석 상태 리셋
            this.isAnalyzing = false;
            this.sessionId = null;
            this.conversationId = null;
            
            // Reset button state on error - enableAnalyzeButton 메소드 사용
            this.enableAnalyzeButton();
        }
    }

    /**
     * Display simulation started status
     */
    showSimulationStarted(response) {
        // 로딩 오버레이 숨기기 (있다면)
        const loadingOverlay = document.querySelector('.loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.classList.remove('show');
        }
        
        // 결과 섹션 표시 - resultsSection ID 사용 (HTML과 일치)
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) {
            resultsSection.classList.remove('hidden');
            resultsSection.style.display = 'block';
        }
        
        // 상태 업데이트 - 진행 중
        const resultStatus = document.querySelector('.result-status');
        if (resultStatus) {
            resultStatus.innerHTML = `
                <i class="fas fa-spinner fa-spin"></i>
                <span>분석 진행 중</span>
            `;
            resultStatus.style.background = 'rgba(59, 130, 246, 0.2)';
            resultStatus.style.borderColor = 'rgba(59, 130, 246, 0.4)';
            resultStatus.style.color = '#93bbfc';
        }
        
        // 시작 메시지 표시 - analysisResult ID 사용 (HTML과 일치)
        const analysisResult = document.getElementById('analysisResult');
        if (analysisResult) {
            analysisResult.innerHTML = `
                <div style="color: #93bbfc; margin-bottom: 1rem;">
                    <i class="fas fa-info-circle"></i> ${response.message || 'SOAR 시뮬레이션이 시작되었습니다.'}
                </div>
                <div style="color: #94a3b8;">
                    <i class="fas fa-hourglass-half"></i> AI 분석이 진행 중입니다. 잠시만 기다려주세요...
                </div>
                <div style="color: #64748b; margin-top: 1rem; font-size: 0.9rem;">
                    <strong>세션 ID:</strong> ${response.sessionId || 'N/A'}<br>
                    <strong>대화 ID:</strong> ${response.conversationId || 'N/A'}<br>
                    <strong>상태:</strong> ${response.status || 'RUNNING'}<br>
                    <strong>시작 시간:</strong> ${response.timestamp ? new Date(response.timestamp).toLocaleString() : new Date().toLocaleString()}
                </div>
            `;
        }
        
        // 메타데이터 표시
        this.displayMetadata({
            sessionId: response.sessionId,
            conversationId: response.conversationId,
            status: response.status,
            timestamp: response.timestamp || new Date().toISOString()
        });
    }

    /**
     * Stop SOAR simulation
     */
    async stopSimulation() {
        console.log('🛑 Stopping SOAR simulation...');
        
        try {
            if (!this.sessionId) {
                this.showNotification('실행 중인 시뮬레이션이 없습니다', 'warning');
                return;
            }
            
            // Stop simulation via API
            const response = await this.errorHandler.executeWithResilience(
                'soar-api',
                async () => {
                    const res = await fetch(`/api/soar/simulation/stop/${this.sessionId}`, {
                        method: 'POST'
                    });
                    
                    if (!res.ok) {
                        throw new Error(`Failed to stop simulation: ${res.statusText}`);
                    }
                    
                    return res.json();
                }
            );
            
            // End session in state manager
            this.stateManager.endSession('STOPPED');
            
            // Complete pipeline visualization
            if (this.pipelineVisual) {
                this.pipelineVisual.completePipeline();
            }
            
            // Hide enhanced control panel
            const controlPanel = document.getElementById('enhancedControlPanel');
            if (controlPanel) {
                controlPanel.classList.add('hidden');
            }
            
            // Reset button state
            const analyzeBtn = document.getElementById('analyzeSoarBtn');
            if (analyzeBtn) {
                analyzeBtn.disabled = false;
                const btnText = document.getElementById('btnText');
                if (btnText) {
                    btnText.innerHTML = '<i class="fas fa-robot mr-3"></i>AI + MCP + SOAR 시뮬레이션 시작';
                }
            }
            
            // Show results if available
            const resultSection = document.getElementById('resultsSection');
            if (resultSection && response.results) {
                resultSection.classList.remove('hidden');
                const resultContent = document.getElementById('soarResultContent');
                if (resultContent) {
                    resultContent.innerHTML = `
                        <strong>세션 ID:</strong> ${this.sessionId}<br>
                        <strong>대화 ID:</strong> ${this.conversationId}<br>
                        <strong>상태:</strong> 중지됨<br>
                        <strong>종료 시간:</strong> ${new Date().toLocaleString()}
                    `;
                }
            }
            
            this.showNotification('시뮬레이션 중지됨', 'info');
            console.log('Simulation stopped:', response);
            
        } catch (error) {
            const result = await this.errorHandler.handleError(error, {
                operation: 'stopSimulation'
            });
            
            this.showNotification(result.message, 'error');
            console.error('Failed to stop simulation:', error);
        }
    }

    /**
     * Send command to SOAR system
     */
    async sendCommand(command) {
        if (!command.trim()) return;
        
        console.log('📤 Sending command:', command);
        
        try {
            // Send via WebSocket
            this.websocket.send('/app/soar/command', {
                sessionId: this.sessionId,
                command: command,
                timestamp: new Date().toISOString()
            });
            
            // Add to command history
            this.addToCommandHistory(command);
            
        } catch (error) {
            console.error('Failed to send command:', error);
            this.showNotification('명령 전송 실패', 'error');
        }
    }

    /**
     * Handle session status updates
     */
    handleSessionStatus(message) {
        console.log('📊 Session status:', message);
        
        this.stateManager.setValueAtPath('session.status', message.status);
        
        if (message.status === 'COMPLETED' || message.status === 'STOPPED') {
            this.stateManager.endSession(message.status);
            if (this.pipelineVisual) {
                this.pipelineVisual.completePipeline();
            }
            
            // Hide enhanced control panel
            const controlPanel = document.getElementById('enhancedControlPanel');
            if (controlPanel) {
                controlPanel.classList.add('hidden');
            }
            
            // Reset button state
            const analyzeBtn = document.getElementById('analyzeSoarBtn');
            if (analyzeBtn) {
                analyzeBtn.disabled = false;
                const btnText = document.getElementById('btnText');
                if (btnText) {
                    btnText.innerHTML = '<i class="fas fa-robot mr-3"></i>AI + MCP + SOAR 시뮬레이션 시작';
                }
            }
            
            // Show results
            const resultSection = document.getElementById('resultsSection');
            if (resultSection) {
                resultSection.classList.remove('hidden');
                const resultContent = document.getElementById('soarResultContent');
                if (resultContent && message.results) {
                    resultContent.innerHTML = `
                        <strong>세션 ID:</strong> ${this.sessionId}<br>
                        <strong>대화 ID:</strong> ${this.conversationId}<br>
                        <strong>상태:</strong> ${message.status === 'COMPLETED' ? '완료' : '중지됨'}<br>
                        <strong>종료 시간:</strong> ${new Date().toLocaleString()}<br>
                        ${message.results ? `<br><strong>결과:</strong><pre class="bg-gray-800 p-2 rounded mt-1 text-xs">${JSON.stringify(message.results, null, 2)}</pre>` : ''}
                    `;
                }
            }
            
            this.showNotification(message.status === 'COMPLETED' ? '세션 완료' : '세션 중지됨', 
                                 message.status === 'COMPLETED' ? 'success' : 'info');
            
            // 세션 완료 시 버튼 텍스트 원복
            if (message.status === 'COMPLETED' || message.status === 'STOPPED') {
                const analyzeBtn = document.getElementById('analyzeSoarBtn');
                if (analyzeBtn) {
                    analyzeBtn.disabled = false;
                    const btnText = document.getElementById('btnText');
                    if (btnText) {
                        btnText.innerHTML = '<i class="fas fa-robot mr-3"></i>AI + MCP + SOAR 시뮬레이션 시작';
                    }
                }
            }
        }
    }

    /**
     * Handle pipeline progress updates
     */
    handlePipelineProgress(message) {
        console.log('📈 Pipeline progress:', message);
        
        this.stateManager.setValueAtPath('pipeline.progress', message.progress);
        
        // 파이프라인 진행 표시
        const pipelineProgress = document.getElementById('pipelineProgress');
        if (pipelineProgress) {
            pipelineProgress.classList.remove('hidden');
        }
        
        if (this.pipelineVisual && message.stage) {
            this.pipelineVisual.updateStage(
                message.stage,
                message.progress,
                message.status || 'active',
                message.message
            );
        }
        
        // 100% 완료 시 버튼 텍스트 원복 및 자동 숨김 예약
        if (message.progress >= 100) {
            console.log('🎉 파이프라인 완료 감지');
            
            // 분석 완료 처리
            this.isAnalyzing = false;
            
            // 버튼 텍스트 원복
            const analyzeBtn = document.getElementById('analyzeSoarBtn');
            if (analyzeBtn) {
                analyzeBtn.disabled = false;
                const btnText = document.getElementById('btnText');
                if (btnText) {
                    btnText.innerHTML = '<i class="fas fa-robot mr-3"></i>AI + MCP + SOAR 시뮬레이션 시작';
                }
            }
            
            // 완료 알림
            this.showNotification('분석이 완료되었습니다', 'success');
            
            // 10초 후 자동 숨김
            this.schedulePipelineHide();
        }
    }

    /**
     * Handle pipeline stage updates
     */
    handlePipelineStage(message) {
        console.log('🎯 Pipeline stage:', message);
        
        this.stateManager.updatePipelineStage(
            message.stage,
            message.progress || 0,
            message.status || 'active'
        );
        
        if (this.pipelineVisual) {
            this.pipelineVisual.updateStage(
                message.stage,
                message.progress || 0,
                message.status || 'active',
                message.message,
                message.error
            );
        }
        
        // 완료 또는 오류 상태 시 자동 숨김
        if (message.status === 'completed' || message.status === 'complete') {
            console.log('파이프라인 스테이지 완료, 3초 후 자동 숨김');
            this.schedulePipelineHide();
        } else if (message.status === 'error' || message.status === 'failed') {
            console.log('파이프라인 오류, 5초 후 자동 숨김');
            // 오류 시 좀 더 오래 보여줌
            if (this.pipelineHideTimer) {
                clearTimeout(this.pipelineHideTimer);
            }
            this.pipelineHideTimer = setTimeout(() => {
                this.hidePipelineProgress();
            }, 5000);
        }
    }

    /**
     * Handle tool execution
     */
    handleToolExecution(message) {
        console.log('🔧 Tool execution:', message);
        
        // 파이프라인 진행 표시 보이기
        const pipelineProgress = document.getElementById('pipelineProgress');
        if (pipelineProgress) {
            pipelineProgress.classList.remove('hidden');
        }
        
        // Update state
        const tools = [...this.stateManager.reactiveState.tools.executed];
        tools.push({
            name: message.toolName,
            timestamp: message.timestamp,
            status: 'executing'
        });
        this.stateManager.setValueAtPath('tools.executed', tools);
        
        // Log to UI
        this.addToolLog(`실행 중: ${message.toolName}`, 'info');
        
        // 도구 실행 상태 표시
        this.updateToolExecutionDisplay(message.toolName, 'executing');
    }

    /**
     * Handle tool results
     */
    handleToolResult(message) {
        console.log('📊 Tool result:', message);
        
        // Update executed tools
        const tools = this.stateManager.reactiveState.tools.executed.map(tool => {
            if (tool.name === message.toolName) {
                return { ...tool, status: message.success ? 'completed' : 'failed' };
            }
            return tool;
        });
        this.stateManager.setValueAtPath('tools.executed', tools);
        
        // Log result
        const logType = message.success ? 'success' : 'error';
        this.addToolLog(`${message.toolName}: ${message.result || '완료'}`, logType);
        
        // 도구 실행 상태 업데이트
        this.updateToolExecutionDisplay(message.toolName, message.success ? 'completed' : 'failed');
        
        // 모든 도구 실행이 완료되었는지 확인
        const allCompleted = tools.every(tool => 
            tool.status === 'completed' || tool.status === 'failed'
        );
        
        if (allCompleted && tools.length > 0) {
            console.log('모든 도구 실행 완료');
            
            // 버튼 텍스트 원복
            const analyzeBtn = document.getElementById('analyzeSoarBtn');
            if (analyzeBtn) {
                analyzeBtn.disabled = false;
                const btnText = document.getElementById('btnText');
                if (btnText) {
                    btnText.innerHTML = '<i class="fas fa-robot mr-3"></i>AI + MCP + SOAR 시뮬레이션 시작';
                }
            }
            
            // UI 정리 예약
            this.schedulePipelineHide();
        }
    }
    
    /**
     * Update tool execution display
     */
    updateToolExecutionDisplay(toolName, status) {
        const toolsContainer = document.getElementById('executedTools');
        if (!toolsContainer) return;
        
        // 도구 실행 상태 표시 업데이트
        const existingToolEl = toolsContainer.querySelector(`[data-tool="${toolName}"]`);
        if (existingToolEl) {
            // 기존 도구 엘리먼트 업데이트
            const statusIcon = existingToolEl.querySelector('.tool-status');
            if (statusIcon) {
                switch(status) {
                    case 'executing':
                        statusIcon.className = 'tool-status fas fa-spinner fa-spin text-blue-400';
                        break;
                    case 'completed':
                        statusIcon.className = 'tool-status fas fa-check-circle text-green-400';
                        break;
                    case 'failed':
                        statusIcon.className = 'tool-status fas fa-exclamation-circle text-red-400';
                        break;
                }
            }
        } else {
            // 새 도구 엘리먼트 생성
            const toolEl = document.createElement('div');
            toolEl.className = 'flex items-center gap-2 p-2 bg-gray-800 rounded';
            toolEl.dataset.tool = toolName;
            
            let iconClass = 'fas fa-spinner fa-spin text-blue-400';
            if (status === 'completed') iconClass = 'fas fa-check-circle text-green-400';
            if (status === 'failed') iconClass = 'fas fa-exclamation-circle text-red-400';
            
            toolEl.innerHTML = `
                <i class="tool-status ${iconClass}"></i>
                <span class="text-sm">${toolName}</span>
            `;
            
            toolsContainer.appendChild(toolEl);
        }
    }

    /**
     * Handle approval requests (단순화된 버전)
     */
    async handleApprovalRequest(message) {
        console.log('🔐 ===========================================');
        console.log('🔐 HANDLE APPROVAL REQUEST');
        console.log('🔐 Message:', message);
        console.log('🔐 Modal available:', !!this.approvalModal);
        console.log('🔐 ===========================================');
        
        // 타입이 없어도 approvalId/requestId와 toolName이 있으면 승인 요청으로 처리
        const isApprovalRequest = message.type === 'APPROVAL_REQUEST' || 
                                 (message.approvalId && message.toolName) || 
                                 (message.requestId && message.toolName);
        
        if (!isApprovalRequest) {
            console.log('Not an approval request, skipping');
            return;
        }
        
        // 승인 ID 확인
        const approvalId = message.approvalId || message.requestId || `APPROVAL-${Date.now()}`;
        
        // 데이터 정규화
        const approvalData = {
            approvalId: approvalId,
            toolName: message.toolName || 'Unknown Tool',
            description: message.description || message.actionDescription || 'Approval Required',
            riskLevel: message.riskLevel || 'MEDIUM',
            parameters: message.parameters || {},
            requestedBy: message.requestedBy || 'System',
            timestamp: message.timestamp || new Date().toISOString()
        };
        
        console.log('Showing modal with data:', approvalData);
        
        // 승인 섹션 표시
        const approvalSection = document.getElementById('soarActionApprovalSection');
        if (approvalSection) {
            approvalSection.classList.remove('hidden');
        }
        
        // 알림 표시
        this.showNotification(`승인 요청: ${approvalData.toolName}`, 'warning', 5000);
        
        // 모달 표시 (무조건 시도)
        if (this.approvalModal) {
            try {
                console.log('🔔 ========== SHOWING MODAL ==========');
                const promise = this.approvalModal.show(approvalData);
                console.log('🔔 Modal.show() returned promise:', !!promise);
                
                if (promise && promise.then) {
                    promise.then(approved => {
                        console.log(`User decision: ${approved ? 'APPROVED' : 'REJECTED'}`);
                        this.handleApprovalDecision(approvalId, approved);
                    }).catch(error => {
                        console.error('Modal promise error:', error);
                        this.handleApprovalDecision(approvalId, false);
                    });
                }
            } catch (error) {
                console.error('Failed to show modal:', error);
                console.error('Error stack:', error.stack);
            }
        } else {
            console.error('CRITICAL: Approval modal is null!');
            // Fallback to confirm dialog
            const approved = confirm(`승인 요청: ${approvalData.toolName}\n\n${approvalData.description}\n\n승인하시겠습니까?`);
            this.handleApprovalDecision(approvalId, approved);
        }
        
        // UI 업데이트
        this.updateApprovalStatus(approvalId, 'PENDING');
    }

    /**
     * Handle approval decision
     * @param {String} approvalId - The approval ID
     * @param {Boolean} approved - Whether approved or rejected
     */
    handleApprovalDecision(approvalId, approved) {
        console.log(`Handling approval decision: ${approvalId} -> ${approved ? 'APPROVED' : 'REJECTED'}`);
        
        // 서버로 승인 결정 전송
        if (this.websocket && this.websocket.isConnected()) {
            const decision = {
                approvalId: approvalId,
                approved: approved,
                reason: approved ? 'User approved' : 'User rejected',
                timestamp: new Date().toISOString(),
                sessionId: this.sessionId
            };
            
            // /app/soar/approve/{approvalId} 엔드포인트로 전송
            this.websocket.send(`/app/soar/approve/${approvalId}`, decision);
            console.log('📤 Sent approval decision to server:', decision);
        }
        
        // UI 업데이트
        this.updateApprovalStatus(approvalId, approved ? 'APPROVED' : 'REJECTED');
        
        // 알림 표시
        this.showNotification(
            `${approved ? '승인' : '거부'}: ${approvalId}`,
            approved ? 'success' : 'warning'
        );
    }
    
    /**
     * Handle approval result from server
     */
    handleApprovalResult(message) {
        console.log('📨 Processing approval result:', message);
        
        const { approvalId, toolName, approved, reviewer, reason, timestamp } = message;
        
        if (approved) {
            console.log('Tool execution approved');
            this.showNotification(`${toolName} 도구 실행이 승인되었습니다`, 'success');
        } else {
            console.log('Tool execution denied');
            this.showNotification(`${toolName} 도구 실행이 거부되었습니다: ${reason || '사유 없음'}`, 'warning');
        }
        
        // 승인 모달 닫기 (열려있는 경우)
        if (this.approvalModal && this.approvalModal.isOpen()) {
            this.approvalModal.close();
        }
        
        // 승인 상태 업데이트
        this.updateApprovalStatus(approvalId, approved ? 'APPROVED' : 'REJECTED');
    }
    
    /**
     * Handle approval response
     */
    handleApprovalResponse(message) {
        console.log('Approval response:', message);
        
        // Update approvals in state
        if (message.approved) {
            const approved = [...this.stateManager.reactiveState.approvals.approved];
            approved.push(message);
            this.stateManager.setValueAtPath('approvals.approved', approved);
        } else {
            const rejected = [...this.stateManager.reactiveState.approvals.rejected];
            rejected.push(message);
            this.stateManager.setValueAtPath('approvals.rejected', rejected);
        }
        
        // Show notification
        const status = message.approved ? 'success' : 'warning';
        this.showNotification(`도구 ${message.approved ? '승인됨' : '거부됨'}: ${message.toolName}`, status);
    }

    /**
     * Handle MCP status updates
     */
    handleMcpStatus(message) {
        console.log('🔌 MCP status:', message);
        
        // Update state
        this.stateManager.setValueAtPath('mcpServers', {
            ...message,
            lastCheck: Date.now()
        });
        
        // Update monitoring dashboard
        if (this.monitoring) {
            this.monitoring.updateMcpStatus(message);
        }
    }

    /**
     * Handle MCP updates
     */
    handleMcpUpdate(message) {
        console.log('MCP update:', message);
        
        // Update specific MCP server status
        if (message.server) {
            this.stateManager.setValueAtPath(
                `mcpServers.${message.server}`,
                message.status
            );
        }
    }

    /**
     * Handle WebSocket errors
     */
    handleWebSocketError(message) {
        console.error('WebSocket error:', message);
        
        // Add to state errors
        this.stateManager.addError({
            message: message.error || 'WebSocket error',
            code: message.code
        });
    }

    /**
     * Handle monitoring metrics
     */
    handleMonitoringMetrics(message) {
        // Update metrics in state
        this.stateManager.setValueAtPath('metrics', message);
        
        // Update monitoring dashboard
        if (this.monitoring) {
            // The monitoring dashboard will auto-update via its own interval
        }
    }

    /**
     * Handle state errors
     */
    handleStateError(error) {
        console.error('State error:', error);
        
        // Show error notification
        this.showNotification(error.message || '알 수 없는 오류', 'error');
    }

    /**
     * Update session UI
     */
    updateSessionUI(status) {
        const statusEl = document.getElementById('sessionStatus');
        if (statusEl) {
            statusEl.textContent = status;
            statusEl.className = `session-status status-${status.toLowerCase()}`;
        }
    }

    /**
     * Update progress bar
     */
    updateProgressBar(progress) {
        const progressBar = document.getElementById('overallProgress');
        if (progressBar) {
            progressBar.style.width = `${progress}%`;
            progressBar.textContent = `${progress}%`;
        }
    }

    /**
     * Update tool log
     */
    updateToolLog(tools) {
        const logContainer = document.getElementById('toolLog');
        if (!logContainer) return;
        
        // Clear and rebuild log
        logContainer.innerHTML = '';
        tools.forEach(tool => {
            const entry = document.createElement('div');
            entry.className = `tool-log-entry status-${tool.status}`;
            entry.innerHTML = `
                <span class="tool-name">${tool.name}</span>
                <span class="tool-status">${tool.status}</span>
                <span class="tool-time">${new Date(tool.timestamp).toLocaleTimeString()}</span>
            `;
            logContainer.appendChild(entry);
        });
    }

    /**
     * Update approval badge
     */
    updateApprovalBadge(count) {
        const badge = document.getElementById('approvalBadge');
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'inline-block' : 'none';
        }
    }

    /**
     * Display error
     */
    displayError(error) {
        const errorPanel = document.getElementById('errorPanel');
        if (errorPanel) {
            errorPanel.style.display = 'block';
            errorPanel.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    ${error.message}
                    <span class="error-time">${new Date(error.timestamp).toLocaleTimeString()}</span>
                </div>
            `;
            
            // Auto-hide after 10 seconds
            setTimeout(() => {
                errorPanel.style.display = 'none';
            }, 10000);
        }
    }

    /**
     * Add tool log entry
     */
    addToolLog(message, type = 'info') {
        const logContainer = document.getElementById('toolLogEntries');
        if (!logContainer) return;
        
        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;
        entry.innerHTML = `
            <span class="log-time">${new Date().toLocaleTimeString()}</span>
            <span class="log-message">${message}</span>
        `;
        
        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    /**
     * Add to command history
     */
    addToCommandHistory(command) {
        const history = document.getElementById('commandHistory');
        if (!history) return;
        
        const entry = document.createElement('div');
        entry.className = 'history-entry';
        entry.innerHTML = `
            <span class="history-time">${new Date().toLocaleTimeString()}</span>
            <span class="history-command">${command}</span>
        `;
        
        history.appendChild(entry);
        history.scrollTop = history.scrollHeight;
    }

    /**
     * Clear logs
     */
    clearLogs() {
        const logContainers = [
            'toolLogEntries',
            'commandHistory',
            'errorPanel'
        ];
        
        logContainers.forEach(id => {
            const container = document.getElementById(id);
            if (container) {
                container.innerHTML = '';
            }
        });
        
        // Clear error history
        this.errorHandler.clearErrorHistory();
        
        // Clear approval history
        if (this.approvalModal) {
            this.approvalModal.clearHistory();
        }
        
        this.showNotification('로그 삭제됨', 'info');
    }

    /**
     * Show notification
     */
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)}"></i>
            <span>${message}</span>
        `;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.classList.add('show');
        }, 10);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 5000);
    }

    /**
     * Get notification icon
     */
    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }
    
    /**
     * Handle complete event
     */
    handleComplete(message) {
        console.log('🏁 Processing complete event:', message);
        try {
            // 이미 파싱된 데이터를 받도록 수정 (WebSocket 구독에서 파싱됨)
            const data = message;
            
            // sessionId 디버깅 로그 추가
            console.log('📋 SessionId 비교:');
            console.log('  - 현재 세션 ID:', this.sessionId);
            console.log('  - 메시지 세션 ID:', data.sessionId);
            console.log('  - 일치 여부:', data.sessionId === this.sessionId);
            
            // 분석 완료 처리 - isAnalyzing을 우선 체크하여 안정성 강화
            if (this.isAnalyzing || (this.sessionId && data.sessionId === this.sessionId)) {
                console.log('분석 완료 처리 진행');
                console.log('  - isAnalyzing:', this.isAnalyzing);
                console.log('  - sessionId 일치:', data.sessionId === this.sessionId);
                
                this.showNotification('분석이 완료되었습니다.', 'success');
                
                // 결과 표시
                if (data.finalResponse) {
                    console.log('📊 최종 응답 수신 및 표시');
                    console.log('  - 응답 길이:', data.finalResponse.length, 'characters');
                    this.displayAnalysisResult(data.finalResponse);
                } else {
                    console.warn('finalResponse가 없습니다');
                    // finalResponse가 없어도 완료 메시지 표시
                    this.displayAnalysisResult('분석이 완료되었으나 결과가 없습니다.');
                }
                
                // 상태 업데이트
                this.updateStatus('completed');
                
                // 분석 상태 초기화
                this.isAnalyzing = false;
                this.sessionId = null;
                this.conversationId = null;
                
                // 버튼 활성화
                this.enableAnalyzeButton();
            } else {
                console.warn('완료 이벤트를 무시함');
                console.log('  - isAnalyzing:', this.isAnalyzing);
                console.log('  - this.sessionId:', this.sessionId);
                console.log('  - data.sessionId:', data.sessionId);
            }
        } catch (error) {
            console.error('Error handling complete event:', error);
            // 에러 발생 시에도 버튼은 활성화
            this.isAnalyzing = false;
            this.enableAnalyzeButton();
        }
    }
    
    /**
     * Handle analysis complete (alias for handleComplete)
     */
    handleAnalysisComplete(message) {
        return this.handleComplete(message);
    }
    
    /**
     * Handle events
     */
    handleEvents(message) {
        console.log('📢 Processing events:', message);
        try {
            const data = typeof message === 'string' ? JSON.parse(message) : message;
            
            // 이벤트 타입에 따라 처리
            if (data.type) {
                switch(data.type) {
                    case 'TOOL_EXECUTION':
                        this.handleToolExecution(data);
                        break;
                    case 'APPROVAL_REQUEST':
                        this.handleApprovalRequest(data);
                        break;
                    case 'STATUS_UPDATE':
                        this.updateStatus(data.status);
                        break;
                    default:
                        console.log('Unknown event type:', data.type);
                }
            }
        } catch (error) {
            console.error('Error handling events:', error);
        }
    }

    /**
     * Create mock simulation data
     */
    createMockSimulation() {
        return {
            sessionId: `mock-${Date.now()}`,
            conversationId: `conv-${Date.now()}`,
            status: 'INITIALIZED',
            timestamp: new Date().toISOString()
        };
    }
    
    /**
     * Display analysis result on screen with professional UI
     * @param {Object|String} result - The analysis result to display
     */
    displayAnalysisResult(result) {
        console.log('📊 Displaying analysis result:', result);
        
        // Parse result if it's a string
        let parsedResult;
        try {
            parsedResult = typeof result === 'string' ? JSON.parse(result) : result;
        } catch (e) {
            console.error('Failed to parse result:', e);
            parsedResult = { analysisResult: result };
        }
        
        // Extract data from the response
        const analysisText = parsedResult.analysisResult || parsedResult.data?.analysisResult || '';
        const threatLevel = parsedResult.data?.threatLevel || parsedResult.threatLevel || 'UNKNOWN';
        const executedTools = parsedResult.data?.executedTools || parsedResult.executedTools || [];
        const recommendations = parsedResult.data?.recommendations || parsedResult.recommendations || [];
        const timestamp = parsedResult.timestamp || new Date().toISOString();
        const requestId = parsedResult.requestId || 'N/A';
        const responseId = parsedResult.responseId || 'N/A';
        const status = parsedResult.status || 'COMPLETED';
        
        // Parse analysis text into sections
        const sections = this.parseAnalysisText(analysisText);
        
        // Show results section
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) {
            resultsSection.classList.remove('hidden');
            resultsSection.style.display = 'block';
            console.log('Results section displayed');
        }
        
        // Update status with threat level color
        this.updateResultStatus(threatLevel, status);
        
        // Display main analysis result with sections
        this.displayMainAnalysis(sections, threatLevel);
        
        // Display executed tools if any
        if (executedTools.length > 0) {
            this.displayExecutedTools(executedTools);
        }
        
        // Display recommendations if any
        if (recommendations.length > 0) {
            this.displayRecommendations(recommendations);
        }
        
        // Display metadata
        this.displayMetadata({
            responseId,
            requestId,
            timestamp,
            status,
            threatLevel
        });
    }
    
    /**
     * Parse analysis text into structured sections
     */
    parseAnalysisText(analysisText) {
        const sections = {
            severityAssessment: '',
            playbooks: [],
            expectedResults: [],
            summary: '',
            nextSteps: ''
        };
        
        if (!analysisText) return sections;
        
        // Split by major sections
        const lines = analysisText.split('\n');
        let currentSection = '';
        
        lines.forEach(line => {
            // Detect severity assessment
            if (line.includes('심각도 재평가') || line.includes('위협 수준')) {
                currentSection = 'severity';
                sections.severityAssessment = line;
            }
            // Detect playbooks
            else if (line.includes('플레이북') || line.includes('자동화된 조치')) {
                currentSection = 'playbooks';
            }
            else if (currentSection === 'playbooks' && line.includes('**')) {
                const match = line.match(/\*\*(.*?)\*\*/);
                if (match) {
                    sections.playbooks.push({
                        name: match[1],
                        description: line.replace(/\*\*(.*?)\*\*:?/, '').trim()
                    });
                }
            }
            // Detect expected results
            else if (line.includes('예상 결과')) {
                currentSection = 'results';
            }
            else if (currentSection === 'results' && line.trim().startsWith(sections.playbooks.length > 0 ? '1.' : '-')) {
                sections.expectedResults.push(line.trim());
            }
            // Detect summary
            else if (line.includes('최종 요약') || line.includes('다음 단계')) {
                currentSection = 'summary';
                sections.summary = line;
            }
            else if (currentSection === 'summary' && line.trim()) {
                sections.nextSteps += line + '\n';
            }
        });
        
        return sections;
    }
    
    /**
     * Update result status with threat level color coding
     */
    updateResultStatus(threatLevel, status) {
        const resultStatus = document.querySelector('.result-status');
        if (!resultStatus) return;
        
        const colors = {
            'CRITICAL': { bg: 'rgba(239, 68, 68, 0.2)', border: 'rgba(239, 68, 68, 0.4)', text: '#fca5a5' },
            'HIGH': { bg: 'rgba(251, 146, 60, 0.2)', border: 'rgba(251, 146, 60, 0.4)', text: '#fdba74' },
            'MEDIUM': { bg: 'rgba(250, 204, 21, 0.2)', border: 'rgba(250, 204, 21, 0.4)', text: '#fde047' },
            'LOW': { bg: 'rgba(34, 197, 94, 0.2)', border: 'rgba(34, 197, 94, 0.4)', text: '#86efac' },
            'UNKNOWN': { bg: 'rgba(107, 114, 128, 0.2)', border: 'rgba(107, 114, 128, 0.4)', text: '#9ca3af' }
        };
        
        const color = colors[threatLevel] || colors['UNKNOWN'];
        const icon = threatLevel === 'CRITICAL' ? 'fa-exclamation-triangle' : 
                    threatLevel === 'HIGH' ? 'fa-exclamation-circle' :
                    threatLevel === 'MEDIUM' ? 'fa-info-circle' :
                    'fa-check-circle';
        
        resultStatus.innerHTML = `
            <i class="fas ${icon}"></i>
            <span>분석 완료 - 위협 수준: ${threatLevel}</span>
        `;
        resultStatus.style.background = color.bg;
        resultStatus.style.borderColor = color.border;
        resultStatus.style.color = color.text;
    }
    
    /**
     * Display main analysis with professional formatting
     */
    displayMainAnalysis(sections, threatLevel) {
        const analysisResult = document.getElementById('analysisResult');
        if (!analysisResult) return;
        
        let html = '<div class="analysis-sections">';
        
        // Severity Assessment Card
        if (sections.severityAssessment) {
            html += `
                <div class="analysis-card severity-card">
                    <div class="card-header">
                        <i class="fas fa-shield-alt"></i>
                        <h4>심각도 평가</h4>
                        <span class="threat-badge threat-${threatLevel.toLowerCase()}">${threatLevel}</span>
                    </div>
                    <div class="card-content">
                        <p>${sections.severityAssessment}</p>
                    </div>
                </div>
            `;
        }
        
        // Playbooks Card
        if (sections.playbooks.length > 0) {
            html += `
                <div class="analysis-card playbook-card">
                    <div class="card-header">
                        <i class="fas fa-play-circle"></i>
                        <h4>실행 플레이북</h4>
                        <span class="count-badge">${sections.playbooks.length}</span>
                    </div>
                    <div class="card-content">
                        <div class="playbook-list">
            `;
            
            sections.playbooks.forEach((playbook, index) => {
                const icon = playbook.name.includes('kill') ? 'fa-stop-circle' :
                           playbook.name.includes('block') ? 'fa-ban' :
                           playbook.name.includes('alert') ? 'fa-bell' :
                           playbook.name.includes('scan') ? 'fa-search' :
                           'fa-cog';
                
                html += `
                    <div class="playbook-item">
                        <div class="playbook-number">${index + 1}</div>
                        <div class="playbook-icon"><i class="fas ${icon}"></i></div>
                        <div class="playbook-details">
                            <div class="playbook-name">${playbook.name}</div>
                            <div class="playbook-desc">${playbook.description}</div>
                        </div>
                        <div class="playbook-status">
                            <i class="fas fa-check-circle" style="color: #86efac;"></i>
                        </div>
                    </div>
                `;
            });
            
            html += `
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Expected Results Card
        if (sections.expectedResults.length > 0) {
            html += `
                <div class="analysis-card results-card">
                    <div class="card-header">
                        <i class="fas fa-bullseye"></i>
                        <h4>예상 결과</h4>
                    </div>
                    <div class="card-content">
                        <ul class="results-list">
            `;
            
            sections.expectedResults.forEach(result => {
                html += `<li>${result}</li>`;
            });
            
            html += `
                        </ul>
                    </div>
                </div>
            `;
        }
        
        // Summary & Next Steps Card
        if (sections.summary || sections.nextSteps) {
            html += `
                <div class="analysis-card summary-card">
                    <div class="card-header">
                        <i class="fas fa-clipboard-check"></i>
                        <h4>요약 및 다음 단계</h4>
                    </div>
                    <div class="card-content">
                        ${sections.summary ? `<p class="summary-text">${sections.summary}</p>` : ''}
                        ${sections.nextSteps ? `<div class="next-steps">${sections.nextSteps}</div>` : ''}
                    </div>
                </div>
            `;
        }
        
        html += '</div>';
        
        // Add export buttons
        html += `
            <div class="export-buttons">
                <button onclick="soarAnalysis.copyToClipboard()" class="export-btn">
                    <i class="fas fa-copy"></i> 클립보드 복사
                </button>
                <button onclick="soarAnalysis.exportAsJSON()" class="export-btn">
                    <i class="fas fa-download"></i> JSON 내보내기
                </button>
            </div>
        `;
        
        analysisResult.innerHTML = html;
        
        // Store result for export
        this.lastAnalysisResult = {
            sections,
            threatLevel,
            timestamp: new Date().toISOString()
        };
    }
    
    /**
     * Display executed tools
     */
    displayExecutedTools(tools) {
        const toolsSection = document.getElementById('toolsSection');
        if (!toolsSection || tools.length === 0) return;
        
        toolsSection.style.display = 'block';
        const toolsGrid = document.getElementById('toolsGrid');
        
        let html = '';
        tools.forEach(tool => {
            const toolInfo = typeof tool === 'string' ? { name: tool } : tool;
            html += `
                <div class="tool-card">
                    <div class="tool-icon">
                        <i class="fas fa-tools"></i>
                    </div>
                    <div class="tool-name">${toolInfo.name}</div>
                    ${toolInfo.status ? `<div class="tool-status">${toolInfo.status}</div>` : ''}
                </div>
            `;
        });
        
        toolsGrid.innerHTML = html;
    }
    
    /**
     * Display recommendations
     */
    displayRecommendations(recommendations) {
        const recsSection = document.getElementById('recommendationsSection');
        if (!recsSection || recommendations.length === 0) return;
        
        recsSection.style.display = 'block';
        const recsList = document.getElementById('recommendationsList');
        
        let html = '';
        recommendations.forEach(rec => {
            html += `
                <li class="recommendation-item">
                    <i class="fas fa-chevron-right"></i>
                    <span>${rec}</span>
                </li>
            `;
        });
        
        recsList.innerHTML = html;
    }
    
    /**
     * Display metadata
     */
    displayMetadata(metadata) {
        const formattedTime = metadata.timestamp ? new Date(metadata.timestamp).toLocaleString('ko-KR') : 'N/A';

        const metadataGrid = document.getElementById('metadataGrid');
        if (metadataGrid) {
            metadataGrid.innerHTML = `
                <div class="metadata-item">
                    <span class="metadata-label">응답 ID:</span>
                    <span class="metadata-value">${metadata.responseId || 'N/A'}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">요청 ID:</span>
                    <span class="metadata-value">${metadata.requestId || 'N/A'}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">상태:</span>
                    <span class="metadata-value ${metadata.status ? 'status-' + metadata.status.toLowerCase() : ''}">${metadata.status || 'N/A'}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">위협 수준:</span>
                    <span class="metadata-value ${metadata.threatLevel ? 'threat-' + metadata.threatLevel.toLowerCase() : ''}">${metadata.threatLevel || 'N/A'}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">완료 시간:</span>
                    <span class="metadata-value">${formattedTime}</span>
                </div>
            `;
        }

        const metadataSection = document.getElementById('metadataSection');
        if (metadataSection) {
            metadataSection.innerHTML = `
                <div class="metadata-content">
                    <h4 class="text-sm font-semibold text-gray-400 mb-2">메타데이터</h4>
                    <div class="text-xs text-gray-500">
                        <div><strong>세션 ID:</strong> ${metadata.sessionId || 'N/A'}</div>
                        <div><strong>대화 ID:</strong> ${metadata.conversationId || 'N/A'}</div>
                        <div><strong>상태:</strong> ${metadata.status || 'N/A'}</div>
                        <div><strong>시간:</strong> ${formattedTime}</div>
                    </div>
                </div>
            `;
        }
    }
    
    /**
     * Copy analysis result to clipboard
     */
    copyToClipboard() {
        if (!this.lastAnalysisResult) return;
        
        const text = JSON.stringify(this.lastAnalysisResult, null, 2);
        navigator.clipboard.writeText(text).then(() => {
            this.showNotification('분석 결과가 클립보드에 복사되었습니다', 'success');
        }).catch(err => {
            console.error('Failed to copy:', err);
            this.showNotification('복사 실패', 'error');
        });
    }
    
    /**
     * Export analysis as JSON
     */
    exportAsJSON() {
        if (!this.lastAnalysisResult) return;
        
        const dataStr = JSON.stringify(this.lastAnalysisResult, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
        
        const exportFileDefaultName = `soar-analysis-${Date.now()}.json`;
        
        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportFileDefaultName);
        linkElement.click();
        
        this.showNotification('분석 결과를 다운로드합니다', 'success');
    }
    
    /**
     * Update system status
     * @param {String} status - The status to update to
     */
    updateStatus(status) {
        console.log('📊 Updating status to:', status);
        
        // 세션 상태 업데이트
        if (this.stateManager) {
            this.stateManager.setValueAtPath('session.status', status);
        }
        
        // UI 상태 업데이트
        const sessionStatus = document.getElementById('sessionStatus');
        if (sessionStatus) {
            sessionStatus.textContent = status;
            sessionStatus.className = `ml-2 font-semibold text-${this.getStatusColor(status)}-400`;
        }
        
        // 분석 완료 시 버튼 재활성화
        if (status === 'completed' || status === 'error' || status === 'stopped') {
            this.enableAnalyzeButton();
            this.isAnalyzing = false;
            
            // 파이프라인 숨기기
            this.schedulePipelineHide();
        }
        
        // 상태별 알림
        if (status === 'completed') {
            this.showNotification('분석이 성공적으로 완료되었습니다', 'success');
        } else if (status === 'error') {
            this.showNotification('분석 중 오류가 발생했습니다', 'error');
        }
    }
    
    /**
     * Update approval status in UI
     * @param {String} approvalId - The approval ID
     * @param {String} status - The approval status (APPROVED, REJECTED, PENDING)
     */
    updateApprovalStatus(approvalId, status) {
        console.log(`📊 Updating approval status: ${approvalId} -> ${status}`);
        
        // 승인 섹션 업데이트
        const approvalSection = document.getElementById('soarActionApprovalSection');
        if (approvalSection) {
            approvalSection.classList.remove('hidden');
            
            const approvalStatus = approvalSection.querySelector('.approval-status');
            if (approvalStatus) {
                let statusIcon = '';
                let statusText = '';
                let statusColor = '';
                
                switch(status) {
                    case 'APPROVED':
                        statusIcon = 'fas fa-check-circle';
                        statusText = '승인됨';
                        statusColor = 'text-green-400';
                        break;
                    case 'REJECTED':
                        statusIcon = 'fas fa-times-circle';
                        statusText = '거부됨';
                        statusColor = 'text-red-400';
                        break;
                    case 'PENDING':
                        statusIcon = 'fas fa-clock';
                        statusText = '대기 중';
                        statusColor = 'text-yellow-400';
                        break;
                    default:
                        statusIcon = 'fas fa-question-circle';
                        statusText = status;
                        statusColor = 'text-gray-400';
                }
                
                approvalStatus.innerHTML = `
                    <i class="${statusIcon} ${statusColor}"></i>
                    <span class="${statusColor}">${statusText}</span>
                    <span class="text-gray-500 text-xs ml-2">(${approvalId})</span>
                `;
            }
        }
        
        // 승인 리스트 업데이트
        const approvalList = document.getElementById('approvalList');
        if (approvalList) {
            const approvalItem = approvalList.querySelector(`[data-approval-id="${approvalId}"]`);
            if (approvalItem) {
                approvalItem.dataset.status = status;
                approvalItem.className = `approval-item approval-${status.toLowerCase()}`;
            }
        }
    }
    
    /**
     * Update specific approval item
     * @param {String} requestId - The request ID
     * @param {Boolean} approved - Whether approved or not
     */
    updateSpecificApproval(requestId, approved) {
        console.log(`📊 Updating specific approval: ${requestId} -> ${approved ? 'APPROVED' : 'REJECTED'}`);
        
        // 승인 상태 업데이트
        this.updateApprovalStatus(requestId, approved ? 'APPROVED' : 'REJECTED');
        
        // 특정 승인 항목 UI 업데이트
        const approvalCard = document.querySelector(`[data-request-id="${requestId}"]`);
        if (approvalCard) {
            approvalCard.classList.add(approved ? 'approved' : 'rejected');
            
            const statusBadge = approvalCard.querySelector('.status-badge');
            if (statusBadge) {
                statusBadge.textContent = approved ? '승인됨' : '거부됨';
                statusBadge.className = `status-badge ${approved ? 'badge-success' : 'badge-danger'}`;
            }
        }
        
        // 알림 표시
        this.showNotification(
            `요청 ${requestId}가 ${approved ? '승인' : '거부'}되었습니다`,
            approved ? 'success' : 'warning'
        );
    }
    
    /**
     * Enable analyze button
     */
    enableAnalyzeButton() {
        const analyzeBtn = document.getElementById('analyzeSoarBtn');
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.classList.remove('disabled', 'opacity-50', 'cursor-not-allowed');
            
            const btnText = document.getElementById('btnText');
            if (btnText) {
                btnText.innerHTML = '<i class="fas fa-robot"></i> AI SOAR 분석 시작';
            } else {
                // btnText가 없으면 버튼 전체 텍스트 업데이트
                analyzeBtn.innerHTML = '<i class="fas fa-robot"></i> <span id="btnText">AI SOAR 분석 시작</span>';
            }
            console.log('버튼 활성화 완료 - disabled:', analyzeBtn.disabled);
        } else {
            console.error('analyzeSoarBtn 요소를 찾을 수 없음');
        }
    }

    /**
     * Clear WebSocket message log
     */
    clearWebSocketLog() {
        const messagesEl = document.getElementById('websocketMessages');
        if (messagesEl) {
            messagesEl.innerHTML = '';
        }
        
        // Reset counters
        const sendCountEl = document.getElementById('wsSendCount');
        const receiveCountEl = document.getElementById('wsReceiveCount');
        if (sendCountEl) sendCountEl.textContent = '0';
        if (receiveCountEl) receiveCountEl.textContent = '0';
        
        console.log('WebSocket 메시지 로그 지워짐');
    }
    
    /**
     * Handle WebSocket disconnect and reconnection
     */
    handleWebSocketDisconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            this.showNotification('WebSocket 재연결 실패', 'error');
            return;
        }
        
        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
        console.log(`WebSocket 재연결 시도 ${this.reconnectAttempts + 1}/${this.maxReconnectAttempts} - ${delay}ms 후`);
        
        setTimeout(async () => {
            try {
                await this.initializeWebSocket();
                console.log('WebSocket 재연결 성공');
                this.reconnectAttempts = 0; // 성공 시 카운터 리셋
            } catch (error) {
                console.error('WebSocket 재연결 실패:', error);
                this.reconnectAttempts++;
                this.handleWebSocketDisconnect(); // 재귀적으로 다시 시도
            }
        }, delay);
    }
    
    /**
     * Force WebSocket reconnection
     */
    async reconnectWebSocket() {
        console.log('Forcing WebSocket reconnection...');
        
        if (this.websocket) {
            // Disconnect existing connection
            this.websocket.disconnect();
            console.log('🔌 Disconnected existing WebSocket');
            
            // Wait a moment
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Reset attempts
            this.reconnectAttempts = 0;
            
            // Reinitialize
            await this.initializeWebSocket();
            console.log('WebSocket reconnected');
        } else {
            console.log('No WebSocket to reconnect');
        }
    }
    
    /**
     * Debug WebSocket connections and subscriptions
     */
    debugWebSocket() {
        console.log('===========================================');
        console.log('WEBSOCKET DEBUG INFO');
        console.log('WebSocket exists?', !!this.websocket);
        console.log('WebSocket connected?', this.websocket ? this.websocket.isConnected() : false);
        console.log('WebSocket state:', this.websocket ? this.websocket.getConnectionState() : 'N/A');
        console.log('WebSocket subscriptions:', this.websocket ? Array.from(this.websocket.subscriptions.keys()) : []);
        console.log('WebSocket listeners:', this.websocket ? Array.from(this.websocket.listeners.keys()) : []);
        console.log('Approval modal exists?', !!this.approvalModal);
        console.log('===========================================');
        return {
            connected: this.websocket ? this.websocket.isConnected() : false,
            subscriptions: this.websocket ? Array.from(this.websocket.subscriptions.keys()) : [],
            listeners: this.websocket ? Array.from(this.websocket.listeners.keys()) : []
        };
    }
    
    /**
     * Test approval modal manually
     */
    testApprovalModal() {
        console.log('🧪 Testing approval modal...');
        
        const testMessage = {
            type: "APPROVAL_REQUEST",
            approvalId: "test-" + Date.now(),
            toolName: "Test Security Tool",
            description: "This is a test approval request to verify the modal is working",
            riskLevel: "HIGH",
            requestedBy: "Test System",
            timestamp: new Date().toISOString()
        };
        
        console.log('🧪 Test message:', testMessage);
        console.log('🧪 Calling handleApprovalRequest...');
        
        this.handleApprovalRequest(testMessage);
    }
    
    /**
     * Get system status
     */
    getSystemStatus() {
        return {
            websocket: this.websocket ? this.websocket.isConnected() : false,
            session: this.stateManager ? this.stateManager.getState() : null,
            circuitBreakers: this.errorHandler ? this.errorHandler.getCircuitBreakersStatus() : {},
            errorStats: this.errorHandler ? this.errorHandler.getErrorStatistics() : {},
            approvalQueue: this.approvalModal ? this.approvalModal.getQueueSize() : 0,
            pipelineReport: this.pipelineVisual ? this.pipelineVisual.getPerformanceReport() : null,
            monitoringMetrics: this.monitoring ? this.monitoring.getMetrics() : null
        };
    }

    /**
     * Export system diagnostics
     */
    exportDiagnostics() {
        const diagnostics = {
            timestamp: new Date().toISOString(),
            status: this.getSystemStatus(),
            stateHistory: this.stateManager ? this.stateManager.getHistory() : [],
            errorHistory: this.errorHandler ? this.errorHandler.getErrorStatistics() : {},
            approvalHistory: this.approvalModal ? this.approvalModal.getHistory() : []
        };
        
        // Download as JSON
        const blob = new Blob([JSON.stringify(diagnostics, null, 2)], {
            type: 'application/json'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `soar-diagnostics-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showNotification('진단 데이터 내보내기 완료', 'success');
    }
}

// Make class available globally
window.SoarAnalysisEnhanced = SoarAnalysisEnhanced;
// Legacy compatibility
window.SoarEnhancedSystem = SoarAnalysisEnhanced;

// 초기화는 아래 코드에서 한 번만 수행됨

// Add notification styles if not already present
if (!document.getElementById('notification-styles')) {
    const styles = `
        .notification {
            position: fixed;
            top: 20px;
            right: -400px;
            min-width: 300px;
            max-width: 500px;
            padding: 1rem 1.5rem;
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 0.75rem;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            color: #e2e8f0;
            font-size: 0.9rem;
            z-index: 20000;
            transition: right 0.3s ease-in-out;
        }

        .notification.show {
            right: 20px;
        }

        .notification-success {
            border-left: 4px solid #22c55e;
        }

        .notification-error {
            border-left: 4px solid #ef4444;
        }

        .notification-warning {
            border-left: 4px solid #facc15;
        }

        .notification-info {
            border-left: 4px solid #3b82f6;
        }

        .notification i {
            font-size: 1.25rem;
        }

        .notification-success i { color: #22c55e; }
        .notification-error i { color: #ef4444; }
        .notification-warning i { color: #facc15; }
        .notification-info i { color: #3b82f6; }
    `;

    const styleSheet = document.createElement('style');
    styleSheet.id = 'notification-styles';
    styleSheet.textContent = styles;
    document.head.appendChild(styleSheet);
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SoarAnalysisEnhanced;
}

// Make available globally for browser environment
if (typeof window !== 'undefined') {
    window.SoarAnalysisEnhanced = SoarAnalysisEnhanced;
    window.SoarEnhancedSystem = SoarAnalysisEnhanced; // Alias for compatibility
    
    // Auto-initialize when DOM is ready (중복 초기화 방지)
    if (!window.soarEnhanced) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                if (!window.soarEnhanced) {
                    // Create global instance
                    window.soarEnhanced = new SoarAnalysisEnhanced();
                    window.soarEnhanced.initialize().then(() => {
                        console.log('SOAR Enhanced System initialized globally');
                    }).catch(err => {
                        console.error('Failed to initialize SOAR Enhanced System:', err);
                    });
                }
            });
        } else {
            // DOM already loaded
            window.soarEnhanced = new SoarAnalysisEnhanced();
            window.soarEnhanced.initialize().then(() => {
                console.log('SOAR Enhanced System initialized globally');
            }).catch(err => {
                console.error('Failed to initialize SOAR Enhanced System:', err);
            });
        }
    }
}