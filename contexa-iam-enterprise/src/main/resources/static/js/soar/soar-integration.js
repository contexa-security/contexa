/**
 * SOAR System Integration
 * 
 * 모든 SOAR 컴포넌트를 통합하고 초기화하는 메인 스크립트
 * WebSocket, SSE, 승인 모달을 완벽하게 연결
 */
(function() {
    'use strict';

    // 전역 SOAR 시스템 객체
    window.SoarSystem = {
        version: '2.0.0',
        components: {},
        initialized: false,
        config: {
            websocketEndpoint: '/ws-soar',
            sseEndpoint: '/api/soar/sse/connect',
            apiBaseUrl: '/api/soar',
            sessionTimeout: 1800000, // 30분
            approvalTimeout: 300000, // 5분
            heartbeatInterval: 30000, // 30초
            retryAttempts: 3,
            retryDelay: 2000,
            debug: true
        }
    };

    /**
     * SOAR 시스템 초기화
     */
    window.SoarSystem.initialize = async function() {
        if (this.initialized) {
            console.warn('SOAR System already initialized');
            return;
        }

        console.log('🚀 Initializing SOAR System v' + this.version);

        try {
            // 1. WebSocket 클라이언트 초기화
            await this.initializeWebSocket();

            // 2. 승인 모달 초기화
            this.initializeApprovalModal();

            // 3. 승인 핸들러 초기화 및 연결
            this.initializeApprovalHandler();

            // 4. 파이프라인 시각화 초기화
            this.initializePipelineVisualization();

            // 5. 모니터링 대시보드 초기화
            this.initializeMonitoring();

            // 6. 오류 핸들러 초기화
            this.initializeErrorHandler();

            // 7. 세션 관리 초기화
            this.initializeSessionManager();

            // 8. 이벤트 리스너 등록
            this.registerGlobalEventListeners();

            // 9. 브라우저 알림 권한 요청
            await this.requestNotificationPermission();

            // 10. 시스템 상태 확인
            await this.checkSystemStatus();

            this.initialized = true;
            console.log('SOAR System initialized successfully');

            // 초기화 완료 이벤트 발생
            this.dispatchEvent('initialized', { timestamp: Date.now() });

        } catch (error) {
            console.error('SOAR System initialization failed:', error);
            this.handleInitializationError(error);
        }
    };

    /**
     * WebSocket 클라이언트 초기화 (중앙 매니저 사용)
     */
    window.SoarSystem.initializeWebSocket = async function() {
        console.log('📡 Initializing WebSocket client through manager...');

        let client;
        
        // 중앙 매니저를 통해 WebSocket 클라이언트 가져오기
        if (window.soarManager) {
            client = window.soarManager.getComponent('WebSocketClient', window.EnhancedWebSocketClient, this.config.websocketEndpoint);
        } else {
            console.warn('SoarManager not found, creating local WebSocket instance');
            client = new window.EnhancedWebSocketClient(this.config.websocketEndpoint);
        }
        
        // 오류 핸들러 설정
        if (window.SoarErrorHandler) {
            client.setErrorHandler(window.SoarErrorHandler);
        }

        // 연결 콜백 설정
        client.onConnect = () => {
            console.log('WebSocket connected');
            this.updateConnectionStatus('connected');
        };

        client.onDisconnect = () => {
            console.warn('WebSocket disconnected');
            this.updateConnectionStatus('disconnected');
        };

        // 연결 시도
        try {
            await client.connect({ timeout: 10000 });
            this.components.websocket = client;
            console.log('WebSocket client initialized');
        } catch (error) {
            console.error('WebSocket connection failed:', error);
            // SSE 폴백 모드로 전환
            console.log('Switching to SSE fallback mode');
            this.components.websocket = null;
        }
    };

    /**
     * 승인 모달 초기화 (중앙 매니저 사용)
     */
    window.SoarSystem.initializeApprovalModal = function() {
        console.log('🔐 Initializing approval modal through manager...');

        // 중앙 매니저를 통해 인스턴스 가져오기
        if (window.soarManager) {
            this.components.approvalModal = window.soarManager.getComponent('ApprovalModal', window.SoarApprovalModal);
        } else {
            // 매니저가 없을 경우 직접 생성 (폴백)
            console.warn('SoarManager not found, creating local instance');
            this.components.approvalModal = new window.SoarApprovalModal();
        }

        console.log('Approval modal initialized');
    };

    /**
     * 승인 핸들러 초기화 및 연결 (중앙 매니저 사용)
     */
    window.SoarSystem.initializeApprovalHandler = function() {
        console.log('🔗 Initializing approval handler through manager...');

        // 중앙 매니저를 통해 인스턴스 가져오기
        if (window.soarManager) {
            this.components.approvalHandler = window.soarManager.getComponent('ApprovalHandler', window.SoarApprovalHandler);
            
            // WebSocket과 모달 연결
            this.components.approvalHandler.initialize(
                this.components.websocket,
                this.components.approvalModal
            );
        } else {
            // 매니저가 없을 경우 직접 생성 (폴백)
            console.warn('SoarManager not found, creating local instance');
            const handler = new window.SoarApprovalHandler();
            
            // WebSocket과 모달 연결
            handler.initialize(
                this.components.websocket,
                this.components.approvalModal
            );

            this.components.approvalHandler = handler;
        }

        console.log('Approval handler initialized and connected');
    };

    /**
     * 파이프라인 시각화 초기화
     */
    window.SoarSystem.initializePipelineVisualization = function() {
        if (window.SoarPipelineVisual) {
            console.log('📊 Initializing pipeline visualization...');
            
            const pipeline = new window.SoarPipelineVisual();
            pipeline.initialize();
            
            this.components.pipeline = pipeline;
            console.log('Pipeline visualization initialized');
        }
    };

    /**
     * 모니터링 대시보드 초기화
     */
    window.SoarSystem.initializeMonitoring = function() {
        if (window.SoarMonitoringDashboard) {
            console.log('📈 Initializing monitoring dashboard...');
            
            const monitoring = new window.SoarMonitoringDashboard();
            monitoring.initialize();
            
            this.components.monitoring = monitoring;
            console.log('Monitoring dashboard initialized');
        }
    };

    /**
     * 오류 핸들러 초기화
     */
    window.SoarSystem.initializeErrorHandler = function() {
        if (window.SoarErrorHandler) {
            console.log('Initializing error handler...');
            
            // 전역 오류 캐처 등록
            window.addEventListener('error', (event) => {
                window.SoarErrorHandler.handleError(event.error, {
                    component: 'Global',
                    severity: 'error'
                });
            });

            window.addEventListener('unhandledrejection', (event) => {
                window.SoarErrorHandler.handleError(event.reason, {
                    component: 'Promise',
                    severity: 'error'
                });
            });

            console.log('Error handler initialized');
        }
    };

    /**
     * 세션 관리 초기화
     */
    window.SoarSystem.initializeSessionManager = function() {
        console.log('🔑 Initializing session manager...');

        // 세션 ID 생성 또는 복구
        let sessionId = sessionStorage.getItem('soarSessionId');
        if (!sessionId) {
            sessionId = 'soar-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('soarSessionId', sessionId);
        }

        window.currentSessionId = sessionId;
        console.log('Session initialized:', sessionId);

        // 세션 타임아웃 관리
        this.startSessionTimeout();
    };

    /**
     * 전역 이벤트 리스너 등록
     */
    window.SoarSystem.registerGlobalEventListeners = function() {
        console.log('📌 Registering global event listeners...');

        // 페이지 언로드 시 정리
        window.addEventListener('beforeunload', () => {
            this.cleanup();
        });

        // 가시성 변경 감지
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                console.log('Page hidden - reducing activity');
                this.pauseBackgroundActivity();
            } else {
                console.log('Page visible - resuming activity');
                this.resumeBackgroundActivity();
            }
        });

        // 네트워크 상태 변경 감지
        window.addEventListener('online', () => {
            console.log('🌐 Network online - reconnecting');
            this.handleNetworkReconnect();
        });

        window.addEventListener('offline', () => {
            console.log('🌐 Network offline');
            this.handleNetworkDisconnect();
        });

        console.log('Global event listeners registered');
    };

    /**
     * 브라우저 알림 권한 요청
     */
    window.SoarSystem.requestNotificationPermission = async function() {
        if ('Notification' in window && Notification.permission === 'default') {
            console.log('🔔 Requesting notification permission...');
            const permission = await Notification.requestPermission();
            console.log('🔔 Notification permission:', permission);
        }
    };

    /**
     * 시스템 상태 확인
     */
    window.SoarSystem.checkSystemStatus = async function() {
        console.log('Checking system status...');

        try {
            const response = await fetch(this.config.apiBaseUrl + '/status', {
                headers: {
                    'X-Session-Id': window.currentSessionId
                }
            });

            if (response.ok) {
                const status = await response.json();
                console.log('📊 System status:', status);
                
                // MCP 서버 상태 업데이트
                this.updateMcpServerStatus(status.mcpServers);
                
                return status;
            }
        } catch (error) {
            console.warn('Failed to check system status:', error);
        }
    };

    /**
     * 연결 상태 업데이트
     */
    window.SoarSystem.updateConnectionStatus = function(status) {
        const indicator = document.getElementById('wsIndicator');
        const state = document.getElementById('wsState');

        if (indicator && state) {
            if (status === 'connected') {
                indicator.className = 'fas fa-circle text-green-400 text-xs';
                state.textContent = '연결됨';
            } else {
                indicator.className = 'fas fa-circle text-red-400 text-xs';
                state.textContent = '연결 끊김';
            }
        }

        // 상태 이벤트 발생
        this.dispatchEvent('connectionStatusChanged', { status });
    };

    /**
     * MCP 서버 상태 업데이트
     */
    window.SoarSystem.updateMcpServerStatus = function(servers) {
        if (!servers) return;

        Object.keys(servers).forEach(serverName => {
            const serverEl = document.getElementById(`mcp-${serverName}`);
            if (serverEl) {
                const isActive = servers[serverName];
                serverEl.className = `mcp-server ${isActive ? 'active' : 'inactive'}`;
                
                const indicator = serverEl.querySelector('.mcp-indicator');
                if (indicator) {
                    indicator.className = `mcp-indicator ${isActive ? 'active' : 'inactive'}`;
                }
            }
        });
    };

    /**
     * 세션 타임아웃 관리
     */
    window.SoarSystem.startSessionTimeout = function() {
        let lastActivity = Date.now();

        // 활동 감지
        const updateActivity = () => {
            lastActivity = Date.now();
        };

        ['click', 'keypress', 'mousemove'].forEach(event => {
            document.addEventListener(event, updateActivity);
        });

        // 타임아웃 체크
        setInterval(() => {
            const elapsed = Date.now() - lastActivity;
            if (elapsed > this.config.sessionTimeout) {
                console.warn('⏱️ Session timeout');
                this.handleSessionTimeout();
            }
        }, 60000); // 1분마다 체크
    };

    /**
     * 세션 타임아웃 처리
     */
    window.SoarSystem.handleSessionTimeout = function() {
        // 세션 정리
        sessionStorage.removeItem('soarSessionId');
        
        // 알림
        if (this.components.approvalHandler) {
            this.components.approvalHandler.showNotification('세션 만료', {
                body: '보안을 위해 세션이 만료되었습니다.',
                icon: '/icons/timeout.png'
            });
        }

        // 페이지 새로고침 또는 로그인 페이지로 이동
        setTimeout(() => {
            location.reload();
        }, 3000);
    };

    /**
     * 백그라운드 활동 일시 중지
     */
    window.SoarSystem.pauseBackgroundActivity = function() {
        // 하트비트 중지 등
        if (this.components.websocket) {
            this.components.websocket.stopHeartbeat();
        }
    };

    /**
     * 백그라운드 활동 재개
     */
    window.SoarSystem.resumeBackgroundActivity = function() {
        // 하트비트 재시작
        if (this.components.websocket) {
            this.components.websocket.startHeartbeat();
        }

        // 시스템 상태 재확인
        this.checkSystemStatus();
    };

    /**
     * 네트워크 재연결 처리
     */
    window.SoarSystem.handleNetworkReconnect = function() {
        // WebSocket 재연결
        if (this.components.websocket && !this.components.websocket.isConnected()) {
            this.components.websocket.connect();
        }

        // 시스템 상태 확인
        this.checkSystemStatus();
    };

    /**
     * 네트워크 연결 끊김 처리
     */
    window.SoarSystem.handleNetworkDisconnect = function() {
        this.updateConnectionStatus('disconnected');
    };

    /**
     * 초기화 오류 처리
     */
    window.SoarSystem.handleInitializationError = function(error) {
        console.error('Initialization error:', error);

        // 오류 메시지 표시
        const errorPanel = document.getElementById('errorPanel');
        if (errorPanel) {
            errorPanel.innerHTML = `
                <div class="text-red-400 font-semibold mb-2">시스템 초기화 실패</div>
                <div class="text-sm">${error.message || '알 수 없는 오류가 발생했습니다.'}</div>
                <button onclick="location.reload()" class="mt-2 px-4 py-2 bg-red-600 hover:bg-red-700 rounded">
                    페이지 새로고침
                </button>
            `;
            errorPanel.style.display = 'block';
        }
    };

    /**
     * 이벤트 발생
     */
    window.SoarSystem.dispatchEvent = function(eventName, detail) {
        const event = new CustomEvent('soar:' + eventName, { detail });
        window.dispatchEvent(event);
        
        if (this.config.debug) {
            console.log(`📢 Event dispatched: soar:${eventName}`, detail);
        }
    };

    /**
     * 리소스 정리
     */
    window.SoarSystem.cleanup = function() {
        console.log('🧹 Cleaning up SOAR System...');

        // 각 컴포넌트 정리
        Object.values(this.components).forEach(component => {
            if (component && typeof component.destroy === 'function') {
                component.destroy();
            }
        });

        // WebSocket 연결 종료
        if (this.components.websocket) {
            this.components.websocket.disconnect();
        }

        this.initialized = false;
        console.log('SOAR System cleaned up');
    };

    /**
     * 디버그 정보 출력
     */
    window.SoarSystem.debug = function() {
        console.group('SOAR System Debug Info');
        console.log('Version:', this.version);
        console.log('Initialized:', this.initialized);
        console.log('Session ID:', window.currentSessionId);
        console.log('Components:', Object.keys(this.components));
        
        if (this.components.websocket) {
            console.log('WebSocket State:', this.components.websocket.getConnectionState());
            console.log('WebSocket Queue:', this.components.websocket.getQueueSize());
        }
        
        if (this.components.approvalHandler) {
            console.log('Pending Approvals:', this.components.approvalHandler.pendingApprovals.size);
        }
        
        console.groupEnd();
    };

    // DOM 로드 완료 시 자동 초기화 - 비활성화 (soar-analysis-enhanced.js에서 처리)
    // 중복 초기화 방지를 위해 주석 처리
    /*
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.SoarSystem.initialize();
        });
    } else {
        // DOM이 이미 로드된 경우
        setTimeout(() => {
            window.SoarSystem.initialize();
        }, 100);
    }
    */
    
    // 수동 초기화 필요 시 사용
    window.SoarSystem.manualInit = function() {
        console.log('Manual initialization requested');
        return window.SoarSystem.initialize();
    };

})();