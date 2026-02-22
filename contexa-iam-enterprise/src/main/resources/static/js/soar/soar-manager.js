/**
 * SOAR System Central Manager
 * 
 * 모든 SOAR 컴포넌트의 초기화와 생명주기를 중앙에서 관리합니다.
 * 싱글톤 패턴을 통해 중복 인스턴스 생성을 방지합니다.
 */

class SoarManager {
    constructor() {
        if (window.soarManager) {
            console.warn('SoarManager 인스턴스가 이미 존재합니다');
            return window.soarManager;
        }
        
        console.log('🎯 SOAR Manager 초기화 시작');
        
        // 싱글톤 인스턴스 저장
        window.soarManager = this;
        
        // 컴포넌트 레지스트리
        this.components = new Map();
        
        // 초기화 상태
        this.initialized = false;
        this.initPromise = null;
        
        // 설정
        this.config = {
            wsEndpoint: '/ws-soar',
            sseEndpoint: '/api/sse/connect',
            enableEnhanced: true,
            debug: true
        };
    }
    
    /**
     * 컴포넌트 등록 및 싱글톤 관리
     */
    getComponent(componentName, ComponentClass, ...args) {
        // 이미 존재하는 컴포넌트는 재사용
        if (this.components.has(componentName)) {
            console.log(`기존 ${componentName} 인스턴스 재사용`);
            return this.components.get(componentName);
        }
        
        // 새 컴포넌트 생성 및 등록
        console.log(`📦 새로운 ${componentName} 인스턴스 생성`);
        const instance = new ComponentClass(...args);
        this.components.set(componentName, instance);
        
        // 전역 참조도 설정 (레거시 호환성)
        if (componentName === 'ApprovalModal') {
            window.soarApprovalModalInstance = instance;
        } else if (componentName === 'ApprovalHandler') {
            window.soarApprovalHandlerInstance = instance;
        } else if (componentName === 'WebSocketClient') {
            window.enhancedWebSocketClient = instance;
        }
        
        return instance;
    }
    
    /**
     * SOAR 시스템 전체 초기화
     */
    async initialize() {
        // 이미 초기화 중이거나 완료된 경우
        if (this.initPromise) {
            console.log('⏳ 초기화가 이미 진행 중입니다...');
            return this.initPromise;
        }
        
        if (this.initialized) {
            console.log('SOAR 시스템이 이미 초기화되었습니다');
            return Promise.resolve();
        }
        
        this.initPromise = this._performInitialization();
        return this.initPromise;
    }
    
    /**
     * 실제 초기화 수행
     */
    async _performInitialization() {
        try {
            console.log('🚀 SOAR 시스템 초기화 시작');
            
            // 1. 메시지 중복 제거기 초기화
            if (typeof SoarMessageDeduplicator !== 'undefined') {
                this.getComponent('MessageDeduplicator', SoarMessageDeduplicator);
            }
            
            // 2. WebSocket 클라이언트 초기화
            if (typeof EnhancedWebSocketClient !== 'undefined') {
                const wsClient = this.getComponent('WebSocketClient', EnhancedWebSocketClient, this.config.wsEndpoint);
                await this._waitForConnection(wsClient);
            }
            
            // 3. 승인 모달 초기화
            if (typeof SoarApprovalModal !== 'undefined') {
                this.getComponent('ApprovalModal', SoarApprovalModal);
            }
            
            // 4. 승인 핸들러 초기화
            if (typeof SoarApprovalHandler !== 'undefined') {
                this.getComponent('ApprovalHandler', SoarApprovalHandler);
            }
            
            // 5. 세션 상태 매니저 초기화
            if (typeof SessionStateManager !== 'undefined') {
                this.getComponent('SessionStateManager', SessionStateManager);
            }
            
            // 6. 에러 핸들러 초기화
            if (typeof SoarErrorHandler !== 'undefined') {
                this.getComponent('ErrorHandler', SoarErrorHandler);
            }
            
            // 7. 파이프라인 시각화 초기화
            if (typeof SoarPipelineVisualization !== 'undefined') {
                this.getComponent('PipelineVisualization', SoarPipelineVisualization);
            }
            
            // 8. 모니터링 대시보드 초기화
            if (typeof SoarMonitoringDashboard !== 'undefined') {
                this.getComponent('MonitoringDashboard', SoarMonitoringDashboard);
            }
            
            // 9. Enhanced 또는 Legacy 시스템 초기화
            if (this.config.enableEnhanced && typeof soarEnhanced !== 'undefined') {
                console.log('🎯 Enhanced SOAR 시스템 초기화');
                // soarEnhanced가 이미 존재한다면 매니저가 관리하는 컴포넌트로 연결
                if (!soarEnhanced.approvalModal) {
                    soarEnhanced.approvalModal = this.components.get('ApprovalModal');
                }
                if (!soarEnhanced.approvalHandler) {
                    soarEnhanced.approvalHandler = this.components.get('ApprovalHandler');
                }
                if (!soarEnhanced.wsClient) {
                    soarEnhanced.wsClient = this.components.get('WebSocketClient');
                }
            } else if (typeof window.initLegacySoar === 'function') {
                console.log('📦 Legacy SOAR 시스템 초기화');
                window.initLegacySoar();
            }
            
            this.initialized = true;
            console.log('SOAR 시스템 초기화 완료');
            
            // 초기화 완료 이벤트 발생
            window.dispatchEvent(new CustomEvent('soar:initialized', {
                detail: { 
                    manager: this,
                    components: Array.from(this.components.keys())
                }
            }));
            
        } catch (error) {
            console.error('SOAR 시스템 초기화 실패:', error);
            this.initPromise = null;
            throw error;
        }
    }
    
    /**
     * WebSocket 연결 대기
     */
    async _waitForConnection(wsClient, maxRetries = 5) {
        for (let i = 0; i < maxRetries; i++) {
            if (wsClient.isConnected()) {
                console.log('WebSocket 연결 성공');
                return;
            }
            console.log(`⏳ WebSocket 연결 대기 중... (${i + 1}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        console.warn('WebSocket 연결 시간 초과');
    }
    
    /**
     * 특정 컴포넌트 가져오기
     */
    get(componentName) {
        return this.components.get(componentName);
    }
    
    /**
     * 시스템 상태 확인
     */
    getStatus() {
        return {
            initialized: this.initialized,
            components: Array.from(this.components.keys()),
            config: this.config
        };
    }
    
    /**
     * 시스템 종료
     */
    async shutdown() {
        console.log('SOAR 시스템 종료 시작');
        
        // WebSocket 연결 종료
        const wsClient = this.components.get('WebSocketClient');
        if (wsClient && wsClient.disconnect) {
            wsClient.disconnect();
        }
        
        // SSE 연결 종료
        const sseClient = this.components.get('SSEClient');
        if (sseClient && sseClient.disconnect) {
            sseClient.disconnect();
        }
        
        // 컴포넌트 정리
        this.components.clear();
        this.initialized = false;
        this.initPromise = null;
        
        console.log('SOAR 시스템 종료 완료');
    }
}

// 전역 SOAR Manager 인스턴스 생성
const soarManager = new SoarManager();

// DOM 로드 완료 시 자동 초기화
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('📄 DOM 로드 완료, SOAR Manager 초기화 시작');
        soarManager.initialize();
    });
} else {
    // 이미 DOM이 로드된 경우
    console.log('📄 DOM 이미 로드됨, SOAR Manager 초기화 시작');
    soarManager.initialize();
}

// 전역 접근을 위한 export
window.SoarManager = SoarManager;
window.soarManager = soarManager;