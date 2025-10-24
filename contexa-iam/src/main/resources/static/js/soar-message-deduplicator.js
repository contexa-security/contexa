/**
 * SOAR Message Deduplicator
 * 
 * 중복 메시지 방지를 위한 중앙 관리 모듈
 * WebSocket과 SSE에서 오는 중복 메시지를 필터링합니다.
 */
class SoarMessageDeduplicator {
    constructor() {
        // 처리된 메시지 ID 저장
        this.processedMessages = new Map();
        this.messageExpiryTime = 60000; // 60초 후 만료
        this.cleanupInterval = 30000; // 30초마다 정리
        
        // 자동 정리 시작
        this.startCleanup();
        
        console.log('SoarMessageDeduplicator 초기화');
    }
    
    /**
     * 메시지가 이미 처리되었는지 확인
     * @param {Object} message - 확인할 메시지
     * @returns {boolean} true면 이미 처리됨 (중복)
     */
    isDuplicate(message) {
        const messageId = this.extractMessageId(message);
        if (!messageId) {
            console.warn('메시지 ID를 추출할 수 없습니다:', message);
            return false;
        }
        
        // 이미 처리된 메시지인지 확인
        if (this.processedMessages.has(messageId)) {
            const processedTime = this.processedMessages.get(messageId);
            const age = Date.now() - processedTime;
            console.log(`🔁 중복 메시지 감지: ${messageId} (${age}ms 전 처리됨)`);
            return true;
        }
        
        return false;
    }
    
    /**
     * 메시지를 처리됨으로 표시
     * @param {Object} message - 처리된 메시지
     */
    markAsProcessed(message) {
        const messageId = this.extractMessageId(message);
        if (!messageId) {
            console.warn('메시지 ID를 추출할 수 없습니다:', message);
            return;
        }
        
        this.processedMessages.set(messageId, Date.now());
        console.log(`메시지 처리 완료: ${messageId}`);
    }
    
    /**
     * 메시지에서 ID 추출
     * @param {Object} message - 메시지 객체
     * @returns {string|null} 메시지 ID
     */
    extractMessageId(message) {
        // 우선순위: messageId > requestId > approvalId
        return message.messageId || 
               message.requestId || 
               message.approvalId ||
               (message.type && message.toolName ? `${message.type}_${message.toolName}_${message.timestamp}` : null);
    }
    
    /**
     * 메시지 필터링 및 처리
     * @param {Object} message - 처리할 메시지
     * @param {Function} handler - 메시지 처리 함수
     * @returns {boolean} true면 메시지가 처리됨
     */
    processMessage(message, handler) {
        // 중복 체크
        if (this.isDuplicate(message)) {
            return false;
        }
        
        // 처리됨으로 표시
        this.markAsProcessed(message);
        
        // 핸들러 실행
        if (typeof handler === 'function') {
            try {
                handler(message);
                return true;
            } catch (error) {
                console.error('메시지 처리 중 오류:', error);
                // 오류 발생 시 처리됨 표시 제거
                const messageId = this.extractMessageId(message);
                if (messageId) {
                    this.processedMessages.delete(messageId);
                }
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 만료된 메시지 정리
     */
    cleanup() {
        const now = Date.now();
        const expiredIds = [];
        
        this.processedMessages.forEach((timestamp, messageId) => {
            if (now - timestamp > this.messageExpiryTime) {
                expiredIds.push(messageId);
            }
        });
        
        expiredIds.forEach(id => {
            this.processedMessages.delete(id);
        });
        
        if (expiredIds.length > 0) {
            console.log(`🧹 ${expiredIds.length}개의 만료된 메시지 ID 정리됨`);
        }
    }
    
    /**
     * 자동 정리 시작
     */
    startCleanup() {
        setInterval(() => {
            this.cleanup();
        }, this.cleanupInterval);
    }
    
    /**
     * 통계 정보 반환
     */
    getStats() {
        return {
            processedCount: this.processedMessages.size,
            oldestMessage: Math.min(...Array.from(this.processedMessages.values())),
            newestMessage: Math.max(...Array.from(this.processedMessages.values()))
        };
    }
    
    /**
     * 모든 처리된 메시지 초기화
     */
    reset() {
        this.processedMessages.clear();
        console.log('메시지 중복 체커 초기화됨');
    }
}

// 전역 인스턴스 생성
if (typeof window !== 'undefined') {
    window.SoarMessageDeduplicator = new SoarMessageDeduplicator();
    
    // 기존 WebSocket 핸들러와 통합
    const originalHandleApprovalRequest = window.handleApprovalRequest;
    if (typeof originalHandleApprovalRequest === 'function') {
        window.handleApprovalRequest = function(message) {
            window.SoarMessageDeduplicator.processMessage(message, originalHandleApprovalRequest);
        };
    }
    
    console.log('SoarMessageDeduplicator 전역 인스턴스 생성 완료');
}