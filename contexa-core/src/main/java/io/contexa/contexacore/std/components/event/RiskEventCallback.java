package io.contexa.contexacore.std.components.event;

/**
 * 위험 이벤트 콜백 인터페이스
 * 
 * 실시간 위험 모니터링 시 이벤트 처리
 * - 위험 감지 시 알림
 * - 오류 발생 시 처리
 */
public interface RiskEventCallback {
    
    /**
     * 위험 감지 시 호출
     * 
     * @param event 위험 이벤트 정보
     */
    void onRiskDetected(RiskEvent event);
    
    /**
     * 오류 발생 시 호출
     * 
     * @param error 발생한 오류
     */
    void onError(Exception error);
} 