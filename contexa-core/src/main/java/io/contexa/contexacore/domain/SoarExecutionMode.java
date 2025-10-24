package io.contexa.contexacore.domain;

/**
 * SOAR Execution Mode
 * 
 * SOAR 시스템의 실행 모드를 정의합니다.
 * 실시간 처리와 비동기 처리를 구분하여 다양한 환경에서 사용 가능합니다.
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
public enum SoarExecutionMode {
    
    /**
     * 동기 모드 (Synchronous Mode)
     * 
     * 승인 응답을 기다리는 동기적 처리
     * - UI 세션이 활성화된 상태
     * - CompletableFuture.get()으로 블로킹 대기
     * - 즉시 응답 필요한 상황
     * - WebSocket/SSE를 통한 실시간 알림
     * - 기존 동작 방식 유지
     */
    SYNC("sync", "Synchronous approval processing with blocking wait"),
    
    /**
     * 비동기 모드 (Asynchronous Mode)
     * 
     * 승인을 기다리지 않는 비동기 처리
     * - Agent 기반 자율 운영
     * - DB에 승인 요청 저장 후 즉시 리턴
     * - 나중에 사용자가 확인 및 승인
     * - 도구 실행 컨텍스트 영속화
     * - 서버 재시작에도 상태 유지
     */
    ASYNC("async", "Asynchronous approval processing with persistence"),
    
    /**
     * 자동 모드
     * 
     * 시스템이 자동으로 적절한 모드 선택
     * - WebSocket 연결 여부 확인
     * - 세션 타입 분석
     * - Agent 실행 여부 판단
     * - 기본값: SYNC
     */
    AUTO("auto", "Automatic mode selection based on context");
    
    private final String code;
    private final String description;
    
    SoarExecutionMode(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getDescription() {
        return description;
    }
    
    /**
     * 코드로부터 실행 모드 조회
     * 
     * @param code 실행 모드 코드
     * @return 실행 모드 (없으면 AUTO 반환)
     */
    public static SoarExecutionMode fromCode(String code) {
        if (code == null || code.trim().isEmpty()) {
            return AUTO;
        }
        
        for (SoarExecutionMode mode : values()) {
            if (mode.code.equalsIgnoreCase(code.trim())) {
                return mode;
            }
        }
        
        return AUTO;
    }
    
    /**
     * 동기 모드인지 확인
     * 
     * @return 동기 모드이면 true
     */
    public boolean isSync() {
        return this == SYNC;
    }
    
    /**
     * 비동기 모드인지 확인
     * 
     * @return 비동기 모드이면 true
     */
    public boolean isAsync() {
        return this == ASYNC;
    }
    
    /**
     * 자동 모드인지 확인
     * 
     * @return 자동 모드이면 true
     */
    public boolean isAuto() {
        return this == AUTO;
    }
}