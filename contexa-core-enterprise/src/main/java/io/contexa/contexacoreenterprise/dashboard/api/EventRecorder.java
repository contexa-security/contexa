package io.contexa.contexacoreenterprise.dashboard.api;

import java.util.Map;

/**
 * 이벤트 기록 인터페이스
 *
 * 메트릭으로 이벤트를 기록하는 공통 계약을 정의합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
public interface EventRecorder {

    /**
     * 이벤트 발생 기록
     *
     * @param eventType 이벤트 타입
     * @param metadata 추가 메타데이터
     */
    void recordEvent(String eventType, Map<String, Object> metadata);

    /**
     * 작업 소요 시간 기록
     *
     * @param operationName 작업 이름
     * @param durationNanos 소요 시간 (나노초)
     */
    void recordDuration(String operationName, long durationNanos);
}
