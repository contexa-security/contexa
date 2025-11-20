package io.contexa.contexacommon.metrics;

import java.util.Map;

/**
 * Vector Store Metrics Interface
 *
 * <p>
 * Core와 Enterprise 사이의 벡터 저장소 메트릭 인터페이스입니다.
 * Enterprise가 있으면 실제 메트릭이 수집되고, 없으면 아무 동작 안 함.
 * </p>
 *
 * @since 0.1.1
 */
public interface VectorStoreMetrics {

    /**
     * 벡터 저장소 작업 기록
     *
     * @param labName Lab 이름
     * @param operationType 작업 타입 (STORE, SEARCH, DELETE, UPDATE)
     * @param documentCount 처리된 문서 수
     * @param durationMs 소요 시간 (밀리초)
     */
    void recordOperation(String labName, Object operationType, int documentCount, long durationMs);

    /**
     * 에러 기록
     *
     * @param labName Lab 이름
     * @param operationType 작업 타입
     * @param error 발생한 에러
     */
    void recordError(String labName, Object operationType, Exception error);

    /**
     * 이벤트 기록 (EventRecorder 인터페이스)
     *
     * @param eventType 이벤트 타입
     * @param metadata 이벤트 메타데이터
     */
    void recordEvent(String eventType, Map<String, Object> metadata);

    /**
     * Lab별 통계 조회
     *
     * @param labName Lab 이름
     * @return Lab 통계 Map
     */
    Map<String, Object> getLabStatistics(String labName);
}
