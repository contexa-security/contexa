package io.contexa.contexacore.autonomous.metrics;

import java.util.Map;

/**
 * Routing Decision Metrics Interface
 *
 * Hot/Cold Path 라우팅 결정 및 메트릭 수집 인터페이스
 *
 * @author contexa
 * @since 3.1.0
 */
public interface RoutingDecisionMetrics {

    /**
     * Hot Path 라우팅 기록
     *
     * @param durationNanos 라우팅 결정 소요 시간 (나노초)
     * @param similarityScore 벡터 유사도 점수 (0.0 ~ 1.0)
     * @param processingMode 처리 모드 (PASS_THROUGH, AI_ANALYSIS 등)
     */
    void recordHotPath(long durationNanos, double similarityScore, String processingMode);

    /**
     * Cold Path 라우팅 기록
     *
     * @param durationNanos 라우팅 결정 소요 시간 (나노초)
     * @param similarityScore 벡터 유사도 점수 (0.0 ~ 1.0)
     * @param processingMode 처리 모드 (PASS_THROUGH, AI_ANALYSIS 등)
     */
    void recordColdPath(long durationNanos, double similarityScore, String processingMode);

    /**
     * 일반 이벤트 기록
     *
     * @param eventType 이벤트 타입
     * @param metadata 이벤트 메타데이터
     */
    void recordEvent(String eventType, Map<String, Object> metadata);
}
