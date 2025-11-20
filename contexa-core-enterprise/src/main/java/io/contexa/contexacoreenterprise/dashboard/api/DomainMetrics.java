package io.contexa.contexacoreenterprise.dashboard.api;

import java.util.Map;

/**
 * 도메인별 메트릭 인터페이스
 *
 * 각 도메인의 건강도와 핵심 메트릭을 제공합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
public interface DomainMetrics extends MetricsCollector {

    /**
     * 도메인 건강도 점수 계산
     *
     * @return 건강도 점수 (0.0-1.0, 1.0이 가장 건강)
     */
    double getHealthScore();

    /**
     * 핵심 메트릭 조회
     *
     * 도메인별로 가장 중요한 메트릭들을 반환합니다.
     *
     * @return 핵심 메트릭 이름과 값의 맵
     */
    Map<String, Double> getKeyMetrics();
}
