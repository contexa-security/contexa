package io.contexa.contexacoreenterprise.dashboard.api;

import java.util.Map;

/**
 * 메트릭 수집기 기본 인터페이스
 *
 * 모든 메트릭 수집기가 구현해야 하는 공통 계약을 정의합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
public interface MetricsCollector {

    /**
     * 메트릭이 속한 도메인 반환
     *
     * @return 도메인 이름 (예: "zerotrust", "hcad", "evolution")
     */
    String getDomain();

    /**
     * 메트릭 수집기 초기화
     *
     * Micrometer Counter, Gauge, Timer 등을 등록합니다.
     */
    void initialize();

    /**
     * 현재 메트릭 통계 조회
     *
     * @return 메트릭 이름과 값의 맵
     */
    Map<String, Object> getStatistics();

    /**
     * 메트릭 초기화
     *
     * 모든 카운터와 통계를 0으로 리셋합니다.
     */
    void reset();
}
