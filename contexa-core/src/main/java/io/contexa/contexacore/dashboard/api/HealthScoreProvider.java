package io.contexa.contexacore.dashboard.api;

import java.util.Map;

/**
 * 건강도 점수 제공 인터페이스
 *
 * 시스템 또는 도메인의 건강도를 계산하고 제공합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
public interface HealthScoreProvider {

    /**
     * 건강도 점수 계산
     *
     * @return 건강도 점수 (0.0-1.0, 1.0이 가장 건강)
     */
    double calculateHealthScore();

    /**
     * 건강도에 영향을 주는 요소들
     *
     * @return 요소 이름과 기여도의 맵
     */
    Map<String, Double> getHealthFactors();
}
