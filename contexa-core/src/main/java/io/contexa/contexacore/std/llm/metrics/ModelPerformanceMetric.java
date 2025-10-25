package io.contexa.contexacore.std.llm.metrics;

import lombok.Getter;

/**
 * 모델 성능 메트릭 유틸리티 클래스
 *
 * 모델별 실행 시간과 성공률을 추적합니다.
 * Thread-safe 구현으로 동시성 환경에서도 안전합니다.
 *
 * DynamicModelSelectionStrategy에서 사용됩니다.
 *
 * @author contexa
 * @since 1.0
 */
@Getter
public class ModelPerformanceMetric {

    private long totalResponseTime = 0;
    private int totalExecutions = 0;
    private int successfulExecutions = 0;

    /**
     * 실행 결과 기록
     *
     * @param responseTime 응답 시간 (ms)
     * @param success 성공 여부
     */
    public synchronized void recordExecution(long responseTime, boolean success) {
        totalResponseTime += responseTime;
        totalExecutions++;
        if (success) {
            successfulExecutions++;
        }
    }

    /**
     * 평균 응답 시간 계산
     *
     * @return 평균 응답 시간 (ms)
     */
    public synchronized double getAverageResponseTime() {
        return totalExecutions > 0 ? (double) totalResponseTime / totalExecutions : 0;
    }

    /**
     * 성공률 계산
     *
     * @return 성공률 (0.0 ~ 1.0)
     */
    public synchronized double getSuccessRate() {
        return totalExecutions > 0 ? (double) successfulExecutions / totalExecutions : 0;
    }

    /**
     * 메트릭 초기화
     */
    public synchronized void reset() {
        totalResponseTime = 0;
        totalExecutions = 0;
        successfulExecutions = 0;
    }
}