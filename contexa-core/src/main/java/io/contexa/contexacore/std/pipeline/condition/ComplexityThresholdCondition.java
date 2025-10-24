package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * 복잡도 임계값 기반 실행 조건
 *
 * 요청의 복잡도가 임계값과 비교하여 단계 실행 여부를 결정합니다.
 *
 * 사용 예시:
 * - 복잡도 0.5 이상일 때만 컨텍스트 검색 실행
 * - 복잡도 0.3 미만일 때만 빠른 경로 실행
 */
@Slf4j
public class ComplexityThresholdCondition<T extends DomainContext>
        implements PipelineStepCondition<T> {

    private final double threshold;
    private final String comparisonMode; // "GREATER_THAN" or "LESS_THAN"

    /**
     * 복잡도 임계값 조건 생성
     *
     * @param threshold 임계값 (0.0 ~ 1.0)
     * @param comparisonMode "GREATER_THAN" (이상) 또는 "LESS_THAN" (미만)
     */
    public ComplexityThresholdCondition(double threshold, String comparisonMode) {
        if (threshold < 0.0 || threshold > 1.0) {
            throw new IllegalArgumentException("Threshold must be between 0.0 and 1.0");
        }
        this.threshold = threshold;
        this.comparisonMode = comparisonMode;
    }

    /**
     * 복잡도 임계값 조건 생성 (기본: GREATER_THAN)
     *
     * @param threshold 임계값 (0.0 ~ 1.0)
     */
    public ComplexityThresholdCondition(double threshold) {
        this(threshold, "GREATER_THAN");
    }

    @Override
    public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
        // 컨텍스트에서 복잡도 조회
        Double complexity = context.get("request_complexity", Double.class);

        if (complexity == null) {
            // 복잡도가 없으면 기본적으로 실행 (안전한 선택)
            log.debug("[ComplexityThreshold] 복잡도 정보 없음 - 기본 실행");
            return true;
        }

        boolean result;
        if ("LESS_THAN".equals(comparisonMode)) {
            result = complexity < threshold;
        } else {
            result = complexity >= threshold;
        }

        log.debug("[ComplexityThreshold] 복잡도: {}, 임계값: {}, 모드: {}, 실행: {}",
                complexity, threshold, comparisonMode, result);

        return result;
    }

    @Override
    public String getConditionDescription() {
        return String.format("복잡도 %s %.2f",
                "LESS_THAN".equals(comparisonMode) ? "<" : ">=", threshold);
    }
}
