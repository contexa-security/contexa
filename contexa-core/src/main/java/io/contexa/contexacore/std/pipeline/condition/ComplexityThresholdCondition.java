package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class ComplexityThresholdCondition<T extends DomainContext>
        implements PipelineStepCondition<T> {

    private final double threshold;
    private final String comparisonMode; 

    
    public ComplexityThresholdCondition(double threshold, String comparisonMode) {
        if (threshold < 0.0 || threshold > 1.0) {
            throw new IllegalArgumentException("Threshold must be between 0.0 and 1.0");
        }
        this.threshold = threshold;
        this.comparisonMode = comparisonMode;
    }

    
    public ComplexityThresholdCondition(double threshold) {
        this(threshold, "GREATER_THAN");
    }

    @Override
    public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
        
        Double complexity = context.get("request_complexity", Double.class);

        if (complexity == null) {
            
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
