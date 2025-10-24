package io.contexa.contexacore.std.strategy;

import lombok.Getter;

import java.util.List;
import java.util.Map;

/**
 * 연구소 실행 전략
 * 
 * 마스터 브레인이 수립하는 정밀한 실행 전략
 * - 어떤 연구소를 어떤 순서로 실행할지 결정
 * - 각 연구소 간 데이터 흐름 정의
 * - 예외 상황별 대응 전략 수립
 * - 성능 최적화 전략 포함
 */
@Getter
public class LabExecutionStrategy {
    
    private final String strategyId;
    private final String operationType;
    private final List<LabExecutionStep> executionSteps;
    private final Map<String, Object> strategyParameters;
    private final FallbackStrategy fallbackStrategy;
    private final QualityGate qualityGate;
    
    public LabExecutionStrategy(String strategyId,
                               String operationType,
                               List<LabExecutionStep> executionSteps,
                               Map<String, Object> strategyParameters,
                               FallbackStrategy fallbackStrategy,
                               QualityGate qualityGate) {
        this.strategyId = strategyId;
        this.operationType = operationType;
        this.executionSteps = executionSteps;
        this.strategyParameters = strategyParameters;
        this.fallbackStrategy = fallbackStrategy;
        this.qualityGate = qualityGate;
    }
    
    /**
     * 연구소 실행 단계
     */
    public static class LabExecutionStep {
        private final String stepId;
        private final String labType;
        private final Map<String, Object> stepParameters;
        private final List<String> dependencies;
        private final int timeoutSeconds;
        private final int retryCount;
        
        public LabExecutionStep(String stepId,
                               String labType,
                               Map<String, Object> stepParameters,
                               List<String> dependencies,
                               int timeoutSeconds,
                               int retryCount) {
            this.stepId = stepId;
            this.labType = labType;
            this.stepParameters = stepParameters;
            this.dependencies = dependencies;
            this.timeoutSeconds = timeoutSeconds;
            this.retryCount = retryCount;
        }
        
    }
    
    /**
     * 폴백 전략
     */
    public static class FallbackStrategy {
        private final FallbackType type;
        private final String fallbackLabType;
        private final Map<String, Object> fallbackParameters;
        
        public FallbackStrategy(FallbackType type,
                               String fallbackLabType,
                               Map<String, Object> fallbackParameters) {
            this.type = type;
            this.fallbackLabType = fallbackLabType;
            this.fallbackParameters = fallbackParameters;
        }
        
        public enum FallbackType {
            IMMEDIATE,      // 즉시 폴백
            GRADUAL,        // 점진적 폴백
            FULL_RECOVERY,  // 완전 복구
            EMERGENCY       // 긴급 모드
        }
        
    }
    
    /**
     * 품질 게이트
     */
    public static class QualityGate {
        private final double minAccuracyThreshold;
        private final double maxResponseTimeMs;
        private final double minConfidenceScore;
        private final List<String> requiredValidations;
        
        public QualityGate(double minAccuracyThreshold,
                          double maxResponseTimeMs,
                          double minConfidenceScore,
                          List<String> requiredValidations) {
            this.minAccuracyThreshold = minAccuracyThreshold;
            this.maxResponseTimeMs = maxResponseTimeMs;
            this.minConfidenceScore = minConfidenceScore;
            this.requiredValidations = requiredValidations;
        }
        
        /**
         * 품질 기준을 통과하는지 검증
         */
        public boolean passesQualityGate(double accuracy, double responseTime, double confidence) {
            return accuracy >= minAccuracyThreshold &&
                   responseTime <= maxResponseTimeMs &&
                   confidence >= minConfidenceScore;
        }
        
        // Getters
        public double getMinAccuracyThreshold() { return minAccuracyThreshold; }
        public double getMaxResponseTimeMs() { return maxResponseTimeMs; }
        public double getMinConfidenceScore() { return minConfidenceScore; }
        public List<String> getRequiredValidations() { return requiredValidations; }
    }
    
    /**
     * Builder 패턴을 위한 정적 메서드
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder 클래스
     */
    public static class Builder {
        private String strategyId;
        private String requestType;
        private int complexity;
        private String priority;
        
        public Builder strategyId(String strategyId) {
            this.strategyId = strategyId;
            return this;
        }
        
        public Builder requestType(String requestType) {
            this.requestType = requestType;
            return this;
        }
        
        public Builder complexity(int complexity) {
            this.complexity = complexity;
            return this;
        }
        
        public Builder priority(String priority) {
            this.priority = priority;
            return this;
        }
        
        public LabExecutionStrategy build() {
            return new LabExecutionStrategy(
                strategyId != null ? strategyId : "strategy-" + System.currentTimeMillis(),
                requestType != null ? requestType : "unknown",
                List.of(), // executionSteps
                Map.of("complexity", complexity, "priority", priority), // strategyParameters
                new FallbackStrategy(FallbackStrategy.FallbackType.IMMEDIATE, "default", Map.of()), // fallbackStrategy
                new QualityGate(0.8, 5000, 0.7, List.of()) // qualityGate
            );
        }
    }
    
    /**
     * 전략 이름을 반환합니다
     */
    public String getStrategyName() {
        return "Strategy-" + strategyId;
    }
    
    /**
     * 예상 실행 시간을 반환합니다
     */
    public long getExpectedDuration() {
        return 5000; // 기본 5초
    }
    
    // Getters
    public String getStrategyId() { return strategyId; }
    public String getOperationType() { return operationType; }
    public List<LabExecutionStep> getExecutionSteps() { return executionSteps; }
    public Map<String, Object> getStrategyParameters() { return strategyParameters; }
    public FallbackStrategy getFallbackStrategy() { return fallbackStrategy; }
    public QualityGate getQualityGate() { return qualityGate; }
} 