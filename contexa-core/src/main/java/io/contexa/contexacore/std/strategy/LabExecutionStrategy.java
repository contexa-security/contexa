package io.contexa.contexacore.std.strategy;

import lombok.Getter;

import java.util.List;
import java.util.Map;

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
            IMMEDIATE,      
            GRADUAL,        
            FULL_RECOVERY,  
            EMERGENCY       
        }
        
    }

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

        public boolean passesQualityGate(double accuracy, double responseTime, double confidence) {
            return accuracy >= minAccuracyThreshold &&
                   responseTime <= maxResponseTimeMs &&
                   confidence >= minConfidenceScore;
        }

        public double getMinAccuracyThreshold() { return minAccuracyThreshold; }
        public double getMaxResponseTimeMs() { return maxResponseTimeMs; }
        public double getMinConfidenceScore() { return minConfidenceScore; }
        public List<String> getRequiredValidations() { return requiredValidations; }
    }

    public static Builder builder() {
        return new Builder();
    }

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
                List.of(), 
                Map.of("complexity", complexity, "priority", priority), 
                new FallbackStrategy(FallbackStrategy.FallbackType.IMMEDIATE, "default", Map.of()), 
                new QualityGate(0.8, 5000, 0.7, List.of()) 
            );
        }
    }

    public String getStrategyName() {
        return "Strategy-" + strategyId;
    }

    public long getExpectedDuration() {
        return 5000; 
    }

    public String getStrategyId() { return strategyId; }
    public String getOperationType() { return operationType; }
    public List<LabExecutionStep> getExecutionSteps() { return executionSteps; }
    public Map<String, Object> getStrategyParameters() { return strategyParameters; }
    public FallbackStrategy getFallbackStrategy() { return fallbackStrategy; }
    public QualityGate getQualityGate() { return qualityGate; }
} 