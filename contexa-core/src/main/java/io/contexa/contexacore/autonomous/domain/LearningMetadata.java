package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LearningMetadata {

    private boolean isLearnable;

    private LearningType learningType;

    @Builder.Default
    private Map<String, Object> learningContext = new HashMap<>();

    private double confidenceScore;

    private String sourceLabId;

    @Builder.Default
    private int priority = 5;

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    private String incidentId;

    @Builder.Default
    private LearningStatus status = LearningStatus.PENDING;

    private String learningSummary;

    private String eventType;

    private LocalDateTime completedAt;

    @Builder.Default
    private Map<String, String> patterns = new HashMap<>();

    @Builder.Default
    private Map<String, Object> outcomes = new HashMap<>();

    public void addPattern(String key, String value) {
        if (patterns == null) {
            patterns = new HashMap<>();
        }
        patterns.put(key, value);
    }

    public void addOutcome(String key, Object value) {
        if (outcomes == null) {
            outcomes = new HashMap<>();
        }
        outcomes.put(key, value);
    }

    public enum LearningType {
        
        THREAT_RESPONSE,

        ACCESS_PATTERN,

        POLICY_FEEDBACK,

        FALSE_POSITIVE_LEARNING,

        PERFORMANCE_OPTIMIZATION,

        COMPLIANCE_LEARNING
    }

    public enum LearningStatus {
        
        PENDING,

        IN_PROGRESS,

        COMPLETED,

        FAILED,

        SKIPPED
    }

    public boolean canLearn() {
        return isLearnable && 
               confidenceScore >= 0.7 && 
               status == LearningStatus.PENDING;
    }

    public boolean isHighPriority() {
        return priority >= 8;
    }

    public void addContext(String key, Object value) {
        if (learningContext == null) {
            learningContext = new HashMap<>();
        }
        learningContext.put(key, value);
    }

    public void markAsCompleted(String summary) {
        this.status = LearningStatus.COMPLETED;
        this.learningSummary = summary;
    }

    public void markAsFailed(String reason) {
        this.status = LearningStatus.FAILED;
        this.learningSummary = reason;
    }
}