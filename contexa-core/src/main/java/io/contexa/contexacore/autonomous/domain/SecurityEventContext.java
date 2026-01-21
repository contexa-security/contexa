package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEventContext {

    private SecurityEvent securityEvent;

    private SecurityContext userContext;

    private String incidentId;

    @Builder.Default
    private ProcessingStatus processingStatus = ProcessingStatus.PENDING;

    private AIAnalysisResult aiAnalysisResult;

    @Builder.Default
    private Map<String, Object> responseActions = new HashMap<>();

    private LearningMetadata learningMetadata;

    @Builder.Default
    private ProcessingMetrics processingMetrics = new ProcessingMetrics();

    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    public enum ProcessingStatus {
        
        PENDING,

        ANALYZING,

        RESPONDING,

        AWAITING_APPROVAL,

        COMPLETED,

        FAILED,

        SKIPPED
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AIAnalysisResult {
        
        private double threatLevel;

        private double confidenceScore;

        private String summary;

        @Builder.Default
        private Map<String, String> recommendedActions = new HashMap<>();

        @Builder.Default
        private Map<String, String> detectedPatterns = new HashMap<>();

        @Builder.Default
        private Map<String, String> mitreMapping = new HashMap<>();

        private long analysisTimeMs;

        private String aiModel;

        @Builder.Default
        private LocalDateTime analyzedAt = LocalDateTime.now();

        public double getConfidence() {
            return confidenceScore;
        }

        @Builder.Default
        private LocalDateTime analysisTimestamp = LocalDateTime.now();

        private List<String> patternTypes;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProcessingMetrics {
        
        private Long detectionTimeMs;

        private Long analysisTimeMs;

        private Long responseTimeMs;

        private Long totalTimeMs;

        @Builder.Default
        private int retryCount = 0;

        @Builder.Default
        private boolean hasError = false;

        private String errorMessage;

        private String processingNode;
    }

    public void addMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put(key, value);
        updateTimestamp();
    }

    public void addResponseAction(String action, Object details) {
        if (responseActions == null) {
            responseActions = new HashMap<>();
        }
        responseActions.put(action, details);
        updateTimestamp();
    }

    public void setAiAnalysisResult(AIAnalysisResult result) {
        this.aiAnalysisResult = result;
        if (result != null) {
            this.processingStatus = ProcessingStatus.ANALYZING;
            if (processingMetrics == null) {
                processingMetrics = new ProcessingMetrics();
            }
            processingMetrics.setAnalysisTimeMs(result.getAnalysisTimeMs());
        }
        updateTimestamp();
    }

    public void updateProcessingStatus(ProcessingStatus status) {
        this.processingStatus = status;
        updateTimestamp();
    }

    public void markAsCompleted() {
        this.processingStatus = ProcessingStatus.COMPLETED;
        if (processingMetrics != null && createdAt != null) {
            processingMetrics.setTotalTimeMs(
                java.time.Duration.between(createdAt, LocalDateTime.now()).toMillis()
            );
        }
        updateTimestamp();
    }

    public void markAsFailed(String errorMessage) {
        this.processingStatus = ProcessingStatus.FAILED;
        if (processingMetrics == null) {
            processingMetrics = new ProcessingMetrics();
        }
        processingMetrics.setHasError(true);
        processingMetrics.setErrorMessage(errorMessage);
        updateTimestamp();
    }

    public boolean isLearnable() {
        return learningMetadata != null && learningMetadata.isLearnable() &&
               processingStatus == ProcessingStatus.COMPLETED &&
               aiAnalysisResult != null && aiAnalysisResult.getConfidenceScore() > 0.7;
    }

    public boolean requiresApproval() {
        boolean highRisk = aiAnalysisResult != null && aiAnalysisResult.getThreatLevel() >= 0.7;
        return highRisk &&
               (processingStatus == ProcessingStatus.AWAITING_APPROVAL ||
                processingStatus == ProcessingStatus.ANALYZING);
    }

    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();

        if (securityEvent != null) {
            summary.put("eventId", securityEvent.getEventId());
            
            summary.put("source", securityEvent.getSource());
            summary.put("severity", securityEvent.getSeverity());
            summary.put("timestamp", securityEvent.getTimestamp());
        }

        summary.put("incidentId", incidentId);
        summary.put("processingStatus", processingStatus);
        summary.put("threatLevel", aiAnalysisResult != null ? aiAnalysisResult.getThreatLevel() : 0.0);
        summary.put("requiresApproval", requiresApproval());

        if (aiAnalysisResult != null) {
            Map<String, Object> aiSummary = new HashMap<>();
            aiSummary.put("threatLevel", aiAnalysisResult.getThreatLevel());
            aiSummary.put("confidenceScore", aiAnalysisResult.getConfidenceScore());
            aiSummary.put("summary", aiAnalysisResult.getSummary());
            summary.put("aiAnalysis", aiSummary);
        }

        if (processingMetrics != null) {
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("totalTimeMs", processingMetrics.getTotalTimeMs());
            metrics.put("hasError", processingMetrics.isHasError());
            metrics.put("retryCount", processingMetrics.getRetryCount());
            summary.put("metrics", metrics);
        }

        if (responseActions != null && !responseActions.isEmpty()) {
            summary.put("responseActionCount", responseActions.size());
        }

        summary.put("createdAt", createdAt);
        summary.put("updatedAt", updatedAt);

        return summary;
    }

    private void updateTimestamp() {
        this.updatedAt = LocalDateTime.now();
    }

    public void merge(SecurityEventContext other) {
        if (other == null) {
            return;
        }

        if (other.getAiAnalysisResult() != null) {
            this.aiAnalysisResult = other.getAiAnalysisResult();
        }

        if (other.getResponseActions() != null) {
            this.responseActions.putAll(other.getResponseActions());
        }

        if (other.getMetadata() != null) {
            this.metadata.putAll(other.getMetadata());
        }

        if (other.getLearningMetadata() != null) {
            this.learningMetadata = other.getLearningMetadata();
        }

        updateTimestamp();
    }
}