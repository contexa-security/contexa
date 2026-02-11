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
public class SecurityEventContext {

    private SecurityEvent securityEvent;

    @Builder.Default
    private ProcessingStatus processingStatus = ProcessingStatus.PENDING;

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

        AWAITING_APPROVAL,

        COMPLETED,

        FAILED,

        SKIPPED
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

    private void updateTimestamp() {
        this.updatedAt = LocalDateTime.now();
    }
}
