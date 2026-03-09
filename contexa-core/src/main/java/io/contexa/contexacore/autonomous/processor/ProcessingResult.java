package io.contexa.contexacore.autonomous.processor;

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
public class ProcessingResult {

    private boolean success;

    private double riskScore;

    private double currentRiskLevel;

    private ProcessingPath processingPath;

    private String action;

    private double confidence;

    private String reasoning;

    @Builder.Default
    private Map<String, Object> analysisData = new HashMap<>();

    private List<String> threatIndicators;

    private long processingTimeMs;

    private LocalDateTime processedAt;

    private int aiAnalysisLevel;

    private List<String> recommendedActions;

    private ProcessingStatus status;

    private String errorMessage;

    private String message;

    public enum ProcessingPath {
        COLD_PATH("Cold Path - AI Analysis"),
        BYPASS("Bypass - No Processing");

        private final String description;

        ProcessingPath(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    public enum ProcessingStatus {
        SUCCESS("Processing completed successfully"),
        PARTIAL_SUCCESS("Processing partially completed"),
        FAILED("Processing failed"),
        TIMEOUT("Processing timeout"),
        SKIPPED("Processing skipped");

        private final String description;

        ProcessingStatus(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    public static ProcessingResult success(ProcessingPath path, double riskScore) {
        return ProcessingResult.builder()
                .processingPath(path)
                .riskScore(riskScore)
                .success(true)
                .status(ProcessingStatus.SUCCESS)
                .processedAt(LocalDateTime.now())
                .build();
    }

    public static ProcessingResult failure(ProcessingPath path, String error) {
        return ProcessingResult.builder()
                .processingPath(path)
                .success(false)
                .status(ProcessingStatus.FAILED)
                .errorMessage(error)
                .processedAt(LocalDateTime.now())
                .build();
    }

    public void addAnalysisData(String key, Object value) {
        if (this.analysisData == null) {
            this.analysisData = new HashMap<>();
        }
        this.analysisData.put(key, value);
    }

    public void setProcessingComplete(long startTimeMs) {
        this.processingTimeMs = System.currentTimeMillis() - startTimeMs;
        this.processedAt = LocalDateTime.now();
    }
}
