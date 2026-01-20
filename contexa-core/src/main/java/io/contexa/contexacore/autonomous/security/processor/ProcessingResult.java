package io.contexa.contexacore.autonomous.security.processor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
    
    
    @Builder.Default
    private Map<String, Object> analysisData = new HashMap<>();
    
    
    private List<String> threatIndicators;
    
    
    private boolean requiresIncident;
    
    
    private IncidentSeverity incidentSeverity;
    
    
    private long processingTimeMs;
    
    
    private LocalDateTime processedAt;
    
    
    private boolean aiAnalysisPerformed;
    
    
    private int aiAnalysisLevel;
    
    
    private List<String> recommendedActions;
    
    
    private ProcessingStatus status;

    
    private String errorMessage;

    
    private boolean anomaly;

    
    private List<String> executedActions;

    
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    
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
    
    
    public enum IncidentSeverity {
        LOW(1, "Low severity incident"),
        MEDIUM(2, "Medium severity incident"),
        HIGH(3, "High severity incident"),
        CRITICAL(4, "Critical severity incident");
        
        private final int level;
        private final String description;
        
        IncidentSeverity(int level, String description) {
            this.level = level;
            this.description = description;
        }
        
        public int getLevel() {
            return level;
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


    
    public boolean isSuccess() {
        return success;
    }

    
    public List<String> getExecutedActions() {
        return executedActions;
    }

    
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    
    public String getIncidentSeverity() {
        if (incidentSeverity != null) {
            return incidentSeverity.name();
        }
        return null;
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

    
    public boolean isAnomaly() {
        return anomaly;
    }

    
    public void setAnomaly(boolean anomaly) {
        this.anomaly = anomaly;
    }
}