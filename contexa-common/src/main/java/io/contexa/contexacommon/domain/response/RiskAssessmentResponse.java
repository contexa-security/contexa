package io.contexa.contexacommon.domain.response;

import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;


@Getter
@Setter
public class RiskAssessmentResponse extends AIResponse {
    
    
    private TrustAssessment assessment;
    
    
    private long processingTimeMs;
    private LocalDateTime assessmentTime;
    private String assessedByNode;
    private String assessmentVersion;
    
    
    private Map<String, Object> aiProcessingDetails;
    private boolean usedHistoryAnalysis;
    private boolean usedBehaviorAnalysis;
    private int analyzedHistoryRecords;
    
    
    public RiskAssessmentResponse() {
        super("default", ExecutionStatus.SUCCESS);
        this.assessmentTime = LocalDateTime.now();
        this.assessmentVersion = "1.0";
        this.withMetadata("domain", "IAM");
        this.withMetadata("operation", "riskAssessment");
    }
    
    public RiskAssessmentResponse(String requestId) {
        super(requestId, ExecutionStatus.SUCCESS);
        this.assessmentTime = LocalDateTime.now();
        this.assessmentVersion = "1.0";
        this.withMetadata("domain", "IAM");
        this.withMetadata("operation", "riskAssessment");
    }
    
    public RiskAssessmentResponse(String requestId, TrustAssessment assessment) {
        this(requestId);
        this.assessment = assessment;
    }
    
    
    public static RiskAssessmentResponse success(String requestId, TrustAssessment assessment) {
        return new RiskAssessmentResponse(requestId, assessment);
    }
    
    
    public static RiskAssessmentResponse failure(String requestId, String errorMessage) {
        RiskAssessmentResponse response = new RiskAssessmentResponse(requestId);
        response.withError(errorMessage);
        return response;
    }
    
    
    public static RiskAssessmentResponse defaultSafe(String requestId) {
        TrustAssessment safeAssessment = new TrustAssessment(
            0.3, 
            java.util.List.of("AI_SYSTEM_ERROR"),
            "AI system unavailable - conservative assessment applied"
        );
        
        RiskAssessmentResponse response = new RiskAssessmentResponse(requestId, safeAssessment);
        response.aiProcessingDetails = Map.of(
            "fallbackMode", true,
            "reason", "AI_UNAVAILABLE"
        );
        return response;
    }
    
    
    public void setProcessingMetrics(long processingTimeMs, String nodeId, 
                                   boolean usedHistory, boolean usedBehavior, 
                                   int historyRecords) {
        this.processingTimeMs = processingTimeMs;
        this.assessedByNode = nodeId;
        this.usedHistoryAnalysis = usedHistory;
        this.usedBehaviorAnalysis = usedBehavior;
        this.analyzedHistoryRecords = historyRecords;
    }
    
    
    public double riskScore() {
        return assessment != null ? (int) Math.round((1.0 - assessment.score()) * 100) : 100;
    }
    
    
    public double trustScore() {
        return assessment != null ? assessment.score() : 0.0;
    }
    
    
    public String recommendation() {
        return assessment != null ? assessment.summary() : "No assessment available";
    }
    
    @Override
    public Object getData() {
        return assessment;
    }
    
    @Override
    public String getResponseType() {
        return "RISK_ASSESSMENT";
    }
}