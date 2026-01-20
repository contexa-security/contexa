package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
@Setter
public class SecurityAnalysisResult {
    private final String sessionId;

    
    private boolean studioQueryCompleted = false;
    private boolean riskAssessmentCompleted = false;
    private boolean policyGenerationCompleted = false;

    
    private StudioQueryResponse studioQueryResult;
    private RiskAssessmentResponse riskAssessmentResult;
    private PolicyResponse policyGenerationResult;

    
    private List<Map<String, Object>> nodes = new ArrayList<>();
    private List<Map<String, Object>> edges = new ArrayList<>();
    private String riskLevel = "UNKNOWN";
    private String complianceStatus = "UNKNOWN";

    
    private Map<String, Object> labResults = new HashMap<>();
    private Map<String, Exception> errors = new HashMap<>();
    private Exception error;

    public SecurityAnalysisResult(String sessionId) {
        this.sessionId = sessionId;
    }

    public boolean isAllCompleted() {
        return studioQueryCompleted && riskAssessmentCompleted && policyGenerationCompleted;
    }

    
    public String getAnalysisId() {
        return this.sessionId; 
    }

    public void setStudioQueryError(Exception e) {
        this.errors.put("StudioQuery", e);
    }

    public void setRiskAssessmentError(Exception e) {
        this.errors.put("RiskAssessment", e);
    }

    public void setPolicyGenerationError(Exception e) {
        this.errors.put("PolicyGeneration", e);
    }
}
