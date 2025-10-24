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

    // Lab 완료 상태
    private boolean studioQueryCompleted = false;
    private boolean riskAssessmentCompleted = false;
    private boolean policyGenerationCompleted = false;

    // Lab 실행 결과
    private StudioQueryResponse studioQueryResult;
    private RiskAssessmentResponse riskAssessmentResult;
    private PolicyResponse policyGenerationResult;

    // 추출된 정보
    private List<Map<String, Object>> nodes = new ArrayList<>();
    private List<Map<String, Object>> edges = new ArrayList<>();
    private String riskLevel = "UNKNOWN";
    private String complianceStatus = "UNKNOWN";

    // 추가 필드
    private Map<String, Object> labResults = new HashMap<>();
    private Map<String, Exception> errors = new HashMap<>();
    private Exception error;

    public SecurityAnalysisResult(String sessionId) {
        this.sessionId = sessionId;
    }

    public boolean isAllCompleted() {
        return studioQueryCompleted && riskAssessmentCompleted && policyGenerationCompleted;
    }

    // 추가 메서드
    public String getAnalysisId() {
        return this.sessionId; // sessionId를 analysisId로 사용
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
