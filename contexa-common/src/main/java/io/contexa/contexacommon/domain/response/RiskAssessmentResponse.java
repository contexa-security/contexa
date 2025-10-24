package io.contexa.contexacommon.domain.response;

import io.contexa.contexacommon.domain.TrustAssessment;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 위험 평가 응답 프로토콜
 * 
 * AI 기반 위험 평가 결과를 담는 응답 클래스입니다.
 * TrustAssessment와 실행 메트릭을 포함합니다.
 */
@Getter
@Setter
public class RiskAssessmentResponse extends IAMResponse {
    
    // 핵심 위험 평가 결과
    private TrustAssessment assessment;
    
    // 처리 메트릭
    private long processingTimeMs;
    private LocalDateTime assessmentTime;
    private String assessedByNode;
    private String assessmentVersion;
    
    // AI 처리 상세 정보
    private Map<String, Object> aiProcessingDetails;
    private boolean usedHistoryAnalysis;
    private boolean usedBehaviorAnalysis;
    private int analyzedHistoryRecords;
    
    /**
     * 기본 생성자 (Jackson 역직렬화용)
     */
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
    
    /**
     * 성공적인 위험 평가 응답 생성
     */
    public static RiskAssessmentResponse success(String requestId, TrustAssessment assessment) {
        return new RiskAssessmentResponse(requestId, assessment);
    }
    
    /**
     * 실패한 위험 평가 응답 생성
     */
    public static RiskAssessmentResponse failure(String requestId, String errorMessage) {
        RiskAssessmentResponse response = new RiskAssessmentResponse(requestId);
        response.withError(errorMessage);
        return response;
    }
    
    /**
     * 기본 안전 위험 평가 응답 생성 (AI 실패 시 사용)
     */
    public static RiskAssessmentResponse defaultSafe(String requestId) {
        TrustAssessment safeAssessment = new TrustAssessment(
            0.3, // 보수적인 낮은 신뢰도
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
    
    /**
     * 처리 메트릭 설정
     */
    public void setProcessingMetrics(long processingTimeMs, String nodeId, 
                                   boolean usedHistory, boolean usedBehavior, 
                                   int historyRecords) {
        this.processingTimeMs = processingTimeMs;
        this.assessedByNode = nodeId;
        this.usedHistoryAnalysis = usedHistory;
        this.usedBehaviorAnalysis = usedBehavior;
        this.analyzedHistoryRecords = historyRecords;
    }
    
    /**
     * 위험도 점수 (0.0-1.0 범위) - 기존 코드 호환성
     */
    public double riskScore() {
        return assessment != null ? (int) Math.round((1.0 - assessment.score()) * 100) : 100;
    }
    
    /**
     * 신뢰도 점수 (0.0-1.0 범위) - 기존 코드 호환성  
     */
    public double trustScore() {
        return assessment != null ? assessment.score() : 0.0;
    }
    
    /**
     * 추천사항 - 기존 코드 호환성
     */
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
    
    @Override
    public String toString() {
        return String.format("RiskAssessmentResponse{id='%s', status=%s, trustScore=%.2f, processingTime=%dms}", 
                getResponseId(), getStatus(), trustScore(), processingTimeMs);
    }
} 