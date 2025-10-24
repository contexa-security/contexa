package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.Getter;
import lombok.Setter;

/**
 * 위험 평가 요청 프로토콜
 * 
 * 제로 트러스트 보안을 위한 AI 기반 위험 평가 요청을 나타내는 클래스입니다.
 * CustomWebSecurityExpressionRoot 에서 호출되어 실시간 위험 평가를 수행합니다.
 */
@Getter
@Setter
public class RiskAssessmentRequest extends IAMRequest<RiskAssessmentContext> {
    
    private static final String PROMPT_TEMPLATE = "riskAssessment";
    private static final DiagnosisType DIAGNOSIS_TYPE = DiagnosisType.RISK_ASSESSMENT;
    
    // 위험 평가 관련 메타데이터
    private String sessionId;
    private String nodeId;
    private String userId;
    private String resourceId;
    private String actionType;
    private boolean enableHistoryAnalysis = true;
    private boolean enableBehaviorAnalysis = true;
    private int maxHistoryRecords = 5;
    
    public RiskAssessmentRequest(RiskAssessmentContext context, String promptTemplate) {
        super(context, promptTemplate, RequestPriority.HIGH, RequestType.STANDARD);
        this.withDiagnosisType(DIAGNOSIS_TYPE);
    }
    
    public RiskAssessmentRequest(RiskAssessmentContext context, String operation, String sessionId) {
        this(context, operation);
        this.sessionId = sessionId;
    }
    
    /**
     * 빠른 생성을 위한 정적 팩토리 메서드
     */
    public static RiskAssessmentRequest create(RiskAssessmentContext context, String operation) {
        return new RiskAssessmentRequest(context, operation);
    }
    
    public static RiskAssessmentRequest create(RiskAssessmentContext context, String operation, String sessionId) {
        return new RiskAssessmentRequest(context, operation, sessionId);
    }
    
    /**
     * 긴급 위험 평가 요청 생성
     */
    public static RiskAssessmentRequest createUrgent(RiskAssessmentContext context) {
        RiskAssessmentRequest request = new RiskAssessmentRequest(context, PROMPT_TEMPLATE);
        request.withParameter("priority", RequestPriority.CRITICAL);
        return request;
    }
    
    @Override
    public String toString() {
        return String.format("RiskAssessmentRequest{id='%s', operation='%s', sessionId='%s', context=%s}", 
                getRequestId(), getPromptTemplate(), sessionId, getContext());
    }
} 