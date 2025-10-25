package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.response.IAMResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * 동적 위협 대응 합성 Lab 응답 객체
 * 
 * DynamicThreatResponseSynthesisLab이 생성한 정책 제안을 담는 응답 객체
 * AI가 추론한 전략적 보안 원칙과 이를 기반으로 생성된 정책 제안을 포함
 * 
 * @author contexa
 * @since 1.0.0
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class DynamicThreatResponseResponse extends IAMResponse {
    
    /**
     * 생성된 정책 제안
     */
    private PolicyProposal policyProposal;
    
    /**
     * AI가 추론한 전략적 보안 원칙 (자연어)
     */
    private String strategicPrinciple;
    
    /**
     * 생성된 SpEL 표현식 (AdvancedPolicyGenerationLab에서 변환됨)
     */
    private String spelExpression;
    
    /**
     * AI 신뢰도 점수 (0.0 ~ 1.0)
     */
    private double aiConfidenceScore;
    
    /**
     * 정책 효과 예측
     */
    private PolicyEffectPrediction effectPrediction;
    
    /**
     * 처리 메타데이터
     */
    private ProcessingMetadata processingMetadata;
    
    /**
     * 정책 제안 객체
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PolicyProposal {
        private String proposalId;
        private String title;
        private String description;
        private String policyType;          // ACCESS_CONTROL, RATE_LIMITING, BLOCKING 등
        private String actionType;           // CREATE, MODIFY, REVOKE 등
        private String scope;                // GLOBAL, RESOURCE_SPECIFIC, USER_SPECIFIC
        private Integer priority;
        private String aiRationale;          // AI의 추론 근거
        private Map<String, Object> policyContent;  // 실제 정책 내용
        private LocalDateTime createdAt;
        private Boolean requiresApproval;
        private String riskLevel;            // LOW, MEDIUM, HIGH, CRITICAL
    }
    
    /**
     * 정책 효과 예측
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PolicyEffectPrediction {
        private Double threatReductionRate;     // 위협 감소율 예측 (0.0 ~ 1.0)
        private Double falsePositiveRate;       // 오탐율 예측 (0.0 ~ 1.0)
        private Double performanceImpact;       // 성능 영향도 (0.0 ~ 1.0)
        private Integer estimatedAffectedUsers; // 영향받을 사용자 수
        private String impactDescription;       // 영향도 설명
        private Double confidenceScore;         // 예측 신뢰도 (0.0 ~ 1.0)
        private LocalDateTime predictionTimestamp; // 예측 시각
        private String modelVersion;           // 사용된 모델 버전
    }
    
    /**
     * 처리 메타데이터
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ProcessingMetadata {
        private String labName;
        private String labVersion;
        private Long processingTimeMs;
        private String llmModel;
        private Integer tokenUsage;
        private Map<String, Object> additionalInfo;
    }
    
    /**
     * 생성자 - 요청 ID와 상태 설정
     */
    public DynamicThreatResponseResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }
    
    /**
     * 기본 생성자
     */
    public DynamicThreatResponseResponse() {
        super("", ExecutionStatus.SUCCESS);
    }
    
    @Override
    public String getResponseType() {
        return "DYNAMIC_THREAT_RESPONSE";
    }
    
    @Override
    public Object getData() {
        Map<String, Object> data = new HashMap<>();
        data.put("policyProposal", policyProposal);
        data.put("strategicPrinciple", strategicPrinciple);
        data.put("spelExpression", spelExpression);
        data.put("effectPrediction", effectPrediction);
        return data;
    }
    
    /**
     * 빌더를 통한 완전한 응답 생성
     */
    public static DynamicThreatResponseResponse createSuccess(
            String requestId,
            PolicyProposal proposal,
            String strategicPrinciple,
            String spelExpression,
            Double confidenceScore) {
        
        DynamicThreatResponseResponse response = new DynamicThreatResponseResponse(
                requestId, 
                ExecutionStatus.SUCCESS
        );
        
        response.setPolicyProposal(proposal);
        response.setStrategicPrinciple(strategicPrinciple);
        response.setSpelExpression(spelExpression);
        response.setAiConfidenceScore(confidenceScore != null ? confidenceScore : 0.0);
        
        return response;
    }
    
    /**
     * 실패 응답 생성
     */
    public static DynamicThreatResponseResponse createFailure(
            String requestId,
            String errorMessage) {
        
        DynamicThreatResponseResponse response = new DynamicThreatResponseResponse(
                requestId, 
                ExecutionStatus.FAILURE
        );
        
        // Error message handling (IAMResponse doesn't have setMessage method)
        
        return response;
    }
    
    /**
     * 정책 제안이 유효한지 검증
     */
    public boolean isValidProposal() {
        return policyProposal != null &&
               policyProposal.getTitle() != null &&
               policyProposal.getPolicyContent() != null &&
               getAiConfidenceScore() >= 0.5;
    }
    
    /**
     * 고위험 정책인지 확인
     */
    public boolean isHighRiskPolicy() {
        return policyProposal != null &&
               ("HIGH".equals(policyProposal.getRiskLevel()) || 
                "CRITICAL".equals(policyProposal.getRiskLevel()));
    }
}