package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.request.StaticAccessOptimizationRequest;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.aiam.protocol.response.StaticAccessOptimizationResponse;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;

/**
 * 정적 접근 최적화 서비스
 * 
 * StaticAccessAnalysisEvent에서 자연어 정책을 받아
 * AdvancedPolicyGenerationLab을 통해 SpEL 표현식으로 변환하는 서비스
 * 
 * 주요 기능:
 * 1. 정적 접근 분석 이벤트 처리
 * 2. 자연어 정책을 AdvancedPolicyGenerationLab으로 전달
 * 3. SpEL 표현식 정책 수신 및 반환
 * 4. 메트릭 수집 및 모니터링
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Service
public class StaticAccessOptimizationService {
    
    private final AdvancedPolicyGenerationLab policyGenerationLab;
    private final IAMDataCollectionService dataCollectionService;
    private final MeterRegistry meterRegistry;
    
    private final Timer processingTimer;
    
    @Autowired
    public StaticAccessOptimizationService(
            AdvancedPolicyGenerationLab policyGenerationLab,
            IAMDataCollectionService dataCollectionService,
            MeterRegistry meterRegistry) {
        this.policyGenerationLab = policyGenerationLab;
        this.dataCollectionService = dataCollectionService;
        this.meterRegistry = meterRegistry;
        
        // 메트릭 초기화
        this.processingTimer = Timer.builder("synthesis.static_access_optimization.duration")
                .description("Static access optimization processing time")
                .register(meterRegistry);
        
        log.info("StaticAccessOptimizationService 초기화 완료 - AdvancedPolicyGenerationLab 연동 서비스");
    }
    
    /**
     * 정적 접근 최적화 처리
     * AdvancedPolicyGenerationLab을 통해 자연어 정책을 SpEL 표현식으로 변환
     */
    public StaticAccessOptimizationResponse process(StaticAccessOptimizationRequest request) {
        Timer.Sample sample = Timer.start(meterRegistry);
        
        try {
            log.info("[정적 최적화] 처리 시작 - 요청 ID: {}", request.getRequestId());
            
            // 1. 자연어 정책 생성 (분석 결과 기반)
            String naturalLanguagePolicy = createNaturalLanguagePolicy(request);
            log.info("[정적 최적화] 자연어 정책 생성: {}", naturalLanguagePolicy);
            
            // 2. AvailableItems 수집
            PolicyGenerationItem.AvailableItems availableItems = dataCollectionService.policyCollectData();
            
            // 3. PolicyGenerationRequest 생성
            PolicyGenerationRequest policyRequest = new PolicyGenerationRequest(
                    naturalLanguagePolicy,
                    availableItems
            );
            
            // 4. AdvancedPolicyGenerationLab 직접 호출 (DynamicThreatResponseSynthesisLab처럼!)
            log.info("[정적 최적화] AdvancedPolicyGenerationLab 호출 중...");
            PolicyResponse policyResponse = policyGenerationLab.process(policyRequest);
            
            if (policyResponse == null) {
                throw new RuntimeException("AdvancedPolicyGenerationLab에서 응답을 받지 못했습니다");
            }
            
            // 5. SpEL 표현식 추출
            String spelExpression = policyResponse.getGeneratedPolicy();
            log.info("[정적 최적화] SpEL 표현식 수신: {}", spelExpression);
            
            // 6. 응답 생성
            StaticAccessOptimizationResponse response = createSuccessResponse(
                    request,
                    naturalLanguagePolicy,
                    spelExpression,
                    policyResponse
            );
            
            sample.stop(processingTimer);
            log.info("[정적 최적화] 처리 완료 - SpEL: {}", spelExpression);
            
            return response;
            
        } catch (Exception e) {
            sample.stop(processingTimer);
            log.error("[정적 최적화] 처리 실패", e);
            return createErrorResponse(request, e);
        }
    }
    
    /**
     * 자연어 정책 생성
     * StaticAccessAnalysisEvent의 분석 결과를 기반으로 자연어 정책 문장 생성
     */
    private String createNaturalLanguagePolicy(StaticAccessOptimizationRequest request) {
        StringBuilder policy = new StringBuilder();
        
        // 분석 타입에 따른 자연어 정책 생성
        switch (request.getAnalysisType()) {
            case "UNUSED_PERMISSIONS":
                policy.append("90일 이상 사용되지 않은 권한을 가진 사용자들의 접근을 제한합니다. ");
                policy.append("단, 시스템 관리자와 긴급 접근 권한은 예외로 합니다. ");
                if (request.getUnusedPermissions() > 0) {
                    policy.append(String.format("%d개의 미사용 권한에 대해 검토가 필요합니다. ", 
                            request.getUnusedPermissions()));
                }
                break;
                
            case "OVER_PRIVILEGED":
                policy.append("과도한 권한을 가진 사용자의 접근을 최소 필요 권한으로 제한합니다. ");
                policy.append("중요 리소스에 대해서는 추가 인증을 요구합니다. ");
                if (request.getOverPrivilegedCount() > 0) {
                    policy.append(String.format("%d명의 사용자가 과도한 권한을 보유하고 있습니다. ", 
                            request.getOverPrivilegedCount()));
                }
                break;
                
            case "SEPARATION_OF_DUTIES":
                policy.append("직무 분리 원칙에 따라 상충되는 권한을 가진 사용자의 동시 접근을 제한합니다. ");
                policy.append("승인 워크플로우를 통해 접근을 관리합니다. ");
                break;
                
            case "LEAST_PRIVILEGE":
                policy.append("최소 권한 원칙을 적용하여 필수 권한만 허용합니다. ");
                policy.append("정기적인 권한 검토 및 재인증을 수행합니다. ");
                break;
                
            default:
                policy.append("표준 보안 정책에 따라 접근을 제어합니다. ");
                policy.append("사용자 인증과 리소스 권한 검증을 수행합니다. ");
        }
        
        // 특정 리소스가 지정된 경우
        if (request.getAnalyzedResource() != null && !request.getAnalyzedResource().isEmpty()) {
            policy.append(String.format("대상 리소스: %s. ", request.getAnalyzedResource()));
            if (request.getAnalyzedResource().contains("CRITICAL")) {
                policy.append("중요 리소스이므로 강화된 보안 정책을 적용합니다. ");
            }
        }
        
        // 특정 사용자가 지정된 경우
        if (request.getAnalyzedUser() != null && !request.getAnalyzedUser().isEmpty()) {
            policy.append(String.format("대상 사용자: %s에 대한 접근 제어를 수행합니다. ", 
                    request.getAnalyzedUser()));
        }
        
        // 시간 기반 제어
        policy.append("업무 시간 내 접근만 허용하고 비정상 시간대 접근은 추가 검증을 수행합니다.");
        
        return policy.toString();
    }
    
    
    /**
     * 성공 응답 생성
     */
    private StaticAccessOptimizationResponse createSuccessResponse(
            StaticAccessOptimizationRequest request,
            String naturalLanguagePolicy,
            String spelExpression,
            PolicyResponse policyResponse) {
        
        // PolicyProposal 생성
        StaticAccessOptimizationResponse.PolicyProposal proposal = 
                new StaticAccessOptimizationResponse.PolicyProposal();
        proposal.setProposalId("SP-" + UUID.randomUUID().toString());
        proposal.setTitle("Static Access Optimization - " + request.getAnalysisType());
        proposal.setDescription(naturalLanguagePolicy);
        proposal.setActionType("ACCESS_RESTRICTION");
        proposal.setRiskLevel(determineRiskLevel(request));
        proposal.setAiRationale("AI-generated policy based on " + request.getAnalysisType() + " analysis");
        proposal.setTargetResource(request.getAnalyzedResource());
        proposal.setTargetUser(request.getAnalyzedUser());
        proposal.setSpelExpression(spelExpression);
        proposal.setScope("RESOURCE_SPECIFIC");
        proposal.setPolicyType("ACCESS_CONTROL");
        proposal.setCreatedAt(LocalDateTime.now());
        proposal.setMetadata(createProposalMetadata(request, policyResponse));
        
        // OptimizationStrategy 생성
        StaticAccessOptimizationResponse.OptimizationStrategy strategy = 
                new StaticAccessOptimizationResponse.OptimizationStrategy();
        strategy.setType(mapAnalysisTypeToStrategy(request.getAnalysisType()));
        strategy.setPrinciple(getStrategyPrinciple(request.getAnalysisType()));
        strategy.setApproach(getStrategyApproach(request.getAnalysisType()));
        strategy.setPriority(determineStrategyPriority(request));
        
        // EffectPrediction 생성
        StaticAccessOptimizationResponse.EffectPrediction prediction = 
                new StaticAccessOptimizationResponse.EffectPrediction();
        prediction.setAccessReductionRate(calculateAccessReductionRate(request));
        prediction.setSecurityImprovement(calculateSecurityImprovement(request));
        prediction.setComplianceScore(calculateComplianceScore(request));
        prediction.setUserImpact(determineUserImpact(request));
        prediction.setEstimatedRolloutTime(estimateRolloutTime(request));
        prediction.setRequiresUserTraining(requiresUserTraining(request));
        prediction.setConfidenceScore(0.85); // AI 기반 생성이므로 높은 신뢰도
        
        // 최종 응답 생성
        return StaticAccessOptimizationResponse.createSuccess(
                request.getRequestId(),
                proposal,
                strategy,
                prediction,
                spelExpression
        );
    }
    
    /**
     * 위험 수준 결정
     */
    private String determineRiskLevel(StaticAccessOptimizationRequest request) {
        if ("OVER_PRIVILEGED".equals(request.getAnalysisType())) {
            return "HIGH";
        } else if ("SEPARATION_OF_DUTIES".equals(request.getAnalysisType())) {
            return "MEDIUM";
        } else if ("UNUSED_PERMISSIONS".equals(request.getAnalysisType())) {
            return "LOW";
        } else {
            return "LOW";
        }
    }
    
    /**
     * 분석 타입을 전략 타입으로 매핑
     */
    private String mapAnalysisTypeToStrategy(String analysisType) {
        switch (analysisType) {
            case "UNUSED_PERMISSIONS":
                return "PERMISSION_CLEANUP";
            case "OVER_PRIVILEGED":
                return "PRIVILEGE_REDUCTION";
            case "SEPARATION_OF_DUTIES":
                return "DUTY_SEPARATION";
            case "LEAST_PRIVILEGE":
                return "LEAST_PRIVILEGE_ENFORCEMENT";
            default:
                return "GENERAL_OPTIMIZATION";
        }
    }
    
    /**
     * 전략 원칙 반환
     */
    private String getStrategyPrinciple(String analysisType) {
        switch (analysisType) {
            case "UNUSED_PERMISSIONS":
                return "Remove unused permissions to reduce attack surface";
            case "OVER_PRIVILEGED":
                return "Apply least privilege principle";
            case "SEPARATION_OF_DUTIES":
                return "Separate conflicting permissions";
            case "LEAST_PRIVILEGE":
                return "Enforce minimum necessary permissions";
            default:
                return "General access optimization";
        }
    }
    
    /**
     * 전략 접근법 반환
     */
    private String getStrategyApproach(String analysisType) {
        switch (analysisType) {
            case "UNUSED_PERMISSIONS":
                return "Identify and revoke permissions not used in the last 90 days";
            case "OVER_PRIVILEGED":
                return "Reduce excessive permissions to minimum required";
            case "SEPARATION_OF_DUTIES":
                return "Implement approval workflows for conflicting access";
            case "LEAST_PRIVILEGE":
                return "Review and minimize all permission assignments";
            default:
                return "Apply standard optimization rules";
        }
    }
    
    /**
     * 전략 우선순위 결정
     */
    private String determineStrategyPriority(StaticAccessOptimizationRequest request) {
        if ("OVER_PRIVILEGED".equals(request.getAnalysisType())) {
            return "CRITICAL";
        } else if ("SEPARATION_OF_DUTIES".equals(request.getAnalysisType())) {
            return "HIGH";
        } else if ("UNUSED_PERMISSIONS".equals(request.getAnalysisType())) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
    
    /**
     * 접근 감소율 계산
     */
    private double calculateAccessReductionRate(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "UNUSED_PERMISSIONS":
                return 0.3; // 30% 감소 예상
            case "OVER_PRIVILEGED":
                return 0.5; // 50% 감소 예상
            case "SEPARATION_OF_DUTIES":
                return 0.2; // 20% 감소 예상
            case "LEAST_PRIVILEGE":
                return 0.4; // 40% 감소 예상
            default:
                return 0.15; // 15% 감소 예상
        }
    }
    
    /**
     * 보안 개선도 계산
     */
    private double calculateSecurityImprovement(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "OVER_PRIVILEGED":
                return 0.8; // 80% 보안 개선
            case "SEPARATION_OF_DUTIES":
                return 0.7; // 70% 보안 개선
            case "UNUSED_PERMISSIONS":
                return 0.5; // 50% 보안 개선
            case "LEAST_PRIVILEGE":
                return 0.75; // 75% 보안 개선
            default:
                return 0.3; // 30% 보안 개선
        }
    }
    
    /**
     * 컴플라이언스 점수 계산
     */
    private double calculateComplianceScore(StaticAccessOptimizationRequest request) {
        // 모든 정책은 컴플라이언스 향상에 기여
        return 0.9; // 90% 컴플라이언스 점수
    }
    
    /**
     * 사용자 영향 결정
     */
    private String determineUserImpact(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "OVER_PRIVILEGED":
                return "HIGH"; // 많은 사용자 영향
            case "SEPARATION_OF_DUTIES":
                return "MEDIUM"; // 중간 정도 사용자 영향
            case "UNUSED_PERMISSIONS":
                return "LOW"; // 적은 사용자 영향
            default:
                return "LOW";
        }
    }
    
    /**
     * 예상 적용 시간 계산
     */
    private String estimateRolloutTime(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "OVER_PRIVILEGED":
                return "2-4 weeks"; // 신중한 적용 필요
            case "SEPARATION_OF_DUTIES":
                return "4-6 weeks"; // 복잡한 변경
            case "UNUSED_PERMISSIONS":
                return "1-2 weeks"; // 상대적으로 간단
            case "LEAST_PRIVILEGE":
                return "3-4 weeks"; // 중간 복잡도
            default:
                return "1-2 weeks";
        }
    }
    
    /**
     * 사용자 교육 필요 여부
     */
    private boolean requiresUserTraining(StaticAccessOptimizationRequest request) {
        return "OVER_PRIVILEGED".equals(request.getAnalysisType()) || 
               "SEPARATION_OF_DUTIES".equals(request.getAnalysisType());
    }
    
    /**
     * 제안 메타데이터 생성
     */
    private Map<String, Object> createProposalMetadata(
            StaticAccessOptimizationRequest request,
            PolicyResponse policyResponse) {
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("analysisType", request.getAnalysisType());
        metadata.put("totalPermissions", request.getTotalPermissions());
        metadata.put("unusedPermissions", request.getUnusedPermissions());
        metadata.put("overPrivilegedCount", request.getOverPrivilegedCount());
        metadata.put("generatedAt", LocalDateTime.now());
        metadata.put("generator", "AdvancedPolicyGenerationLab");
        metadata.put("confidence", policyResponse.getPolicyConfidenceScore() != null ? policyResponse.getPolicyConfidenceScore() : 0.85);
        metadata.put("version", "2.0.0");
        
        return metadata;
    }
    
    /**
     * 오류 응답 생성
     */
    private StaticAccessOptimizationResponse createErrorResponse(
            StaticAccessOptimizationRequest request, 
            Exception e) {
        return StaticAccessOptimizationResponse.createError(
                request.getRequestId(),
                "PROCESSING_ERROR",
                "Failed to process static access optimization: " + e.getMessage()
        );
    }
}