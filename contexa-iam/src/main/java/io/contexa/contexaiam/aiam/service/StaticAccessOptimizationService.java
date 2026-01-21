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

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
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

        this.processingTimer = Timer.builder("synthesis.static_access_optimization.duration")
                .description("Static access optimization processing time")
                .register(meterRegistry);
        
            }

    public StaticAccessOptimizationResponse process(StaticAccessOptimizationRequest request) {
        Timer.Sample sample = Timer.start(meterRegistry);
        
        try {

            String naturalLanguagePolicy = createNaturalLanguagePolicy(request);

            PolicyGenerationItem.AvailableItems availableItems = dataCollectionService.policyCollectData();

            PolicyGenerationRequest policyRequest = new PolicyGenerationRequest(
                    naturalLanguagePolicy,
                    availableItems
            );

                        PolicyResponse policyResponse = policyGenerationLab.process(policyRequest);
            
            if (policyResponse == null) {
                throw new RuntimeException("AdvancedPolicyGenerationLab에서 응답을 받지 못했습니다");
            }

            String spelExpression = policyResponse.getGeneratedPolicy();

            StaticAccessOptimizationResponse response = createSuccessResponse(
                    request,
                    naturalLanguagePolicy,
                    spelExpression,
                    policyResponse
            );
            
            sample.stop(processingTimer);
                        
            return response;
            
        } catch (Exception e) {
            sample.stop(processingTimer);
            log.error("[정적 최적화] 처리 실패", e);
            return createErrorResponse(request, e);
        }
    }

    private String createNaturalLanguagePolicy(StaticAccessOptimizationRequest request) {
        StringBuilder policy = new StringBuilder();

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

        if (request.getAnalyzedResource() != null && !request.getAnalyzedResource().isEmpty()) {
            policy.append(String.format("대상 리소스: %s. ", request.getAnalyzedResource()));
            if (request.getAnalyzedResource().contains("CRITICAL")) {
                policy.append("중요 리소스이므로 강화된 보안 정책을 적용합니다. ");
            }
        }

        if (request.getAnalyzedUser() != null && !request.getAnalyzedUser().isEmpty()) {
            policy.append(String.format("대상 사용자: %s에 대한 접근 제어를 수행합니다. ", 
                    request.getAnalyzedUser()));
        }

        policy.append("업무 시간 내 접근만 허용하고 비정상 시간대 접근은 추가 검증을 수행합니다.");
        
        return policy.toString();
    }

    private StaticAccessOptimizationResponse createSuccessResponse(
            StaticAccessOptimizationRequest request,
            String naturalLanguagePolicy,
            String spelExpression,
            PolicyResponse policyResponse) {

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

        StaticAccessOptimizationResponse.OptimizationStrategy strategy = 
                new StaticAccessOptimizationResponse.OptimizationStrategy();
        strategy.setType(mapAnalysisTypeToStrategy(request.getAnalysisType()));
        strategy.setPrinciple(getStrategyPrinciple(request.getAnalysisType()));
        strategy.setApproach(getStrategyApproach(request.getAnalysisType()));
        strategy.setPriority(determineStrategyPriority(request));

        StaticAccessOptimizationResponse.EffectPrediction prediction = 
                new StaticAccessOptimizationResponse.EffectPrediction();
        prediction.setAccessReductionRate(calculateAccessReductionRate(request));
        prediction.setSecurityImprovement(calculateSecurityImprovement(request));
        prediction.setComplianceScore(calculateComplianceScore(request));
        prediction.setUserImpact(determineUserImpact(request));
        prediction.setEstimatedRolloutTime(estimateRolloutTime(request));
        prediction.setRequiresUserTraining(requiresUserTraining(request));
        prediction.setConfidenceScore(0.85); 

        return StaticAccessOptimizationResponse.createSuccess(
                request.getRequestId(),
                proposal,
                strategy,
                prediction,
                spelExpression
        );
    }

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

    private double calculateAccessReductionRate(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "UNUSED_PERMISSIONS":
                return 0.3; 
            case "OVER_PRIVILEGED":
                return 0.5; 
            case "SEPARATION_OF_DUTIES":
                return 0.2; 
            case "LEAST_PRIVILEGE":
                return 0.4; 
            default:
                return 0.15; 
        }
    }

    private double calculateSecurityImprovement(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "OVER_PRIVILEGED":
                return 0.8; 
            case "SEPARATION_OF_DUTIES":
                return 0.7; 
            case "UNUSED_PERMISSIONS":
                return 0.5; 
            case "LEAST_PRIVILEGE":
                return 0.75; 
            default:
                return 0.3; 
        }
    }

    private double calculateComplianceScore(StaticAccessOptimizationRequest request) {
        
        return 0.9; 
    }

    private String determineUserImpact(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "OVER_PRIVILEGED":
                return "HIGH"; 
            case "SEPARATION_OF_DUTIES":
                return "MEDIUM"; 
            case "UNUSED_PERMISSIONS":
                return "LOW"; 
            default:
                return "LOW";
        }
    }

    private String estimateRolloutTime(StaticAccessOptimizationRequest request) {
        switch (request.getAnalysisType()) {
            case "OVER_PRIVILEGED":
                return "2-4 weeks"; 
            case "SEPARATION_OF_DUTIES":
                return "4-6 weeks"; 
            case "UNUSED_PERMISSIONS":
                return "1-2 weeks"; 
            case "LEAST_PRIVILEGE":
                return "3-4 weeks"; 
            default:
                return "1-2 weeks";
        }
    }

    private boolean requiresUserTraining(StaticAccessOptimizationRequest request) {
        return "OVER_PRIVILEGED".equals(request.getAnalysisType()) || 
               "SEPARATION_OF_DUTIES".equals(request.getAnalysisType());
    }

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