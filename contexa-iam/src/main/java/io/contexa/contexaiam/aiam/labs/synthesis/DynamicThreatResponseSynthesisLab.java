package io.contexa.contexaiam.aiam.labs.synthesis;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.protocol.context.DynamicThreatResponseContext;
import io.contexa.contexaiam.aiam.protocol.request.DynamicThreatResponseRequest;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.DynamicThreatResponseResponse;
import io.contexa.contexaiam.aiam.protocol.response.DynamicThreatResponseResponse.PolicyProposal;
import io.contexa.contexaiam.aiam.protocol.response.DynamicThreatResponseResponse.PolicyEffectPrediction;
import io.contexa.contexaiam.aiam.protocol.response.DynamicThreatResponseResponse.ProcessingMetadata;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 동적 위협 대응 합성 Lab
 * 
 * 실시간 위협 대응 경험을 학습하여 전략적 보안 원칙을 추론하고
 * 이를 실행 가능한 정책으로 변환하는 AI Lab
 * 
 * 처리 흐름:
 * 1. DynamicThreatResponseEvent 수신
 * 2. AI를 통한 전략적 보안 원칙 추론
 * 3. AdvancedPolicyGenerationLab을 통한 SpEL 표현식 변환
 * 4. PolicyProposal 생성 및 반환
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
public class DynamicThreatResponseSynthesisLab extends AbstractIAMLab<DynamicThreatResponseRequest, DynamicThreatResponseResponse> {
    
    private final PipelineOrchestrator orchestrator;
    private final AdvancedPolicyGenerationLab policyGenerationLab;
    private final IAMDataCollectionService dataCollectionService;
    private final MeterRegistry meterRegistry;
    
    // 처리 타이머
    private final Timer processingTimer;
    
    @Autowired
    public DynamicThreatResponseSynthesisLab(
            io.opentelemetry.api.trace.Tracer tracer,
            PipelineOrchestrator orchestrator,
            AdvancedPolicyGenerationLab policyGenerationLab,
            IAMDataCollectionService dataCollectionService,
            MeterRegistry meterRegistry) {
        super(tracer, "DynamicThreatResponseSynthesisLab", "1.0.0", LabSpecialization.POLICY_GENERATION);
        this.orchestrator = orchestrator;
        this.policyGenerationLab = policyGenerationLab;
        this.dataCollectionService = dataCollectionService;
        this.meterRegistry = meterRegistry;
        
        // 메트릭 초기화
        this.processingTimer = Timer.builder("synthesis.dynamic_threat_response.duration")
                .description("Dynamic threat response processing time")
                .register(meterRegistry);
        
        log.info("DynamicThreatResponseSynthesisLab 초기화 완료 - AI 기반 위협 대응 정책 합성");
    }
    
    @Override
    public boolean supportsStreaming() {
        return true;
    }
    
    @Override
    protected DynamicThreatResponseResponse doProcess(DynamicThreatResponseRequest request) throws Exception {
        log.info("[동적 위협 대응 합성] 처리 시작 - 이벤트 ID: {}", request.getEventId());
        
        try {
            // 1단계: AI를 통한 전략적 보안 원칙 추론
            String strategicPrinciple = inferStrategicPrinciple(request);
            log.info("[AI 추론] 전략적 원칙: {}", strategicPrinciple);
            
            // 2단계: AdvancedPolicyGenerationLab을 통한 SpEL 표현식 변환
            String spelExpression = generateSpelExpression(strategicPrinciple, request);
            log.info("[정책 변환] SpEL 표현식: {}", spelExpression);
            
            // 3단계: PolicyProposal 생성
            PolicyProposal proposal = createPolicyProposal(request, strategicPrinciple, spelExpression);
            
            // 4단계: 효과 예측
            PolicyEffectPrediction prediction = predictPolicyEffect(request, proposal);
            
            // 5단계: 응답 생성
            return buildSuccessResponse(request, proposal, strategicPrinciple, spelExpression, prediction);
            
        } catch (Exception e) {
            log.error("[동적 위협 대응 합성] 처리 실패", e);
            return DynamicThreatResponseResponse.createFailure(
                    request.getRequestId(),
                    "정책 합성 실패: " + e.getMessage()
            );
        }
    }
    
    @Override
    protected Mono<DynamicThreatResponseResponse> doProcessAsync(DynamicThreatResponseRequest request) {
        log.info("[동적 위협 대응 합성] 비동기 처리 시작 - 이벤트 ID: {}", request.getEventId());
        
        return Mono.fromCallable(() -> inferStrategicPrinciple(request))
                .flatMap(principle -> {
                    log.info("[AI 추론] 비동기 전략적 원칙: {}", principle);
                    return generateSpelExpressionAsync(principle, request)
                            .map(spel -> buildProposalData(request, principle, spel));
                })
                .map(data -> {
                    PolicyProposal proposal = (PolicyProposal) data.get("proposal");
                    String principle = (String) data.get("principle");
                    String spel = (String) data.get("spel");
                    PolicyEffectPrediction prediction = predictPolicyEffect(request, proposal);
                    return buildSuccessResponse(request, proposal, principle, spel, prediction);
                })
                .doOnSuccess(response -> log.info("[동적 위협 대응 합성] 비동기 처리 완료"))
                .onErrorResume(error -> {
                    log.error("[동적 위협 대응 합성] 비동기 처리 실패", error);
                    return Mono.just(DynamicThreatResponseResponse.createFailure(
                            request.getRequestId(),
                            "비동기 정책 합성 실패: " + error.getMessage()
                    ));
                });
    }
    
    @Override
    protected Flux<String> doProcessStream(DynamicThreatResponseRequest request) {
        log.info("[동적 위협 대응 합성] 스트리밍 처리 시작 - 이벤트 ID: {}", request.getEventId());
        
        return Flux.concat(
                Flux.just("[시작] 동적 위협 대응 정책 합성 프로세스\n"),
                Flux.just("[1단계] 위협 분석 중...\n"),
                Flux.just(analyzeThreatContext(request)),
                Flux.just("\n[2단계] AI 전략적 원칙 추론 중...\n"),
                Flux.defer(() -> {
                    String principle = inferStrategicPrinciple(request);
                    return Flux.just("추론된 원칙: " + principle + "\n");
                }),
                Flux.just("\n[3단계] SpEL 표현식 생성 중...\n"),
                Flux.defer(() -> {
                    String principle = inferStrategicPrinciple(request);
                    String spel = generateSpelExpression(principle, request);
                    return Flux.just("생성된 표현식: " + spel + "\n");
                }),
                Flux.just("\n[4단계] 정책 제안 생성 완료\n"),
                Flux.just("[완료] 정책 제안이 생성되었습니다.\n")
        );
    }
    
    /**
     * AI를 통한 전략적 보안 원칙 추론
     * PipelineOrchestrator를 사용하여 AI 진단 수행
     */
    private String inferStrategicPrinciple(DynamicThreatResponseRequest request) {
        log.info("[AI 추론] 전략적 원칙 추론 시작 - PipelineOrchestrator 사용");
        
        try {
            // AI Request 생성 - 위협 정보를 자연어로 변환
            AIRequest<DynamicThreatResponseContext> aiRequest = createThreatAnalysisRequest(request);
            
            // Pipeline Configuration 생성
            PipelineConfiguration config = createThreatResponsePipelineConfig();
            
            // orchestrator를 통해 AI 진단 수행
            Mono<DynamicThreatResponseResponse> responseMono = orchestrator.execute(
                aiRequest, 
                config,
                DynamicThreatResponseResponse.class
            );
            
            DynamicThreatResponseResponse aiResponse = responseMono.block();
            
            if (aiResponse != null && aiResponse.getStrategicPrinciple() != null) {
                log.info("[AI 추론] 전략적 원칙 생성 성공: {}", aiResponse.getStrategicPrinciple());
                return aiResponse.getStrategicPrinciple();
            }
            
            // Fallback 원칙 생성
            log.warn("[AI 추론] AI 응답이 없어 Fallback 원칙 사용");
            return generateFallbackPrinciple(request);
            
        } catch (Exception e) {
            log.error("[AI 추론] 전략적 원칙 추론 실패", e);
            return generateFallbackPrinciple(request);
        }
    }
    
    /**
     * 위협 분석을 위한 AIRequest 생성
     */
    private AIRequest<DynamicThreatResponseContext> createThreatAnalysisRequest(DynamicThreatResponseRequest request) {
        DynamicThreatResponseContext context = request.getContext();
        
        AIRequest<DynamicThreatResponseContext> aiRequest = new AIRequest<>(
            context,
            "threatAnalysis",
            context.getOrganizationId() != null ? context.getOrganizationId() : "default-org"
        );
        
        // 위협 정보를 자연어로 변환하여 AI에게 전달
        StringBuilder prompt = new StringBuilder();
        prompt.append("다음 위협 상황에 대한 전략적 보안 원칙을 생성해주세요:\n");
        prompt.append("위협 유형: ").append(context.getThreatInfo().getThreatType()).append("\n");
        prompt.append("공격 벡터: ").append(context.getThreatInfo().getAttackVector()).append("\n");
        prompt.append("대상 리소스: ").append(context.getThreatInfo().getTargetResource()).append("\n");
        prompt.append("심각도: ").append(context.getThreatInfo().getSeverity()).append("\n");
        prompt.append("\n자연어 정책 형식으로 응답해주세요.");
        
        aiRequest.withParameter("prompt", prompt.toString());
        aiRequest.withParameter("requestType", "threat_response_synthesis");
        aiRequest.withParameter("outputFormat", "natural_language_policy");
        
        return aiRequest;
    }
    
    /**
     * 위협 대응을 위한 Pipeline Configuration 생성
     */
    private PipelineConfiguration createThreatResponsePipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .enableStreaming(false)
                .build();
    }
    
    /**
     * AdvancedPolicyGenerationLab을 통한 SpEL 표현식 생성
     */
    private String generateSpelExpression(String strategicPrinciple, DynamicThreatResponseRequest request) {
        try {
            // IAMDataCollectionService에서 AvailableItems 획득
            PolicyGenerationItem.AvailableItems availableItems = dataCollectionService.policyCollectData();
            log.info("[정책 변환] AvailableItems 수집 완료 - 역할: {}, 권한: {}, 조건: {}",
                    availableItems.roles() != null ? availableItems.roles().size() : 0,
                    availableItems.permissions() != null ? availableItems.permissions().size() : 0,
                    availableItems.conditions() != null ? availableItems.conditions().size() : 0);
            
            // PolicyGenerationRequest 생성 - 자연어 정책과 AvailableItems 모두 전달
            PolicyGenerationRequest policyRequest = new PolicyGenerationRequest(
                    strategicPrinciple,
                    availableItems
            );
            
            // AdvancedPolicyGenerationLab 실행
            PolicyResponse policyResponse = policyGenerationLab.process(policyRequest);
            
            if (policyResponse != null && policyResponse.getGeneratedPolicy() != null) {
                return policyResponse.getGeneratedPolicy();
            }
            
            // Fallback SpEL 생성
            return generateFallbackSpel(request);
            
        } catch (Exception e) {
            log.error("[정책 변환] SpEL 표현식 생성 실패", e);
            return generateFallbackSpel(request);
        }
    }
    
    /**
     * 비동기 SpEL 표현식 생성
     */
    private Mono<String> generateSpelExpressionAsync(String strategicPrinciple, DynamicThreatResponseRequest request) {
        // IAMDataCollectionService에서 AvailableItems 획득
        PolicyGenerationItem.AvailableItems availableItems = dataCollectionService.policyCollectData();
        
        PolicyGenerationRequest policyRequest = new PolicyGenerationRequest(
                strategicPrinciple,
                availableItems
        );
        
        return policyGenerationLab.processAsync(policyRequest)
                .map(response -> {
                    if (response != null && response.getGeneratedPolicy() != null) {
                        return response.getGeneratedPolicy();
                    }
                    return generateFallbackSpel(request);
                })
                .onErrorReturn(generateFallbackSpel(request));
    }
    
    /**
     * PolicyProposal 생성
     */
    private PolicyProposal createPolicyProposal(
            DynamicThreatResponseRequest request,
            String strategicPrinciple,
            String spelExpression) {
        
        return PolicyProposal.builder()
                .proposalId("PP-" + UUID.randomUUID().toString())
                .title(generateProposalTitle(request))
                .description(generateProposalDescription(request))
                .policyType(request.getContext().getHint().getPreferredPolicyType())
                .actionType("CREATE")
                .scope(request.getContext().getHint().getScope())
                .priority(request.getContext().getHint().getPriority())
                .aiRationale(strategicPrinciple)
                .policyContent(buildPolicyContent(spelExpression, request))
                .createdAt(LocalDateTime.now())
                .requiresApproval(request.getContext().getHint().getRequiresApproval())
                .riskLevel(calculateRiskLevel(request))
                .build();
    }
    
    /**
     * 정책 효과 예측 (ML 모델 사용)
     */
    private PolicyEffectPrediction predictPolicyEffect(
            DynamicThreatResponseRequest request,
            PolicyProposal proposal) {
        
        // ML 모델을 사용한 예측
        Timer.Sample sample = Timer.start(meterRegistry);
        try {
            PolicyEffectPrediction prediction = createPolicyEffectPrediction(request, proposal);
            sample.stop(Timer.builder("synthesis.prediction.duration")
                    .description("Policy effect prediction duration")
                    .register(meterRegistry));
            return prediction;
        } catch (Exception e) {
            log.error("ML 예측 실패, Fallback 사용", e);
            sample.stop(Timer.builder("synthesis.prediction.duration")
                    .tag("status", "fallback")
                    .register(meterRegistry));
            return createFallbackPrediction(request, proposal);
        }
    }
    
    /**
     * 정책 효과 예측 생성
     */
    private PolicyEffectPrediction createPolicyEffectPrediction(
            DynamicThreatResponseRequest request,
            PolicyProposal proposal) {
        
        double threatReduction = calculateThreatReduction(request);
        double falsePositiveRate = calculateFalsePositiveRate(proposal);
        double performanceImpact = calculatePerformanceImpact(proposal);
        int affectedUsers = estimateAffectedUsers(request);
        String impactDescription = generateImpactDescription(threatReduction, falsePositiveRate);
        double confidenceScore = calculateConfidenceScore(request, 
                PolicyEffectPrediction.builder()
                        .threatReductionRate(threatReduction)
                        .falsePositiveRate(falsePositiveRate)
                        .build());
        
        return PolicyEffectPrediction.builder()
                .threatReductionRate(threatReduction)
                .falsePositiveRate(falsePositiveRate)
                .performanceImpact(performanceImpact)
                .estimatedAffectedUsers(affectedUsers)
                .impactDescription(impactDescription)
                .confidenceScore(confidenceScore)
                .predictionTimestamp(LocalDateTime.now())
                .modelVersion("AI-BASED")
                .build();
    }
    
    /**
     * 성공 응답 생성
     */
    private DynamicThreatResponseResponse buildSuccessResponse(
            DynamicThreatResponseRequest request,
            PolicyProposal proposal,
            String strategicPrinciple,
            String spelExpression,
            PolicyEffectPrediction prediction) {
        
        DynamicThreatResponseResponse response = DynamicThreatResponseResponse.createSuccess(
                request.getRequestId(),
                proposal,
                strategicPrinciple,
                spelExpression,
                calculateConfidenceScore(request, prediction)
        );
        
        response.setEffectPrediction(prediction);
        response.setProcessingMetadata(ProcessingMetadata.builder()
                .labName(getLabName())
                .labVersion(getVersion())
                .processingTimeMs(System.currentTimeMillis())
                .llmModel("gpt-4-turbo")
                .tokenUsage(calculateTokenUsage(request, prediction))
                .build());
        
        return response;
    }
    
    /**
     * 위협 컨텍스트 분석 (스트리밍용)
     */
    private String analyzeThreatContext(DynamicThreatResponseRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append("위협 유형: ").append(request.getContext().getThreatInfo().getThreatType()).append("\n");
        sb.append("공격 벡터: ").append(request.getContext().getThreatInfo().getAttackVector()).append("\n");
        sb.append("대상 리소스: ").append(request.getContext().getThreatInfo().getTargetResource()).append("\n");
        sb.append("심각도: ").append(request.getContext().getThreatInfo().getSeverity());
        return sb.toString();
    }
    
    /**
     * Proposal 데이터 빌드 (비동기용)
     */
    private Map<String, Object> buildProposalData(
            DynamicThreatResponseRequest request,
            String principle,
            String spel) {
        
        Map<String, Object> data = new HashMap<>();
        data.put("proposal", createPolicyProposal(request, principle, spel));
        data.put("principle", principle);
        data.put("spel", spel);
        return data;
    }
    
    // ==================== Helper Methods ====================
    
    private String generateFallbackPrinciple(DynamicThreatResponseRequest request) {
        return String.format(
                "%s 유형의 위협이 %s를 통해 %s를 대상으로 발생한 경우, %s 조치를 통해 차단해야 한다.",
                request.getContext().getThreatInfo().getThreatType(),
                request.getContext().getThreatInfo().getAttackVector(),
                request.getContext().getThreatInfo().getTargetResource(),
                request.getContext().getResponseInfo().getMitigationAction()
        );
    }
    
    private String generateFallbackSpel(DynamicThreatResponseRequest request) {
        // 위협 심각도에 따른 SpEL 표현식 생성
        // 주의: #threatType, #targetResource는 Contexa에 존재하지 않는 변수
        // 실제 존재하는 #trust, #ai 변수 및 Spring Security 메서드 사용
        String severity = request.getContext().getThreatInfo().getSeverity();
        String mitigationAction = request.getContext().getResponseInfo().getMitigationAction();

        // 심각도에 따른 LLM Action 기반 정책 생성 (Hot Path 우선)
        switch (severity) {
            case "CRITICAL":
                // 매우 고위험: LLM BLOCK 판정 또는 AI 실시간 분석 필요
                return "#trust.isBlocked() or (#trust.needsInvestigation() and #ai.hasSafeBehavior(10.0) == false)";
            case "HIGH":
                // 고위험: 차단/조사 대상 사용자 - ALLOW가 아닌 경우
                return "#trust.hasActionIn('BLOCK', 'INVESTIGATE', 'ESCALATE') and not #trust.isAllowed()";
            case "MEDIUM":
                // 중위험: MFA 추가 인증 필요 사용자
                return "#trust.needsChallenge() and not hasRole('ROLE_TRUSTED_USER')";
            case "LOW":
            default:
                // 저위험: 인증 필수 + 허용/모니터링 상태 확인
                return "isAuthenticated() and (#trust.isAllowed() or #trust.isMonitored())";
        }
    }
    
    private String generateProposalTitle(DynamicThreatResponseRequest request) {
        return String.format(
                "%s 위협 대응 정책",
                request.getContext().getThreatInfo().getThreatType()
        );
    }
    
    private String generateProposalDescription(DynamicThreatResponseRequest request) {
        return String.format(
                "이벤트 %s에서 학습된 %s 위협에 대한 자동 대응 정책",
                request.getEventId(),
                request.getContext().getThreatInfo().getThreatType()
        );
    }
    
    private Map<String, Object> buildPolicyContent(String spelExpression, DynamicThreatResponseRequest request) {
        Map<String, Object> content = new HashMap<>();
        content.put("expression", spelExpression);
        content.put("action", request.getContext().getResponseInfo().getMitigationAction());
        content.put("targetResource", request.getContext().getThreatInfo().getTargetResource());
        content.put("severity", request.getContext().getThreatInfo().getSeverity());
        return content;
    }
    
    private String calculateRiskLevel(DynamicThreatResponseRequest request) {
        String severity = request.getContext().getThreatInfo().getSeverity();
        if ("CRITICAL".equals(severity)) return "CRITICAL";
        if ("HIGH".equals(severity)) return "HIGH";
        if ("MEDIUM".equals(severity)) return "MEDIUM";
        return "LOW";
    }
    
    private double calculateThreatReduction(DynamicThreatResponseRequest request) {
        // ML 모델 사용
        // 심각도에 따른 위협 감소율 계산
        String severity = request.getContext().getThreatInfo().getSeverity();
        switch (severity) {
            case "CRITICAL":
                return 0.95;
            case "HIGH":
                return 0.85;
            case "MEDIUM":
                return 0.70;
            case "LOW":
                return 0.50;
            default:
                return 0.30;
        }
    }
    
    private double calculateFalsePositiveRate(PolicyProposal proposal) {
        // 설정에서 읽기
        String scope = proposal.getScope();
        // 범위에 따른 오탐율 계산
        switch (scope) {
            case "GLOBAL":
                return 0.15;
            case "RESOURCE_SPECIFIC":
                return 0.08;
            case "USER_SPECIFIC":
                return 0.05;
            default:
                return 0.10;
        }
    }
    
    private double calculatePerformanceImpact(PolicyProposal proposal) {
        // 설정에서 읽기
        String policyType = proposal.getPolicyType();
        // 정책 타입에 따른 성능 영향도
        switch (policyType) {
            case "BLOCKING":
                return 0.10;
            case "RATE_LIMITING":
                return 0.15;
            case "MONITORING":
                return 0.05;
            default:
                return 0.08;
        }
    }
    
    private int estimateAffectedUsers(DynamicThreatResponseRequest request) {
        // ML 모델 사용
        // 범위에 따른 영향받는 사용자 수 추정
        String scope = request.getContext().getHint().getScope();
        switch (scope) {
            case "GLOBAL":
                return 10000;
            case "ORGANIZATION":
                return 1000;
            case "DEPARTMENT":
                return 100;
            case "RESOURCE_SPECIFIC":
                return 50;
            case "USER_SPECIFIC":
                return 10;
            default:
                return 100;
        }
    }
    
    private String generateImpactDescription(double threatReduction, double falsePositiveRate) {
        return String.format(
                "예상 위협 감소율: %.0f%%, 예상 오탐율: %.0f%%",
                threatReduction * 100,
                falsePositiveRate * 100
        );
    }
    
    private double calculateConfidenceScore(DynamicThreatResponseRequest request, PolicyEffectPrediction prediction) {
        double base = 0.7; // 기본 신뢰도
        
        if (request.getContext().getResponseInfo().isSuccessful()) {
            base += 0.1; // 성공 보너스
        }
        if (prediction.getThreatReductionRate() > 0.8) {
            base += 0.1; // 높은 위협 감소율 보너스
        }
        if (prediction.getFalsePositiveRate() < 0.1) {
            base += 0.1; // 낮은 오탐율 보너스
        }
        
        return Math.min(base, 0.95); // 최대 신뢰도 95%
    }
    
    private String extractResourceType(String resource) {
        if (resource == null) return "UNKNOWN";
        
        // 더 정교한 리소스 타입 추출 로직
        String lowerResource = resource.toLowerCase();
        
        if (lowerResource.matches(".*(/api/|/rest/|/graphql/).*")) return "API";
        if (lowerResource.matches(".*(database|db|sql|mongo|redis).*")) return "DATABASE";
        if (lowerResource.matches(".*(file|document|upload|download).*")) return "FILE";
        if (lowerResource.matches(".*(network|socket|port|tcp|udp).*")) return "NETWORK";
        if (lowerResource.matches(".*(auth|login|session|token).*")) return "AUTHENTICATION";
        if (lowerResource.matches(".*(admin|management|config).*")) return "ADMINISTRATION";
        
        return "SYSTEM";
    }
    
    /**
     * Fallback 예측 생성
     */
    private PolicyEffectPrediction createFallbackPrediction(
            DynamicThreatResponseRequest request,
            PolicyProposal proposal) {
        
        // 심각도 기반 위협 감소율
        String severity = request.getContext().getThreatInfo().getSeverity();
        double threatReduction = calculateThreatReduction(request);
        
        double falsePositiveRate = calculateFalsePositiveRate(proposal);
        double performanceImpact = calculatePerformanceImpact(proposal);
        
        int affectedUsers = estimateAffectedUsers(request);
        
        return PolicyEffectPrediction.builder()
                .threatReductionRate(threatReduction)
                .falsePositiveRate(falsePositiveRate)
                .performanceImpact(performanceImpact)
                .estimatedAffectedUsers(affectedUsers)
                .impactDescription(generateImpactDescription(threatReduction, falsePositiveRate))
                .confidenceScore(0.6)  // Fallback은 낮은 신뢰도
                .build();
    }
    
    /**
     * 토큰 사용량 계산
     */
    private int calculateTokenUsage(
            DynamicThreatResponseRequest request,
            PolicyEffectPrediction prediction) {
        
        int baseTokens = 2000; // 기본 토큰 사용량
        
        // 복잡도에 따른 토큰 조정
        if ("CRITICAL".equals(request.getContext().getThreatInfo().getSeverity())) {
            baseTokens += 500;
        }
        
        // 예측 신뢰도에 따른 조정
        if (prediction != null && prediction.getConfidenceScore() < 0.7) {
            baseTokens += 300;  // 낮은 신뢰도는 더 많은 분석 필요
        }
        
        return Math.min(baseTokens, 4000); // 최대 4000 토큰
    }
    
    /**
     * AI 요청 생성
     */
    private AIRequest<ThreatContext> createAIRequest(DynamicThreatResponseRequest request) {
        ThreatContext context = new ThreatContext(
                request.getContext().getThreatInfo(),
                request.getContext().getResponseInfo()
        );
        
        AIRequest<ThreatContext> aiRequest = new AIRequest<>(
                context,
                "threatResponseSynthesis",
                "default-org"
        );
        
        aiRequest.withParameter("threatType", request.getContext().getThreatInfo().getThreatType());
        aiRequest.withParameter("attackVector", request.getContext().getThreatInfo().getAttackVector());
        aiRequest.withParameter("mitigationAction", request.getContext().getResponseInfo().getMitigationAction());
        
        return aiRequest;
    }
    
    /**
     * Pipeline 구성
     */
    private PipelineConfiguration createPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .timeoutSeconds(60)
                .build();
    }
    
    /**
     * 위협 컨텍스트 (내부 클래스)
     */
    private static class ThreatContext extends DomainContext {
        private final DynamicThreatResponseContext.ThreatInfo threatInfo;
        private final DynamicThreatResponseContext.ResponseInfo responseInfo;
        private final SecurityLevel securityLevel;
        private final AuditRequirement auditRequirement;
        
        public ThreatContext(
                DynamicThreatResponseContext.ThreatInfo threatInfo,
                DynamicThreatResponseContext.ResponseInfo responseInfo) {
            super("system", "threat-response-session");  // userId, sessionId
            this.threatInfo = threatInfo;
            this.responseInfo = responseInfo;
            this.securityLevel = SecurityLevel.HIGH;
            this.auditRequirement = AuditRequirement.BASIC;
        }
        
        @Override
        public String getDomainType() {
            return "THREAT_RESPONSE";
        }
        
        @Override
        public int getPriorityLevel() {
            if (threatInfo != null && "CRITICAL".equals(threatInfo.getSeverity())) {
                return 10;  // URGENT
            }
            return 5;  // NORMAL
        }
        
        public SecurityLevel getSecurityLevel() {
            return securityLevel;
        }
        
        public AuditRequirement getAuditRequirement() {
            return auditRequirement;
        }
    }
}