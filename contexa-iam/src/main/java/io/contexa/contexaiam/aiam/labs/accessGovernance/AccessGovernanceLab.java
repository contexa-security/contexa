package io.contexa.contexaiam.aiam.labs.accessGovernance;

import io.contexa.contexacore.autonomous.event.StaticAccessAnalysisEvent;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.components.retriever.AccessGovernanceContextRetriever;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.protocol.request.AccessGovernanceRequest;
import io.contexa.contexaiam.aiam.protocol.response.AccessGovernanceResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 권한 거버넌스 분석 Lab
 *
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지하는 AI Lab
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 * 
 * Lab 목표:
 * - 권한 배분 최적화: "우리 시스템의 권한 배분 상태가 전반적으로 건강하고 최적화되어 있는가?"
 * - 과도한 권한 탐지: "과도한 권한을 가진 사용자를 찾아줘"
 * - 미사용 권한 식별: "사용하지 않는 권한이 있나?"
 * - 권한 상속 경로 추적: "권한 상속 구조가 올바른가?"
 * - 업무 분리 위반 검사: "업무 분리 원칙에 위반되는 권한 배분이 있는가?"
 */
@Slf4j
public class AccessGovernanceLab extends AbstractIAMLab<AccessGovernanceRequest, AccessGovernanceResponse> {

    private final PipelineOrchestrator orchestrator;
    private final AccessVectorService accessVectorService;
    private final ApplicationEventPublisher eventPublisher;

    public AccessGovernanceLab(
            io.opentelemetry.api.trace.Tracer tracer,
            PipelineOrchestrator orchestrator,
            AccessGovernanceContextRetriever contextRetriever,
            AccessVectorService accessVectorService,
            ApplicationEventPublisher eventPublisher) {
        super(tracer, "AccessGovernance", "1.0", LabSpecialization.SECURITY_ANALYSIS);
        this.orchestrator = orchestrator;
        this.accessVectorService = accessVectorService;
        this.eventPublisher = eventPublisher;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected AccessGovernanceResponse doProcess(AccessGovernanceRequest request) throws Exception {
        return performAccessGovernanceAnalysis(request).block();
    }

    @Override
    protected Mono<AccessGovernanceResponse> doProcessAsync(AccessGovernanceRequest request) {
        return performAccessGovernanceAnalysis(request);
    }

    @Override
    protected Flux<String> doProcessStream(AccessGovernanceRequest request) {
        return processStreamingRequest(request);
    }

    /**
     * 핵심: 권한 거버넌스 분석 + Vector DB 저장 + StaticAccessAnalysisEvent 발행
     *
     * 의미 있는 문제점 발견 시 StaticAccessAnalysisEvent를 발행하여
     * AutonomousPolicySynthesizer가 수신하여 StaticAccessOptimizationLab으로 라우팅,
     * 권한 최적화 정책 생성으로 이어집니다.
     */
    private Mono<AccessGovernanceResponse> performAccessGovernanceAnalysis(AIRequest<AccessGovernanceContext> request) {
        log.info("[DIAGNOSIS] ===== 권한 거버넌스 분석 시작 ===== Scope: {}, Type: {}",
                request.getContext().getAuditScope(),
                request.getContext().getAnalysisType());

        return Mono.fromCallable(() -> {
                accessVectorService.storeAnalysisRequest(request.getContext());
                PipelineConfiguration config = createPipelineConfig();
                return orchestrator.execute(request, config, AccessGovernanceResponse.class)
                            .cast(AccessGovernanceResponse.class);
                })
                .flatMap(response -> response)
                .doOnSuccess(response -> {
                    AccessGovernanceResponse accessGovernanceResponse = (AccessGovernanceResponse)response;
                    accessVectorService.storeAnalysisResult(request.getContext(), accessGovernanceResponse);
                    log.info("[DIAGNOSIS] ===== 권한 거버넌스 분석 완료 ===== 점수: {}, 위험도: {}",
                            accessGovernanceResponse.getOverallGovernanceScore(), accessGovernanceResponse.getRiskLevel());

                    // StaticAccessAnalysisEvent 발행 (조건부: 의미 있는 문제점 발견 시)
                    if (hasSignificantFindings(accessGovernanceResponse)) {
                        publishStaticAccessAnalysisEvent(request.getContext(), accessGovernanceResponse);
                    }
                })
                .doOnError(error -> log.error("[DIAGNOSIS] ===== 권한 거버넌스 분석 실패 =====", error));
    }

    /**
     * 의미 있는 문제점 발견 여부 확인
     *
     * 발행 조건:
     * - 분석 결과에 문제점 존재 (findings.size() > 0)
     * - 미사용 권한 발견 (dormantPermissions > 0)
     * - 과도한 권한 탐지 (excessivePermissions > 0)
     * - 직무 분리 위반 (sodViolations > 0)
     *
     * @param response 권한 거버넌스 분석 응답
     * @return 의미 있는 문제점이 있으면 true
     */
    private boolean hasSignificantFindings(AccessGovernanceResponse response) {
        // 발견 사항 체크
        if (response.getFindings() != null && !response.getFindings().isEmpty()) {
            return true;
        }

        // 통계 정보 체크
        AccessGovernanceResponse.Statistics stats = response.getStatistics();
        if (stats != null) {
            return stats.getDormantPermissions() > 0 ||
                   stats.getExcessivePermissions() > 0 ||
                   stats.getSodViolations() > 0;
        }

        return false;
    }

    /**
     * StaticAccessAnalysisEvent 발행
     *
     * AutonomousPolicySynthesizer가 수신하여 StaticAccessOptimizationLab으로 라우팅,
     * 권한 감사 결과를 바탕으로 최적화 정책 생성으로 이어집니다.
     *
     * @param context 분석 컨텍스트
     * @param response 분석 응답
     */
    private void publishStaticAccessAnalysisEvent(AccessGovernanceContext context, AccessGovernanceResponse response) {
        try {
            // 분석 유형 결정
            StaticAccessAnalysisEvent.AnalysisType analysisType = determineAnalysisType(response);

            // Finding 변환
            List<StaticAccessAnalysisEvent.AccessFinding> findings = convertToAccessFindings(response);

            // Statistics에서 수치 추출
            AccessGovernanceResponse.Statistics stats = response.getStatistics();
            Integer totalPermissions = stats != null ? stats.getTotalPermissions() : null;
            Integer unusedPermissions = stats != null ? stats.getDormantPermissions() : null;
            Integer overPrivilegedCount = stats != null ? stats.getExcessivePermissions() : null;

            // Recommendations 변환
            Map<String, Object> recommendations = convertRecommendations(response);

            StaticAccessAnalysisEvent analysisEvent = StaticAccessAnalysisEvent.builder()
                .eventSource(this)
                .severity(response.getRiskLevel())
                .description("권한 거버넌스 감사 완료: " + response.getSummary())
                .analysisType(analysisType)
                .findings(findings)
                .analyzedResource(context.getAuditScope())
                .analyzedUser(null) // 전체 사용자 분석
                .totalPermissions(totalPermissions)
                .unusedPermissions(unusedPermissions)
                .overPrivilegedCount(overPrivilegedCount)
                .recommendations(recommendations)
                .additionalContext(buildAdditionalContext(context, response))
                .build();

            eventPublisher.publishEvent(analysisEvent);

            log.info("StaticAccessAnalysisEvent published: analysisType={}, findingsCount={}, " +
                     "unusedPermissions={}, overPrivilegedCount={}",
                analysisType, findings.size(), unusedPermissions, overPrivilegedCount);

        } catch (Exception e) {
            log.error("Failed to publish StaticAccessAnalysisEvent", e);
        }
    }

    /**
     * 분석 유형 결정
     */
    private StaticAccessAnalysisEvent.AnalysisType determineAnalysisType(AccessGovernanceResponse response) {
        AccessGovernanceResponse.Statistics stats = response.getStatistics();
        if (stats == null) {
            return StaticAccessAnalysisEvent.AnalysisType.ACCESS_REVIEW;
        }

        // 우선순위에 따라 분석 유형 결정
        if (stats.getSodViolations() > 0) {
            return StaticAccessAnalysisEvent.AnalysisType.SEPARATION_OF_DUTIES;
        }
        if (stats.getExcessivePermissions() > 0) {
            return StaticAccessAnalysisEvent.AnalysisType.OVER_PRIVILEGED;
        }
        if (stats.getDormantPermissions() > 0) {
            return StaticAccessAnalysisEvent.AnalysisType.UNUSED_PERMISSIONS;
        }

        return StaticAccessAnalysisEvent.AnalysisType.ACCESS_REVIEW;
    }

    /**
     * Finding 변환
     */
    private List<StaticAccessAnalysisEvent.AccessFinding> convertToAccessFindings(AccessGovernanceResponse response) {
        List<StaticAccessAnalysisEvent.AccessFinding> findings = new ArrayList<>();

        if (response.getFindings() != null) {
            for (AccessGovernanceResponse.Finding finding : response.getFindings()) {
                StaticAccessAnalysisEvent.AccessFinding accessFinding = StaticAccessAnalysisEvent.AccessFinding.builder()
                    .findingId(finding.getType() + "-" + System.currentTimeMillis())
                    .type(finding.getType())
                    .severity(finding.getSeverity())
                    .description(finding.getDescription())
                    .affectedUser(finding.getAffectedUsers() != null && !finding.getAffectedUsers().isEmpty()
                        ? String.join(", ", finding.getAffectedUsers()) : null)
                    .affectedRole(finding.getAffectedRoles() != null && !finding.getAffectedRoles().isEmpty()
                        ? String.join(", ", finding.getAffectedRoles()) : null)
                    .recommendation(finding.getRecommendation())
                    .riskScore(mapSeverityToRiskScore(finding.getSeverity()))
                    .build();

                findings.add(accessFinding);
            }
        }

        return findings;
    }

    /**
     * Severity를 Risk Score로 변환
     */
    private Integer mapSeverityToRiskScore(String severity) {
        if (severity == null) return 50;

        switch (severity.toUpperCase()) {
            case "CRITICAL": return 95;
            case "HIGH": return 80;
            case "MEDIUM": return 50;
            case "LOW": return 30;
            default: return 50;
        }
    }

    /**
     * Recommendations 변환
     */
    private Map<String, Object> convertRecommendations(AccessGovernanceResponse response) {
        Map<String, Object> recommendations = new HashMap<>();

        if (response.getRecommendations() != null) {
            for (int i = 0; i < response.getRecommendations().size(); i++) {
                AccessGovernanceResponse.Recommendation rec = response.getRecommendations().get(i);
                Map<String, Object> recMap = new HashMap<>();
                recMap.put("category", rec.getCategory());
                recMap.put("priority", rec.getPriority());
                recMap.put("title", rec.getTitle());
                recMap.put("description", rec.getDescription());
                recMap.put("steps", rec.getImplementationSteps());

                recommendations.put("recommendation_" + (i + 1), recMap);
            }
        }

        return recommendations;
    }

    /**
     * 추가 컨텍스트 빌드
     */
    private Map<String, Object> buildAdditionalContext(AccessGovernanceContext context, AccessGovernanceResponse response) {
        Map<String, Object> additionalContext = new HashMap<>();
        additionalContext.put("organizationId", context.getOrganizationId());
        additionalContext.put("analysisType", context.getAnalysisType());
        additionalContext.put("auditScope", context.getAuditScope());
        additionalContext.put("overallGovernanceScore", response.getOverallGovernanceScore());
        additionalContext.put("riskLevel", response.getRiskLevel());
        return additionalContext;
    }

    /**
     * 스트리밍 처리 (실시간 분석 과정 전달)
     */
    private Flux<String> processStreamingRequest(AccessGovernanceRequest request) {
        log.info("[STREAMING] 권한 거버넌스 분석 스트리밍 시작 - Scope: {}, Type: {}", 
                request.getContext().getAuditScope(), 
                request.getContext().getAnalysisType());

        AccessGovernanceContext context = request.getContext();
        accessVectorService.storeAnalysisRequest(context);
        PipelineConfiguration config = createStreamPipelineConfig();

        return orchestrator.executeStream(request, config)
                .doOnComplete(() -> log.info("[STREAMING] 권한 거버넌스 분석 스트리밍 완료"))
                .doOnError(error -> log.error("[STREAMING] 권한 거버넌스 분석 스트리밍 오류", error));
    }

    // 벡터 저장 관련 메서드들은 AccessVectorService로 이관됨

    /**
     * 관리자 피드백 학습
     */
    public void learnFromFeedback(String reportId, boolean isCorrect, String feedback) {
        log.info("피드백 학습: reportId={}, correct={}", reportId, isCorrect);
        accessVectorService.storeFeedback(reportId, isCorrect, feedback);
    }

    private AIRequest<AccessGovernanceContext> createAIRequest(AccessGovernanceContext context) {
        return new AIRequest<>(context, "accessGovernanceAnalysis", context.getOrganizationId());
    }

    private PipelineConfiguration createPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .enableCaching(true)
                .build();
    }

    private PipelineConfiguration createStreamPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .build();
    }
} 