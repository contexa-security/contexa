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

@Slf4j
public class AccessGovernanceLab extends AbstractIAMLab<AccessGovernanceRequest, AccessGovernanceResponse> {

    private final PipelineOrchestrator orchestrator;
    private final AccessVectorService accessVectorService;
    private final ApplicationEventPublisher eventPublisher;

    public AccessGovernanceLab(
            PipelineOrchestrator orchestrator,
            AccessGovernanceContextRetriever contextRetriever,
            AccessVectorService accessVectorService,
            ApplicationEventPublisher eventPublisher) {
        super("AccessGovernance", "1.0", LabSpecialization.SECURITY_ANALYSIS);
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

    private Mono<AccessGovernanceResponse> performAccessGovernanceAnalysis(AIRequest<AccessGovernanceContext> request) {
        
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

                    if (hasSignificantFindings(accessGovernanceResponse)) {
                        publishStaticAccessAnalysisEvent(request.getContext(), accessGovernanceResponse);
                    }
                })
                .doOnError(error -> log.error("[DIAGNOSIS] ===== 권한 거버넌스 분석 실패 =====", error));
    }

    private boolean hasSignificantFindings(AccessGovernanceResponse response) {
        
        if (response.getFindings() != null && !response.getFindings().isEmpty()) {
            return true;
        }

        AccessGovernanceResponse.Statistics stats = response.getStatistics();
        if (stats != null) {
            return stats.getDormantPermissions() > 0 ||
                   stats.getExcessivePermissions() > 0 ||
                   stats.getSodViolations() > 0;
        }

        return false;
    }

    private void publishStaticAccessAnalysisEvent(AccessGovernanceContext context, AccessGovernanceResponse response) {
        try {
            
            StaticAccessAnalysisEvent.AnalysisType analysisType = determineAnalysisType(response);

            List<StaticAccessAnalysisEvent.AccessFinding> findings = convertToAccessFindings(response);

            AccessGovernanceResponse.Statistics stats = response.getStatistics();
            Integer totalPermissions = stats != null ? stats.getTotalPermissions() : null;
            Integer unusedPermissions = stats != null ? stats.getDormantPermissions() : null;
            Integer overPrivilegedCount = stats != null ? stats.getExcessivePermissions() : null;

            Map<String, Object> recommendations = convertRecommendations(response);

            StaticAccessAnalysisEvent analysisEvent = StaticAccessAnalysisEvent.builder()
                .eventSource(this)
                .severity(response.getRiskLevel())
                .description("권한 거버넌스 감사 완료: " + response.getSummary())
                .analysisType(analysisType)
                .findings(findings)
                .analyzedResource(context.getAuditScope())
                .analyzedUser(null) 
                .totalPermissions(totalPermissions)
                .unusedPermissions(unusedPermissions)
                .overPrivilegedCount(overPrivilegedCount)
                .recommendations(recommendations)
                .additionalContext(buildAdditionalContext(context, response))
                .build();

            eventPublisher.publishEvent(analysisEvent);

        } catch (Exception e) {
            log.error("Failed to publish StaticAccessAnalysisEvent", e);
        }
    }

    private StaticAccessAnalysisEvent.AnalysisType determineAnalysisType(AccessGovernanceResponse response) {
        AccessGovernanceResponse.Statistics stats = response.getStatistics();
        if (stats == null) {
            return StaticAccessAnalysisEvent.AnalysisType.ACCESS_REVIEW;
        }

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

    private Integer mapSeverityToRiskScore(String severity) {

        return 50;
    }

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

    private Map<String, Object> buildAdditionalContext(AccessGovernanceContext context, AccessGovernanceResponse response) {
        Map<String, Object> additionalContext = new HashMap<>();
        additionalContext.put("organizationId", context.getOrganizationId());
        additionalContext.put("analysisType", context.getAnalysisType());
        additionalContext.put("auditScope", context.getAuditScope());
        additionalContext.put("overallGovernanceScore", response.getOverallGovernanceScore());
        additionalContext.put("riskLevel", response.getRiskLevel());
        return additionalContext;
    }

    private Flux<String> processStreamingRequest(AccessGovernanceRequest request) {
        
        AccessGovernanceContext context = request.getContext();
        accessVectorService.storeAnalysisRequest(context);
        PipelineConfiguration config = createStreamPipelineConfig();

        return orchestrator.executeStream(request, config)
                .doOnComplete(() -> log.info("[STREAMING] 권한 거버넌스 분석 스트리밍 완료"))
                .doOnError(error -> log.error("[STREAMING] 권한 거버넌스 분석 스트리밍 오류", error));
    }

    public void learnFromFeedback(String reportId, boolean isCorrect, String feedback) {
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