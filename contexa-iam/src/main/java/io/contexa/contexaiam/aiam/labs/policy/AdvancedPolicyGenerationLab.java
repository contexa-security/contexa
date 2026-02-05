package io.contexa.contexaiam.aiam.labs.policy;

import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.domain.dto.AiGeneratedPolicyDraftDto;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@Slf4j
public class AdvancedPolicyGenerationLab extends AbstractIAMLab<PolicyGenerationRequest, PolicyResponse> {

    private final PipelineOrchestrator orchestrator;
    private final IAMDataCollectionService dataCollectionService;
    private final PolicyGenerationVectorService vectorService;

    public AdvancedPolicyGenerationLab(PipelineOrchestrator orchestrator,
                                       IAMDataCollectionService dataCollectionService,
                                       PolicyGenerationVectorService vectorService) {
        super("AdvancedPolicyGenerationLab", "2.0.0", LabSpecialization.POLICY_GENERATION);
        this.orchestrator = orchestrator;
        this.dataCollectionService = dataCollectionService;
        this.vectorService = vectorService;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected PolicyResponse doProcess(PolicyGenerationRequest request) throws Exception {
        AiGeneratedPolicyDraftDto policyDraft = processRequestAsync(request).block();
        return convertDtoToPolicyResponse(policyDraft, "sync-request-id");
    }

    @Override
    protected Mono<PolicyResponse> doProcessAsync(PolicyGenerationRequest request) {
        return processRequestAsync(request)
        .map(policyDraft -> convertDtoToPolicyResponse(policyDraft, "async-request-id"));
    }

    @Override
    protected Flux<String> doProcessStream(PolicyGenerationRequest request) {
        return processRequestAsyncStream(request);
    }

    private Mono<AiGeneratedPolicyDraftDto> processRequestAsync(PolicyGenerationRequest request) {

        try {
            vectorService.storePolicyGenerationRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }
        return Mono.fromCallable(() -> {
                    return request;
                })
                .flatMap(aiRequest -> {
                    return orchestrator.execute(aiRequest,createStudioQueryPipelineConfig(), PolicyResponse.class);
                })
                .map(response -> {
                    if (response == null) {
                        log.warn("비동기 Pipeline에서 null 응답 수신, fallback 생성");
                        return createFallbackPolicyData(request.getNaturalLanguageQuery());
                    }

                    try {
                        AiGeneratedPolicyDraftDto policyDto = convertPolicyResponseToDto((PolicyResponse) response, request.getNaturalLanguageQuery());
                        vectorService.storeGeneratedPolicy(request, policyDto);
                        return policyDto;
                    } catch (Exception e) {
                        log.error("벡터 저장소 정책 저장 실패", e);
                        return convertPolicyResponseToDto((PolicyResponse) response, request.getNaturalLanguageQuery());
                    }
                })
                .doOnError(error -> {
                    if (error instanceof Throwable) {
                        log.error("[DIAGNOSIS] AI 정책 진단 생성 실패: {}", ((Throwable) error).getMessage(), (Throwable) error);
                    }
                })
                .onErrorResume(error -> {
                    log.error("AI 정책 비동기 생성 실패", error);
                    return Mono.just(createFallbackPolicyData(request.getNaturalLanguageQuery()));
                });
    }

    private Flux<String> processRequestAsyncStream(PolicyGenerationRequest request){

        try {

            AIRequest<PolicyContext> aiRequest = createPolicyGenerationStreamingRequest(request);

            Flux<String> streamingFlux = orchestrator.executeStream(aiRequest, createStudioQueryStreamPipelineConfig());
            return streamingFlux
                    .map(this::cleanStreamingChunk)
                    .concatWith(Mono.just("[DONE]"))
                    .doOnError(error -> {
                        log.error("실제 스트리밍 중 오류 발생", error);
                    })
                    .onErrorResume(error -> {
                        log.error("실제 스트리밍 실패, 에러 메시지 반환", error);
                        return Flux.just("ERROR: AI 서비스 연결 실패: " + error.getMessage(), "[DONE]");
                    });

        } catch (Exception e) {
            log.error("실제 AI 스트리밍 초기화 실패", e);
            return Flux.just("ERROR: 실제 스트리밍 초기화 실패: " + e.getMessage(), "[DONE]");
        }
    }

    private PipelineConfiguration<PolicyContext> createStudioQueryPipelineConfig() {
        return (PipelineConfiguration<PolicyContext>) PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .build();
    }

    private PipelineConfiguration<PolicyContext> createStudioQueryStreamPipelineConfig() {
        return (PipelineConfiguration<PolicyContext>) PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .enableStreaming(true)
                .timeoutSeconds(300)
                .build();
    }

    private PolicyResponse convertDtoToPolicyResponse(AiGeneratedPolicyDraftDto dto, String requestId) {
        PolicyResponse response = new PolicyResponse(requestId, AIResponse.ExecutionStatus.SUCCESS);
        response.setPolicyData(dto.policyData());
        response.setRoleIdToNameMap(dto.roleIdToNameMap());
        response.setPermissionIdToNameMap(dto.permissionIdToNameMap());
        response.setConditionIdToNameMap(dto.conditionIdToNameMap());
        return response;
    }

    private AIRequest<PolicyContext> createPolicyGenerationStreamingRequest(PolicyGenerationRequest request) {

        if (request.getAvailableItems() == null) {
            request.setAvailableItems(dataCollectionService.policyCollectData());
            request.withParameter("availableItems", dataCollectionService.policyCollectData());
        }
        if (request.getAvailableItems() != null) {
            request.withParameter("systemMetadata", buildSystemMetadataFromAvailableItems(request.getAvailableItems()));
        }

        return request;
    }

    private String buildSystemMetadataFromAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        StringBuilder metadata = new StringBuilder();
        metadata.append("현재 사용 가능한 항목들 (반드시 이 ID들만 사용하세요):\n\n");

        if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
            metadata.append("사용 가능한 역할:\n");
            availableItems.roles().forEach(role ->
                    metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n",
                            role.id(), role.name(), role.description() != null ? role.description() : "")));
        } else {
            metadata.append("사용 가능한 역할: 없음\n");
        }

        if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
            metadata.append("\n🔑 사용 가능한 권한:\n");
            availableItems.permissions().forEach(perm ->
                    metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n",
                            perm.id(), perm.name(), perm.description() != null ? perm.description() : "")));
        } else {
            metadata.append("\n🔑 사용 가능한 권한: 없음\n");
        }

        if (availableItems.conditions() != null && !availableItems.conditions().isEmpty()) {
            metadata.append("\n⏰ 사용 가능한 조건 템플릿:\n");
            availableItems.conditions().forEach(cond ->
                    metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s, 호환가능: %s\n",
                            cond.id(), cond.name(),
                            cond.description() != null ? cond.description() : "",
                            cond.isCompatible() != null ? cond.isCompatible() : true)));
        } else {
            metadata.append("\n⏰ 사용 가능한 조건 템플릿: 없음\n");
        }

        metadata.append("\n경고: 위에 나열된 ID들 외의 다른 ID는 절대 사용하지 마세요. 존재하지 않는 ID를 사용하면 시스템 오류가 발생합니다.\n");

        return metadata.toString();
    }

    private String cleanStreamingChunk(String chunk) {
        if (chunk == null || chunk.isEmpty()) {
            return "";
        }

        try {
            byte[] bytes = chunk.getBytes(StandardCharsets.UTF_8);
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            String cleaned = decoded.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
            return cleaned;
        } catch (Exception e) {
            log.warn("스트리밍 청크 정제 실패: {}", e.getMessage());
            return chunk;
        }
    }

    private AiGeneratedPolicyDraftDto convertPolicyResponseToDto(PolicyResponse policyResponse, String naturalLanguageQuery) {
        if (policyResponse == null) {
            log.warn("PolicyResponse가 null, fallback 생성");
            return createFallbackPolicyData(naturalLanguageQuery);
        }

        if (policyResponse.getPolicyData() != null) {
            return new AiGeneratedPolicyDraftDto(
                    policyResponse.getPolicyData(),
                    policyResponse.getRoleIdToNameMap(),
                    policyResponse.getPermissionIdToNameMap(),
                    policyResponse.getConditionIdToNameMap()
            );
        }

        if (policyResponse.getGeneratedPolicy() != null && !policyResponse.getGeneratedPolicy().trim().isEmpty()) {
            return validateAndOptimizePolicyResult(policyResponse.getGeneratedPolicy(), naturalLanguageQuery);
        }

        log.warn("PolicyResponse에 유효한 데이터가 없음, fallback 생성");
        return createFallbackPolicyData(naturalLanguageQuery);
    }

    private AiGeneratedPolicyDraftDto validateAndOptimizePolicyResult(String jsonResponse, String naturalLanguageQuery) {
        if (jsonResponse == null || jsonResponse.trim().isEmpty()) {
            log.warn("빈 JSON 응답, fallback 사용");
            return createFallbackPolicyData(naturalLanguageQuery);
        }

        try {

            if (jsonResponse.contains("{") && jsonResponse.contains("}")) {
            }

            return createFallbackPolicyData(naturalLanguageQuery);

        } catch (Exception e) {
            log.error("JSON 검증 실패, fallback 사용", e);
            return createFallbackPolicyData(naturalLanguageQuery);
        }
    }

    private AiGeneratedPolicyDraftDto createFallbackPolicyData(String naturalLanguageQuery) {
        log.warn("Fallback 정책 데이터 생성: {}", naturalLanguageQuery);

        BusinessPolicyDto fallbackPolicy = new BusinessPolicyDto();
        fallbackPolicy.setPolicyName("AI 생성 정책 (Fallback)");
        fallbackPolicy.setDescription("요청: " + (naturalLanguageQuery != null ? naturalLanguageQuery : "알 수 없음"));

        return new AiGeneratedPolicyDraftDto(
                fallbackPolicy,
                Map.of(),
                Map.of(),
                Map.of()
        );
    }
}