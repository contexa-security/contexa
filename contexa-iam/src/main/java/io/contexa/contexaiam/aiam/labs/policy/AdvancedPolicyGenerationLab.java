package io.contexa.contexaiam.aiam.labs.policy;

import io.contexa.contexacommon.domain.LabSpecialization;
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
            log.error("Vector store request storage failed", e);
        }
        return Mono.fromCallable(() -> enrichRequest(request, false))
                .flatMap(enrichedRequest -> {
                    return orchestrator.execute(enrichedRequest, createPolicyPipelineConfig(), PolicyResponse.class);
                })
                .map(response -> {
                    if (response == null) {
                        log.error("Null response received from async Pipeline, generating fallback");
                        return createFallbackPolicyData(request.getNaturalLanguageQuery());
                    }

                    try {
                        AiGeneratedPolicyDraftDto policyDto = convertPolicyResponseToDto((PolicyResponse) response, request.getNaturalLanguageQuery());
                        vectorService.storeGeneratedPolicy(request, policyDto);
                        return policyDto;
                    } catch (Exception e) {
                        log.error("Vector store policy storage failed", e);
                        return convertPolicyResponseToDto((PolicyResponse) response, request.getNaturalLanguageQuery());
                    }
                })
                .doOnError(error -> {
                    if (error instanceof Throwable) {
                        log.error("[DIAGNOSIS] AI policy diagnosis generation failed: {}", ((Throwable) error).getMessage(), (Throwable) error);
                    }
                })
                .onErrorResume(error -> {
                    log.error("AI policy async generation failed", error);
                    return Mono.just(createFallbackPolicyData(request.getNaturalLanguageQuery()));
                });
    }

    private Flux<String> processRequestAsyncStream(PolicyGenerationRequest request) {
        return Flux.defer(() -> {
            try {
                PolicyGenerationRequest enrichedRequest = enrichRequest(request, true);
                return orchestrator.executeStream(enrichedRequest, createPolicyStreamPipelineConfig())
                        .map(this::cleanStreamingChunk)
                        .concatWith(Mono.just("[DONE]"))
                        .doOnError(error -> {
                            log.error("Streaming error occurred", error);
                        })
                        .onErrorResume(error -> {
                            log.error("Streaming failed, returning error message", error);
                            return Flux.just("ERROR: AI service connection failed: " + error.getMessage(), "[DONE]");
                        });
            } catch (Exception e) {
                log.error("AI streaming initialization failed", e);
                return Flux.just("ERROR: Streaming initialization failed: " + e.getMessage(), "[DONE]");
            }
        });
    }

    /**
     * Enriches the request with IAM data context and system metadata.
     * Common logic extracted from processRequestAsync and processRequestAsyncStream.
     * <p>
     * This follows the same pattern as StudioQueryLab.enrichRequest():
     * - "iamDataContext": Formatted IAM data for AbstractBasePromptTemplate.extractContextInfo()
     * - "systemMetadata": System metadata for prompt generation
     * </p>
     *
     * @param request the original request
     * @param isStreaming true if streaming mode, false otherwise
     * @return the enriched request
     */
    private PolicyGenerationRequest enrichRequest(PolicyGenerationRequest request, boolean isStreaming) {
        if (request.getAvailableItems() == null) {
            PolicyGenerationItem.AvailableItems availableItems = dataCollectionService.policyCollectData();
            request.setAvailableItems(availableItems);
        }

        String formattedData = buildSystemMetadataFromAvailableItems(request.getAvailableItems());
        request.withParameter("iamDataContext", formattedData);
        request.withParameter("systemMetadata", formattedData);

        if (isStreaming) {
            request.withParameter("requestType", "policy_generation_streaming");
            request.withParameter("outputFormat", "natural_language");
        } else {
            request.withParameter("requestType", "policy_generation");
            request.withParameter("outputFormat", "json_object");
        }

        return request;
    }

    private PipelineConfiguration<PolicyContext> createPolicyPipelineConfig() {
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

    private PipelineConfiguration<PolicyContext> createPolicyStreamPipelineConfig() {
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

    private String buildSystemMetadataFromAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        StringBuilder metadata = new StringBuilder();
        metadata.append("Available items (use only these IDs):\n\n");

        if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
            metadata.append("[Available Roles]\n");
            availableItems.roles().forEach(role ->
                    metadata.append(String.format("- ID: %d, Name: %s, Description: %s\n",
                            role.id(), role.name(), role.description() != null ? role.description() : "")));
        } else {
            metadata.append("[Available Roles] None\n");
        }

        if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
            metadata.append("\n[Available Permissions]\n");
            availableItems.permissions().forEach(perm ->
                    metadata.append(String.format("- ID: %d, Name: %s, Description: %s\n",
                            perm.id(), perm.name(), perm.description() != null ? perm.description() : "")));
        } else {
            metadata.append("\n[Available Permissions] None\n");
        }

        if (availableItems.conditions() != null && !availableItems.conditions().isEmpty()) {
            metadata.append("\n[Available Condition Templates]\n");
            availableItems.conditions().forEach(cond ->
                    metadata.append(String.format("- ID: %d, Name: %s, Description: %s, Compatible: %s\n",
                            cond.id(), cond.name(),
                            cond.description() != null ? cond.description() : "",
                            cond.isCompatible() != null ? cond.isCompatible() : true)));
        } else {
            metadata.append("\n[Available Condition Templates] None\n");
        }

        metadata.append("\nWarning: Do not use any IDs other than those listed above. Using non-existent IDs will cause system errors.\n");

        return metadata.toString();
    }

    private String cleanStreamingChunk(String chunk) {
        if (chunk == null || chunk.isEmpty()) {
            return "";
        }

        try {
            byte[] bytes = chunk.getBytes(StandardCharsets.UTF_8);
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            return decoded.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
        } catch (Exception e) {
            log.error("Streaming chunk cleanup failed: {}", e.getMessage());
            return chunk;
        }
    }

    private AiGeneratedPolicyDraftDto convertPolicyResponseToDto(PolicyResponse policyResponse, String naturalLanguageQuery) {
        if (policyResponse == null) {
            log.error("PolicyResponse is null, generating fallback");
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

        log.error("PolicyResponse has no valid data, generating fallback");
        return createFallbackPolicyData(naturalLanguageQuery);
    }

    private AiGeneratedPolicyDraftDto validateAndOptimizePolicyResult(String jsonResponse, String naturalLanguageQuery) {
        if (jsonResponse == null || jsonResponse.trim().isEmpty()) {
            log.error("Empty JSON response, using fallback");
            return createFallbackPolicyData(naturalLanguageQuery);
        }

        try {

            if (jsonResponse.contains("{") && jsonResponse.contains("}")) {
            }

            return createFallbackPolicyData(naturalLanguageQuery);

        } catch (Exception e) {
            log.error("JSON validation failed, using fallback", e);
            return createFallbackPolicyData(naturalLanguageQuery);
        }
    }

    private AiGeneratedPolicyDraftDto createFallbackPolicyData(String naturalLanguageQuery) {
        log.error("Generating fallback policy data: {}", naturalLanguageQuery);

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