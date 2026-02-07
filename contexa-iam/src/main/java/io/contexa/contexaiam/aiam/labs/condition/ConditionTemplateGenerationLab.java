package io.contexa.contexaiam.aiam.labs.condition;

import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
public class ConditionTemplateGenerationLab
        extends AbstractIAMLab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> {

    private final PipelineOrchestrator orchestrator;

    public ConditionTemplateGenerationLab(PipelineOrchestrator orchestrator) {
        super("ConditionTemplateGeneration", "2.0", LabSpecialization.RECOMMENDATION_SYSTEM);
        this.orchestrator = orchestrator;
    }

    @Override
    protected ConditionTemplateGenerationResponse doProcess(
            ConditionTemplateGenerationRequest request) throws Exception {
        return processConditionTemplateAsync(request).block();
    }

    @Override
    protected Mono<ConditionTemplateGenerationResponse> doProcessAsync(
            ConditionTemplateGenerationRequest request) {
        return processConditionTemplateAsync(request);
    }

    private Mono<ConditionTemplateGenerationResponse> processConditionTemplateAsync(
            ConditionTemplateGenerationRequest request) {

        PipelineConfiguration<ConditionTemplateContext> config = createPipelineConfig();

        return orchestrator.execute(request, config, ConditionTemplateGenerationResponse.class)
                .map(response -> {
                    if (response == null) {
                        return createFailureResponse(request);
                    }
                    return response;
                })
                .onErrorResume(error -> {
                    log.error("Condition template async generation failed", error);
                    return Mono.just(createFailureResponse(request));
                });
    }

    private PipelineConfiguration<ConditionTemplateContext> createPipelineConfig() {
        return (PipelineConfiguration<ConditionTemplateContext>) PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(30)
                .build();
    }

    private ConditionTemplateGenerationResponse createFailureResponse(
            ConditionTemplateGenerationRequest request) {
        String templateType = request.getContext().getTemplateType();
        String resourceId = request.getContext().getResourceIdentifier();
        return ConditionTemplateGenerationResponse.failure(
                templateType, resourceId, "Pipeline returned null or failed");
    }
}
