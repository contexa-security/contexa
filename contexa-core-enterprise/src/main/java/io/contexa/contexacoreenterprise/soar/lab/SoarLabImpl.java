package io.contexa.contexacoreenterprise.soar.lab;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class SoarLabImpl extends AbstractAILab<SoarRequest, SoarResponse>  {

    private final PipelineOrchestrator orchestrator;

    public SoarLabImpl(PipelineOrchestrator orchestrator) {
        super("SoarLab");
        this.orchestrator = orchestrator;
    }

    @Override
    protected SoarResponse doProcess(SoarRequest request) throws Exception {
        
        PipelineConfiguration config = createPipelineConfiguration();

        AIRequest<SoarContext> aiRequest = new AIRequest<>(request.getContext(), new TemplateType("Soar"), new DiagnosisType("Soar"))
                .withParameter("query", request.getQuery())
                .withParameter("sessionId", request.getSessionId());

                return orchestrator.execute(aiRequest, config, SoarResponse.class).block();
    }

    @Override
    protected Mono<SoarResponse> doProcessAsync(SoarRequest request) {
        
        PipelineConfiguration config = createPipelineConfiguration();

        return orchestrator.execute(request, config, SoarResponse.class)
                .cast(SoarResponse.class);
    }

    @Override
    protected Flux<String> doProcessStream(SoarRequest request) {
        
        return Flux.defer(() -> {
            try {
                
                PipelineConfiguration config = createPipelineConfiguration();

                return orchestrator.executeStream(request, config)
                        .cast(String.class)
                        .doOnError(error -> log.error("[DefaultSoarLab] PipelineOrchestrator streaming failed: {}", error.getMessage()));

            } catch (Exception e) {
                log.error("[DefaultSoarLab] Streaming processing failed: {}", e.getMessage(), e);
                return Flux.error(e);
            }
        });
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    private PipelineConfiguration createPipelineConfiguration() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .build();
    }
}
