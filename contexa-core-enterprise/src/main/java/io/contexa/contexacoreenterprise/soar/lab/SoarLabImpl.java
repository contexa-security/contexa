package io.contexa.contexacoreenterprise.soar.lab;

import io.opentelemetry.api.trace.Tracer;
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

    public SoarLabImpl(Tracer tracer, PipelineOrchestrator orchestrator) {
        super("SoarLab", tracer);
        this.orchestrator = orchestrator;

            }

    @Override
    protected SoarResponse doProcess(SoarRequest request) throws Exception {
        
        PipelineConfiguration<SoarContext> config = createPipelineConfiguration(request);

        AIRequest<SoarContext> aiRequest = new AIRequest<>(request.getContext(), "SOAR_ANALYSIS", request.getOrganizationId())
                .withParameter("query", request.getQuery())
                .withParameter("sessionId", request.getSessionId());

                return orchestrator.execute(aiRequest, config, SoarResponse.class).block();
    }

    @Override
    protected Mono<SoarResponse> doProcessAsync(SoarRequest request) {
        
        PipelineConfiguration<SoarContext> config = createPipelineConfiguration(request);

        return orchestrator.execute(request, config, SoarResponse.class)
                .cast(SoarResponse.class)
                .doOnSuccess(response -> log.info("[DefaultSoarLab] PipelineOrchestrator 비동기 처리 완료: {}", request.getSessionId()));
    }

    @Override
    protected Flux<String> doProcessStream(SoarRequest request) {
        
        return Flux.defer(() -> {
            try {
                
                PipelineConfiguration<SoarContext> config = createPipelineConfiguration(request);

                return orchestrator.executeStream(request, config)
                        .cast(String.class)
                        .doOnNext(chunk -> log.debug("[DefaultSoarLab] 스트리밍 청크 수신: {}", chunk.length()))
                        .doOnComplete(() -> log.info("[DefaultSoarLab] PipelineOrchestrator 스트리밍 처리 완료: {}", request.getSessionId()))
                        .doOnError(error -> log.error("[DefaultSoarLab] PipelineOrchestrator 스트리밍 처리 실패: {}", error.getMessage()));

            } catch (Exception e) {
                log.error("[DefaultSoarLab] 스트리밍 처리 실패: {}", e.getMessage(), e);
                return Flux.error(e);
            }
        });
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    private PipelineConfiguration createPipelineConfiguration(SoarRequest request) {
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
