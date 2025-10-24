package io.contexa.contexacore.soar.lab;

import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * SOAR AI 연구소 기본 구현체
 *
 * PipelineOrchestrator를 통한 6단계 파이프라인을 활용하여
 * 보안 위협 분석과 대응 전략을 수립합니다.
 * AbstractAILab을 상속하여 Template Method Pattern과 Pipeline Pattern을 결합
 */
@Slf4j
@Component
public class SoarLab extends AbstractAILab<SoarRequest, SoarResponse>  {

    private final PipelineOrchestrator orchestrator;

    public SoarLab(Tracer tracer, PipelineOrchestrator orchestrator) {
        super("SoarLab", tracer);
        this.orchestrator = orchestrator;

        log.info("AdvancedPolicyGenerationLab 초기화 완료 - PipelineOrchestrator 기반 (스트리밍→StreamingUniversalPipelineExecutor 자동선택)");
    }

    @Override
    protected SoarResponse doProcess(SoarRequest request) throws Exception {
        log.info("[DefaultSoarLab] PipelineOrchestrator를 통한 SOAR 처리 시작: {}", request.getSessionId());

        PipelineConfiguration<SoarContext> config = createPipelineConfiguration(request);

        AIRequest<SoarContext> aiRequest = new AIRequest<>(request.getContext(), "SOAR_ANALYSIS", request.getOrganizationId())
                .withParameter("query", request.getQuery())
                .withParameter("sessionId", request.getSessionId());

        log.info("[DefaultSoarLab] PipelineOrchestrator 처리 완료: {}", request.getSessionId());
        return orchestrator.execute(aiRequest, config, SoarResponse.class).block();
    }

    @Override
    protected Mono<SoarResponse> doProcessAsync(SoarRequest request) {
        log.info("[DefaultSoarLab] PipelineOrchestrator를 통한 비동기 SOAR 처리 시작: {}", request.getSessionId());

        PipelineConfiguration<SoarContext> config = createPipelineConfiguration(request);

        return orchestrator.execute(request, config, SoarResponse.class)
                .cast(SoarResponse.class)
                .doOnSuccess(response -> log.info("[DefaultSoarLab] PipelineOrchestrator 비동기 처리 완료: {}", request.getSessionId()));
    }

    @Override
    protected Flux<String> doProcessStream(SoarRequest request) {
        log.info("[DefaultSoarLab] PipelineOrchestrator를 통한 스트리밍 SOAR 처리 시작: {}", request.getSessionId());

        return Flux.defer(() -> {
            try {
                // 파이프라인 구성 생성 (request 전달하여 도구 실행 필요 여부 판단)
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
